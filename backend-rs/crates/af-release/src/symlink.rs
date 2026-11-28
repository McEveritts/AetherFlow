//! Stage 2, Stage 4 & Stage 5: Atomic symlink swaps (`ln -s` + `rename` / `mv -Tf`),
//! `.previous_release` tracking, and oldest-release pruning (`cleanup_old_releases`).

use crate::error::{ReleaseError, ReleaseResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Resolves the target of `current_link` if it exists.
/// On Unix, reads the symlink and canonicalizes if possible; on non-Unix test environments,
/// also supports reading a `.af_symlink_target` pointer file when OS symlinks are unprivileged.
pub fn read_current_link_target(current_link: &Path) -> Option<PathBuf> {
    if let Ok(target) = fs::read_link(current_link) {
        let resolved = if target.is_relative() {
            current_link
                .parent()
                .map(|p| p.join(&target))
                .unwrap_or(target)
        } else {
            target
        };
        return Some(canonicalize_preserve_normal(&resolved));
    }

    #[cfg(not(unix))]
    {
        if current_link.is_file() {
            if let Ok(raw) = fs::read_to_string(current_link) {
                if let Some(rest) = raw.trim().strip_prefix("AF_SYMLINK:") {
                    let p = PathBuf::from(rest.trim());
                    return Some(canonicalize_preserve_normal(&p));
                }
            }
        }
    }

    None
}

/// Strips Windows `\\?\` verbatim prefix if `fs::canonicalize` produces one so path comparisons
/// remain consistent across `.previous_release` and directory listings.
pub fn canonicalize_preserve_normal(path: &Path) -> PathBuf {
    match fs::canonicalize(path) {
        Ok(canon) => {
            let s = canon.to_string_lossy();
            if let Some(stripped) = s.strip_prefix(r"\\?\") {
                PathBuf::from(stripped)
            } else {
                canon
            }
        }
        Err(_) => path.to_path_buf(),
    }
}

/// Creates a directory symlink from `current_link -> target_dir` and atomically renames it over `current_link`.
///
/// On Unix, uses `std::os::unix::fs::symlink(target_dir, &tmp_link)` followed by `fs::rename(&tmp_link, current_link)`
/// (POSIX atomic `rename(2)` over an existing symlink, equivalent to `ln -s ... && mv -Tf ...`).
pub fn atomic_replace_symlink(
    current_link: &Path,
    target_dir: &Path,
    suffix_tag: &str,
) -> ReleaseResult<()> {
    if !target_dir.is_dir() {
        return Err(ReleaseError::SymlinkSwap {
            link: current_link.to_path_buf(),
            target: target_dir.to_path_buf(),
            reason: format!(
                "target release directory does not exist: {}",
                target_dir.display()
            ),
        });
    }
    atomic_replace_symlink_unchecked(current_link, target_dir, suffix_tag)
}

/// Atomically replaces `link_path` with a symlink pointing to an existing regular file `target_file`.
pub fn atomic_replace_file_symlink(
    link_path: &Path,
    target_file: &Path,
    suffix_tag: &str,
) -> ReleaseResult<()> {
    if !target_file.is_file() {
        return Err(ReleaseError::SymlinkSwap {
            link: link_path.to_path_buf(),
            target: target_file.to_path_buf(),
            reason: format!("target file does not exist: {}", target_file.display()),
        });
    }
    atomic_replace_symlink_unchecked(link_path, target_file, suffix_tag)
}

fn atomic_replace_symlink_unchecked(
    current_link: &Path,
    target_path: &Path,
    suffix_tag: &str,
) -> ReleaseResult<()> {
    let parent = match current_link.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    crate::fs_security::create_dir_all_no_symlinks(parent, 0o755)?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;

        let leaf = current_link
            .file_name()
            .ok_or_else(|| ReleaseError::SymlinkSwap {
                link: current_link.to_path_buf(),
                target: target_path.to_path_buf(),
                reason: "symlink path has no leaf component".to_string(),
            })?;
        let leaf_c = CString::new(leaf.as_bytes()).map_err(|_| ReleaseError::SymlinkSwap {
            link: current_link.to_path_buf(),
            target: target_path.to_path_buf(),
            reason: "symlink leaf name contains NUL byte".to_string(),
        })?;
        let target_c = CString::new(target_path.as_os_str().as_bytes()).map_err(|_| {
            ReleaseError::SymlinkSwap {
                link: current_link.to_path_buf(),
                target: target_path.to_path_buf(),
                reason: "symlink target path contains NUL byte".to_string(),
            }
        })?;
        let tmp_name = format!(
            "{}.{}.{}.{}",
            leaf.to_string_lossy(),
            suffix_tag,
            nanos,
            uuid::Uuid::new_v4()
        );
        let tmp_c = CString::new(tmp_name.as_bytes()).map_err(|_| ReleaseError::SymlinkSwap {
            link: current_link.to_path_buf(),
            target: target_path.to_path_buf(),
            reason: "temporary symlink name contains NUL byte".to_string(),
        })?;

        let parent_dir = crate::fs_security::open_dir_nofollow(parent)?;
        let parent_dfd = parent_dir.as_raw_fd();

        if unsafe { libc::symlinkat(target_c.as_ptr(), parent_dfd, tmp_c.as_ptr()) } != 0 {
            let err = std::io::Error::last_os_error();
            return Err(ReleaseError::SymlinkSwap {
                link: current_link.to_path_buf(),
                target: target_path.to_path_buf(),
                reason: format!(
                    "failed to create temporary symlink {}: {}",
                    parent.join(&tmp_name).display(),
                    err
                ),
            });
        }

        if unsafe { libc::renameat(parent_dfd, tmp_c.as_ptr(), parent_dfd, leaf_c.as_ptr()) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::unlinkat(parent_dfd, tmp_c.as_ptr(), 0);
            }
            return Err(ReleaseError::SymlinkSwap {
                link: current_link.to_path_buf(),
                target: target_path.to_path_buf(),
                reason: format!(
                    "failed to atomically replace {} -> {}: {}",
                    parent.join(&tmp_name).display(),
                    current_link.display(),
                    err
                ),
            });
        }

        crate::fs_security::sync_dir_fd(parent_dfd, parent)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let tmp_link = PathBuf::from(format!(
            "{}.{}.{}.{}",
            current_link.display(),
            suffix_tag,
            nanos,
            uuid::Uuid::new_v4()
        ));

        create_symlink_or_pointer(&tmp_link, target_path).map_err(|e| {
            ReleaseError::SymlinkSwap {
                link: current_link.to_path_buf(),
                target: target_path.to_path_buf(),
                reason: format!(
                    "failed to create temporary symlink {}: {}",
                    tmp_link.display(),
                    e
                ),
            }
        })?;

        // On Windows, renaming a directory symlink over an existing directory symlink can fail
        // with AccessDenied unless the destination symlink is removed first.
        if fs::symlink_metadata(current_link).is_ok() {
            let _ = fs::remove_dir(current_link).or_else(|_| fs::remove_file(current_link));
        }

        fs::rename(&tmp_link, current_link).map_err(|e| {
            let _ = fs::remove_file(&tmp_link);
            ReleaseError::SymlinkSwap {
                link: current_link.to_path_buf(),
                target: target_path.to_path_buf(),
                reason: format!(
                    "failed to atomically replace {} -> {}: {}",
                    tmp_link.display(),
                    current_link.display(),
                    e
                ),
            }
        })?;

        crate::fs_security::sync_parent_dir_best_effort(parent);
        Ok(())
    }
}

#[cfg(windows)]
fn create_symlink_or_pointer(link_path: &Path, target_dir: &Path) -> std::io::Result<()> {
    match std::os::windows::fs::symlink_dir(target_dir, link_path) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fallback for unprivileged Windows test environments without Developer Mode symlink privilege
            fs::write(link_path, format!("AF_SYMLINK:{}\n", target_dir.display()))
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn create_symlink_or_pointer(link_path: &Path, target_dir: &Path) -> std::io::Result<()> {
    fs::write(link_path, format!("AF_SYMLINK:{}\n", target_dir.display()))
}

/// Executes Stage 2 Atomic Symlink Swap:
/// 1. If `current_link` already points to a release distinct from `new_release_dir`,
///    records its resolved path atomically in `${RELEASES_DIR}/.previous_release`.
/// 2. Atomically swaps `current_link` to `new_release_dir`.
///
/// Returns the previous release path if one existed.
pub fn perform_symlink_swap(
    releases_dir: &Path,
    current_link: &Path,
    new_release_dir: &Path,
    epoch_tag: &str,
) -> ReleaseResult<Option<PathBuf>> {
    crate::fs_security::create_dir_all_no_symlinks(releases_dir, 0o755)?;

    let canon_new = canonicalize_preserve_normal(new_release_dir);
    let previous = read_current_link_target(current_link);
    if let Some(ref prev_target) = previous {
        let canon_prev = canonicalize_preserve_normal(prev_target);
        if canon_prev != canon_new {
            let prev_file = releases_dir.join(".previous_release");
            crate::fs_security::atomic_write_bytes_with_mode(
                &prev_file,
                format!("{}\n", prev_target.display()).as_bytes(),
                0o644,
            )?;
        }
    }

    let suffix = format!("tmp.{}", epoch_tag);
    atomic_replace_symlink(current_link, new_release_dir, &suffix)?;
    Ok(previous)
}

/// Atomically writes `${RELEASES_DIR}/.previous_release` to point at `target_dir`.
pub fn write_previous_release(releases_dir: &Path, target_dir: &Path) -> ReleaseResult<()> {
    crate::fs_security::create_dir_all_no_symlinks(releases_dir, 0o755)?;
    let prev_file = releases_dir.join(".previous_release");
    crate::fs_security::atomic_write_bytes_with_mode(
        &prev_file,
        format!("{}\n", target_dir.display()).as_bytes(),
        0o644,
    )
}

/// Validates that `prev_path` is an absolute, non-symlink real directory directly beneath one of
/// `allowed_releases_dirs` (with no `.` or `..` components).
pub fn validate_previous_release_target(
    prev_path: &Path,
    allowed_releases_dirs: &[&Path],
) -> ReleaseResult<PathBuf> {
    use std::path::Component;

    if !prev_path.is_absolute()
        || prev_path.file_name().is_none()
        || prev_path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(ReleaseError::Rollback(format!(
            "Previous release target {} is not a canonical absolute path",
            prev_path.display()
        )));
    }
    let trimmed_path = prev_path.to_string_lossy();
    if trimmed_path.ends_with('/') {
        return Err(ReleaseError::Rollback(format!(
            "Previous release target {} must not end with a trailing slash",
            prev_path.display()
        )));
    }
    let prev_meta = fs::symlink_metadata(prev_path).map_err(|_| {
        ReleaseError::Rollback(format!(
            "Previous release directory missing: {}",
            prev_path.display()
        ))
    })?;
    if prev_meta.file_type().is_symlink() || !prev_meta.is_dir() {
        return Err(ReleaseError::Rollback(format!(
            "Previous release target is a symlink or non-directory: {}",
            prev_path.display()
        )));
    }
    let canon_prev = canonicalize_preserve_normal(prev_path);
    let in_allowed_root = allowed_releases_dirs.iter().any(|allowed_dir| {
        let canon_allowed = canonicalize_preserve_normal(allowed_dir);
        canon_prev.parent() == Some(canon_allowed.as_path())
    });
    if !in_allowed_root {
        return Err(ReleaseError::Rollback(format!(
            "Previous release target {} escapes allowed releases directories",
            prev_path.display()
        )));
    }
    Ok(prev_path.to_path_buf())
}

/// Reads and validates `${RELEASES_DIR}/.previous_release`, ensuring the recorded directory still exists,
/// is not a symlink, and resides directly beneath `releases_dir`.
pub fn read_previous_release(releases_dir: &Path) -> ReleaseResult<PathBuf> {
    read_previous_release_in_roots(releases_dir, &[releases_dir])
}

/// Reads and validates `${RELEASES_DIR}/.previous_release`, ensuring the recorded directory still exists,
/// is not a symlink, and resides directly beneath one of `allowed_releases_dirs` (e.g., both the
/// dry-run releases directory and the live base releases directory during `--dry-run` rollbacks).
pub fn read_previous_release_in_roots(
    releases_dir: &Path,
    allowed_releases_dirs: &[&Path],
) -> ReleaseResult<PathBuf> {
    use std::io::Read;

    let prev_file = releases_dir.join(".previous_release");
    match fs::symlink_metadata(&prev_file) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(ReleaseError::Rollback(format!(
                    "Previous release file {} is a symlink or non-regular file",
                    prev_file.display()
                )));
            }
        }
        Err(_) => {
            return Err(ReleaseError::Rollback(format!(
                "No previous release record found at {}",
                prev_file.display()
            )));
        }
    }
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = opts
        .open(&prev_file)
        .map_err(|e| ReleaseError::io(format!("reading {}", prev_file.display()), e))?;
    let fmeta = file
        .metadata()
        .map_err(|e| ReleaseError::io(format!("stat {}", prev_file.display()), e))?;
    if !fmeta.is_file() {
        return Err(ReleaseError::Rollback(format!(
            "Previous release file {} is not a regular file",
            prev_file.display()
        )));
    }
    let mut raw = String::new();
    file.take(65_537)
        .read_to_string(&mut raw)
        .map_err(|e| ReleaseError::io(format!("reading {}", prev_file.display()), e))?;
    if raw.len() > 65_536 {
        return Err(ReleaseError::Rollback(format!(
            "Previous release file {} exceeds 64 KiB cap",
            prev_file.display()
        )));
    }
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(ReleaseError::Rollback(format!(
            "Previous release file is empty at {}",
            prev_file.display()
        )));
    }
    let prev_path = PathBuf::from(trimmed);
    validate_previous_release_target(&prev_path, allowed_releases_dirs)
}

/// Executes Stage 5 Housekeeping (`cleanup_old_releases`), retaining at least `max_releases`
/// directories and never pruning the active `current_link` target or `.previous_release` target.
///
/// Directories are sorted in ascending numeric/lexicographic order (oldest epoch first),
/// matching `find "${RELEASES_DIR}" -mindepth 1 -maxdepth 1 -type d | sort -n`.
/// Returns the list of pruned directory paths.
pub fn cleanup_old_releases(
    releases_dir: &Path,
    current_link: &Path,
    max_releases: usize,
) -> ReleaseResult<Vec<PathBuf>> {
    let mut pruned = Vec::new();
    prune_old_releases(releases_dir, current_link, max_releases, &mut pruned)?;
    Ok(pruned)
}

pub(crate) fn prune_old_releases(
    releases_dir: &Path,
    current_link: &Path,
    max_releases: usize,
    pruned: &mut Vec<PathBuf>,
) -> ReleaseResult<()> {
    if !releases_dir.is_dir() {
        return Ok(());
    }

    let current_target = read_current_link_target(current_link);
    let previous_target = read_previous_release(releases_dir)
        .ok()
        .map(|p| canonicalize_preserve_normal(&p));

    let entries = fs::read_dir(releases_dir).map_err(|e| {
        ReleaseError::io(
            format!("reading releases directory {}", releases_dir.display()),
            e,
        )
    })?;

    let mut dirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(".staging.") || name.starts_with(".staging-") {
            let is_stale = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|mtime| SystemTime::now().duration_since(mtime).ok())
                .map(|age| age >= std::time::Duration::from_secs(120 * 60))
                .unwrap_or(false);
            if is_stale {
                let _ = fs::remove_dir_all(&path);
            }
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        dirs.push(path);
    }

    // Sort by numeric epoch when directory basenames are integers, falling back to lexicographical order
    dirs.sort_by(|a, b| {
        let name_a = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let name_b = b.file_name().and_then(|s| s.to_str()).unwrap_or("");
        match (name_a.parse::<u64>(), name_b.parse::<u64>()) {
            (Ok(na), Ok(nb)) => na.cmp(&nb),
            _ => name_a.cmp(name_b),
        }
    });

    if dirs.len() <= max_releases {
        return Ok(());
    }

    let to_prune = dirs.len() - max_releases;
    for dir in dirs {
        if pruned.len() >= to_prune {
            break;
        }
        let canon_dir = canonicalize_preserve_normal(&dir);
        if current_target
            .as_ref()
            .map(|c| c == &canon_dir || c == &dir)
            .unwrap_or(false)
        {
            continue;
        }
        if previous_target
            .as_ref()
            .map(|p| p == &canon_dir || p == &dir)
            .unwrap_or(false)
        {
            continue;
        }
        fs::remove_dir_all(&dir)
            .map_err(|e| ReleaseError::io(format!("pruning old release {}", dir.display()), e))?;
        pruned.push(dir);
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod crate09_symlink_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn crate09_atomic_symlink_swap_uses_dirfd_renameat_sync_and_rejects_symlink_parent() {
        let root = std::env::temp_dir().join(format!("af-symlink-test-{}", uuid::Uuid::new_v4()));
        let rel_a = root.join("releases/100");
        let rel_b = root.join("releases/200");
        fs::create_dir_all(&rel_a).unwrap();
        fs::create_dir_all(&rel_b).unwrap();

        let current = root.join("opt/current");
        atomic_replace_symlink(&current, &rel_a, "epoch100").unwrap();
        assert_eq!(
            read_current_link_target(&current),
            Some(canonicalize_preserve_normal(&rel_a))
        );

        atomic_replace_symlink(&current, &rel_b, "epoch200").unwrap();
        assert_eq!(
            read_current_link_target(&current),
            Some(canonicalize_preserve_normal(&rel_b))
        );

        // No temporary symlink entries may remain in parent directory.
        let entries: Vec<String> = fs::read_dir(current.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["current".to_string()]);

        // Symlinked parent directory must be refused cleanly.
        let outside = root.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let sym_parent = root.join("sym-parent");
        symlink(&outside, &sym_parent).unwrap();
        let err = atomic_replace_symlink(&sym_parent.join("current"), &rel_b, "bad").unwrap_err();
        assert!(matches!(err, ReleaseError::PathValidation { .. }));

        let _ = fs::remove_dir_all(&root);
    }
}
