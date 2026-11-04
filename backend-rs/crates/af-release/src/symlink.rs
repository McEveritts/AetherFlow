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

/// Creates a directory symlink from `link_path -> target_dir` and atomically renames it over `current_link`.
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

    if let Some(parent) = current_link.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            ReleaseError::io(
                format!("creating parent directory for symlink {}", parent.display()),
                e,
            )
        })?;
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_link = PathBuf::from(format!(
        "{}.{}.{}.{}",
        current_link.display(),
        suffix_tag,
        nanos,
        uuid::Uuid::new_v4()
    ));

    create_symlink_or_pointer(&tmp_link, target_dir).map_err(|e| ReleaseError::SymlinkSwap {
        link: current_link.to_path_buf(),
        target: target_dir.to_path_buf(),
        reason: format!("failed to create temporary symlink {}: {}", tmp_link.display(), e),
    })?;

    #[cfg(not(unix))]
    {
        // On Windows, renaming a directory symlink over an existing directory symlink can fail
        // with AccessDenied unless the destination symlink is removed first.
        if fs::symlink_metadata(current_link).is_ok() {
            let _ = fs::remove_dir(current_link).or_else(|_| fs::remove_file(current_link));
        }
    }

    fs::rename(&tmp_link, current_link).map_err(|e| {
        let _ = fs::remove_file(&tmp_link);
        ReleaseError::SymlinkSwap {
            link: current_link.to_path_buf(),
            target: target_dir.to_path_buf(),
            reason: format!(
                "failed to atomically replace {} -> {}: {}",
                tmp_link.display(),
                current_link.display(),
                e
            ),
        }
    })?;

    Ok(())
}

#[cfg(unix)]
fn create_symlink_or_pointer(link_path: &Path, target_dir: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target_dir, link_path)
}

#[cfg(windows)]
fn create_symlink_or_pointer(link_path: &Path, target_dir: &Path) -> std::io::Result<()> {
    match std::os::windows::fs::symlink_dir(target_dir, link_path) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fallback for unprivileged Windows test environments without Developer Mode symlink privilege
            fs::write(
                link_path,
                format!("AF_SYMLINK:{}\n", target_dir.display()),
            )
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn create_symlink_or_pointer(link_path: &Path, target_dir: &Path) -> std::io::Result<()> {
    fs::write(
        link_path,
        format!("AF_SYMLINK:{}\n", target_dir.display()),
    )
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
                0o600,
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
        0o600,
    )
}

/// Reads and validates `${RELEASES_DIR}/.previous_release`, ensuring the recorded directory still exists
/// and is not a symlink.
pub fn read_previous_release(releases_dir: &Path) -> ReleaseResult<PathBuf> {
    let prev_file = releases_dir.join(".previous_release");
    if let Ok(meta) = fs::symlink_metadata(&prev_file) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(ReleaseError::Rollback(format!(
                "Previous release file {} is a symlink or non-regular file",
                prev_file.display()
            )));
        }
    } else {
        return Err(ReleaseError::Rollback(format!(
            "No previous release record found at {}",
            prev_file.display()
        )));
    }
    let raw = fs::read_to_string(&prev_file)
        .map_err(|e| ReleaseError::io(format!("reading {}", prev_file.display()), e))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ReleaseError::Rollback(format!(
            "Previous release file is empty at {}",
            prev_file.display()
        )));
    }
    let prev_path = PathBuf::from(trimmed);
    if !prev_path.is_dir() {
        return Err(ReleaseError::Rollback(format!(
            "Previous release directory missing: {}",
            prev_path.display()
        )));
    }
    Ok(prev_path)
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
    if !releases_dir.is_dir() {
        return Ok(Vec::new());
    }

    let current_target = read_current_link_target(current_link);
    let previous_target = fs::read_to_string(releases_dir.join(".previous_release"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| canonicalize_preserve_normal(Path::new(&s)));

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
        return Ok(Vec::new());
    }

    let to_prune = dirs.len() - max_releases;
    let mut pruned = Vec::new();

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
        fs::remove_dir_all(&dir).map_err(|e| {
            ReleaseError::io(format!("pruning old release {}", dir.display()), e)
        })?;
        pruned.push(dir);
    }

    Ok(pruned)
}
