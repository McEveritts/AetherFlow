//! Hardened filesystem primitives for `af-release`.
//!
//! Provides symlink-free ancestor validation, exclusive private directory creation (`0700`),
//! exclusive private file creation (`0600` before any bytes hit disk), atomic fsync + rename
//! writes, and Unix `aetherflow` service user ownership resolution/preservation.

use crate::error::{ReleaseError, ReleaseResult};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// Verifies that no existing ancestor component of `path` (up to and including `path` itself
/// if it already exists) is a symbolic link (`lstat` / `fs::symlink_metadata`).
///
/// Rejects pre-planted directory symlinks or ancestor symlinks that could redirect directory
/// creation or file extraction outside the intended root.
pub fn ensure_no_symlink_ancestors(path: &Path) -> ReleaseResult<()> {
    crate::config::validate_no_parent_traversal(path, "filesystem path")?;
    let mut accum = PathBuf::new();
    for comp in path.components() {
        accum.push(comp);
        match fs::symlink_metadata(&accum) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(ReleaseError::PathValidation {
                    path: accum,
                    reason: format!("refusing operation through symlink while checking '{}'", path.display()),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ReleaseError::io(format!("inspecting {}", accum.display()), error)),
        }
    }
    Ok(())
}

pub fn ensure_no_symlink_in_relative_chain(base_dir: &Path, rel_path: &Path) -> ReleaseResult<()> {
    if rel_path.is_absolute() {
        return Err(ReleaseError::PathValidation {
            path: rel_path.to_path_buf(),
            reason: "release member path must be relative".to_string(),
        });
    }
    crate::config::validate_no_parent_traversal(rel_path, "release member path")?;
    ensure_no_symlink_ancestors(&base_dir.join(rel_path))
}

/// Ensures `dir` and all missing parents exist without traversing any symlinked ancestor,
/// applying `mode` (on Unix) to newly created or existing target directories.
pub fn create_dir_all_no_symlinks(dir: &Path, mode: u32) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(dir)?;

    let mut accum = PathBuf::new();
    for comp in dir.components() {
        accum.push(comp);
        if matches!(comp, Component::Prefix(_) | Component::RootDir | Component::CurDir) {
            continue;
        }
        match fs::symlink_metadata(&accum) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(ReleaseError::PathValidation {
                        path: accum,
                        reason: "symlinked directory component rejected".to_string(),
                    });
                }
                if !meta.is_dir() {
                    return Err(ReleaseError::PathValidation {
                        path: accum,
                        reason: "path component exists and is not a directory".to_string(),
                    });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                create_single_dir_with_mode(&accum, mode)?;
            }
            Err(err) => {
                return Err(ReleaseError::io(
                    format!("inspecting directory component {}", accum.display()),
                    err,
                ));
            }
        }
    }

    Ok(())
}

/// Creates a brand-new directory exclusively (`create_dir`, failing if `dir` already exists
/// as a file, symlink, or directory) after validating all parent ancestors are symlink-free
/// and created. Sets Unix mode `mode` (e.g. `0o700` or `0o755`) on creation.
pub fn create_new_dir_exclusive(dir: &Path, parent_mode: u32, dir_mode: u32) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(dir)?;
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_all_no_symlinks(parent, parent_mode)?;
        }
    }
    if fs::symlink_metadata(dir).is_ok() {
        return Err(ReleaseError::PathValidation {
            path: dir.to_path_buf(),
            reason: "target directory or pre-planted entry already exists".to_string(),
        });
    }
    create_single_dir_with_mode(dir, dir_mode)?;
    Ok(())
}

fn create_single_dir_with_mode(dir: &Path, mode: u32) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder.mode(mode);
        builder
            .create(dir)
            .map_err(|e| ReleaseError::io(format!("creating directory {}", dir.display()), e))?;
        let meta = fs::symlink_metadata(dir).map_err(|e| {
            ReleaseError::io(format!("stat newly created directory {}", dir.display()), e)
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(ReleaseError::PathValidation {
                path: dir.to_path_buf(),
                reason: "created directory path resolved to a non-directory or symlink".to_string(),
            });
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).map_err(|e| {
            ReleaseError::io(
                format!("setting permissions {:o} on {}", mode, dir.display()),
                e,
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::create_dir(dir)
            .map_err(|e| ReleaseError::io(format!("creating directory {}", dir.display()), e))?;
    }
    Ok(())
}

/// Enforces explicit Unix permissions `mode` on `dir` without following symlinks.
pub fn set_dir_mode(dir: &Path, mode: u32) -> ReleaseResult<()> {
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| ReleaseError::io(format!("stat directory {}", dir.display()), e))?;
    if meta.file_type().is_symlink() {
        return Err(ReleaseError::PathValidation {
            path: dir.to_path_buf(),
            reason: "refusing to chmod symlinked directory".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).map_err(|e| {
            ReleaseError::io(
                format!("setting directory mode {:o} on {}", mode, dir.display()),
                e,
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}

/// Enforces explicit Unix permissions `mode` on `file_path` after verifying it is not a symlink.
pub fn set_file_mode(file_path: &Path, mode: u32) -> ReleaseResult<()> {
    let meta = fs::symlink_metadata(file_path)
        .map_err(|e| ReleaseError::io(format!("stat file {}", file_path.display()), e))?;
    if meta.file_type().is_symlink() {
        return Err(ReleaseError::PathValidation {
            path: file_path.to_path_buf(),
            reason: "refusing to chmod symlinked file".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(file_path, fs::Permissions::from_mode(mode)).map_err(|e| {
            ReleaseError::io(
                format!("setting file mode {:o} on {}", mode, file_path.display()),
                e,
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}

/// Opens a brand-new file exclusively (`O_CREAT | O_EXCL` / `create_new(true)`) with Unix
/// permissions set to `mode` (e.g., `0o600`) **before** any bytes are written, bypassing
/// permissive process `umask` defaults and rejecting pre-existing files or symlinks.
pub fn open_exclusive_private_file(path: &Path, mode: u32) -> ReleaseResult<File> {
    ensure_no_symlink_ancestors(path)?;
    let mut opts = OpenOptions::new();
    opts.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    let file = opts.open(path).map_err(|e| {
        ReleaseError::io(
            format!("creating exclusive file {} (mode {:o})", path.display(), mode),
            e,
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| {
                ReleaseError::io(
                    format!("enforcing mode {:o} on {}", mode, path.display()),
                    e,
                )
            })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(file)
}

/// Atomically writes `contents` to `target` via a globally unique (`UUIDv4` + PID) exclusive
/// sibling temporary file created with `mode` (`0600` for secrets/DBs/manifests), `sync_all()`,
/// and atomic `fs::rename`.
pub fn atomic_write_bytes_with_mode(
    target: &Path,
    contents: &[u8],
    mode: u32,
) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(target)?;
    let parent = target.parent().ok_or_else(|| ReleaseError::PathValidation {
        path: target.to_path_buf(),
        reason: "target file has no parent directory".to_string(),
    })?;
    if !parent.try_exists().map_err(|error| {
        ReleaseError::io(format!("inspecting parent {}", parent.display()), error)
    })? {
        create_dir_all_no_symlinks(parent, 0o755)?;
    }

    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("tmp");
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let mut tmp_file = open_exclusive_private_file(&tmp_path, mode)?;
    if let Err(e) = tmp_file
        .write_all(contents)
        .and_then(|()| tmp_file.sync_all())
    {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(ReleaseError::io(
            format!("writing and syncing temporary file {}", tmp_path.display()),
            e,
        ));
    }
    drop(tmp_file);

    fs::rename(&tmp_path, target).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        ReleaseError::io(
            format!("atomically renaming {} -> {}", tmp_path.display(), target.display()),
            e,
        )
    })?;
    Ok(())
}

/// Atomically copies `src` to `dest` via a globally unique exclusive sibling temporary file
/// created with `mode` BEFORE writing, `sync_all()`, optional ownership application, and `fs::rename`.
pub fn atomic_copy_file_with_mode(
    src: &Path,
    dest: &Path,
    mode: u32,
    preserve_from: Option<&OwnershipMetadata>,
) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(src)?;
    ensure_no_symlink_ancestors(dest)?;
    let parent = dest.parent().ok_or_else(|| ReleaseError::PathValidation {
        path: dest.to_path_buf(),
        reason: "destination file has no parent directory".to_string(),
    })?;
    if !parent.try_exists().map_err(|error| {
        ReleaseError::io(format!("inspecting parent {}", parent.display()), error)
    })? {
        create_dir_all_no_symlinks(parent, 0o755)?;
    }

    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("copy");
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let mut src_file = File::open(src)
        .map_err(|e| ReleaseError::io(format!("opening source file {}", src.display()), e))?;
    let mut tmp_file = open_exclusive_private_file(&tmp_path, mode)?;

    if let Err(e) = std::io::copy(&mut src_file, &mut tmp_file).and_then(|_| tmp_file.sync_all()) {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(ReleaseError::io(
            format!("copying {} -> {}", src.display(), tmp_path.display()),
            e,
        ));
    }
    drop(tmp_file);

    if let Err(e) = apply_service_ownership(&tmp_path, preserve_from, mode) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    fs::rename(&tmp_path, dest).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        ReleaseError::io(
            format!("renaming {} -> {}", tmp_path.display(), dest.display()),
            e,
        )
    })?;

    sync_parent_dir_best_effort(parent);
    Ok(())
}

/// Best-effort `fsync` on a directory after atomic file renames on Unix.
pub fn sync_parent_dir_best_effort(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(f) = File::open(dir) {
            let _ = f.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Recorded Unix ownership (`uid`, `gid`, and file mode) of an existing database or secret file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl OwnershipMetadata {
    /// Captures ownership metadata from `path` if it exists and is not a symlink.
    pub fn capture(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::symlink_metadata(path).ok()?;
            if meta.file_type().is_symlink() {
                return None;
            }
            Some(Self {
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode() & 0o777,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }
}

/// Resolves the `aetherflow` system account `(uid, gid)` via `getpwnam_r` on Unix if present.
#[cfg(unix)]
pub fn lookup_aetherflow_ugid() -> Option<(u32, u32)> {
    use std::ffi::CString;
    let name = CString::new("aetherflow").ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc == 0 && !result.is_null() {
        Some((pwd.pw_uid, pwd.pw_gid))
    } else {
        None
    }
}

/// Applies preserved `(uid, gid)` (or the `aetherflow` service user's `(uid, gid)` when available)
/// and `mode` to `path` without following symlinks.
///
/// When running as root (`euid == 0`), `fchown`/`lchown` failures are surfaced as errors;
/// when running as an unprivileged test user, `EPERM` on `chown` is ignored while `chmod` is enforced.
pub fn apply_service_ownership(
    path: &Path,
    preserve_from: Option<&OwnershipMetadata>,
    default_mode: u32,
) -> ReleaseResult<()> {
    set_file_mode(path, default_mode)?;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let target_ugid = preserve_from
            .map(|m| (m.uid, m.gid))
            .or_else(lookup_aetherflow_ugid);

        if let Some((uid, gid)) = target_ugid {
            if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
                let rc = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    let euid = unsafe { libc::geteuid() };
                    if euid == 0 {
                        return Err(ReleaseError::io(
                            format!("chown {}:{} on {}", uid, gid, path.display()),
                            err,
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Applies `aetherflow:aetherflow` ownership (when the user exists) and `0700` mode to `data_dir`
/// during non-dry-run Stage 0 layout verification, matching `ensure_fhs_layout` in `release-manager.sh`.
pub fn apply_data_dir_ownership_and_mode(data_dir: &Path) -> ReleaseResult<()> {
    set_dir_mode(data_dir, 0o700)?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        if let Some((uid, gid)) = lookup_aetherflow_ugid() {
            if let Ok(c_path) = CString::new(data_dir.as_os_str().as_bytes()) {
                let rc = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    if unsafe { libc::geteuid() } == 0 {
                        return Err(ReleaseError::io(
                            format!("chown aetherflow:aetherflow on {}", data_dir.display()),
                            err,
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
