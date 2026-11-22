use super::preflight::is_effective_root_user;
use super::SAFE_CONF_KEY_RE;
use crate::error::{CliError, CliResult};
use af_host::{reject_if_symlink, reject_symlink_chain, validate_no_parent_traversal};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

/// Validates that `path` has no parent traversal (`..`) and that no existing ancestor or leaf
/// component is a symbolic link.
pub fn ensure_no_symlink_ancestors(path: &Path, context: &str) -> CliResult<()> {
    validate_no_parent_traversal(path, context)?;
    reject_if_symlink(path, context)?;
    Ok(())
}

/// Ensures `dir` and all of its ancestors under `fs_root` contain no symlinks, creates `dir`
/// if missing, re-verifies no symlink was introduced, and applies `unix_mode` on Unix.
pub(super) fn ensure_dir_no_symlinks(
    fs_root: &Path,
    dir: &Path,
    unix_mode: u32,
    context: &str,
) -> CliResult<()> {
    ensure_no_symlink_ancestors(dir, context)?;
    reject_symlink_chain(fs_root, dir)?;
    fs::create_dir_all(dir)
        .map_err(|e| CliError::io(format!("creating {} ({})", dir.display(), context), e))?;
    reject_symlink_chain(fs_root, dir)?;
    reject_if_symlink(dir, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(unix_mode)).map_err(|error| {
            CliError::io(format!("setting permissions on {}", dir.display()), error)
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = unix_mode;
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn lookup_group_gid(group_name: &str) -> Option<libc::gid_t> {
    use std::ffi::CString;

    let name_c = CString::new(group_name).ok()?;
    let mut buf_len = 4096usize;
    loop {
        let mut buf = vec![0u8; buf_len];
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                name_c.as_ptr(),
                &mut grp,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            return unsafe { result.as_ref().map(|g| g.gr_gid) };
        }
        if rc == libc::ERANGE && buf_len < 65536 {
            buf_len *= 2;
            continue;
        }
        return None;
    }
}

/// Ensures `/install` has mode `0o750` and `root:aetherflow` group ownership when running as root
/// so `aetherflow-api` can traverse `/install` to inspect `.lock` files.
pub(super) fn ensure_install_dir_secure(fs_root: &Path, install_dir: &Path) -> CliResult<()> {
    ensure_dir_no_symlinks(fs_root, install_dir, 0o750, "provision install dir")?;
    #[cfg(unix)]
    if is_effective_root_user() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        if let Some(gid) = lookup_group_gid("aetherflow") {
            if let Ok(dir_c) = CString::new(install_dir.as_os_str().as_bytes()) {
                let fd = unsafe {
                    libc::open(
                        dir_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd >= 0 {
                    let dir_file = unsafe { File::from_raw_fd(fd) };
                    if unsafe { libc::fchown(dir_file.as_raw_fd(), 0, gid) } != 0 {
                        return Err(CliError::io(
                            format!(
                                "setting root:aetherflow ownership on {}",
                                install_dir.display()
                            ),
                            std::io::Error::last_os_error(),
                        ));
                    }
                    let _ = unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o750) };
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn enforce_root_private_file_perms(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    if is_effective_root_user() {
        if let Ok(path_c) = CString::new(path.as_os_str().as_bytes()) {
            let _ = unsafe { libc::lchown(path_c.as_ptr(), 0, 0) };
        }
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

pub(super) fn quote_posix_single(value: &str) -> CliResult<String> {
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(CliError::Validation(
            "config value must not contain newlines or NUL bytes".to_string(),
        ));
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn unquote_shell_config_value(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while i < chars.len() {
        let ch = chars[i];
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                out.push(ch);
            }
            i += 1;
        } else if in_double {
            if ch == '"' {
                in_double = false;
                i += 1;
            } else if ch == '\\' && i + 1 < chars.len() {
                let next = chars[i + 1];
                if matches!(next, '"' | '\\' | '$' | '`') {
                    out.push(next);
                    i += 2;
                } else {
                    out.push(ch);
                    i += 1;
                }
            } else {
                out.push(ch);
                i += 1;
            }
        } else if ch == '$' && i + 1 < chars.len() && chars[i + 1] == '\'' {
            // ANSI-C quoting ($'...') emitted by bash `printf '%q'` for special chars
            i += 2;
            while i < chars.len() {
                let c = chars[i];
                if c == '\'' {
                    i += 1;
                    break;
                }
                if c == '\\' && i + 1 < chars.len() {
                    let esc = chars[i + 1];
                    match esc {
                        '\\' | '\'' | '"' => {
                            out.push(esc);
                            i += 2;
                        }
                        't' => {
                            out.push('\t');
                            i += 2;
                        }
                        'n' => {
                            out.push('\n');
                            i += 2;
                        }
                        'r' => {
                            out.push('\r');
                            i += 2;
                        }
                        _ => {
                            out.push(esc);
                            i += 2;
                        }
                    }
                } else {
                    out.push(c);
                    i += 1;
                }
            }
        } else if ch == '\'' {
            in_single = true;
            i += 1;
        } else if ch == '"' {
            in_double = true;
            i += 1;
        } else if ch == '\\' && i + 1 < chars.len() {
            out.push(chars[i + 1]);
            i += 2;
        } else {
            out.push(ch);
            i += 1;
        }
    }

    out
}

pub(crate) fn parse_config_map(raw: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            if SAFE_CONF_KEY_RE.is_match(key) && !key.eq_ignore_ascii_case("passwd") {
                map.insert(key.to_string(), unquote_shell_config_value(v));
            }
        }
    }
    map
}

/// Opens a new file exclusively (`O_CREAT | O_EXCL` via `create_new(true)`) with `unix_mode`
/// applied at inode creation time on Unix so private state/secret files (`0o600`) are never
/// world- or group-readable even momentarily before `chmod`.
pub(super) fn open_exclusive_private_file(
    path: &Path,
    unix_mode: u32,
    context: &str,
) -> CliResult<File> {
    ensure_no_symlink_ancestors(path, context)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(unix_mode);
    }
    let file = opts.open(path).map_err(|e| {
        CliError::io(
            format!("creating exclusive file {} ({})", path.display(), context),
            e,
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(unix_mode))
            .map_err(|error| {
                CliError::io(format!("setting permissions on {}", path.display()), error)
            })?;
    }
    #[cfg(not(unix))]
    {
        let _ = unix_mode;
    }
    Ok(file)
}

/// Atomically writes `contents` to `target_path` by creating a uniquely named sibling temporary
/// file with `create_new(true)` and `unix_mode`, flushing via `sync_all()`, and renaming into place.
pub(super) fn write_file_atomic_exclusive(
    target_path: &Path,
    contents: &[u8],
    unix_mode: u32,
    context: &str,
) -> CliResult<()> {
    ensure_no_symlink_ancestors(target_path, context)?;
    let parent = target_path.parent().ok_or_else(|| {
        CliError::Validation(format!(
            "{} path '{}' has no parent directory",
            context,
            target_path.display()
        ))
    })?;
    if !parent.as_os_str().is_empty() {
        ensure_no_symlink_ancestors(parent, context)?;
        fs::create_dir_all(parent).map_err(|e| {
            CliError::io(
                format!("creating parent dir {} ({})", parent.display(), context),
                e,
            )
        })?;
        ensure_no_symlink_ancestors(parent, context)?;
    }

    let file_name = target_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "artifact".to_string());
    let tmp_name = format!(
        ".af-tmp-{}-{}-{}",
        file_name,
        std::process::id(),
        Uuid::new_v4()
    );
    let tmp_path = parent.join(tmp_name);

    let write_res = (|| -> CliResult<()> {
        let mut f = open_exclusive_private_file(&tmp_path, unix_mode, context)?;
        f.write_all(contents).map_err(|e| {
            CliError::io(
                format!(
                    "writing temporary file {} ({})",
                    tmp_path.display(),
                    context
                ),
                e,
            )
        })?;
        f.sync_all().map_err(|e| {
            CliError::io(
                format!(
                    "syncing temporary file {} ({})",
                    tmp_path.display(),
                    context
                ),
                e,
            )
        })?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = ensure_no_symlink_ancestors(target_path, context) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    fs::rename(&tmp_path, target_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        CliError::io(
            format!(
                "renaming {} -> {} ({})",
                tmp_path.display(),
                target_path.display(),
                context
            ),
            e,
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(target_path, fs::Permissions::from_mode(unix_mode));
    }

    Ok(())
}
