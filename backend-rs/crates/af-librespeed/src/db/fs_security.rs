use super::SQLITE_MAGIC;
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const SQLITE_SIDECAR_SUFFIXES: [(&str, &str); 3] = [
    ("-wal", "SQLite WAL sidecar"),
    ("-shm", "SQLite SHM sidecar"),
    ("-journal", "SQLite rollback journal sidecar"),
];

pub(super) fn check_not_symlink(path: &Path, label: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!("refusing symlink for {label}: {}", path.display());
            }
            Ok(Some(meta))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to stat {label}: {}", path.display())),
    }
}

pub(super) fn verify_no_symlinks_on_db_path(db_path: &Path) -> Result<()> {
    if let Some(meta) = check_not_symlink(db_path, "database_file")? {
        if meta.is_dir() {
            bail!(
                "database_file points to a directory, expected regular file: {}",
                db_path.display()
            );
        }
    }

    for ancestor in db_path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if let Some(meta) = check_not_symlink(ancestor, "database ancestor directory")? {
            if !meta.is_dir() {
                bail!(
                    "database ancestor path is not a directory: {}",
                    ancestor.display()
                );
            }
        }
    }

    verify_sidecar_symlinks(db_path)
}

fn verify_sidecar_symlinks(db_path: &Path) -> Result<()> {
    for (suffix, label) in SQLITE_SIDECAR_SUFFIXES {
        let sc_path = sidecar_path(db_path, suffix);
        if let Some(meta) = check_not_symlink(&sc_path, label)? {
            if !meta.is_file() {
                bail!("{label} is not a regular file: {}", sc_path.display());
            }
        }
    }
    Ok(())
}

pub(super) fn verify_and_harden_sidecars(db_path: &Path) -> Result<()> {
    verify_sidecar_symlinks(db_path)?;
    for (suffix, _label) in SQLITE_SIDECAR_SUFFIXES {
        let sc_path = sidecar_path(db_path, suffix);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&sc_path)
        {
            Ok(sc_file) => {
                let meta = sc_file.metadata().with_context(|| {
                    format!("failed to fstat SQLite sidecar {}", sc_path.display())
                })?;
                if !meta.is_file() {
                    bail!(
                        "SQLite sidecar is not a regular file: {}",
                        sc_path.display()
                    );
                }
                sc_file
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .with_context(|| {
                        format!(
                            "failed to tighten permissions to 0600 on SQLite sidecar {}",
                            sc_path.display()
                        )
                    })?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed secure O_NOFOLLOW open on SQLite sidecar {}",
                        sc_path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

pub(super) fn verify_parent_dir_not_world_writable(db_path: &Path) -> Result<()> {
    let parent = match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let meta = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "failed to inspect telemetry database directory {}",
            parent.display()
        )
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!(
            "telemetry database parent is not a regular directory: {}",
            parent.display()
        );
    }
    let mode = meta.permissions().mode();
    if (mode & 0o002) != 0 {
        bail!(
            "refusing world-writable parent directory (mode {:04o}) for telemetry database: {}",
            mode & 0o7777,
            parent.display()
        );
    }
    Ok(())
}

fn sidecar_path(base: &Path, suffix: &str) -> PathBuf {
    let mut os = base.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

pub(super) fn ensure_parent_dirs(db_path: &Path) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create telemetry database directory {}",
                    parent.display()
                )
            })?;
        }
    }
    Ok(())
}

fn move_file_noreplace(src: &Path, dst: &Path) -> Result<bool> {
    check_not_symlink(dst, "BoltDB backup path")?;
    let src_c = CString::new(src.as_os_str().as_bytes())
        .with_context(|| format!("invalid NUL in source path {}", src.display()))?;
    let dst_c = CString::new(dst.as_os_str().as_bytes())
        .with_context(|| format!("invalid NUL in backup path {}", dst.display()))?;

    // SAFETY: src_c and dst_c are valid NUL-terminated C strings; AT_FDCWD resolves relative paths safely.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EEXIST) | Some(libc::ENOTEMPTY) => Ok(false),
        Some(libc::ENOSYS) | Some(libc::EINVAL) => match fs::hard_link(src, dst) {
            Ok(()) => {
                fs::remove_file(src).with_context(|| {
                    format!(
                        "failed to unlink migrated database source {} after hard_link",
                        src.display()
                    )
                })?;
                Ok(true)
            }
            Err(link_err) if link_err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(link_err) => Err(link_err).with_context(|| {
                format!(
                    "failed non-overwriting hard_link backup {} -> {}",
                    src.display(),
                    dst.display()
                )
            }),
        },
        _ => Err(err).with_context(|| {
            format!(
                "failed atomic RENAME_NOREPLACE backup {} -> {}",
                src.display(),
                dst.display()
            )
        }),
    }
}

pub(super) fn guard_and_backup_legacy_boltdb(db_path: &Path) -> Result<Option<PathBuf>> {
    let Some(meta) = check_not_symlink(db_path, "database_file")? else {
        return Ok(None);
    };
    if !meta.is_file() {
        bail!("database_file is not a regular file: {}", db_path.display());
    }
    if meta.len() == 0 {
        return Ok(None);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(db_path)
        .with_context(|| format!("failed to inspect existing database {}", db_path.display()))?;

    let mut header = [0u8; 16];
    let n = file.read(&mut header)?;
    drop(file);

    if n == 16 && &header == SQLITE_MAGIC {
        return Ok(None);
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let already_bolt_ext = db_path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("bolt"));
    let bak_ext = if already_bolt_ext {
        ".bak"
    } else {
        ".bolt.bak"
    };

    let mut candidates = Vec::with_capacity(66);
    candidates.push(sidecar_path(db_path, bak_ext));
    candidates.push(sidecar_path(db_path, &format!("{bak_ext}.{ts}")));
    for seq in 1..=64u32 {
        candidates.push(sidecar_path(db_path, &format!("{bak_ext}.{ts}.{seq}")));
    }

    let mut chosen_backup = None;
    for candidate in candidates {
        if move_file_noreplace(db_path, &candidate)? {
            chosen_backup = Some(candidate);
            break;
        }
    }
    let Some(backup_path) = chosen_backup else {
        bail!(
            "exhausted non-overwriting BoltDB backup slots for {}",
            db_path.display()
        );
    };
    let bak_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&backup_path)
        .with_context(|| {
            format!(
                "failed secure O_NOFOLLOW open on BoltDB backup {}",
                backup_path.display()
            )
        })?;
    bak_file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!(
                "failed to tighten permissions to 0600 on BoltDB backup {}",
                backup_path.display()
            )
        })?;
    drop(bak_file);
    warn!(
        old_path = %db_path.display(),
        backup_path = %backup_path.display(),
        "Detected non-SQLite/legacy BoltDB database file; moved aside (0600) before initializing SQLite WAL telemetry"
    );
    info!("SQLite telemetry initialized cleanly after legacy backup");
    Ok(Some(backup_path))
}
