//! Stage 1.5 & Stage 4: WAL-safe online SQLite backups (`rusqlite::backup::Backup`),
//! `PRAGMA integrity_check` verification, `MANIFEST.sha256` generation, and corruption recovery.

use crate::artifact::{compute_file_sha256, parse_sha256_manifest};
use crate::config::{ReleaseConfig, ResolvedDbPath};
use crate::error::{ReleaseError, ReleaseResult};
#[cfg(not(unix))]
use crate::fs_security::{atomic_copy_file_with_mode, sync_parent_dir_best_effort};
use crate::fs_security::{
    atomic_publish_staged_file_with_mode, atomic_write_bytes_with_mode, create_dir_all_no_symlinks,
    ensure_no_symlink_ancestors, OwnershipMetadata,
};
use crate::lock::ReleaseLockGuard;
use rusqlite::{backup::Backup, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Outcome of Stage 1.5 State Snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotReport {
    /// Whether a snapshot file was actually written (`false` when no live DB exists on a real deploy).
    pub created: bool,
    /// Path to the source SQLite database that was backed up.
    pub source_db: PathBuf,
    /// Path to the `.bak` snapshot inside `${RELEASE_DIR}/data-snapshot/`.
    pub backup_path: Option<PathBuf>,
    /// Path to `${RELEASE_DIR}/data-snapshot/MANIFEST.sha256`.
    pub manifest_path: Option<PathBuf>,
    /// Lowercase SHA-256 digest of the `.bak` snapshot.
    pub sha256: Option<String>,
}

/// Executes a WAL-safe online SQLite backup from `src` (opened read-only / FD-isolated so a hot
/// WAL is never checkpointed by a dry-run or snapshot) into `dest` using SQLite's online backup API.
///
/// Snapshot outputs are owned by `root:root` mode `0600` (when running as root) so unprivileged
/// local/service accounts cannot read backup snapshots. For live service DB migration/restore
/// (`aetherflow:aetherflow 0600`), use `sqlite_online_backup_with_ownership`.
pub fn sqlite_online_backup(src: &Path, dest: &Path) -> ReleaseResult<()> {
    sqlite_online_backup_inner(src, dest, None, true, false)
}

pub(crate) fn sqlite_online_backup_with_ownership(
    src: &Path,
    dest: &Path,
    preserve_from: Option<&OwnershipMetadata>,
    allow_replace_symlink_leaf: bool,
) -> ReleaseResult<()> {
    sqlite_online_backup_inner(src, dest, preserve_from, false, allow_replace_symlink_leaf)
}

fn sqlite_online_backup_inner(
    src: &Path,
    dest: &Path,
    preserve_from: Option<&OwnershipMetadata>,
    root_owned_override: bool,
    allow_replace_symlink_leaf: bool,
) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(src)?;
    let src_meta = fs::symlink_metadata(src).map_err(|_| ReleaseError::Snapshot {
        db_path: src.to_path_buf(),
        reason: "source database file does not exist".to_string(),
    })?;
    if src_meta.file_type().is_symlink() || !src_meta.is_file() {
        return Err(ReleaseError::Snapshot {
            db_path: src.to_path_buf(),
            reason: "source database path is not a regular non-symlink file".to_string(),
        });
    }
    let mut total_src_bytes = src_meta.len();
    for suffix in ["-wal", "-journal"] {
        let mut sc_os = src.as_os_str().to_os_string();
        sc_os.push(suffix);
        if let Ok(sc_meta) = fs::symlink_metadata(PathBuf::from(sc_os)) {
            if sc_meta.is_file() && !sc_meta.file_type().is_symlink() {
                total_src_bytes = total_src_bytes.saturating_add(sc_meta.len());
            }
        }
    }
    let min_scratch_free_bytes = total_src_bytes
        .saturating_mul(3)
        .saturating_add(16 * 1024 * 1024);

    #[cfg(unix)]
    let src_parent_trusted = {
        let euid = unsafe { libc::geteuid() };
        euid != 0 || crate::fs_security::is_trusted_root_sqlite_files(src)
    };
    #[cfg(not(unix))]
    let src_parent_trusted = true;

    atomic_publish_staged_file_with_mode(
        dest,
        0o600,
        preserve_from,
        root_owned_override,
        allow_replace_symlink_leaf,
        true,
        min_scratch_free_bytes,
        |staged_path| {
            if src_parent_trusted {
                crate::fs_security::validate_sqlite_file_and_sidecars_nofollow(src)?;
                run_direct_sqlite_backup(src, staged_path, dest)
            } else {
                #[cfg(unix)]
                {
                    run_fd_isolated_sqlite_backup(src, staged_path, dest)
                }
                #[cfg(not(unix))]
                {
                    run_direct_sqlite_backup(src, staged_path, dest)
                }
            }
        },
    )
}

fn run_direct_sqlite_backup(src: &Path, staged_path: &Path, dest: &Path) -> ReleaseResult<()> {
    let src_conn = Connection::open_with_flags(
        src,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| ReleaseError::Snapshot {
        db_path: src.to_path_buf(),
        reason: format!("failed to open source DB read-only: {}", e),
    })?;
    src_conn
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|e| ReleaseError::Snapshot {
            db_path: src.to_path_buf(),
            reason: format!("failed to harden source DB trusted_schema: {}", e),
        })?;
    let _ = src_conn.busy_timeout(Duration::from_secs(10));

    let mut dst_conn = Connection::open(staged_path).map_err(|e| ReleaseError::Snapshot {
        db_path: dest.to_path_buf(),
        reason: format!(
            "failed to open staged destination DB {}: {}",
            staged_path.display(),
            e
        ),
    })?;
    dst_conn
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|e| ReleaseError::Snapshot {
            db_path: dest.to_path_buf(),
            reason: format!(
                "failed to harden staged destination DB trusted_schema: {}",
                e
            ),
        })?;
    let _ = dst_conn.busy_timeout(Duration::from_secs(10));

    let backup = Backup::new(&src_conn, &mut dst_conn).map_err(|e| ReleaseError::Snapshot {
        db_path: src.to_path_buf(),
        reason: format!("failed to initialize online backup: {}", e),
    })?;
    backup
        .run_to_completion(256, Duration::from_millis(10), None)
        .map_err(|e| ReleaseError::Snapshot {
            db_path: src.to_path_buf(),
            reason: format!("online backup copy failed: {}", e),
        })?;
    Ok(())
}

/// Closes `src_path` symlink-swap TOCTOU when `root` (`euid == 0`) backs up a SQLite database
/// residing inside a non-root-owned or non-root-writable directory (such as `aetherflow`-owned
/// `/var/lib/aetherflow` or a user-writable legacy data directory).
///
/// Opens the source database and optional `-wal` sidecar strictly via `openat(src_parent_dfd, ...,
/// O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)` + `fstat(S_IFREG)`, copies those pinned FDs
/// into a root-owned `0700` [`crate::fs_security::TrustedRootScratchDir`], runs SQLite's online
/// backup API strictly on the isolated scratch copy (never touching the live DB's WAL), and
/// verifies `PRAGMA integrity_check == "ok"` (retrying up to 3 times if a live checkpoint raced
/// with the FD copy).
#[cfg(unix)]
pub(crate) fn run_fd_isolated_sqlite_backup(
    src: &Path,
    staged_path: &Path,
    dest: &Path,
) -> ReleaseResult<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let src_parent = src.parent().ok_or_else(|| ReleaseError::Snapshot {
        db_path: src.to_path_buf(),
        reason: "source database path has no parent directory".to_string(),
    })?;
    let src_leaf = src.file_name().ok_or_else(|| ReleaseError::Snapshot {
        db_path: src.to_path_buf(),
        reason: "source database path has no filename".to_string(),
    })?;
    let src_leaf_c =
        CString::new(src_leaf.as_bytes()).map_err(|_| ReleaseError::PathValidation {
            path: src.to_path_buf(),
            reason: "source database filename contains NUL byte".to_string(),
        })?;
    let build_sc = |suffix: &[u8]| -> ReleaseResult<CString> {
        let mut bytes = src_leaf.as_bytes().to_vec();
        bytes.extend_from_slice(suffix);
        CString::new(bytes).map_err(|_| ReleaseError::PathValidation {
            path: src.to_path_buf(),
            reason: "source SQLite sidecar filename contains NUL byte".to_string(),
        })
    };
    let wal_leaf_c = build_sc(b"-wal")?;
    let shm_leaf_c = build_sc(b"-shm")?;
    let journal_leaf_c = build_sc(b"-journal")?;

    let mut last_err: Option<ReleaseError> = None;
    for attempt in 0..3_u8 {
        let src_parent_dir = crate::fs_security::open_dir_nofollow(src_parent)?;
        let src_fd = unsafe {
            libc::openat(
                src_parent_dir.as_raw_fd(),
                src_leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if src_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(if err.raw_os_error() == Some(libc::ELOOP) {
                ReleaseError::Snapshot {
                    db_path: src.to_path_buf(),
                    reason: "refusing symlinked source database file".to_string(),
                }
            } else {
                ReleaseError::io(format!("opening source database {}", src.display()), err)
            });
        }
        let mut src_file = unsafe { fs::File::from_raw_fd(src_fd) };
        let src_meta = src_file
            .metadata()
            .map_err(|e| ReleaseError::io(format!("fstat source database {}", src.display()), e))?;
        use std::os::unix::fs::MetadataExt;
        if !src_meta.is_file() || src_meta.nlink() != 1 {
            return Err(ReleaseError::Snapshot {
                db_path: src.to_path_buf(),
                reason: "source database path is not an exclusive regular non-symlink file"
                    .to_string(),
            });
        }

        let open_opt_sidecar =
            |sc_c: &CString, label: &str| -> ReleaseResult<Option<(fs::File, u64)>> {
                let fd = unsafe {
                    libc::openat(
                        src_parent_dir.as_raw_fd(),
                        sc_c.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                if fd >= 0 {
                    let f = unsafe { fs::File::from_raw_fd(fd) };
                    let meta = f.metadata().map_err(|e| {
                        ReleaseError::io(format!("fstat source {} for {}", label, src.display()), e)
                    })?;
                    if !meta.is_file() || meta.nlink() != 1 {
                        return Err(ReleaseError::Snapshot {
                            db_path: src.to_path_buf(),
                            reason: format!(
                                "source {} sidecar is not an exclusive regular non-symlink file",
                                label
                            ),
                        });
                    }
                    Ok(Some((f, meta.len())))
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOENT) {
                        Ok(None)
                    } else if err.raw_os_error() == Some(libc::ELOOP) {
                        Err(ReleaseError::Snapshot {
                            db_path: src.to_path_buf(),
                            reason: format!("refusing symlinked source {} sidecar", label),
                        })
                    } else {
                        Err(ReleaseError::io(
                            format!("opening source {} for {}", label, src.display()),
                            err,
                        ))
                    }
                }
            };

        let mut wal_file = open_opt_sidecar(&wal_leaf_c, "WAL")?;
        let _shm_check = open_opt_sidecar(&shm_leaf_c, "SHM")?;
        let mut journal_file = open_opt_sidecar(&journal_leaf_c, "journal")?;

        let total_declared = src_meta
            .len()
            .saturating_add(wal_file.as_ref().map_or(0, |(_, sz)| *sz))
            .saturating_add(journal_file.as_ref().map_or(0, |(_, sz)| *sz));
        let copy_cap = crate::fs_security::MAX_SQLITE_SCRATCH_COPY_BYTES;
        if total_declared > copy_cap {
            return Err(ReleaseError::Snapshot {
                db_path: src.to_path_buf(),
                reason: format!(
                    "source database and sidecars ({} bytes) exceed root scratch copy cap ({} bytes)",
                    total_declared, copy_cap
                ),
            });
        }

        let min_free = total_declared
            .saturating_mul(3)
            .saturating_add(16 * 1024 * 1024);
        let mut scratch =
            crate::fs_security::TrustedRootScratchDir::create_with_min_free(min_free)?;
        scratch.track_file("src.sqlite");
        scratch.track_file("src.sqlite-wal");
        scratch.track_file("src.sqlite-shm");
        scratch.track_file("src.sqlite-journal");
        scratch.track_file("dst.sqlite");
        scratch.track_file("dst.sqlite-wal");
        scratch.track_file("dst.sqlite-shm");
        scratch.track_file("dst.sqlite-journal");
        let scratch_src = scratch.path().join("src.sqlite");
        let scratch_wal = scratch.path().join("src.sqlite-wal");
        let scratch_journal = scratch.path().join("src.sqlite-journal");
        let scratch_dst = scratch.path().join("dst.sqlite");

        let mut remaining_cap = copy_cap;
        let mut copy_fd_to = |reader: &mut fs::File,
                              name: &str,
                              path: &Path|
         -> ReleaseResult<()> {
            let c_name = CString::new(name).expect("static scratch name has no NUL");
            let out_fd = unsafe {
                libc::openat(
                    scratch.dir_fd(),
                    c_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if out_fd < 0 {
                return Err(ReleaseError::io(
                    format!("creating scratch copy {}", path.display()),
                    std::io::Error::last_os_error(),
                ));
            }
            use std::io::Write;
            let mut out = unsafe { fs::File::from_raw_fd(out_fd) };
            let cap = remaining_cap;
            let mut copied: u64 = 0;
            let mut tail8 = [0u8; 8];
            let mut tail_len: usize = 0;
            let mut buf = [0u8; 65536];
            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| ReleaseError::io(format!("reading for {}", path.display()), e))?;
                if n == 0 {
                    break;
                }
                copied = copied.saturating_add(n as u64);
                if copied > cap {
                    return Err(ReleaseError::Snapshot {
                            db_path: src.to_path_buf(),
                            reason: format!(
                                "source database and sidecars exceeded root scratch copy cap ({} bytes)",
                                copy_cap
                            ),
                        });
                }
                out.write_all(&buf[..n])
                    .map_err(|e| ReleaseError::io(format!("copying into {}", path.display()), e))?;
                if n >= 8 {
                    tail8.copy_from_slice(&buf[n - 8..n]);
                    tail_len = 8;
                } else {
                    let keep = (tail_len + n).min(8);
                    let shift = (tail_len + n).saturating_sub(8);
                    if shift < tail_len {
                        tail8.copy_within(shift..tail_len, 0);
                    }
                    let dst_start = keep - n;
                    tail8[dst_start..keep].copy_from_slice(&buf[..n]);
                    tail_len = keep;
                }
            }
            if name.ends_with("-journal")
                && copied >= 16
                && tail_len == 8
                && tail8 == crate::fs_security::SQLITE_JOURNAL_MAGIC
            {
                return Err(ReleaseError::PathValidation {
                        path: src.to_path_buf(),
                        reason: "refusing SQLite rollback journal containing forbidden super-journal trailer".to_string(),
                    });
            }
            remaining_cap = cap.saturating_sub(copied);
            Ok(())
        };

        copy_fd_to(&mut src_file, "src.sqlite", &scratch_src)?;
        if let Some((ref mut wf, _)) = wal_file {
            copy_fd_to(wf, "src.sqlite-wal", &scratch_wal)?;
        }
        if let Some((ref mut jf, _)) = journal_file {
            copy_fd_to(jf, "src.sqlite-journal", &scratch_journal)?;
        }

        // Open our private scratch copy read-write so SQLite cleanly recovers any copied `-wal`
        // frames into a fresh per-attempt `dst.sqlite` inside `scratch` (preventing a corrupt
        // retry from poisoning `staged_path`), verify `PRAGMA integrity_check == "ok"`, and only
        // then copy the verified bytes into `staged_path`.
        let backup_attempt = (|| -> ReleaseResult<()> {
            let src_conn = Connection::open(&scratch_src).map_err(|e| ReleaseError::Snapshot {
                db_path: src.to_path_buf(),
                reason: format!("failed to open isolated scratch source DB: {}", e),
            })?;
            src_conn
                .pragma_update(None, "trusted_schema", "OFF")
                .map_err(|e| ReleaseError::Snapshot {
                    db_path: src.to_path_buf(),
                    reason: format!(
                        "failed to harden isolated scratch source DB trusted_schema: {}",
                        e
                    ),
                })?;
            let _ = src_conn.busy_timeout(Duration::from_secs(10));

            let mut dst_conn =
                Connection::open(&scratch_dst).map_err(|e| ReleaseError::Snapshot {
                    db_path: dest.to_path_buf(),
                    reason: format!(
                        "failed to open scratch destination DB {}: {}",
                        scratch_dst.display(),
                        e
                    ),
                })?;
            dst_conn
                .pragma_update(None, "trusted_schema", "OFF")
                .map_err(|e| ReleaseError::Snapshot {
                    db_path: dest.to_path_buf(),
                    reason: format!(
                        "failed to harden scratch destination DB trusted_schema: {}",
                        e
                    ),
                })?;
            let _ = dst_conn.busy_timeout(Duration::from_secs(10));

            let backup =
                Backup::new(&src_conn, &mut dst_conn).map_err(|e| ReleaseError::Snapshot {
                    db_path: src.to_path_buf(),
                    reason: format!("failed to initialize online backup: {}", e),
                })?;
            backup
                .run_to_completion(256, Duration::from_millis(10), None)
                .map_err(|e| ReleaseError::Snapshot {
                    db_path: src.to_path_buf(),
                    reason: format!("online backup copy failed: {}", e),
                })?;
            drop(backup);

            let check: String = dst_conn
                .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
                .map_err(|e| ReleaseError::Snapshot {
                    db_path: dest.to_path_buf(),
                    reason: format!("integrity check on isolated backup failed: {}", e),
                })?;
            let cleaned: String = check
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if cleaned != "ok" {
                return Err(ReleaseError::IntegrityFailed {
                    db_path: dest.to_path_buf(),
                    result: if cleaned.is_empty() {
                        "error".to_string()
                    } else {
                        cleaned
                    },
                });
            }
            drop(dst_conn);
            drop(src_conn);

            let mut verified_src = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&scratch_dst)
                .map_err(|e| {
                    ReleaseError::io(
                        format!("reopening verified scratch DB {}", scratch_dst.display()),
                        e,
                    )
                })?;
            let mut staged_out = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(staged_path)
                .map_err(|e| {
                    ReleaseError::io(
                        format!("opening staged output DB {}", staged_path.display()),
                        e,
                    )
                })?;
            std::io::copy(&mut verified_src, &mut staged_out).map_err(|e| {
                ReleaseError::io(
                    format!("writing verified backup into {}", staged_path.display()),
                    e,
                )
            })?;
            Ok(())
        })();

        match backup_attempt {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < 3 {
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| ReleaseError::Snapshot {
        db_path: src.to_path_buf(),
        reason: "isolated online backup failed after retries".to_string(),
    }))
}

/// Runs `PRAGMA integrity_check;` against `db_path` and returns the normalized first-line status
/// (`"ok"` when healthy, `"missing"` when absent, or `"error"` / diagnostic string on corruption).
///
/// Validates symlink-free ancestors and regular non-symlink `<db>` + `-wal`/`-shm`/`-journal`
/// sidecars (`O_NOFOLLOW | O_NONBLOCK`). When `root` (`euid == 0`) inspects a database inside a
/// non-root-owned/writable directory (such as `aetherflow`-owned `/var/lib/aetherflow`), copies
/// pinned `O_NOFOLLOW` FDs into a root-owned `0700` [`crate::fs_security::TrustedRootScratchDir`]
/// so SQLite never opens live `-shm` (`O_RDWR|O_CREAT`) or blocks on a FIFO in an untrusted dir.
pub fn sqlite_integrity(db_path: &Path) -> String {
    if ensure_no_symlink_ancestors(db_path).is_err() {
        return "error".to_string();
    }
    let mut source = match crate::fs_security::validate_sqlite_file_and_sidecars_nofollow(db_path) {
        Ok(Some(file)) => file,
        Ok(None) => return "missing".to_string(),
        Err(_) => return "error".to_string(),
    };
    let mut header = [0_u8; 16];
    if source.read_exact(&mut header).is_err() || &header != b"SQLite format 3\0" {
        return "error".to_string();
    }

    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 && !crate::fs_security::is_trusted_root_sqlite_files(db_path) {
            return sqlite_integrity_via_root_scratch(db_path);
        }
    }

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let Ok(conn) = Connection::open_with_flags(db_path, flags) else {
        return "error".to_string();
    };
    if conn.pragma_update(None, "trusted_schema", "OFF").is_err() {
        return "error".to_string();
    }
    let _ = conn.busy_timeout(Duration::from_secs(5));
    let res: Result<String, _> = conn.query_row("PRAGMA integrity_check;", [], |row| row.get(0));
    match res {
        Ok(raw) => {
            let first_line = raw.lines().next().unwrap_or("");
            let cleaned: String = first_line.chars().filter(|c| !c.is_whitespace()).collect();
            if cleaned.is_empty() {
                "error".to_string()
            } else {
                cleaned
            }
        }
        Err(_) => "error".to_string(),
    }
}

#[cfg(unix)]
pub(crate) fn sqlite_integrity_via_root_scratch(db_path: &Path) -> String {
    let mut last_result = "error".to_string();
    for attempt in 0..3 {
        match crate::fs_security::open_sqlite_isolated_readonly(db_path) {
            Ok(conn) => {
                let res: Result<String, _> =
                    conn.query_row("PRAGMA integrity_check;", [], |row| row.get(0));
                match res {
                    Ok(raw) => {
                        let first_line = raw.lines().next().unwrap_or("");
                        let cleaned: String =
                            first_line.chars().filter(|c| !c.is_whitespace()).collect();
                        if cleaned == "ok" {
                            return cleaned;
                        }
                        last_result = if cleaned.is_empty() {
                            "error".to_string()
                        } else {
                            cleaned
                        };
                    }
                    Err(_) => {
                        last_result = "error".to_string();
                    }
                }
            }
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return "missing".to_string();
            }
            Err(_) => {
                last_result = "error".to_string();
            }
        }
        if attempt + 1 < 3 {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    last_result
}

/// Creates a minimal dry-run placeholder SQLite database at `db_path` with `0600` permissions
/// enforced before publishing via private staging (`TrustedRootScratchDir` when the parent is
/// untrusted for root), matching:
/// `CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); INSERT INTO _meta VALUES ('version','dryrun');`
pub fn create_dry_run_placeholder_db(db_path: &Path) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(db_path)?;
    if let Some(parent) = db_path.parent() {
        create_dir_all_no_symlinks(parent, 0o700)?;
    }
    match fs::symlink_metadata(db_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(ReleaseError::PathValidation {
                    path: db_path.to_path_buf(),
                    reason: "dry-run placeholder database path is a symlink or non-regular file"
                        .to_string(),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting dry-run placeholder DB {}", db_path.display()),
                err,
            ));
        }
    }
    crate::fs_security::atomic_publish_staged_file_with_mode(
        db_path,
        0o600,
        None,
        true,
        false,
        true,
        16 * 1024 * 1024,
        |staged_path| {
            let conn = crate::fs_security::open_sqlite_nofollow_hardened(staged_path, true)?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); \
                 INSERT INTO _meta VALUES ('version','dryrun');",
            )
            .map_err(|e| ReleaseError::Snapshot {
                db_path: db_path.to_path_buf(),
                reason: format!("failed to seed dry-run placeholder DB: {}", e),
            })?;
            drop(conn);
            Ok(())
        },
    )
}

/// Executes Stage 1.5 State Snapshot into `${RELEASE_DIR}/data-snapshot/${SQLITE_DB}.bak`,
/// verifies `PRAGMA integrity_check == "ok"`, and writes `MANIFEST.sha256` (all with private
/// `0700` directory and `0600` file permissions before writing).
///
/// Preserves the exact dry-run vs live-deploy guarantees of `state_snapshot` in `deploy/release-manager.sh`:
/// - During `--dry-run`, if `resolved.path` exists and differs from `${DATA_DIR}/${SQLITE_DB}`,
///   it is first copied via read-only online backup into `${DATA_DIR}/${SQLITE_DB}`. If that copy fails,
///   any partial copy/WAL/SHM files are removed and Stage 1.5 returns an error without falling through
///   to a placeholder database.
/// - During `--dry-run`, if no live DB exists, a placeholder DB is created at `${DATA_DIR}/${SQLITE_DB}`.
/// - During a real deploy (`dry_run == false`), if `resolved.path` does not exist, the snapshot is skipped
///   cleanly (`created: false`).
pub fn create_state_snapshot(
    config: &ReleaseConfig,
    resolved: &ResolvedDbPath,
    release_dir: &Path,
    dry_run: bool,
) -> ReleaseResult<SnapshotReport> {
    ensure_no_symlink_ancestors(release_dir)?;
    let mut snapshot_db = resolved.path.clone();

    if dry_run {
        let copy = config.data_dir.join(&config.sqlite_db);
        create_dir_all_no_symlinks(&config.data_dir, 0o700)?;

        ensure_no_symlink_ancestors(&resolved.path)?;
        let resolved_exists =
            crate::fs_security::validate_sqlite_file_and_sidecars_nofollow(&resolved.path)?
                .is_some();
        if resolved_exists && resolved.path != copy {
            if let Err(err) = sqlite_online_backup(&resolved.path, &copy) {
                let _ = fs::remove_file(&copy);
                let _ = fs::remove_file(format!("{}-wal", copy.display()));
                let _ = fs::remove_file(format!("{}-shm", copy.display()));
                return Err(ReleaseError::Snapshot {
                    db_path: resolved.path.clone(),
                    reason: format!(
                        "[DRY-RUN] Failed to copy live database from {} (source: {}): {}",
                        resolved.path.display(),
                        resolved.source,
                        err
                    ),
                });
            }
        }
        snapshot_db = copy;
    }

    ensure_no_symlink_ancestors(&snapshot_db)?;
    let snapshot_db_exists =
        crate::fs_security::validate_sqlite_file_and_sidecars_nofollow(&snapshot_db)?.is_some();
    if !snapshot_db_exists {
        if dry_run {
            create_dry_run_placeholder_db(&snapshot_db)?;
        } else {
            return Ok(SnapshotReport {
                created: false,
                source_db: resolved.path.clone(),
                backup_path: None,
                manifest_path: None,
                sha256: None,
            });
        }
    }

    let snapshot_dir = release_dir.join("data-snapshot");
    crate::fs_security::apply_root_owned_dir_mode(&snapshot_dir, 0o700)?;

    let bak_filename = format!("{}.bak", config.sqlite_db);
    let bak_path = snapshot_dir.join(&bak_filename);
    let lock_file = snapshot_dir.join(".snapshot.lock");

    {
        let _lock = ReleaseLockGuard::acquire(&lock_file, config.snapshot_timeout)?;
        sqlite_online_backup(&snapshot_db, &bak_path)?;
    }

    let integrity = sqlite_integrity(&bak_path);
    if integrity != "ok" {
        return Err(ReleaseError::IntegrityFailed {
            db_path: bak_path,
            result: integrity,
        });
    }

    let sha256 = compute_file_sha256(&bak_path)?;
    let manifest_path = snapshot_dir.join("MANIFEST.sha256");
    let manifest_line = format!("{}  {}\n", sha256, bak_filename);
    atomic_write_bytes_with_mode(&manifest_path, manifest_line.as_bytes(), 0o600)?;

    Ok(SnapshotReport {
        created: true,
        source_db: snapshot_db,
        backup_path: Some(bak_path),
        manifest_path: Some(manifest_path),
        sha256: Some(sha256),
    })
}
/// Verifies that `${snapshot_dir}/${bak_filename}` matches the SHA-256 digest recorded in
/// `${snapshot_dir}/MANIFEST.sha256` and is not a symlink.
pub fn verify_snapshot_manifest(snapshot_dir: &Path, bak_filename: &str) -> ReleaseResult<String> {
    ensure_no_symlink_ancestors(snapshot_dir)?;
    let bak_path = snapshot_dir.join(bak_filename);
    let manifest_path = snapshot_dir.join("MANIFEST.sha256");

    let bak_meta = fs::symlink_metadata(&bak_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "missing snapshot backup {}: {}",
            bak_path.display(),
            e
        ))
    })?;
    if bak_meta.file_type().is_symlink() || !bak_meta.is_file() {
        return Err(ReleaseError::Rollback(format!(
            "snapshot backup {} is a symlink or non-regular file",
            bak_path.display()
        )));
    }

    let manifest_meta = fs::symlink_metadata(&manifest_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "missing snapshot MANIFEST.sha256 at {}: {}",
            manifest_path.display(),
            e
        ))
    })?;
    if manifest_meta.file_type().is_symlink() || !manifest_meta.is_file() {
        return Err(ReleaseError::Rollback(format!(
            "snapshot manifest {} is a symlink or non-regular file",
            manifest_path.display()
        )));
    }

    let manifest_content = fs::read_to_string(&manifest_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "failed to read snapshot manifest {}: {}",
            manifest_path.display(),
            e
        ))
    })?;
    let expected = parse_sha256_manifest(&manifest_content, bak_filename).map_err(|e| {
        ReleaseError::Rollback(format!(
            "invalid snapshot manifest {}: {}",
            manifest_path.display(),
            e
        ))
    })?;
    let actual = compute_file_sha256(&bak_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "failed to hash snapshot {}: {}",
            bak_path.display(),
            e
        ))
    })?;
    if actual != expected {
        return Err(ReleaseError::Rollback(format!(
            "snapshot SHA-256 mismatch for {}: expected {}, got {}",
            bak_path.display(),
            expected,
            actual
        )));
    }
    Ok(actual)
}

/// Outcome of Stage 4 SQLite Integrity Check & Snapshot Restore (`state_restore`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    /// Whether the live database was already healthy (`PRAGMA integrity_check == "ok"`).
    pub live_db_healthy: bool,
    /// Whether the snapshot `.bak` was restored over a corrupted or missing live database.
    pub restored_from_snapshot: bool,
    /// If a corrupted live database was quarantined, its `.corrupted.<epoch>` path.
    pub quarantined_corrupted_path: Option<PathBuf>,
}

/// Checks the integrity of the resolved live database and restores `${target_release}/data-snapshot/${SQLITE_DB}.bak`
/// if and only if the live database fails `PRAGMA integrity_check`, the snapshot passes both
/// `MANIFEST.sha256` digest verification and `PRAGMA integrity_check == "ok"`, and `stop_services` succeeds.
///
/// Before replacing the database file:
/// 1. Verifies `MANIFEST.sha256` and `PRAGMA integrity_check == "ok"` on `.bak`.
/// 2. Requires `stop_services(db_path)` to succeed (`?`) so `aetherflow-api` and `aetherflow-runner`
///    cannot continue writing or recreate a WAL over the restored file.
/// 3. Captures ownership (`uid`, `gid`, `mode`) from the existing `db_path` (or parent directory)
///    before quarantining.
/// 4. Copies `.bak` into an exclusive `0600` sibling temporary file in `db_path`'s parent directory,
///    runs `sync_all()`, verifies `PRAGMA integrity_check == "ok"` on the staged temp file, and applies
///    preserved ownership (or `aetherflow:aetherflow` service user ownership).
/// 5. Quarantines `${db_path}` to `${db_path}.corrupted.<epoch>.<uuid>`, removes `-wal`/`-shm` sidecars,
///    atomically renames the verified temp file to `${db_path}`, and removes `-wal`/`-shm` again.
pub fn restore_state_if_corrupted<F>(
    config: &ReleaseConfig,
    resolved: &ResolvedDbPath,
    target_release: &Path,
    dry_run: bool,
    mut stop_services: F,
) -> ReleaseResult<RestoreReport>
where
    F: FnMut(&Path) -> ReleaseResult<()>,
{
    let db_path = &resolved.path;
    let snapshot_dir = target_release.join("data-snapshot");
    let bak_filename = format!("{}.bak", config.sqlite_db);
    let bak_path = snapshot_dir.join(&bak_filename);

    if dry_run {
        return Ok(RestoreReport {
            live_db_healthy: true,
            restored_from_snapshot: false,
            quarantined_corrupted_path: None,
        });
    }

    let parent = db_path.parent().ok_or_else(|| {
        ReleaseError::Rollback(format!(
            "database path {} has no parent directory",
            db_path.display()
        ))
    })?;
    ensure_no_symlink_ancestors(parent)?;

    let db_meta = fs::symlink_metadata(db_path).ok();
    let bak_exists = fs::symlink_metadata(&bak_path)
        .map(|m| !m.file_type().is_symlink() && m.is_file())
        .unwrap_or(false);

    if db_meta.is_none() && !bak_exists {
        return Ok(RestoreReport {
            live_db_healthy: true,
            restored_from_snapshot: false,
            quarantined_corrupted_path: None,
        });
    }

    let integrity = match db_meta.as_ref() {
        None => "missing".to_string(),
        Some(meta) if meta.file_type().is_symlink() || !meta.is_file() => "error".to_string(),
        Some(_) => sqlite_integrity(db_path),
    };

    if integrity == "ok" {
        return Ok(RestoreReport {
            live_db_healthy: true,
            restored_from_snapshot: false,
            quarantined_corrupted_path: None,
        });
    }

    if !bak_exists {
        return Err(ReleaseError::Rollback(format!(
            "live database at {} failed integrity check ({}) and no snapshot exists at {}",
            db_path.display(),
            integrity,
            bak_path.display()
        )));
    }

    // 1. Verify MANIFEST.sha256 digest and SQLite integrity of the backup BEFORE stopping services or touching live DB
    verify_snapshot_manifest(&snapshot_dir, &bak_filename)?;

    let bak_integrity = sqlite_integrity(&bak_path);
    if bak_integrity != "ok" {
        return Err(ReleaseError::Rollback(format!(
            "refusing to restore corrupted snapshot {} (integrity={})",
            bak_path.display(),
            bak_integrity
        )));
    }

    // 2. Require service stop to succeed before touching WAL/SHM sidecars or live database
    stop_services(db_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "refusing to restore database {} because stopping services failed: {}",
            db_path.display(),
            e
        ))
    })?;

    // 2.5. Re-verify integrity once writers are quiesced so a transient torn-WAL read never
    //      causes a healthy live database to be quarantined and overwritten by an older snapshot.
    if matches!(
        fs::symlink_metadata(db_path),
        Ok(ref meta) if !meta.file_type().is_symlink() && meta.is_file()
    ) && sqlite_integrity(db_path) == "ok"
    {
        return Ok(RestoreReport {
            live_db_healthy: true,
            restored_from_snapshot: false,
            quarantined_corrupted_path: None,
        });
    }

    // 3. Capture ownership/permissions from existing regular DB (or parent dir) before quarantine
    let preserved_ownership = OwnershipMetadata::capture(db_path)
        .or_else(|| OwnershipMetadata::capture(parent))
        .map(|mut m| {
            // Ensure restored DB is never group/world-accessible while preserving user read/write
            m.mode = 0o600;
            m
        });

    create_dir_all_no_symlinks(parent, 0o700)?;

    // 4. Quarantine regular corrupted DB or unlink untrusted leaf symlink/non-regular entry, and
    //    remove stale WAL/SHM sidecars using parent dirfd (never following leaf symlinks).
    let db_filename = db_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("aetherflow.sqlite");
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let corrupted_name = format!("{db_filename}.corrupted.{epoch}.{}", uuid::Uuid::new_v4());

    #[cfg(unix)]
    let quarantined: Option<PathBuf> = crate::fs_security::atomic_restore_db_with_quarantine(
        &bak_path,
        db_path,
        0o600,
        preserved_ownership.as_ref(),
        &corrupted_name,
    )?;

    #[cfg(not(unix))]
    let quarantined: Option<PathBuf> = {
        let mut q: Option<PathBuf> = None;
        if let Ok(meta) = fs::symlink_metadata(db_path) {
            if meta.file_type().is_symlink() || !meta.is_file() {
                let _ = fs::remove_file(db_path);
            } else {
                let corrupted_path = parent.join(&corrupted_name);
                fs::rename(db_path, &corrupted_path).map_err(|e| {
                    ReleaseError::io(
                        format!(
                            "quarantining corrupted DB {} -> {}",
                            db_path.display(),
                            corrupted_path.display()
                        ),
                        e,
                    )
                })?;
                q = Some(corrupted_path);
            }
        }
        if let Err(e) =
            atomic_copy_file_with_mode(&bak_path, db_path, 0o600, preserved_ownership.as_ref())
        {
            if let Some(ref qp) = q {
                let _ = fs::rename(qp, db_path);
            }
            return Err(e);
        }
        let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", db_path.display()));
        let jrn_path = PathBuf::from(format!("{}-journal", db_path.display()));
        let _ = fs::remove_file(&wal_path);
        let _ = fs::remove_file(&shm_path);
        let _ = fs::remove_file(&jrn_path);
        sync_parent_dir_best_effort(parent);
        q
    };

    Ok(RestoreReport {
        live_db_healthy: false,
        restored_from_snapshot: true,
        quarantined_corrupted_path: quarantined,
    })
}
