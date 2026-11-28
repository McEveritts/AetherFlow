use anyhow::{Context, Result};
use rusqlite::Connection;
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

pub struct OwnerLease {
    pub id: String,
    database: PathBuf,
    _file: File,
    skip_drop_retire: bool,
}

pub(super) fn lease_path(database: &Path, owner: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        uuid::Uuid::parse_str(owner).is_ok(),
        "invalid lifecycle owner identity"
    );
    Ok(database.with_extension("lifecycle-owners").join(owner))
}

impl OwnerLease {
    pub fn create(database: &Path) -> Result<Self> {
        let id = uuid::Uuid::new_v4().to_string();
        let path = lease_path(database, &id)?;
        let parent = path.parent().context("missing lifecycle lease directory")?;

        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::{AsRawFd, FromRawFd};

            let euid = unsafe { libc::geteuid() };
            let mut db_owner: Option<(libc::uid_t, libc::gid_t)> = None;
            if euid == 0 {
                let mut owner_res: Option<Result<Option<(libc::uid_t, libc::gid_t)>>> = None;
                crate::fs_security::with_effective_fsuid(|| {
                    owner_res = Some((|| -> Result<Option<(libc::uid_t, libc::gid_t)>> {
                        if let Some(db_parent) =
                            database.parent().filter(|p| !p.as_os_str().is_empty())
                        {
                            if let Ok(db_parent_dir) =
                                crate::fs_security::open_dir_nofollow(db_parent)
                            {
                                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                                if unsafe { libc::fstat(db_parent_dir.as_raw_fd(), &mut st) } == 0
                                    && st.st_uid != 0
                                {
                                    anyhow::ensure!(
                                        (st.st_mode & 0o002) == 0,
                                        "refusing world-writable lifecycle database parent directory {}",
                                        db_parent.display()
                                    );
                                    return Ok(Some((st.st_uid, st.st_gid)));
                                }
                            }
                        }
                        Ok(None)
                    })());
                    Ok(())
                })?;
                db_owner = owner_res.expect("db_owner resolution closure executed")?;
            }

            if let Some((uid, gid)) = db_owner {
                // Create/open the lease directory and lease file strictly under the DB parent's
                // unprivileged `(uid, gid)` so root never invokes `fchown`/`fchmod` on any
                // pre-existing directory inside an unprivileged-owned `DATA_DIR` (preventing
                // confused-deputy rename attacks against root-owned sibling directories).
                let db_parent = database
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .context("missing lifecycle database parent directory")?;
                let parent_leaf = parent
                    .file_name()
                    .context("missing lifecycle lease directory leaf name")?;
                let parent_leaf_c =
                    CString::new(std::os::unix::ffi::OsStrExt::as_bytes(parent_leaf))?;
                let mut out: Option<Result<Self>> = None;
                crate::fs_security::with_uid_gid_fsuid(uid, gid, || {
                    out = Some((|| -> Result<Self> {
                        let db_parent_dir = crate::fs_security::open_dir_nofollow(db_parent)?;
                        let mk_rc = unsafe {
                            libc::mkdirat(
                                db_parent_dir.as_raw_fd(),
                                parent_leaf_c.as_ptr(),
                                0o750 as libc::mode_t,
                            )
                        };
                        let created_fresh = if mk_rc == 0 {
                            true
                        } else {
                            let err = std::io::Error::last_os_error();
                            if err.kind() == std::io::ErrorKind::AlreadyExists {
                                false
                            } else {
                                return Err(err).with_context(|| {
                                    format!(
                                        "failed to create lifecycle lease directory {}",
                                        parent.display()
                                    )
                                });
                            }
                        };
                        let dir_fd = unsafe {
                            libc::openat(
                                db_parent_dir.as_raw_fd(),
                                parent_leaf_c.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_DIRECTORY
                                    | libc::O_NOFOLLOW
                                    | libc::O_CLOEXEC,
                            )
                        };
                        if dir_fd < 0 {
                            return Err(std::io::Error::last_os_error()).with_context(|| {
                                format!(
                                    "failed to open lifecycle lease directory {}",
                                    parent.display()
                                )
                            });
                        }
                        let parent_dir = unsafe { File::from_raw_fd(dir_fd) };
                        let mut pst: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(parent_dir.as_raw_fd(), &mut pst) } != 0 {
                            return Err(std::io::Error::last_os_error().into());
                        }
                        anyhow::ensure!(
                            (pst.st_mode & libc::S_IFMT) == libc::S_IFDIR,
                            "lifecycle lease directory {} is not a directory",
                            parent.display()
                        );
                        anyhow::ensure!(
                            pst.st_uid == uid,
                            "refusing lifecycle lease directory {} owned by unexpected uid {} (expected {})",
                            parent.display(),
                            pst.st_uid,
                            uid
                        );
                        if created_fresh {
                            if unsafe { libc::fchmod(parent_dir.as_raw_fd(), 0o750) } != 0 {
                                return Err(std::io::Error::last_os_error()).with_context(|| {
                                    format!(
                                        "failed to set lifecycle lease directory mode 0750 on {}",
                                        parent.display()
                                    )
                                });
                            }
                        } else {
                            anyhow::ensure!(
                                (pst.st_mode & 0o022) == 0,
                                "refusing group/world-writable lifecycle lease directory {}",
                                parent.display()
                            );
                        }

                        let id_c = CString::new(id.as_str())?;
                        let fd = unsafe {
                            libc::openat(
                                parent_dir.as_raw_fd(),
                                id_c.as_ptr(),
                                libc::O_RDWR
                                    | libc::O_CREAT
                                    | libc::O_EXCL
                                    | libc::O_NOFOLLOW
                                    | libc::O_NONBLOCK
                                    | libc::O_CLOEXEC,
                                0o640 as libc::c_uint,
                            )
                        };
                        if fd < 0 {
                            return Err(std::io::Error::last_os_error().into());
                        }
                        let file = unsafe { File::from_raw_fd(fd) };
                        let fmeta = file.metadata()?;
                        anyhow::ensure!(fmeta.is_file(), "created lifecycle lease is not a file");
                        if unsafe { libc::fchmod(file.as_raw_fd(), 0o640) } != 0 {
                            let err = std::io::Error::last_os_error();
                            let _ =
                                unsafe { libc::unlinkat(parent_dir.as_raw_fd(), id_c.as_ptr(), 0) };
                            return Err(err.into());
                        }
                        anyhow::ensure!(
                            lock_exclusive(&file)?,
                            "new lifecycle owner lease already locked"
                        );
                        let lease = Self {
                            id,
                            database: database.to_owned(),
                            _file: file,
                            skip_drop_retire: false,
                        };
                        lease._file.sync_all()?;
                        let _ = crate::fs_security::sync_dir_fd(parent_dir.as_raw_fd(), parent);
                        Ok(lease)
                    })());
                    Ok(())
                })?;
                return out.expect("OwnerLease::create unprivileged closure executed");
            }

            let mut out: Option<Result<Self>> = None;
            crate::fs_security::with_effective_fsuid(|| {
                out = Some((|| -> Result<Self> {
                    let parent_dir =
                        crate::fs_security::open_or_create_dir_nofollow(parent, 0o755)?;
                    let id_c = CString::new(id.as_str())?;
                    let fd = unsafe {
                        libc::openat(
                            parent_dir.as_raw_fd(),
                            id_c.as_ptr(),
                            libc::O_RDWR
                                | libc::O_CREAT
                                | libc::O_EXCL
                                | libc::O_NOFOLLOW
                                | libc::O_NONBLOCK
                                | libc::O_CLOEXEC,
                            0o640 as libc::c_uint,
                        )
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    let file = unsafe { File::from_raw_fd(fd) };
                    let fmeta = file.metadata()?;
                    anyhow::ensure!(fmeta.is_file(), "created lifecycle lease is not a file");
                    let _ = unsafe { libc::fchmod(file.as_raw_fd(), 0o644) };
                    anyhow::ensure!(
                        lock_exclusive(&file)?,
                        "new lifecycle owner lease already locked"
                    );
                    let lease = Self {
                        id,
                        database: database.to_owned(),
                        _file: file,
                        skip_drop_retire: false,
                    };
                    lease._file.sync_all()?;
                    let _ = crate::fs_security::sync_dir_fd(parent_dir.as_raw_fd(), parent);
                    Ok(lease)
                })());
                Ok(())
            })?;
            out.expect("OwnerLease::create closure executed")
        }
        #[cfg(not(unix))]
        {
            crate::fs_security::create_dir_all_no_symlinks(parent, 0o755)?;
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            let file = options.open(&path)?;
            anyhow::ensure!(
                lock_exclusive(&file)?,
                "new lifecycle owner lease already locked"
            );
            let lease = Self {
                id,
                database: database.to_owned(),
                _file: file,
                skip_drop_retire: false,
            };
            lease._file.sync_all()?;
            File::open(parent)?.sync_all()?;
            Ok(lease)
        }
    }

    /// Retires this lease using an already-open SQLite connection (running the
    /// SQLite check under the caller's active `fsuid` and unlinking the lease
    /// file under effective credentials), avoiding a redundant root-scratch DB
    /// copy in [`Drop`].
    pub fn retire_with_conn(&mut self, conn: &Connection) -> Result<()> {
        if self.skip_drop_retire {
            return Ok(());
        }
        anyhow::ensure!(
            conn.is_autocommit(),
            "lifecycle cleanup requires committed receipts"
        );
        let active: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE owner_id=?1 AND status NOT IN ('completed','failed','interrupted'))",
            [self.id.as_str()],
            |row| row.get(0),
        )?;
        anyhow::ensure!(!active, "lifecycle owner still has a reservation");
        self.skip_drop_retire = true;
        #[cfg(unix)]
        {
            let mut out: Option<Result<()>> = None;
            crate::fs_security::with_effective_fsuid(|| {
                out = Some(unlink_owner_lease_file(
                    &self.database,
                    &self.id,
                    &self._file,
                ));
                Ok(())
            })?;
            out.expect("OwnerLease::retire_with_conn unlink closure executed")
        }
        #[cfg(not(unix))]
        {
            unlink_owner_lease_file(&self.database, &self.id, &self._file)
        }
    }
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        if self.skip_drop_retire {
            return;
        }
        let _ = crate::fs_security::with_effective_fsuid(|| {
            let cleanup = || -> Result<()> {
                let conn = crate::fs_security::open_sqlite_isolated_readonly(&self.database)?;
                let _ = conn.busy_timeout(std::time::Duration::ZERO);
                retire_owner(&conn, &self.database, &self.id, &self._file)
            };
            let _ = cleanup();
            Ok(())
        });
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<bool> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error.into())
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &File) -> Result<bool> {
    anyhow::bail!("lifecycle owner leases require advisory lock support")
}

fn open_owner_file(database: &Path, owner: &str) -> Result<File> {
    let path = lease_path(database, owner)?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::MetadataExt;

        let parent = path.parent().context("missing lifecycle lease directory")?;
        let parent_dir = crate::fs_security::open_dir_nofollow(parent)
            .context("cannot inspect lifecycle owner lease directory")?;
        let owner_c = CString::new(owner)?;
        let fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                owner_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot inspect lifecycle owner lease");
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        anyhow::ensure!(metadata.is_file(), "invalid lifecycle owner lease file");
        anyhow::ensure!(metadata.nlink() == 1, "linked lifecycle owner lease file");
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        crate::fs_security::ensure_no_symlink_ancestors(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .context("cannot inspect lifecycle owner lease")?;
        let metadata = file.metadata()?;
        anyhow::ensure!(metadata.is_file(), "invalid lifecycle owner lease file");
        Ok(file)
    }
}

pub fn owner_is_alive(database: &Path, owner: &str) -> Result<bool> {
    let file = open_owner_file(database, owner)?;
    Ok(!lock_exclusive(&file)?)
}

#[cfg(unix)]
fn unlink_owner_lease_file(database: &Path, owner: &str, file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let path = lease_path(database, owner)?;
    let parent = path.parent().context("missing lifecycle lease directory")?;
    let directory = crate::fs_security::open_dir_nofollow(parent)?;
    anyhow::ensure!(
        directory.metadata()?.mode() & 0o022 == 0,
        "lifecycle lease directory is writable by other users"
    );
    let expected = file.metadata()?;
    anyhow::ensure!(
        expected.is_file() && expected.nlink() == 1,
        "invalid lifecycle owner lease inode"
    );
    let name = std::ffi::CString::new(owner)?;
    let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            observed.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let observed = unsafe { observed.assume_init() };
    anyhow::ensure!(
        observed.st_mode & libc::S_IFMT == libc::S_IFREG
            && observed.st_nlink == 1
            && observed.st_dev == expected.dev()
            && observed.st_ino == expected.ino(),
        "lifecycle owner lease inode changed"
    );
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn unlink_owner_lease_file(_database: &Path, _owner: &str, _file: &File) -> Result<()> {
    anyhow::bail!("lifecycle owner cleanup requires advisory lock support")
}

#[cfg(unix)]
fn retire_owner(conn: &Connection, database: &Path, owner: &str, file: &File) -> Result<()> {
    anyhow::ensure!(
        conn.is_autocommit(),
        "lifecycle cleanup requires committed receipts"
    );
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE owner_id=?1 AND status NOT IN ('completed','failed','interrupted'))",
        [owner], |row| row.get(0),
    )?;
    anyhow::ensure!(!active, "lifecycle owner still has a reservation");
    unlink_owner_lease_file(database, owner, file)
}

#[cfg(not(unix))]
fn retire_owner(_conn: &Connection, _database: &Path, _owner: &str, _file: &File) -> Result<()> {
    anyhow::bail!("lifecycle owner cleanup requires advisory lock support")
}

pub(super) fn retire_finished_owners(conn: &Connection, database: &Path) -> Result<()> {
    if !conn.is_autocommit() {
        return Ok(());
    }
    let owners: Vec<String> = conn
        .prepare("SELECT DISTINCT owner_id FROM package_lifecycle_jobs WHERE status IN ('completed','failed','interrupted') AND owner_id!=''")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for owner in owners {
        if let Ok(file) = open_owner_file(database, &owner) {
            if matches!(lock_exclusive(&file), Ok(true)) {
                let _ = retire_owner(conn, database, &owner, &file);
            }
        }
    }
    Ok(())
}
