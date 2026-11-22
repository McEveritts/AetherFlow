use anyhow::{Context, Result};
use rusqlite::Connection;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

pub struct OwnerLease {
    pub id: String,
    database: PathBuf,
    _file: File,
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
        crate::fs_security::create_dir_all_no_symlinks(parent, 0o755)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        anyhow::ensure!(
            lock_exclusive(&file)?,
            "new lifecycle owner lease already locked"
        );
        let lease = Self {
            id,
            database: database.to_owned(),
            _file: file,
        };
        lease._file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(lease)
    }
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        let cleanup = || -> Result<()> {
            let conn = Connection::open_with_flags(
                &self.database,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            conn.busy_timeout(std::time::Duration::ZERO)?;
            retire_owner(&conn, &self.database, &self.id, &self._file)
        };
        let _ = cleanup();
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
    crate::fs_security::ensure_no_symlink_ancestors(&path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("cannot inspect lifecycle owner lease")?;
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "invalid lifecycle owner lease file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(metadata.nlink() == 1, "linked lifecycle owner lease file");
    }
    Ok(file)
}

pub fn owner_is_alive(database: &Path, owner: &str) -> Result<bool> {
    let file = open_owner_file(database, owner)?;
    Ok(!lock_exclusive(&file)?)
}

#[cfg(unix)]
fn retire_owner(conn: &Connection, database: &Path, owner: &str, file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    anyhow::ensure!(
        conn.is_autocommit(),
        "lifecycle cleanup requires committed receipts"
    );
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE owner_id=?1 AND status NOT IN ('completed','failed','interrupted'))",
        [owner], |row| row.get(0),
    )?;
    anyhow::ensure!(!active, "lifecycle owner still has a reservation");
    let path = lease_path(database, owner)?;
    let parent = path.parent().context("missing lifecycle lease directory")?;
    crate::fs_security::ensure_no_symlink_ancestors(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
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
