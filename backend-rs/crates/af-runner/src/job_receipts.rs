use af_models::SelfUpdateJobStatus;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[cfg(test)]
#[path = "receipt_security_regressions.rs"]
mod security_regressions;

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::other(error.to_string())
}

fn c_name(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(io_error)
}

fn open_at(parent: libc::c_int, name: &OsStr, flags: libc::c_int, mode: u32) -> Result<File> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            c_name(name)?.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn entry_at(parent: &File, name: &OsStr) -> Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            c_name(name)?.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { metadata.assume_init() })
}

fn verify_entry(parent: &File, name: &OsStr, file: &File, directory: bool) -> Result<()> {
    let held = file.metadata()?;
    let entry = entry_at(parent, name)?;
    let kind = if directory {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    if entry.st_mode & libc::S_IFMT != kind
        || held.dev() != entry.st_dev
        || held.ino() != entry.st_ino
        || held.nlink() == 0
        || (!directory && (!held.is_file() || held.nlink() != 1))
    {
        return Err(io_error("Receipt entry identity or link count changed"));
    }
    Ok(())
}

pub struct ReceiptDirectory {
    chain: Vec<(OsString, File)>,
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

impl ReceiptDirectory {
    pub fn open_existing(path: &Path) -> Result<Option<Self>> {
        match Self::open(path, false) {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn try_clone(&self) -> Result<Self> {
        self.verify()?;
        Ok(Self {
            chain: self
                .chain
                .iter()
                .map(|(name, file)| Ok((name.clone(), file.try_clone()?)))
                .collect::<Result<_>>()?,
        })
    }

    pub fn names(&self) -> Result<Vec<OsString>> {
        self.verify()?;
        let file = open_at(
            self.file().as_raw_fd(),
            OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        let stream = unsafe { libc::fdopendir(file.as_raw_fd()) };
        if stream.is_null() {
            return Err(Error::last_os_error());
        }
        std::mem::forget(file);
        let stream = DirectoryStream(stream);
        let mut names = Vec::new();
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error);
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(OsStr::from_bytes(name.to_bytes()).to_os_string());
            }
        }
        self.verify()?;
        Ok(names)
    }

    pub fn read_status(&self, name: &OsStr, unit: &str) -> Result<Option<SelfUpdateJobStatus>> {
        let guard = ReceiptLock::acquire_in(self.try_clone()?, name, false)?;
        let Some((mut status, _file)) = guard.read()? else {
            return Ok(None);
        };
        if status.job_unit.is_empty() {
            status.job_unit = unit.into();
        }
        status
            .validate_invariants(Some(unit))
            .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
        Ok(Some(status))
    }

    pub fn compare_exchange(
        &self,
        name: &OsStr,
        expected: &SelfUpdateJobStatus,
        replacement: &SelfUpdateJobStatus,
    ) -> Result<SelfUpdateJobStatus> {
        compare_exchange_locked(
            ReceiptLock::acquire_in(self.try_clone()?, name, true)?,
            expected,
            replacement,
        )
    }

    pub fn launch_is_alive(&self, name: &OsStr, required: bool) -> Result<bool> {
        let guard = ReceiptLock::acquire_in(self.try_clone()?, name, false)?;
        launch_is_alive_locked(guard, required)
    }

    fn open(path: &Path, create: bool) -> Result<Self> {
        if path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(io_error("Receipt directory traversal is forbidden"));
        }
        let root = if path.is_absolute() { "/" } else { "." };
        let mut directory = Self {
            chain: vec![(
                root.into(),
                open_at(
                    libc::AT_FDCWD,
                    OsStr::new(root),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?,
            )],
        };
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            directory.verify()?;
            if create {
                let result = unsafe {
                    libc::mkdirat(directory.file().as_raw_fd(), c_name(name)?.as_ptr(), 0o755)
                };
                if result != 0 && Error::last_os_error().kind() != ErrorKind::AlreadyExists {
                    return Err(Error::last_os_error());
                }
            }
            let child = open_at(
                directory.file().as_raw_fd(),
                name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            verify_entry(directory.file(), name, &child, true)?;
            directory.chain.push((name.to_os_string(), child));
        }
        directory.verify()?;
        Ok(directory)
    }

    fn file(&self) -> &File {
        &self.chain.last().unwrap().1
    }

    fn child(&self, name: &OsStr, create: bool) -> Result<Self> {
        self.verify()?;
        if create {
            let result =
                unsafe { libc::mkdirat(self.file().as_raw_fd(), c_name(name)?.as_ptr(), 0o755) };
            if result != 0 && Error::last_os_error().kind() != ErrorKind::AlreadyExists {
                return Err(Error::last_os_error());
            }
        }
        let child = open_at(
            self.file().as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        verify_entry(self.file(), name, &child, true)?;
        let mut chain = self
            .chain
            .iter()
            .map(|(component, file)| Ok((component.clone(), file.try_clone()?)))
            .collect::<Result<Vec<_>>>()?;
        chain.push((name.to_os_string(), child));
        let directory = Self { chain };
        directory.verify()?;
        Ok(directory)
    }

    fn verify(&self) -> Result<()> {
        let root = self.chain[0].1.metadata()?;
        if !root.is_dir() || root.nlink() == 0 {
            return Err(io_error("Receipt directory root disappeared"));
        }
        for index in 1..self.chain.len() {
            verify_entry(
                &self.chain[index - 1].1,
                &self.chain[index].0,
                &self.chain[index].1,
                true,
            )?;
        }
        Ok(())
    }

    fn open_file(&self, name: &OsStr, flags: libc::c_int, mode: u32) -> Result<File> {
        self.verify()?;
        let file = open_at(self.file().as_raw_fd(), name, flags, mode)?;
        verify_entry(self.file(), name, &file, false)?;
        self.verify()?;
        Ok(file)
    }
}

struct ReceiptLock {
    directory: ReceiptDirectory,
    name: OsString,
    lock_name: OsString,
    file: File,
}

impl ReceiptLock {
    fn acquire(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| io_error("Missing receipt filename"))?;
        let directory = ReceiptDirectory::open(path.parent().unwrap_or(Path::new(".")), true)?;
        Self::acquire_in(directory, name, true)
    }

    fn acquire_in(directory: ReceiptDirectory, name: &OsStr, exclusive: bool) -> Result<Self> {
        if Path::new(name).components().count() != 1
            || !matches!(
                Path::new(name).components().next(),
                Some(Component::Normal(_))
            )
        {
            return Err(io_error("Invalid receipt filename"));
        }
        let mut lock_name = name.to_os_string();
        lock_name.push(".lock");
        let file = directory.open_file(&lock_name, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        let operation = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH | libc::LOCK_NB
        };
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            return Err(Error::last_os_error());
        }
        let guard = Self {
            directory,
            name: name.to_os_string(),
            lock_name,
            file,
        };
        guard.verify()?;
        Ok(guard)
    }

    fn verify(&self) -> Result<()> {
        self.directory.verify()?;
        verify_entry(self.directory.file(), &self.lock_name, &self.file, false)
    }

    fn read(&self) -> Result<Option<(SelfUpdateJobStatus, File)>> {
        self.verify()?;
        let mut file = match self.directory.open_file(&self.name, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Receipt exceeds maximum size",
            ));
        }
        self.verify()?;
        verify_entry(self.directory.file(), &self.name, &file, false)?;
        Ok(Some((
            serde_json::from_slice(&bytes)
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))?,
            file,
        )))
    }

    fn persist(&self, status: &SelfUpdateJobStatus, previous: Option<&File>) -> Result<()> {
        self.verify()?;
        let mut temporary = self.name.clone();
        temporary.push(format!(".tmp.{}", uuid::Uuid::new_v4()));
        let mut file = self.directory.open_file(
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o644,
        )?;
        let result = (|| {
            file.write_all(&serde_json::to_vec_pretty(status).map_err(io_error)?)?;
            file.sync_all()?;
            self.verify()?;
            verify_entry(self.directory.file(), &temporary, &file, false)?;
            if let Some(previous) = previous {
                verify_entry(self.directory.file(), &self.name, previous, false)?;
            } else {
                match entry_at(self.directory.file(), &self.name) {
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    _ => return Err(io_error("Receipt appeared during update")),
                }
            }
            if unsafe {
                libc::renameat(
                    self.directory.file().as_raw_fd(),
                    c_name(&temporary)?.as_ptr(),
                    self.directory.file().as_raw_fd(),
                    c_name(&self.name)?.as_ptr(),
                )
            } != 0
            {
                return Err(Error::last_os_error());
            }
            self.verify()?;
            verify_entry(self.directory.file(), &self.name, &file, false)?;
            self.directory.file().sync_all()
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(
                    self.directory.file().as_raw_fd(),
                    c_name(&temporary)?.as_ptr(),
                    0,
                )
            };
        }
        result
    }
}

pub fn write(path: &Path, status: &SelfUpdateJobStatus) -> Result<()> {
    status
        .validate_invariants(Some(&status.job_unit))
        .map_err(io_error)?;
    let guard = ReceiptLock::acquire(path)?;
    let previous = guard.read()?;
    if let Some((current, _)) = previous.as_ref() {
        current
            .validate_invariants(Some(&status.job_unit))
            .map_err(io_error)?;
        if current.job_unit != status.job_unit {
            return Err(io_error("Self-update receipt identity does not match"));
        }
        if current.completed || (current.status != "launching" && status.status == "launching") {
            return Ok(());
        }
    }
    guard.persist(status, previous.as_ref().map(|(_, file)| file))
}

pub fn compare_exchange(
    path: &Path,
    expected: &SelfUpdateJobStatus,
    replacement: &SelfUpdateJobStatus,
) -> Result<SelfUpdateJobStatus> {
    compare_exchange_locked(ReceiptLock::acquire(path)?, expected, replacement)
}

fn compare_exchange_locked(
    guard: ReceiptLock,
    expected: &SelfUpdateJobStatus,
    replacement: &SelfUpdateJobStatus,
) -> Result<SelfUpdateJobStatus> {
    replacement
        .validate_invariants(Some(&expected.job_unit))
        .map_err(io_error)?;
    let (current, file) = guard
        .read()?
        .ok_or_else(|| io_error("Self-update receipt disappeared"))?;
    current
        .validate_invariants(Some(&expected.job_unit))
        .map_err(io_error)?;
    if current != *expected || current.completed {
        return Ok(current);
    }
    guard.persist(replacement, Some(&file))?;
    Ok(replacement.clone())
}

pub fn claim(path: &Path, unit: &str) -> Result<()> {
    let guard = ReceiptLock::acquire(path)?;
    let previous = guard.read()?;
    if let Some((current, _)) = previous.as_ref() {
        current.validate_invariants(Some(unit)).map_err(io_error)?;
        if current.completed {
            return Err(io_error(
                "Self-update admission was closed; refusing a late worker",
            ));
        }
    }
    let running = SelfUpdateJobStatus {
        status: "running".into(),
        completed: false,
        success: false,
        job_unit: unit.into(),
        error: String::new(),
        exit_code: None,
    };
    running.validate_invariants(Some(unit)).map_err(io_error)?;
    guard.persist(&running, previous.as_ref().map(|(_, file)| file))
}

fn launch_owner_path(path: &Path) -> PathBuf {
    path.with_extension("json.launch-owner")
}

pub struct LaunchOwner {
    directory: ReceiptDirectory,
    _lease_directory: ReceiptDirectory,
    _file: File,
}

impl LaunchOwner {
    pub fn directory_identity(&self) -> Result<(u64, u64)> {
        self.directory.verify()?;
        let metadata = self.directory.file().metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
}

pub fn begin_launch(path: &Path) -> Result<LaunchOwner> {
    let guard = ReceiptLock::acquire(path)?;
    let lease_path = path.with_extension("lifecycle-owners");
    let lease_directory = guard
        .directory
        .child(lease_path.file_name().unwrap(), true)?;
    let owner = uuid::Uuid::new_v4().to_string();
    let file = lease_directory.open_file(
        OsStr::new(&owner),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o644,
    )?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::last_os_error());
    }
    file.sync_all()?;
    lease_directory.file().sync_all()?;
    guard.verify()?;
    let owner_path = launch_owner_path(path);
    let mut owner_file = guard.directory.open_file(
        owner_path.file_name().unwrap(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o644,
    )?;
    owner_file.write_all(owner.as_bytes())?;
    owner_file.sync_all()?;
    guard.verify()?;
    verify_entry(
        guard.directory.file(),
        owner_path.file_name().unwrap(),
        &owner_file,
        false,
    )?;
    lease_directory.verify()?;
    guard.directory.file().sync_all()?;
    Ok(LaunchOwner {
        directory: guard.directory,
        _lease_directory: lease_directory,
        _file: file,
    })
}

#[cfg(test)]
pub fn launch_is_alive(path: &Path) -> Result<bool> {
    let guard = ReceiptLock::acquire(path)?;
    launch_is_alive_locked(guard, true)
}

fn launch_is_alive_locked(guard: ReceiptLock, required: bool) -> Result<bool> {
    let owner_path = launch_owner_path(Path::new(&guard.name));
    let owner_name = owner_path.file_name().unwrap();
    let mut owner_file = match guard.directory.open_file(owner_name, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound && !required => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut owner = String::new();
    Read::by_ref(&mut owner_file)
        .take(129)
        .read_to_string(&mut owner)?;
    if owner.len() > 128 {
        return Err(io_error("Launch owner marker exceeds maximum size"));
    }
    uuid::Uuid::parse_str(owner.trim()).map_err(io_error)?;
    verify_entry(guard.directory.file(), owner_name, &owner_file, false)?;
    let lease_path = Path::new(&guard.name).with_extension("lifecycle-owners");
    let directory = guard
        .directory
        .child(lease_path.file_name().unwrap(), false)?;
    let file = directory.open_file(OsStr::new(owner.trim()), libc::O_RDONLY, 0)?;
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    let alive = if locked == 0 {
        false
    } else if Error::last_os_error().kind() == ErrorKind::WouldBlock {
        true
    } else {
        return Err(Error::last_os_error());
    };
    guard.verify()?;
    directory.verify()?;
    verify_entry(directory.file(), OsStr::new(owner.trim()), &file, false)?;
    Ok(alive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::{Command, Output, Stdio};

    const UNIT: &str =
        "aetherflow-self-update-restart-aetherflow-api-1234567890abcdef1234567890abcdef.service";

    struct Fixture {
        root: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir_name = format!(
                "c11-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..10]
            );
            let base = std::env::var_os("TMPDIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let candidate = base.join(&dir_name);
            let root = if candidate.join("sync").as_os_str().len() < 95 {
                candidate
            } else {
                PathBuf::from("/tmp").join(dir_name)
            };
            fs::create_dir(&root).unwrap();
            let path = root.join("jobs").join(format!("{UNIT}.json"));
            fs::create_dir(root.join("jobs")).unwrap();
            fs::create_dir(root.join("victim")).unwrap();
            fs::write(root.join("maintenance.lock"), b"").unwrap();
            Self { root, path }
        }

        fn status(phase: &str) -> SelfUpdateJobStatus {
            SelfUpdateJobStatus {
                status: phase.into(),
                completed: phase == "succeeded" || phase == "failed",
                success: phase == "succeeded",
                job_unit: UNIT.into(),
                error: if phase == "failed" {
                    "fixture failure".into()
                } else {
                    String::new()
                },
                exit_code: match phase {
                    "succeeded" => Some(0),
                    "failed" => Some(1),
                    _ => None,
                },
            }
        }

        fn prime(&self) {
            write(&self.path, &Self::status("launching")).unwrap();
        }

        fn identity(&self) -> (u64, u64) {
            let directory = ReceiptDirectory::open(self.path.parent().unwrap(), false).unwrap();
            let metadata = directory.file().metadata().unwrap();
            (metadata.dev(), metadata.ino())
        }

        fn fake(&self, body: &str) {
            let program = format!("#!/usr/bin/python3\nimport os, sys, json, socket\nroot = {}\nwith open(root + '/calls', 'a') as log: log.write(sys.argv[1] + '\\n')\n{}\n", serde_json::to_string(self.root.to_str().unwrap()).unwrap(), body);
            fs::write(self.root.join("fake-systemctl"), program).unwrap();
            fs::set_permissions(
                self.root.join("fake-systemctl"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }

        fn command(&self, identity: Option<(u64, u64)>) -> Command {
            let maintenance = fs::metadata(self.root.join("maintenance.lock")).unwrap();
            let mut command = Command::new("/bin/bash");
            command
                .args([
                    "-c",
                    include_str!("core_restart_worker.sh"),
                    "test-core-restart",
                    "aetherflow-api",
                ])
                .arg(&self.path)
                .arg(UNIT)
                .arg(self.root.join("maintenance.lock"))
                .arg(self.root.join("fake-systemctl"))
                .arg(maintenance.dev().to_string())
                .arg(maintenance.ino().to_string());
            if let Some((device, inode)) = identity {
                command.arg(device.to_string()).arg(inode.to_string());
            }
            command
        }

        fn run(&self, identity: (u64, u64)) -> Output {
            self.command(Some(identity)).output().unwrap()
        }

        fn load(&self) -> SelfUpdateJobStatus {
            serde_json::from_slice(&fs::read(&self.path).unwrap()).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn receipt_regular_success_cas_terminal_and_owner_fences() {
        let fixture = Fixture::new();
        let owner = begin_launch(&fixture.path).unwrap();
        assert_eq!(owner.directory_identity().unwrap(), fixture.identity());
        assert!(launch_is_alive(&fixture.path).unwrap());
        let owner_id = fs::read_to_string(launch_owner_path(&fixture.path)).unwrap();
        assert!(af_release::lifecycle::owner_is_alive(&fixture.path, owner_id.trim()).unwrap());
        fixture.prime();
        claim(&fixture.path, UNIT).unwrap();
        assert_eq!(
            compare_exchange(
                &fixture.path,
                &Fixture::status("launching"),
                &Fixture::status("failed")
            )
            .unwrap()
            .status,
            "running"
        );
        write(&fixture.path, &Fixture::status("launching")).unwrap();
        assert_eq!(fixture.load().status, "running");
        write(&fixture.path, &Fixture::status("succeeded")).unwrap();
        write(&fixture.path, &Fixture::status("failed")).unwrap();
        assert_eq!(fixture.load().status, "succeeded");
        assert!(claim(&fixture.path, UNIT).is_err());
        drop(owner);
        assert!(!launch_is_alive(&fixture.path).unwrap());
    }

    #[test]
    fn receipt_refuses_symlink_parent_files_and_hardlinks() {
        let fixture = Fixture::new();
        fs::rename(fixture.root.join("jobs"), fixture.root.join("original")).unwrap();
        symlink(fixture.root.join("victim"), fixture.root.join("jobs")).unwrap();
        assert!(write(&fixture.path, &Fixture::status("launching")).is_err());
        assert!(begin_launch(&fixture.path).is_err());
        assert_eq!(
            fs::read_dir(fixture.root.join("victim")).unwrap().count(),
            0
        );
        fs::remove_file(fixture.root.join("jobs")).unwrap();
        fs::rename(fixture.root.join("original"), fixture.root.join("jobs")).unwrap();
        let victim = fixture.root.join("victim/file");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &fixture.path).unwrap();
        assert!(write(&fixture.path, &Fixture::status("launching")).is_err());
        fs::remove_file(&fixture.path).unwrap();
        fs::hard_link(&victim, &fixture.path).unwrap();
        assert!(write(&fixture.path, &Fixture::status("launching")).is_err());
        fs::remove_file(&fixture.path).unwrap();
        let lock_path = fixture.path.with_extension("json.lock");
        fs::remove_file(&lock_path).unwrap();
        symlink(&victim, &lock_path).unwrap();
        assert!(claim(&fixture.path, UNIT).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    }

    #[test]
    fn receipt_held_directory_and_lock_replacement_fail_closed() {
        let fixture = Fixture::new();
        fixture.prime();
        let owner = begin_launch(&fixture.path).unwrap();
        let guard = ReceiptLock::acquire(&fixture.path).unwrap();
        let (_, previous) = guard.read().unwrap().unwrap();
        fs::rename(fixture.root.join("jobs"), fixture.root.join("original")).unwrap();
        fs::create_dir(fixture.root.join("jobs")).unwrap();
        assert!(owner.directory_identity().is_err());
        assert!(guard
            .directory
            .child(OsStr::new("must-not-appear"), true)
            .is_err());
        assert!(guard
            .persist(&Fixture::status("failed"), Some(&previous))
            .is_err());
        assert_eq!(fs::read_dir(fixture.root.join("jobs")).unwrap().count(), 0);
        drop(guard);
        fs::remove_dir(fixture.root.join("jobs")).unwrap();
        fs::rename(fixture.root.join("original"), fixture.root.join("jobs")).unwrap();
        let guard = ReceiptLock::acquire(&fixture.path).unwrap();
        fs::remove_file(fixture.path.with_extension("json.lock")).unwrap();
        fs::write(fixture.path.with_extension("json.lock"), b"").unwrap();
        assert!(guard.read().is_err());
    }

    #[test]
    fn receipt_owner_marker_and_lease_directory_symlinks_are_rejected() {
        let fixture = Fixture::new();
        symlink(
            fixture.root.join("victim"),
            fixture.path.with_extension("lifecycle-owners"),
        )
        .unwrap();
        assert!(begin_launch(&fixture.path).is_err());
        fs::remove_file(fixture.path.with_extension("lifecycle-owners")).unwrap();
        let owner = begin_launch(&fixture.path).unwrap();
        fs::remove_file(launch_owner_path(&fixture.path)).unwrap();
        let victim = fixture.root.join("victim/owner");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, launch_owner_path(&fixture.path)).unwrap();
        assert!(launch_is_alive(&fixture.path).is_err());
        drop(owner);
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    }

    #[test]
    fn restart_worker_success_failure_missing_and_terminal_receipts() {
        for phase in ["missing", "launching", "succeeded", "failed"] {
            for exit_code in [0, 7] {
                let fixture = Fixture::new();
                if phase != "missing" {
                    write(&fixture.path, &Fixture::status(phase)).unwrap();
                }
                fixture.fake(&format!("sys.exit({exit_code})"));
                let output = fixture.run(fixture.identity());
                if phase == "launching" {
                    assert_eq!(
                        output.status.code(),
                        Some(exit_code),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert_eq!(
                        fixture.load().status,
                        if exit_code == 0 {
                            "succeeded"
                        } else {
                            "failed"
                        }
                    );
                    assert_eq!(fixture.load().exit_code, Some(exit_code));
                } else {
                    assert!(!output.status.success());
                    assert!(!fixture.root.join("calls").exists());
                    if phase != "missing" {
                        assert_eq!(fixture.load().status, phase);
                    }
                }
            }
        }
    }

    #[test]
    fn restart_worker_refuses_symlink_or_replaced_scheduled_parent() {
        for primed in [false, true] {
            for symlinked in [false, true] {
                let fixture = Fixture::new();
                fixture.prime();
                fixture.fake("sys.exit(0)");
                let identity = fixture.identity();
                fs::rename(fixture.root.join("jobs"), fixture.root.join("original")).unwrap();
                if symlinked {
                    symlink(fixture.root.join("victim"), fixture.root.join("jobs")).unwrap();
                } else {
                    fs::create_dir(fixture.root.join("jobs")).unwrap();
                }
                if primed {
                    fs::write(
                        &fixture.path,
                        serde_json::to_vec(&Fixture::status("launching")).unwrap(),
                    )
                    .unwrap();
                }
                let before: Vec<_> = fs::read_dir(fixture.root.join("jobs"))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect();
                let output = fixture.run(identity);
                assert!(!output.status.success());
                assert!(!fixture.root.join("calls").exists());
                let after: Vec<_> = fs::read_dir(fixture.root.join("jobs"))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect();
                assert_eq!(before, after);
                assert_eq!(
                    serde_json::from_slice::<SelfUpdateJobStatus>(
                        &fs::read(
                            fixture
                                .root
                                .join("original")
                                .join(fixture.path.file_name().unwrap())
                        )
                        .unwrap()
                    )
                    .unwrap()
                    .status,
                    "launching"
                );
            }
        }
    }

    #[test]
    fn restart_worker_refuses_legacy_arguments_and_replacement_during_restart() {
        let fixture = Fixture::new();
        fixture.prime();
        fixture.fake("if sys.argv[1] == 'restart':\n os.rename(root + '/jobs', root + '/original')\n os.symlink(root + '/victim', root + '/jobs')");
        assert!(!fixture.command(None).output().unwrap().status.success());
        assert!(!fixture.root.join("calls").exists());
        let output = fixture.run(fixture.identity());
        assert!(!output.status.success());
        assert_eq!(
            fs::read_to_string(fixture.root.join("calls")).unwrap(),
            "restart\n"
        );
        assert_eq!(
            fs::read_dir(fixture.root.join("victim")).unwrap().count(),
            0
        );
    }

    #[test]
    fn restart_worker_refuses_leaf_symlinks_hardlinks_and_wrong_job_owner() {
        for kind in [
            "receipt-symlink",
            "receipt-hardlink",
            "lock-symlink",
            "lock-hardlink",
            "owner",
        ] {
            let fixture = Fixture::new();
            fixture.prime();
            fixture.fake("sys.exit(0)");
            let target = fixture.root.join("victim/file");
            fs::write(
                &target,
                serde_json::to_vec(&Fixture::status("launching")).unwrap(),
            )
            .unwrap();
            let before = fs::read(&target).unwrap();
            if kind == "owner" {
                let mut wrong = Fixture::status("launching");
                wrong.job_unit = wrong
                    .job_unit
                    .replace("aetherflow-api", "aetherflow-runner");
                fs::write(&fixture.path, serde_json::to_vec(&wrong).unwrap()).unwrap();
            } else {
                let replaced = if kind.starts_with("receipt") {
                    fixture.path.clone()
                } else {
                    fixture.path.with_extension("json.lock")
                };
                fs::remove_file(&replaced).unwrap();
                if kind.ends_with("symlink") {
                    symlink(&target, replaced).unwrap();
                } else {
                    fs::hard_link(&target, replaced).unwrap();
                }
            }
            assert!(!fixture.run(fixture.identity()).status.success(), "{kind}");
            assert!(!fixture.root.join("calls").exists(), "{kind}");
            assert_eq!(fs::read(&target).unwrap(), before, "{kind}");
        }
    }

    #[test]
    fn receipt_refuses_replaced_destination_and_nonregular_fifo() {
        let fixture = Fixture::new();
        fixture.prime();
        let guard = ReceiptLock::acquire(&fixture.path).unwrap();
        let (_, previous) = guard.read().unwrap().unwrap();
        fs::rename(&fixture.path, fixture.path.with_extension("original")).unwrap();
        fs::write(
            &fixture.path,
            serde_json::to_vec(&Fixture::status("succeeded")).unwrap(),
        )
        .unwrap();
        assert!(guard
            .persist(&Fixture::status("failed"), Some(&previous))
            .is_err());
        assert_eq!(fixture.load().status, "succeeded");
        drop(guard);
        fs::remove_file(&fixture.path).unwrap();
        let name = c_name(fixture.path.as_os_str()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(claim(&fixture.path, UNIT).is_err());
    }

    #[test]
    fn restart_worker_cleanup_failure_releases_sidecar_before_failure_receipt() {
        let fixture = Fixture::new();
        fixture.prime();
        fixture.fake("sys.exit(0)");
        fs::write(fixture.root.join("sitecustomize.py"),
            "import os\noriginal = os.replace\nattempts = 0\ndef replace(source, target, **options):\n global attempts\n attempts += 1\n if attempts == 1:\n  os.unlink(source, dir_fd=options['src_dir_fd'])\n  raise FileNotFoundError('fixture removed temporary before failed rename')\n return original(source, target, **options)\nos.replace = replace\n").unwrap();
        let command = fixture.command(Some(fixture.identity()));
        let output = Command::new("/usr/bin/timeout")
            .arg("10s")
            .arg(command.get_program())
            .args(command.get_args())
            .env("PYTHONPATH", &fixture.root)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fixture.load().status, "failed");
        assert!(!fixture.root.join("calls").exists());
    }

    #[test]
    fn restart_worker_child_retains_maintenance_flock_after_worker_death() {
        use std::os::unix::net::UnixListener;
        let fixture = Fixture::new();
        fixture.prime();
        let listener = UnixListener::bind(fixture.root.join("sync")).unwrap();
        fixture.fake("guard = next(fd for fd in range(3, 256) if os.path.exists('/proc/self/fd/' + str(fd)) and os.fstat(fd).st_ino == os.stat(root + '/maintenance.lock').st_ino)\nstream = socket.socket(socket.AF_UNIX)\nstream.connect(root + '/sync')\nstream.sendall(b'R')\nstream.recv(1)\nos.close(guard)\nstream.sendall(b'D')");
        let mut worker = fixture
            .command(Some(fixture.identity()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut signal = [0];
        stream.read_exact(&mut signal).unwrap();
        assert_eq!(signal, *b"R");
        worker.kill().unwrap();
        worker.wait().unwrap();
        let maintenance = File::open(fixture.root.join("maintenance.lock")).unwrap();
        assert_ne!(
            unsafe { libc::flock(maintenance.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert_eq!(Error::last_os_error().kind(), ErrorKind::WouldBlock);
        stream.write_all(b"X").unwrap();
        stream.read_exact(&mut signal).unwrap();
        assert_eq!(signal, *b"D");
        assert_eq!(
            unsafe { libc::flock(maintenance.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }
}
