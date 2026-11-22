use crate::path::UPLOAD_TEMP_PREFIX;
use crate::syscall::{
    fstat_fd, fstatat_nofollow, open_regular_file_at, openat_no_symlinks, renameat_noreplace,
    sync_dir,
};
use crate::BrowserFs;
use rand::Rng;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, OwnedFd};

#[derive(Debug)]
pub struct PendingUpload {
    parent_fd: OwnedFd,
    temp_name: CString,
    target_name: CString,
    file: File,
    committed: bool,
}

impl BrowserFs {
    pub fn open_file(&self, path: &str) -> io::Result<File> {
        let (parent_fd, leaf) = self.resolve_parent_and_leaf(path)?;
        open_regular_file_at(parent_fd.as_raw_fd(), leaf.as_c_str())
    }

    pub fn begin_upload(&self, path: &str) -> io::Result<PendingUpload> {
        let (parent_fd, target_name) = self.resolve_parent_and_leaf(path)?;
        match fstatat_nofollow(parent_fd.as_raw_fd(), target_name.as_c_str()) {
            Ok(st) => {
                let mode_type = st.st_mode & libc::S_IFMT;
                match mode_type {
                    libc::S_IFREG if st.st_nlink > 1 => {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "hardlinked regular files are not permitted",
                        ));
                    }
                    libc::S_IFREG | libc::S_IFDIR => {
                        return Err(Error::new(
                            ErrorKind::AlreadyExists,
                            "destination already exists",
                        ));
                    }
                    libc::S_IFLNK => {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "symlinks are not permitted",
                        ));
                    }
                    _ => {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "special files are not permitted",
                        ));
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }

        allocate_pending_upload(parent_fd, target_name)
    }

    pub fn begin_replace(&self, path: &str) -> io::Result<PendingUpload> {
        let (parent_fd, target_name) = self.resolve_parent_and_leaf(path)?;
        let st = fstatat_nofollow(parent_fd.as_raw_fd(), target_name.as_c_str())?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => {
                if st.st_nlink != 1 {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "hardlinked regular files are not permitted",
                    ));
                }
            }
            libc::S_IFDIR => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "replacement target is not a regular file",
                ));
            }
            libc::S_IFLNK => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "replacing symlinks is not permitted",
                ));
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "replacing special files is not permitted",
                ));
            }
        }

        allocate_pending_upload(parent_fd, target_name)
    }
}

impl PendingUpload {
    pub fn file(&self) -> io::Result<File> {
        self.file.try_clone()
    }

    pub fn commit(self) -> io::Result<()> {
        self.commit_with_directory_sync(sync_dir)
    }

    pub fn commit_replace(self, expected: &std::fs::File) -> io::Result<()> {
        self.commit_replace_with_directory_sync(expected, sync_dir)
    }

    pub(crate) fn commit_with_directory_sync(
        mut self,
        directory_sync: impl FnOnce(libc::c_int) -> io::Result<()>,
    ) -> io::Result<()> {
        let st_before = fstat_fd(self.file.as_raw_fd())?;
        if (st_before.st_mode & libc::S_IFMT) != libc::S_IFREG || st_before.st_nlink != 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "temporary upload file must be a single-link regular file",
            ));
        }
        self.file.sync_all()?;
        match fstatat_nofollow(self.parent_fd.as_raw_fd(), self.target_name.as_c_str()) {
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    "destination already exists",
                ))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        renameat_noreplace(
            self.parent_fd.as_raw_fd(),
            self.temp_name.as_c_str(),
            self.parent_fd.as_raw_fd(),
            self.target_name.as_c_str(),
        )?;
        self.committed = true;
        if let Err(error) = directory_sync(self.parent_fd.as_raw_fd()) {
            tracing::warn!(%error, "Upload published but directory durability could not be confirmed");
        }
        Ok(())
    }

    pub(crate) fn commit_replace_with_directory_sync(
        mut self,
        expected: &std::fs::File,
        directory_sync: impl FnOnce(libc::c_int) -> io::Result<()>,
    ) -> io::Result<()> {
        let st_temp = fstat_fd(self.file.as_raw_fd())?;
        if (st_temp.st_mode & libc::S_IFMT) != libc::S_IFREG || st_temp.st_nlink != 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "temporary upload file must be a single-link regular file",
            ));
        }
        self.file.sync_all()?;

        let st_expected = fstat_fd(expected.as_raw_fd())?;
        if (st_expected.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "expected handle is not a regular file",
            ));
        }
        if st_expected.st_nlink > 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "hardlinked regular files are not permitted",
            ));
        }

        let st_target = fstatat_nofollow(self.parent_fd.as_raw_fd(), self.target_name.as_c_str())?;
        let target_mode = st_target.st_mode & libc::S_IFMT;
        if target_mode == libc::S_IFLNK {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "replacing symlinks is not permitted",
            ));
        }
        if target_mode != libc::S_IFREG {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "replacement target is not a regular file",
            ));
        }
        if st_target.st_nlink != 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "hardlinked regular files are not permitted",
            ));
        }
        if st_expected.st_nlink != 1
            || st_target.st_dev != st_expected.st_dev
            || st_target.st_ino != st_expected.st_ino
        {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "replacement target identity does not match expected file",
            ));
        }

        let rc = unsafe {
            libc::renameat(
                self.parent_fd.as_raw_fd(),
                self.temp_name.as_ptr(),
                self.parent_fd.as_raw_fd(),
                self.target_name.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(Error::last_os_error());
        }
        self.committed = true;
        if let Err(error) = directory_sync(self.parent_fd.as_raw_fd()) {
            tracing::warn!(%error, "Replacement upload published but directory durability could not be confirmed");
        }
        Ok(())
    }
}

impl std::io::Write for PendingUpload {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for PendingUpload {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                libc::unlinkat(self.parent_fd.as_raw_fd(), self.temp_name.as_ptr(), 0);
            }
        }
    }
}

pub(crate) fn allocate_pending_upload(
    parent_fd: OwnedFd,
    target_name: CString,
) -> io::Result<PendingUpload> {
    let mut rng = rand::thread_rng();
    for _ in 0..64 {
        let token: u128 = rng.gen();
        let candidate = format!("{UPLOAD_TEMP_PREFIX}{token:032x}");
        let temp_name = CString::new(candidate).expect("hex temp name has no NUL");
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        match openat_no_symlinks(parent_fd.as_raw_fd(), temp_name.as_c_str(), flags, 0o600) {
            Ok(fd) => {
                return Ok(PendingUpload {
                    parent_fd,
                    temp_name,
                    target_name,
                    file: File::from(fd),
                    committed: false,
                });
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(Error::new(
        ErrorKind::AlreadyExists,
        "failed to allocate unique temporary upload file",
    ))
}
