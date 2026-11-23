use chrono::{DateTime, TimeZone, Utc};
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_XDEV: u64 = 0x01;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub(crate) struct DirGuard(pub(crate) *mut libc::DIR);

impl Drop for DirGuard {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

pub(crate) fn open_dir_stream(dir_fd: libc::c_int) -> io::Result<(DirGuard, libc::c_int)> {
    let dup_fd = dup_cloexec(dir_fd)?;
    let dir_ptr = unsafe { libc::fdopendir(dup_fd.as_raw_fd()) };
    if dir_ptr.is_null() {
        return Err(Error::last_os_error());
    }
    std::mem::forget(dup_fd);
    let guard = DirGuard(dir_ptr);
    let raw_fd = unsafe { libc::dirfd(guard.0) };
    if raw_fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok((guard, raw_fd))
}

pub(crate) fn open_regular_file_at(dirfd: libc::c_int, leaf: &CStr) -> io::Result<File> {
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let fd = openat_no_symlinks(dirfd, leaf, flags, 0)?;
    let st = fstat_fd(fd.as_raw_fd())?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    if st.st_nlink > 1 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "hardlinked regular files are not permitted",
        ));
    }
    clear_nonblock(fd.as_raw_fd())?;
    let st_after = fstat_fd(fd.as_raw_fd())?;
    if (st_after.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st_after.st_dev != st.st_dev
        || st_after.st_ino != st.st_ino
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "file identity changed during open validation",
        ));
    }
    if st_after.st_nlink > 1 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "hardlinked regular files are not permitted",
        ));
    }
    Ok(File::from(fd))
}

pub(crate) fn readlink_at_utf8(dirfd: libc::c_int, name: &CStr) -> io::Result<String> {
    let mut buffer = [0u8; 4097];
    let count = unsafe {
        libc::readlinkat(
            dirfd,
            name.as_ptr(),
            buffer.as_mut_ptr() as *mut libc::c_char,
            buffer.len(),
        )
    };
    if count < 0 {
        return Err(Error::last_os_error());
    }
    let length = count as usize;
    if length == 0 || length >= buffer.len() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "symlink target length out of bounds",
        ));
    }
    let text = std::str::from_utf8(&buffer[..length]).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "symlink target contains non-UTF-8 bytes",
        )
    })?;
    Ok(text.to_string())
}

pub(crate) fn openat2_beneath_internal(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
) -> io::Result<OwnedFd> {
    openat2_with_resolve(
        dirfd,
        name,
        flags | libc::O_CLOEXEC,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    )
}

pub(crate) fn openat2_strict_no_symlinks(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
) -> io::Result<OwnedFd> {
    openat2_with_resolve(
        dirfd,
        name,
        flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
}

fn openat2_with_resolve(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
    resolve: u64,
) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: flags as u64,
        mode: if (flags & libc::O_CREAT) != 0 {
            mode as u64
        } else {
            0
        },
        resolve,
    };
    for attempt in 0..64 {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if rc >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(rc as libc::c_int) });
        }
        let err = Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EINTR) if attempt < 63 => {
                if attempt >= 4 {
                    std::thread::yield_now();
                }
            }
            _ => return Err(err),
        }
    }
    Err(Error::from_raw_os_error(libc::EAGAIN))
}

pub(crate) fn openat_no_symlinks(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: flags as u64,
        mode: if (flags & libc::O_CREAT) != 0 {
            mode as u64
        } else {
            0
        },
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    for attempt in 0..64 {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if rc >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(rc as libc::c_int) });
        }
        let err = Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EINTR) if attempt < 63 => {
                if attempt >= 4 {
                    std::thread::yield_now();
                }
            }
            Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => break,
            _ => return Err(err),
        }
    }

    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(crate) fn is_mount_boundary_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EXDEV)
}

pub(crate) fn openat_no_symlinks_no_xdev(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
    expected_dev: libc::dev_t,
) -> io::Result<OwnedFd> {
    let effective_flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = match openat2_with_resolve(
        dirfd,
        name,
        effective_flags,
        mode,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    ) {
        Ok(fd) => fd,
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
            ) =>
        {
            let raw = unsafe {
                libc::openat(dirfd, name.as_ptr(), effective_flags, mode as libc::c_uint)
            };
            if raw < 0 {
                return Err(Error::last_os_error());
            }
            unsafe { OwnedFd::from_raw_fd(raw) }
        }
        Err(err) => return Err(err),
    };
    let st = fstat_fd(fd.as_raw_fd())?;
    if st.st_dev != expected_dev {
        return Err(Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(fd)
}

pub(crate) fn dup_cloexec(fd: libc::c_int) -> io::Result<OwnedFd> {
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new_fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

pub(crate) fn fstat_fd(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc < 0 {
        return Err(Error::last_os_error());
    }
    Ok(st)
}

pub(crate) fn fstatat_nofollow(dirfd: libc::c_int, name: &CStr) -> io::Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    let rc = unsafe {
        libc::fstatat(
            dirfd,
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
        )
    };
    if rc < 0 {
        return Err(Error::last_os_error());
    }
    Ok(st)
}

pub(crate) fn clear_nonblock(fd: libc::c_int) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn renameat_noreplace(
    olddirfd: libc::c_int,
    oldname: &CStr,
    newdirfd: libc::c_int,
    newname: &CStr,
) -> io::Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            olddirfd,
            oldname.as_ptr(),
            newdirfd,
            newname.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn sync_dir(dirfd: libc::c_int) -> io::Result<()> {
    let rc = unsafe { libc::fsync(dirfd) };
    if rc < 0 {
        let err = Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::EINVAL) | Some(libc::EBADF)) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

pub(crate) fn format_mtime(st: &libc::stat) -> Option<String> {
    let nsec = u32::try_from(st.st_mtime_nsec).ok()?;
    let dt: DateTime<Utc> = Utc.timestamp_opt(st.st_mtime, nsec).single()?;
    Some(dt.to_rfc3339())
}
