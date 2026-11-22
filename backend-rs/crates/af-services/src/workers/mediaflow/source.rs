use super::*;

const MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES: usize = 64 * 1024;

#[cfg(unix)]
pub(in crate::workers) fn read_exact_at_file(
    file: &fs::File,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), String> {
    use std::os::unix::fs::FileExt;
    let mut read_total = 0usize;
    while read_total < buf.len() {
        match file.read_at(&mut buf[read_total..], offset + read_total as u64) {
            Ok(0) => {
                return Err("Source file truncated concurrently during fingerprinting".to_string());
            }
            Ok(n) => read_total += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(format!("Failed reading source file for fingerprint: {err}"));
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(in crate::workers) fn read_exact_at_file(
    file: &fs::File,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut cloned = file
        .try_clone()
        .map_err(|e| format!("Failed cloning source file for fingerprint: {e}"))?;
    cloned
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed seeking source file for fingerprint: {e}"))?;
    cloned
        .read_exact(buf)
        .map_err(|e| format!("Failed reading source file for fingerprint: {e}"))?;
    let _ = cloned.seek(SeekFrom::Start(0));
    Ok(())
}

pub(in crate::workers) fn compute_pinned_file_fingerprint(
    file: &fs::File,
    size: u64,
) -> Result<String, String> {
    compute_mediaflow_fingerprint(file, size, true)
}

pub(in crate::workers) fn compute_mediaflow_fingerprint(
    file: &fs::File,
    size: u64,
    source_file: bool,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    if source_file {
        hasher.update(b"af-mediaflow-source-v1\0");
    } else {
        hasher.update(b"af-mediaflow-output-v1\0");
    }
    hasher.update(size.to_le_bytes());
    #[cfg(unix)]
    if source_file {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|err| format!("Failed to stat source file for fingerprint: {err}"))?;
        hasher.update(metadata.ctime().to_le_bytes());
        hasher.update(metadata.ctime_nsec().to_le_bytes());
    }

    let sample = MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES as u64;
    if size <= sample * 3 {
        let mut offset = 0u64;
        let mut buf = vec![0u8; (size as usize).min(MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES)];
        while offset < size {
            let chunk_len = ((size - offset) as usize).min(buf.len());
            read_exact_at_file(file, offset, &mut buf[..chunk_len])?;
            hasher.update(offset.to_le_bytes());
            hasher.update((chunk_len as u64).to_le_bytes());
            hasher.update(&buf[..chunk_len]);
            offset += chunk_len as u64;
        }
    } else {
        let mid_offset = (size / 2).saturating_sub(sample / 2);
        let tail_offset = size.saturating_sub(sample);
        let mut buf = vec![0u8; MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES];
        for offset in [0u64, mid_offset, tail_offset] {
            read_exact_at_file(file, offset, &mut buf)?;
            hasher.update(offset.to_le_bytes());
            hasher.update(sample.to_le_bytes());
            hasher.update(&buf);
        }
    }

    Ok(format!("v1:sha256:{}", hex::encode(hasher.finalize())))
}

pub struct PinnedMediaflowSource {
    #[cfg(unix)]
    pub(super) parent_dir: fs::File,
    pub(super) source_file: fs::File,
    pub canon_parent: PathBuf,
    pub canon_src: PathBuf,
    pub source_fname: String,
    pub identity: MediaflowSourceIdentity,
    #[cfg(unix)]
    pub(super) src_mode: u32,
    #[cfg(unix)]
    change_time: (i64, i64),
}

impl PinnedMediaflowSource {
    #[cfg(unix)]
    pub fn source_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.source_file.as_raw_fd()
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_cast)] // libc::stat field widths vary across Linux targets.
    pub(in crate::workers) fn matches_live_stat(&self, st: &libc::stat) -> bool {
        (st.st_mode & libc::S_IFMT) == libc::S_IFREG
            && st.st_nlink == 1
            && (st.st_dev as u64) == self.identity.dev
            && (st.st_ino as u64) == self.identity.ino
            && st.st_size >= 0
            && (st.st_size as u64) == self.identity.size
            && (st.st_mtime as i64) == self.identity.mtime_sec
            && (st.st_mtime_nsec as i64) == self.identity.mtime_nsec
            && (st.st_ctime as i64, st.st_ctime_nsec as i64) == self.change_time
    }

    /// Re-verifies that the pinned source file descriptor, its live directory entry,
    /// and its bounded SHA-256 content fingerprint still match the identity captured at pin time.
    pub fn verify_still_matches_live(&self) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::io::AsRawFd;

            let fmeta = self
                .source_file
                .metadata()
                .map_err(|e| format!("Failed to stat pinned source file: {e}"))?;
            if !fmeta.is_file()
                || fmeta.nlink() != 1
                || fmeta.dev() != self.identity.dev
                || fmeta.ino() != self.identity.ino
                || fmeta.len() != self.identity.size
                || fmeta.mtime() != self.identity.mtime_sec
                || fmeta.mtime_nsec() != self.identity.mtime_nsec
                || (fmeta.ctime(), fmeta.ctime_nsec()) != self.change_time
            {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }

            let live_fp = compute_pinned_file_fingerprint(&self.source_file, self.identity.size)?;
            let live_st = fstatat_nofollow(self.parent_dir.as_raw_fd(), &self.source_fname)
                .map_err(|_| MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string())?;
            if live_fp != self.identity.fingerprint || !self.matches_live_stat(&live_st) {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let fmeta = self
                .source_file
                .metadata()
                .map_err(|e| format!("Failed to stat pinned source file: {e}"))?;
            if !fmeta.is_file() || fmeta.len() != self.identity.size {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }
            let live_fp = compute_pinned_file_fingerprint(&self.source_file, self.identity.size)?;
            if live_fp != self.identity.fingerprint {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
pub(in crate::workers) fn cstring_from_os_name(
    name: &str,
    label: &str,
) -> Result<std::ffi::CString, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(format!("Invalid {label} entry name"));
    }
    std::ffi::CString::new(name.as_bytes()).map_err(|_| format!("{label} contains interior NUL"))
}

#[cfg(unix)]
pub(in crate::workers) fn fstatat_nofollow(
    dirfd: std::os::unix::io::RawFd,
    entry_name: &str,
) -> std::io::Result<libc::stat> {
    use std::os::unix::ffi::OsStrExt;
    let c_name = std::ffi::CString::new(std::ffi::OsStr::new(entry_name).as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dirfd, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(st)
    }
}

#[cfg(unix)]
pub(in crate::workers) fn unlinkat_entry(dirfd: std::os::unix::io::RawFd, entry_name: &str) {
    if let Ok(c_name) = std::ffi::CString::new(entry_name.as_bytes()) {
        unsafe {
            let _ = libc::unlinkat(dirfd, c_name.as_ptr(), 0);
        }
    }
}

#[cfg(unix)]
pub(in crate::workers) fn write_dirfd_json_atomic(
    dirfd: std::os::unix::io::RawFd,
    target_name: &str,
    payload: &[u8],
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    let target_c = cstring_from_os_name(target_name, "metadata filename")?;
    let tmp_name = format!(
        ".tmp_meta_{}_{}",
        uuid::Uuid::new_v4().simple(),
        target_name.trim_start_matches('.')
    );
    let tmp_c = cstring_from_os_name(&tmp_name, "temporary metadata filename")?;

    let fd = unsafe {
        libc::openat(
            dirfd,
            tmp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Failed to open temporary metadata file {tmp_name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    unsafe {
        let _ = libc::fchmod(fd, 0o600);
    }
    let mut tmp_file = unsafe { fs::File::from_raw_fd(fd) };
    if let Err(err) = tmp_file
        .write_all(payload)
        .and_then(|()| tmp_file.sync_all())
    {
        drop(tmp_file);
        unlinkat_entry(dirfd, &tmp_name);
        return Err(format!("Failed writing metadata file {target_name}: {err}"));
    }
    drop(tmp_file);

    if let Ok(existing_st) = fstatat_nofollow(dirfd, target_name) {
        if (existing_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            unlinkat_entry(dirfd, &tmp_name);
            return Err(format!("Refusing symlink metadata target {target_name}"));
        }
    }

    let rc = unsafe { libc::renameat(dirfd, tmp_c.as_ptr(), dirfd, target_c.as_ptr()) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unlinkat_entry(dirfd, &tmp_name);
        return Err(format!(
            "Failed activating metadata file {target_name}: {err}"
        ));
    }
    unsafe {
        let _ = libc::fsync(dirfd);
    }
    Ok(())
}

#[cfg(unix)]
pub(in crate::workers) fn touch_dirfd_entry_mtime_nofollow(
    dirfd: std::os::unix::io::RawFd,
    entry_name: &str,
    now_unix: i64,
) -> Result<(), String> {
    let entry_c = cstring_from_os_name(entry_name, "trash entry filename")?;
    let ts = libc::timespec {
        tv_sec: now_unix as libc::time_t,
        tv_nsec: 0,
    };
    let times = [ts, ts];
    let rc = unsafe {
        libc::utimensat(
            dirfd,
            entry_c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        return Err(format!(
            "Failed updating mtime on trashed media {entry_name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(in crate::workers) fn persist_trash_entry_metadata_dirfd(
    trash_fd: std::os::unix::io::RawFd,
    trash_entry_name: &str,
    job_id: i64,
    original_name: &str,
    now_unix: i64,
) -> Result<(), String> {
    let _ = touch_dirfd_entry_mtime_nofollow(trash_fd, trash_entry_name, now_unix);
    let meta = MediaflowTrashMeta {
        job_id,
        trashed_at_unix: now_unix,
        original_name: original_name.to_string(),
    };
    let bytes =
        serde_json::to_vec(&meta).map_err(|e| format!("Failed serializing trash metadata: {e}"))?;
    let meta_name = trash_meta_filename(trash_entry_name);
    write_dirfd_json_atomic(trash_fd, &meta_name, &bytes)
}

pub(in crate::workers) fn read_regular_json_bounded<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Option<T> {
    use std::io::Read;

    #[cfg(unix)]
    let file = {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return None;
        }
        let f = unsafe { fs::File::from_raw_fd(fd) };
        if !f.metadata().ok()?.is_file() {
            return None;
        }
        f
    };
    #[cfg(not(unix))]
    let file = {
        let meta = fs::symlink_metadata(path).ok()?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return None;
        }
        fs::File::open(path).ok()?
    };

    let mut buf = Vec::new();
    file.take(64 * 1024).read_to_end(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

pub fn open_and_pin_mediaflow_source(raw_path: &str) -> Result<PinnedMediaflowSource, String> {
    let roots = mediaflow_allowed_roots();
    open_and_pin_mediaflow_source_in_roots(raw_path, &roots)
}

pub fn open_and_pin_mediaflow_source_in_roots(
    raw_path: &str,
    roots: &[PathBuf],
) -> Result<PinnedMediaflowSource, String> {
    let src_path = Path::new(raw_path);
    if raw_path.trim().is_empty() || !src_path.is_absolute() {
        return Err("Source path must be an absolute path".to_string());
    }
    let Some(fname_os) = src_path.file_name() else {
        return Err("Source path has no filename".to_string());
    };
    let Some(fname_str) = fname_os.to_str() else {
        return Err("Source filename must be valid UTF-8".to_string());
    };
    if fname_str.starts_with(".tmp_mediaflow_")
        || fname_str.ends_with(".tmp.mkv")
        || src_path
            .components()
            .any(|c| c.as_os_str() == ".mediaflow_trash")
    {
        return Err("Refusing temporary or trash path in MediaFlow queue".to_string());
    }
    let Some(parent) = src_path.parent() else {
        return Err("Source path has no parent directory".to_string());
    };

    let parent_lmeta =
        fs::symlink_metadata(parent).map_err(|_| "Parent directory does not exist".to_string())?;
    if parent_lmeta.file_type().is_symlink() || !parent_lmeta.is_dir() {
        return Err("Source parent directory must not be a symlink".to_string());
    }

    let lmeta =
        fs::symlink_metadata(src_path).map_err(|_| "Source file does not exist".to_string())?;
    if lmeta.file_type().is_symlink() {
        return Err("Refusing symlink source file".to_string());
    }
    if !lmeta.file_type().is_file() {
        return Err("Source path is not a regular file".to_string());
    }

    let canon_parent = fs::canonicalize(parent)
        .map_err(|e| format!("Failed to canonicalize parent directory: {e}"))?;
    let canon_src = fs::canonicalize(src_path)
        .map_err(|e| format!("Failed to canonicalize source file: {e}"))?;
    if canon_src != canon_parent.join(fname_os) {
        return Err("Source path resolved through an unexpected link".to_string());
    }

    if !is_path_within_allowed_mediaflow_roots(&canon_src, roots) {
        return Err("Source file is outside allowed MediaFlow library roots".to_string());
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        if lmeta.nlink() != 1 {
            return Err("Refusing hard-linked source file (st_nlink != 1)".to_string());
        }

        let parent_cstr = std::ffi::CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| "Parent directory path contains interior NUL".to_string())?;
        let dir_fd = unsafe {
            libc::open(
                parent_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dir_fd < 0 {
            return Err(format!(
                "Failed to open pinned parent directory safely: {}",
                std::io::Error::last_os_error()
            ));
        }
        let parent_dir = unsafe { fs::File::from_raw_fd(dir_fd) };
        let dir_meta = parent_dir
            .metadata()
            .map_err(|e| format!("Failed to stat pinned parent directory: {e}"))?;
        let canon_parent_meta = fs::symlink_metadata(&canon_parent)
            .map_err(|e| format!("Failed to verify canonical parent directory: {e}"))?;
        if dir_meta.dev() != canon_parent_meta.dev() || dir_meta.ino() != canon_parent_meta.ino() {
            return Err("Parent directory changed concurrently during pinning".to_string());
        }

        let fname_cstr = cstring_from_os_name(fname_str, "source filename")?;
        let src_fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                fname_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if src_fd < 0 {
            return Err(format!(
                "Failed to open pinned source file safely: {}",
                std::io::Error::last_os_error()
            ));
        }
        let source_file = unsafe { fs::File::from_raw_fd(src_fd) };
        let fmeta = source_file
            .metadata()
            .map_err(|e| format!("Failed to stat opened source file: {e}"))?;
        if !fmeta.is_file() {
            return Err("Opened source descriptor is not a regular file".to_string());
        }
        if fmeta.nlink() != 1 {
            return Err("Refusing hard-linked source descriptor (st_nlink != 1)".to_string());
        }
        if fmeta.dev() != lmeta.dev() || fmeta.ino() != lmeta.ino() {
            return Err("Source file inode changed concurrently during validation".to_string());
        }

        let fingerprint = compute_pinned_file_fingerprint(&source_file, fmeta.len())?;
        let fmeta_after = source_file
            .metadata()
            .map_err(|e| format!("Failed to re-stat pinned source file: {e}"))?;
        if !fmeta_after.is_file()
            || fmeta_after.nlink() != 1
            || fmeta_after.dev() != fmeta.dev()
            || fmeta_after.ino() != fmeta.ino()
            || fmeta_after.len() != fmeta.len()
            || fmeta_after.mtime() != fmeta.mtime()
            || fmeta_after.mtime_nsec() != fmeta.mtime_nsec()
            || fmeta_after.ctime() != fmeta.ctime()
            || fmeta_after.ctime_nsec() != fmeta.ctime_nsec()
        {
            return Err("Source file changed concurrently during fingerprinting".to_string());
        }

        let identity = MediaflowSourceIdentity {
            dev: fmeta.dev(),
            ino: fmeta.ino(),
            size: fmeta.len(),
            mtime_sec: fmeta.mtime(),
            mtime_nsec: fmeta.mtime_nsec(),
            fingerprint,
        };
        let pinned = PinnedMediaflowSource {
            parent_dir,
            source_file,
            canon_parent,
            canon_src,
            source_fname: fname_str.to_string(),
            identity,
            src_mode: fmeta.mode(),
            change_time: (fmeta.ctime(), fmeta.ctime_nsec()),
        };
        let live_st = fstatat_nofollow(pinned.parent_dir.as_raw_fd(), &pinned.source_fname)
            .map_err(|_| "Source directory entry vanished during pinning".to_string())?;
        if !pinned.matches_live_stat(&live_st) {
            return Err("Source file changed concurrently during pinning".to_string());
        }
        Ok(pinned)
    }

    #[cfg(not(unix))]
    {
        let source_file = fs::OpenOptions::new()
            .read(true)
            .open(&canon_src)
            .map_err(|e| format!("Failed to open source file safely: {e}"))?;
        let fmeta = source_file
            .metadata()
            .map_err(|e| format!("Failed to stat opened source file: {e}"))?;
        if !fmeta.is_file() {
            return Err("Opened source descriptor is not a regular file".to_string());
        }
        let fingerprint = compute_pinned_file_fingerprint(&source_file, fmeta.len())?;
        let modified_secs = fmeta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| (d.as_secs() as i64, d.subsec_nanos() as i64))
            .unwrap_or((0, 0));
        Ok(PinnedMediaflowSource {
            source_file,
            canon_parent,
            canon_src,
            source_fname: fname_str.to_string(),
            identity: MediaflowSourceIdentity {
                dev: 0,
                ino: 0,
                size: fmeta.len(),
                mtime_sec: modified_secs.0,
                mtime_nsec: modified_secs.1,
                fingerprint,
            },
        })
    }
}
