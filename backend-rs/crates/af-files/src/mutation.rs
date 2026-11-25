use crate::dir_ops::MAX_LIST_ENTRIES;
use crate::path::{
    is_internal_upload_temp, parse_relative_path, MAX_PATH_COMPONENTS, UPLOAD_TEMP_PREFIX,
};
use crate::syscall::{
    dup_cloexec, fstat_fd, fstatat_nofollow, is_mount_boundary_error, open_dir_stream,
    open_regular_file_at, openat_no_symlinks, openat_no_symlinks_no_xdev, renameat_noreplace,
    sync_dir,
};
use crate::upload::allocate_pending_upload;
use crate::{BrowserFs, RemovalError, RemoveTreeOutcome};
use rand::Rng;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

impl BrowserFs {
    pub fn create_directory(&self, path: &str) -> io::Result<()> {
        let (parent_fd, leaf) = self.resolve_parent_and_leaf(path)?;
        let rc = unsafe { libc::mkdirat(parent_fd.as_raw_fd(), leaf.as_ptr(), 0o755) };
        if rc < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn create_directory_all(&self, path: &str) -> io::Result<()> {
        let components = parse_relative_path(path, false)?;
        let mut current = dup_cloexec(self.root_fd.as_raw_fd())?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        for &comp in &components {
            let c_comp = CString::new(comp)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
            let rc = unsafe { libc::mkdirat(current.as_raw_fd(), c_comp.as_ptr(), 0o755) };
            if rc < 0 {
                let err = Error::last_os_error();
                if err.kind() != ErrorKind::AlreadyExists {
                    return Err(err);
                }
            }
            current = openat_no_symlinks(current.as_raw_fd(), c_comp.as_c_str(), flags, 0)?;
        }
        Ok(())
    }

    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.rename_with_leaf_policy(from, to, false)
    }

    pub fn rename_allowing_leaf_symlink(&self, from: &str, to: &str) -> io::Result<()> {
        self.rename_with_leaf_policy(from, to, true)
    }

    fn rename_with_leaf_policy(
        &self,
        from: &str,
        to: &str,
        allow_leaf_symlink: bool,
    ) -> io::Result<()> {
        let (from_parent, from_leaf) = self.resolve_parent_and_leaf(from)?;
        let (to_parent, to_leaf) = self.resolve_parent_and_leaf(to)?;
        let st = fstatat_nofollow(from_parent.as_raw_fd(), from_leaf.as_c_str())?;
        let mode_type = st.st_mode & libc::S_IFMT;
        let allowed_type = mode_type == libc::S_IFREG
            || mode_type == libc::S_IFDIR
            || (allow_leaf_symlink && mode_type == libc::S_IFLNK);
        if !allowed_type {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "renaming non-regular or symlink entries is not permitted",
            ));
        }
        if mode_type == libc::S_IFREG && st.st_nlink > 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "hardlinked regular files are not permitted",
            ));
        }
        match fstatat_nofollow(to_parent.as_raw_fd(), to_leaf.as_c_str()) {
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
            from_parent.as_raw_fd(),
            from_leaf.as_c_str(),
            to_parent.as_raw_fd(),
            to_leaf.as_c_str(),
        )
    }

    pub fn replace_file_by_rename(
        &self,
        from: &str,
        to: &str,
        expected_target: &std::fs::File,
    ) -> io::Result<u64> {
        let from_components = parse_relative_path(from, false)?;
        let to_components = parse_relative_path(to, false)?;
        if from_components == to_components {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "source and destination paths must be different",
            ));
        }

        let (from_parent, from_leaf) = self.resolve_parent_and_leaf(from)?;
        let (to_parent, to_leaf) = self.resolve_parent_and_leaf(to)?;

        let source_stat = fstatat_nofollow(from_parent.as_raw_fd(), from_leaf.as_c_str())?;
        let source_mode = source_stat.st_mode & libc::S_IFMT;
        if source_mode == libc::S_IFLNK {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "replacing files with symlinks is not permitted",
            ));
        }
        if source_mode != libc::S_IFREG {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "replacement source is not a regular file",
            ));
        }
        if source_stat.st_nlink != 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "hardlinked regular files are not permitted",
            ));
        }

        let expected_stat = fstat_fd(expected_target.as_raw_fd())?;
        if (expected_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "expected handle is not a regular file",
            ));
        }
        if expected_stat.st_nlink > 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "hardlinked regular files are not permitted",
            ));
        }

        let target_stat = fstatat_nofollow(to_parent.as_raw_fd(), to_leaf.as_c_str())?;
        let target_mode = target_stat.st_mode & libc::S_IFMT;
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
        if target_stat.st_nlink != 1 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "hardlinked regular files are not permitted",
            ));
        }
        if expected_stat.st_nlink != 1
            || target_stat.st_dev != expected_stat.st_dev
            || target_stat.st_ino != expected_stat.st_ino
        {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "replacement target identity does not match expected file",
            ));
        }
        if source_stat.st_dev == target_stat.st_dev && source_stat.st_ino == target_stat.st_ino {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "source and destination refer to the same file",
            ));
        }

        let replaced_bytes = target_stat.st_size.max(0) as u64;
        let rename_rc = unsafe {
            libc::renameat(
                from_parent.as_raw_fd(),
                from_leaf.as_ptr(),
                to_parent.as_raw_fd(),
                to_leaf.as_ptr(),
            )
        };
        if rename_rc < 0 {
            return Err(Error::last_os_error());
        }
        if let Err(error) = sync_dir(to_parent.as_raw_fd()) {
            tracing::warn!(%error, "File rename replacement published but destination directory durability could not be confirmed");
        }
        if from_parent.as_raw_fd() != to_parent.as_raw_fd() {
            if let Err(error) = sync_dir(from_parent.as_raw_fd()) {
                tracing::warn!(%error, "File rename replacement published but source directory durability could not be confirmed");
            }
        }
        Ok(replaced_bytes)
    }

    pub fn copy(&self, from: &str, to: &str) -> io::Result<u64> {
        let from_components = parse_relative_path(from, false)?;
        let to_components = parse_relative_path(to, false)?;

        let (from_leaf_str, from_parent_comps) = from_components
            .split_last()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "root path not allowed"))?;
        let (to_leaf_str, to_parent_comps) = to_components
            .split_last()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "root path not allowed"))?;

        let from_parent = self.open_dir_components(from_parent_comps)?;
        let to_parent = self.open_dir_components(to_parent_comps)?;
        let from_leaf = CString::new(*from_leaf_str)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
        let to_leaf = CString::new(*to_leaf_str)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;

        let from_st = fstatat_nofollow(from_parent.as_raw_fd(), from_leaf.as_c_str())?;
        let mode_type = from_st.st_mode & libc::S_IFMT;
        match mode_type {
            libc::S_IFREG => {
                if from_st.st_nlink > 1 {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "hardlinked regular files are not permitted",
                    ));
                }
            }
            libc::S_IFDIR => {}
            libc::S_IFLNK => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "copying symlinks is not permitted",
                ));
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "copying special files is not permitted",
                ));
            }
        }

        if from_components == to_components {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "destination already exists",
            ));
        }
        if mode_type == libc::S_IFDIR
            && to_components.len() > from_components.len()
            && to_components[..from_components.len()] == from_components[..]
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "cannot copy directory into itself or its descendant",
            ));
        }

        match fstatat_nofollow(to_parent.as_raw_fd(), to_leaf.as_c_str()) {
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    "destination already exists",
                ))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }

        if mode_type == libc::S_IFREG {
            let mut src_file = open_regular_file_at(from_parent.as_raw_fd(), from_leaf.as_c_str())?;
            let mut staging = allocate_pending_upload(to_parent, to_leaf)?;
            let copied = io::copy(&mut src_file, &mut staging)?;
            staging.commit()?;
            return Ok(copied);
        }

        let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let src_root_fd =
            openat_no_symlinks(from_parent.as_raw_fd(), from_leaf.as_c_str(), dir_flags, 0)?;
        let (staging_name, staging_root_fd) = allocate_staging_dir(to_parent.as_raw_fd())?;

        struct StagingDirGuard {
            parent_fd: libc::c_int,
            staging_name: CString,
            committed: bool,
        }
        impl Drop for StagingDirGuard {
            fn drop(&mut self) {
                if !self.committed {
                    cleanup_staging_tree(self.parent_fd, self.staging_name.as_c_str());
                }
            }
        }

        let mut guard = StagingDirGuard {
            parent_fd: to_parent.as_raw_fd(),
            staging_name,
            committed: false,
        };

        let staging_st = fstat_fd(staging_root_fd.as_raw_fd())?;
        let total_bytes = copy_directory_tree(
            src_root_fd,
            staging_root_fd,
            to_components.len(),
            (staging_st.st_dev, staging_st.st_ino),
        )?;

        match fstatat_nofollow(to_parent.as_raw_fd(), to_leaf.as_c_str()) {
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
            to_parent.as_raw_fd(),
            guard.staging_name.as_c_str(),
            to_parent.as_raw_fd(),
            to_leaf.as_c_str(),
        )?;
        guard.committed = true;
        if let Err(error) = sync_dir(to_parent.as_raw_fd()) {
            tracing::warn!(%error, "Directory copy published but directory durability could not be confirmed");
        }
        Ok(total_bytes)
    }

    pub fn remove(&self, path: &str) -> io::Result<()> {
        self.remove_with_size(path).map(|_| ())
    }

    pub fn remove_allowing_leaf_symlink(&self, path: &str) -> io::Result<()> {
        self.remove_with_size_allowing_leaf_symlink(path)
            .map(|_| ())
    }

    pub fn remove_with_size(&self, path: &str) -> io::Result<u64> {
        self.remove_with_size_policy(path, false)
    }

    pub fn remove_with_size_allowing_leaf_symlink(&self, path: &str) -> io::Result<u64> {
        self.remove_with_size_policy(path, true)
    }

    fn remove_with_size_policy(&self, path: &str, allow_leaf_symlink: bool) -> io::Result<u64> {
        let (parent_fd, leaf) = self.resolve_parent_and_leaf(path)?;
        let st = fstatat_nofollow(parent_fd.as_raw_fd(), leaf.as_c_str())?;
        let mode_type = st.st_mode & libc::S_IFMT;
        let flags = match mode_type {
            libc::S_IFREG => {
                if st.st_nlink > 1 {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "hardlinked files are not permitted",
                    ));
                }
                0
            }
            libc::S_IFDIR => libc::AT_REMOVEDIR,
            libc::S_IFLNK if allow_leaf_symlink => 0,
            libc::S_IFLNK => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "removing symlinks is not permitted",
                ))
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "removing special files is not permitted",
                ))
            }
        };
        let rc = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), leaf.as_ptr(), flags) };
        if rc < 0 {
            let err = Error::last_os_error();
            if mode_type == libc::S_IFDIR
                && matches!(err.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST))
                && remove_orphaned_upload_temps_if_only_children(
                    parent_fd.as_raw_fd(),
                    leaf.as_c_str(),
                )?
            {
                let retry_rc = unsafe {
                    libc::unlinkat(parent_fd.as_raw_fd(), leaf.as_ptr(), libc::AT_REMOVEDIR)
                };
                if retry_rc < 0 {
                    return Err(Error::last_os_error());
                }
                return Ok(0);
            }
            return Err(err);
        }
        Ok(if mode_type == libc::S_IFREG {
            st.st_size.max(0) as u64
        } else {
            0
        })
    }

    pub fn remove_tree_with_size(&self, path: &str) -> Result<u64, RemovalError> {
        self.remove_tree_with_outcome(path)
            .map(|outcome| outcome.removed_bytes)
    }

    pub fn remove_tree_with_size_allowing_symlinks(&self, path: &str) -> Result<u64, RemovalError> {
        self.remove_tree_with_outcome_allowing_symlinks(path)
            .map(|outcome| outcome.removed_bytes)
    }

    pub fn remove_tree_with_outcome(&self, path: &str) -> Result<RemoveTreeOutcome, RemovalError> {
        self.remove_tree_with_outcome_policy(path, false, &openat_no_symlinks_no_xdev)
    }

    pub fn remove_tree_with_outcome_allowing_symlinks(
        &self,
        path: &str,
    ) -> Result<RemoveTreeOutcome, RemovalError> {
        self.remove_tree_with_outcome_policy(path, true, &openat_no_symlinks_no_xdev)
    }

    pub(crate) fn remove_tree_with_outcome_policy<F>(
        &self,
        path: &str,
        allow_symlinks: bool,
        open_dir: &F,
    ) -> Result<RemoveTreeOutcome, RemovalError>
    where
        F: Fn(libc::c_int, &CStr, libc::c_int, libc::mode_t, libc::dev_t) -> io::Result<OwnedFd>,
    {
        let components = parse_relative_path(path, false).map_err(|error| RemovalError {
            removed_bytes: 0,
            error,
        })?;
        let (leaf_str, parent_components) =
            components.split_last().ok_or_else(|| RemovalError {
                removed_bytes: 0,
                error: Error::new(ErrorKind::InvalidInput, "root path not allowed"),
            })?;
        let root_dev = fstat_fd(self.root_fd.as_raw_fd())
            .map_err(|error| RemovalError {
                removed_bytes: 0,
                error,
            })?
            .st_dev;

        let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let mut parent_fd = openat_no_symlinks(self.root_fd.as_raw_fd(), c".", dir_flags, 0)
            .map_err(|error| RemovalError {
                removed_bytes: 0,
                error,
            })?;
        let mut rel_path = PathBuf::new();
        for &comp in parent_components {
            rel_path.push(comp);
            let c_comp = CString::new(comp).map_err(|_| RemovalError {
                removed_bytes: 0,
                error: Error::new(ErrorKind::InvalidInput, "path contains NUL"),
            })?;
            match open_dir(
                parent_fd.as_raw_fd(),
                c_comp.as_c_str(),
                dir_flags,
                0,
                root_dev,
            ) {
                Ok(next_fd) => parent_fd = next_fd,
                Err(err) if is_mount_boundary_error(&err) => {
                    return Ok(RemoveTreeOutcome {
                        removed_bytes: 0,
                        skipped_mount_paths: vec![rel_path],
                    });
                }
                Err(error) => {
                    return Err(RemovalError {
                        removed_bytes: 0,
                        error,
                    });
                }
            }
        }
        rel_path.push(leaf_str);
        let leaf = CString::new(*leaf_str).map_err(|_| RemovalError {
            removed_bytes: 0,
            error: Error::new(ErrorKind::InvalidInput, "path contains NUL"),
        })?;
        let mut outcome = RemoveTreeOutcome::default();
        remove_entry_recursive_with_opener(
            parent_fd.as_raw_fd(),
            leaf.as_c_str(),
            &rel_path,
            root_dev,
            &mut outcome,
            0,
            allow_symlinks,
            open_dir,
        )
        .map_err(|error| RemovalError {
            removed_bytes: outcome.removed_bytes,
            error,
        })?;
        Ok(outcome)
    }
}

fn allocate_staging_dir(parent_fd: libc::c_int) -> io::Result<(CString, OwnedFd)> {
    let mut rng = rand::thread_rng();
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    for _ in 0..64 {
        let token: u128 = rng.gen();
        let candidate = format!("{UPLOAD_TEMP_PREFIX}{token:032x}");
        let temp_name = CString::new(candidate).expect("hex temp name has no NUL");
        let rc = unsafe { libc::mkdirat(parent_fd, temp_name.as_ptr(), 0o700) };
        if rc < 0 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::AlreadyExists {
                continue;
            }
            return Err(err);
        }
        match openat_no_symlinks(parent_fd, temp_name.as_c_str(), dir_flags, 0) {
            Ok(fd) => return Ok((temp_name, fd)),
            Err(err) => {
                unsafe {
                    libc::unlinkat(parent_fd, temp_name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(err);
            }
        }
    }

    Err(Error::new(
        ErrorKind::AlreadyExists,
        "failed to allocate unique temporary staging directory",
    ))
}

fn copy_directory_tree(
    src_root_fd: OwnedFd,
    staging_root_fd: OwnedFd,
    base_depth: usize,
    staging_identity: (libc::dev_t, libc::ino_t),
) -> io::Result<u64> {
    struct CopyFrame {
        src_fd: OwnedFd,
        dst_fd: OwnedFd,
        depth: usize,
        children: std::vec::IntoIter<CString>,
    }

    let root_children = list_raw_copy_children(src_root_fd.as_raw_fd())?;
    let mut stack = vec![CopyFrame {
        src_fd: src_root_fd,
        dst_fd: staging_root_fd,
        depth: base_depth,
        children: root_children.into_iter(),
    }];
    let mut total_bytes = 0u64;
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let file_flags =
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;

    while let Some(frame) = stack.last_mut() {
        if let Some(child_name) = frame.children.next() {
            let src_raw = frame.src_fd.as_raw_fd();
            let dst_raw = frame.dst_fd.as_raw_fd();
            let child_depth = frame.depth + 1;
            if child_depth > MAX_PATH_COMPONENTS {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "path component limit exceeded",
                ));
            }

            let st = fstatat_nofollow(src_raw, child_name.as_c_str())?;
            if (st.st_dev, st.st_ino) == staging_identity {
                continue;
            }
            match st.st_mode & libc::S_IFMT {
                libc::S_IFREG => {
                    if st.st_nlink > 1 {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "hardlinked regular files are not permitted",
                        ));
                    }
                    let mut src_file = open_regular_file_at(src_raw, child_name.as_c_str())?;
                    let dst_fd =
                        openat_no_symlinks(dst_raw, child_name.as_c_str(), file_flags, 0o600)?;
                    let mut dst_file = File::from(dst_fd);
                    let copied = io::copy(&mut src_file, &mut dst_file)?;
                    dst_file.sync_all()?;
                    total_bytes = total_bytes
                        .checked_add(copied)
                        .ok_or_else(|| Error::other("copied byte count overflow"))?;
                }
                libc::S_IFDIR => {
                    let rc = unsafe { libc::mkdirat(dst_raw, child_name.as_ptr(), 0o755) };
                    if rc < 0 {
                        return Err(Error::last_os_error());
                    }
                    let child_src_fd =
                        openat_no_symlinks(src_raw, child_name.as_c_str(), dir_flags, 0)?;
                    let child_dst_fd =
                        openat_no_symlinks(dst_raw, child_name.as_c_str(), dir_flags, 0)?;
                    let grand_children = list_raw_copy_children(child_src_fd.as_raw_fd())?;
                    stack.push(CopyFrame {
                        src_fd: child_src_fd,
                        dst_fd: child_dst_fd,
                        depth: child_depth,
                        children: grand_children.into_iter(),
                    });
                }
                libc::S_IFLNK => {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "copying symlinks is not permitted",
                    ));
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "copying special files is not permitted",
                    ));
                }
            }
        } else {
            let finished = stack.pop().expect("non-empty stack");
            if stack.is_empty() && unsafe { libc::fchmod(finished.dst_fd.as_raw_fd(), 0o755) } < 0 {
                return Err(Error::last_os_error());
            }
            sync_dir(finished.dst_fd.as_raw_fd())?;
        }
    }

    Ok(total_bytes)
}

fn list_raw_copy_children(dir_fd: libc::c_int) -> io::Result<Vec<CString>> {
    let (guard, _) = open_dir_stream(dir_fd)?;
    let mut names = Vec::new();
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let ent = unsafe { libc::readdir(guard.0) };
        if ent.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                return Err(Error::from_raw_os_error(errno));
            }
            break;
        }
        let c_name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let name_bytes = c_name.to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name_str = std::str::from_utf8(name_bytes).map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                "directory contains non-UTF-8 entry name",
            )
        })?;
        if is_internal_upload_temp(name_str) {
            continue;
        }
        if names.len() >= MAX_LIST_ENTRIES {
            return Err(Error::other("directory entry limit exceeded"));
        }
        names.push(c_name.to_owned());
    }
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

fn cleanup_staging_tree(parent_fd: libc::c_int, staging_name: &CStr) {
    let Ok(parent_st) = fstat_fd(parent_fd) else {
        return;
    };
    let mut ignored = RemoveTreeOutcome::default();
    let rel_path = PathBuf::from(OsStr::from_bytes(staging_name.to_bytes()));
    let _ = remove_entry_recursive_with_opener(
        parent_fd,
        staging_name,
        &rel_path,
        parent_st.st_dev,
        &mut ignored,
        0,
        false,
        &openat_no_symlinks_no_xdev,
    );
}

fn remove_orphaned_upload_temps_if_only_children(
    parent_fd: libc::c_int,
    name: &CStr,
) -> io::Result<bool> {
    let expected_dev = fstat_fd(parent_fd)?.st_dev;
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let dir_fd = match openat_no_symlinks_no_xdev(parent_fd, name, dir_flags, 0, expected_dev) {
        Ok(fd) => fd,
        Err(err) if is_mount_boundary_error(&err) => return Ok(false),
        Err(err) => return Err(err),
    };
    let (guard, dir_raw_fd) = open_dir_stream(dir_fd.as_raw_fd())?;

    let mut temp_regular_files: Vec<CString> = Vec::new();
    let mut temp_subdirs: Vec<CString> = Vec::new();
    let mut invalid_temp_entries: Vec<CString> = Vec::new();

    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let ent = unsafe { libc::readdir(guard.0) };
        if ent.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                return Err(Error::from_raw_os_error(errno));
            }
            break;
        }
        let c_child = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let child_bytes = c_child.to_bytes();
        if child_bytes == b"." || child_bytes == b".." {
            continue;
        }
        let is_temp = std::str::from_utf8(child_bytes).is_ok_and(is_internal_upload_temp);
        if !is_temp {
            return Ok(false);
        }
        let child_st = match fstatat_nofollow(dir_raw_fd, c_child) {
            Ok(st) => st,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        match child_st.st_mode & libc::S_IFMT {
            libc::S_IFREG if child_st.st_nlink == 1 => {
                temp_regular_files.push(c_child.to_owned());
            }
            libc::S_IFDIR => {
                temp_subdirs.push(c_child.to_owned());
            }
            _ => {
                invalid_temp_entries.push(c_child.to_owned());
            }
        }
    }
    drop(guard);

    temp_regular_files.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    temp_subdirs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    invalid_temp_entries.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut discarded = RemoveTreeOutcome::default();
    if let Some(invalid_name) = invalid_temp_entries.first() {
        let rel = PathBuf::from(OsStr::from_bytes(invalid_name.as_bytes()));
        remove_entry_recursive_with_opener(
            dir_fd.as_raw_fd(),
            invalid_name.as_c_str(),
            &rel,
            expected_dev,
            &mut discarded,
            1,
            false,
            &openat_no_symlinks_no_xdev,
        )?;
    }

    for temp_file in temp_regular_files {
        let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), temp_file.as_ptr(), 0) };
        if rc < 0 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::NotFound {
                continue;
            }
            return Err(err);
        }
    }

    for temp_subdir in temp_subdirs {
        let rel = PathBuf::from(OsStr::from_bytes(temp_subdir.as_bytes()));
        match remove_entry_recursive_with_opener(
            dir_fd.as_raw_fd(),
            temp_subdir.as_c_str(),
            &rel,
            expected_dev,
            &mut discarded,
            1,
            false,
            &openat_no_symlinks_no_xdev,
        ) {
            Ok(true) => return Ok(false),
            Ok(false) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        }
    }

    Ok(discarded.skipped_mount_paths.is_empty())
}

#[allow(clippy::too_many_arguments)]
fn remove_entry_recursive_with_opener<F>(
    parent_fd: libc::c_int,
    name: &CStr,
    rel_path: &Path,
    expected_dev: libc::dev_t,
    outcome: &mut RemoveTreeOutcome,
    depth: usize,
    allow_symlinks: bool,
    open_dir: &F,
) -> io::Result<bool>
where
    F: Fn(libc::c_int, &CStr, libc::c_int, libc::mode_t, libc::dev_t) -> io::Result<OwnedFd>,
{
    if depth > MAX_PATH_COMPONENTS {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path component limit exceeded",
        ));
    }

    let st = fstatat_nofollow(parent_fd, name)?;
    let mode_type = st.st_mode & libc::S_IFMT;
    match mode_type {
        libc::S_IFREG => {
            if st.st_nlink > 1 {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "hardlinked files are not permitted",
                ));
            }
            let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
            if rc < 0 {
                return Err(Error::last_os_error());
            }
            let size = st.st_size.max(0) as u64;
            outcome.removed_bytes = outcome.removed_bytes.saturating_add(size);
            Ok(false)
        }
        libc::S_IFDIR => {
            if st.st_dev != expected_dev {
                outcome.skipped_mount_paths.push(rel_path.to_path_buf());
                return Ok(true);
            }
            let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
            let dir_fd = match open_dir(parent_fd, name, dir_flags, 0, expected_dev) {
                Ok(fd) => fd,
                Err(err) if is_mount_boundary_error(&err) => {
                    outcome.skipped_mount_paths.push(rel_path.to_path_buf());
                    return Ok(true);
                }
                Err(err) => return Err(err),
            };
            let (guard, dir_raw_fd) = open_dir_stream(dir_fd.as_raw_fd())?;

            let mut regular_files: Vec<(CString, u64)> = Vec::new();
            let mut temp_regular_files: Vec<CString> = Vec::new();
            let mut symlinks: Vec<CString> = Vec::new();
            let mut subdirs: Vec<CString> = Vec::new();
            let mut temp_subdirs: Vec<CString> = Vec::new();
            let mut invalid_entries: Vec<CString> = Vec::new();

            loop {
                unsafe {
                    *libc::__errno_location() = 0;
                }
                let ent = unsafe { libc::readdir(guard.0) };
                if ent.is_null() {
                    let errno = unsafe { *libc::__errno_location() };
                    if errno != 0 {
                        return Err(Error::from_raw_os_error(errno));
                    }
                    break;
                }
                let c_child = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
                let child_bytes = c_child.to_bytes();
                if child_bytes == b"." || child_bytes == b".." {
                    continue;
                }
                let is_temp = std::str::from_utf8(child_bytes).is_ok_and(is_internal_upload_temp);
                let child_st = match fstatat_nofollow(dir_raw_fd, c_child) {
                    Ok(st) => st,
                    Err(err) if err.kind() == ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                };
                match child_st.st_mode & libc::S_IFMT {
                    libc::S_IFREG if child_st.st_nlink == 1 => {
                        if is_temp {
                            temp_regular_files.push(c_child.to_owned());
                        } else {
                            regular_files
                                .push((c_child.to_owned(), child_st.st_size.max(0) as u64));
                        }
                    }
                    libc::S_IFLNK if allow_symlinks => {
                        symlinks.push(c_child.to_owned());
                    }
                    libc::S_IFDIR => {
                        if is_temp {
                            temp_subdirs.push(c_child.to_owned());
                        } else {
                            subdirs.push(c_child.to_owned());
                        }
                    }
                    _ => {
                        invalid_entries.push(c_child.to_owned());
                    }
                }
            }
            drop(guard);

            regular_files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            temp_regular_files.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            symlinks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            subdirs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            temp_subdirs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            invalid_entries.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

            for (child_name, size) in regular_files {
                let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), child_name.as_ptr(), 0) };
                if rc < 0 {
                    let err = Error::last_os_error();
                    if err.kind() == ErrorKind::NotFound {
                        continue;
                    }
                    return Err(err);
                }
                outcome.removed_bytes = outcome.removed_bytes.saturating_add(size);
            }

            for temp_name in temp_regular_files {
                let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), temp_name.as_ptr(), 0) };
                if rc < 0 {
                    let err = Error::last_os_error();
                    if err.kind() == ErrorKind::NotFound {
                        continue;
                    }
                    return Err(err);
                }
            }

            for link_name in symlinks {
                let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), link_name.as_ptr(), 0) };
                if rc < 0 {
                    let err = Error::last_os_error();
                    if err.kind() == ErrorKind::NotFound {
                        continue;
                    }
                    return Err(err);
                }
            }

            let mut skipped_any = false;
            for subdir_name in subdirs {
                let child_rel = rel_path.join(OsStr::from_bytes(subdir_name.as_bytes()));
                if remove_entry_recursive_with_opener(
                    dir_fd.as_raw_fd(),
                    subdir_name.as_c_str(),
                    &child_rel,
                    expected_dev,
                    outcome,
                    depth + 1,
                    allow_symlinks,
                    open_dir,
                )? {
                    skipped_any = true;
                }
            }

            for temp_subdir in temp_subdirs {
                let child_rel = rel_path.join(OsStr::from_bytes(temp_subdir.as_bytes()));
                let mut discarded_temp = RemoveTreeOutcome::default();
                match remove_entry_recursive_with_opener(
                    dir_fd.as_raw_fd(),
                    temp_subdir.as_c_str(),
                    &child_rel,
                    expected_dev,
                    &mut discarded_temp,
                    depth + 1,
                    allow_symlinks,
                    open_dir,
                ) {
                    Ok(skipped) => {
                        if skipped {
                            skipped_any = true;
                            outcome
                                .skipped_mount_paths
                                .extend(discarded_temp.skipped_mount_paths);
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                }
            }

            for invalid_name in invalid_entries {
                let child_rel = rel_path.join(OsStr::from_bytes(invalid_name.as_bytes()));
                if remove_entry_recursive_with_opener(
                    dir_fd.as_raw_fd(),
                    invalid_name.as_c_str(),
                    &child_rel,
                    expected_dev,
                    outcome,
                    depth + 1,
                    allow_symlinks,
                    open_dir,
                )? {
                    skipped_any = true;
                }
            }

            drop(dir_fd);
            if skipped_any {
                return Ok(true);
            }
            let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
            if rc < 0 {
                return Err(Error::last_os_error());
            }
            Ok(false)
        }
        libc::S_IFLNK if allow_symlinks => {
            let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
            if rc < 0 {
                return Err(Error::last_os_error());
            }
            Ok(false)
        }
        libc::S_IFLNK => Err(Error::new(
            ErrorKind::PermissionDenied,
            "removing symlinks is not permitted",
        )),
        _ => Err(Error::new(
            ErrorKind::PermissionDenied,
            "removing special files is not permitted",
        )),
    }
}
