use crate::dir_ops::{entry_from_stat, read_dir_entries_bounded, MAX_LIST_ENTRIES};
use crate::path::{
    is_internal_upload_temp, parse_relative_path, parse_symlink_target_segments,
    push_clean_trace_path, push_symlink_alias_trace, MAX_PATH_COMPONENTS, MAX_SYMLINK_EXPANSIONS,
};
use crate::syscall::{
    clear_nonblock, format_mtime, fstat_fd, fstatat_nofollow, openat2_beneath_internal,
    openat2_strict_no_symlinks, readlink_at_utf8,
};
use crate::{BrowserFs, Entry, ResolvedDir, ResolvedDirListing, ResolvedEntry, ResolvedFile};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, OwnedFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalTargetKind {
    File,
    Directory,
}

#[derive(Debug)]
enum VerifiedInternalTarget {
    File(ResolvedFile),
    Directory(ResolvedDir),
}

impl BrowserFs {
    pub fn scoped_resolving_internal_links(&self, path: &str) -> io::Result<ResolvedDir> {
        match self.resolve_internal_target(path, true, InternalTargetKind::Directory)? {
            VerifiedInternalTarget::Directory(resolved) => Ok(resolved),
            VerifiedInternalTarget::File(_) => Err(Error::new(
                ErrorKind::InvalidInput,
                "resolved target is not a directory",
            )),
        }
    }

    pub fn open_file_resolving_internal_links(&self, path: &str) -> io::Result<ResolvedFile> {
        match self.resolve_internal_target(path, false, InternalTargetKind::File)? {
            VerifiedInternalTarget::File(resolved) => Ok(resolved),
            VerifiedInternalTarget::Directory(_) => Err(Error::new(
                ErrorKind::InvalidInput,
                "resolved target is not a regular file",
            )),
        }
    }

    pub fn metadata_resolving_internal_links(&self, path: &str) -> io::Result<ResolvedEntry> {
        let initial_components = parse_relative_path(path, true)?;
        if initial_components.is_empty() {
            let root_path_fd =
                openat2_strict_no_symlinks(self.root_fd.as_raw_fd(), c".", libc::O_PATH)?;
            let root_stat = fstat_fd(root_path_fd.as_raw_fd())?;
            if (root_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "root path is not a directory",
                ));
            }
            return Ok(ResolvedEntry {
                entry: Entry {
                    name: String::new(),
                    path: String::new(),
                    kind: "directory".to_string(),
                    size: 0,
                    modified: format_mtime(&root_stat),
                },
                resolved_path: String::new(),
                resolution_paths: Vec::new(),
                was_symlink: false,
            });
        }

        let requested_norm = initial_components.join("/");
        let c_request = CString::new(requested_norm.as_str())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
        let probe_fd =
            openat2_beneath_internal(self.root_fd.as_raw_fd(), c_request.as_c_str(), libc::O_PATH)?;
        let probe_stat = fstat_fd(probe_fd.as_raw_fd())?;
        let probe_mode = probe_stat.st_mode & libc::S_IFMT;

        match probe_mode {
            libc::S_IFREG => {
                if probe_stat.st_nlink > 1 {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "hardlinked regular files are not permitted",
                    ));
                }
                let (resolved_components, resolution_paths) =
                    self.derive_resolved_components(&initial_components)?;
                let (leaf_name, parent_slice) =
                    resolved_components.split_last().ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "resolved file path cannot be root")
                    })?;
                let parent_refs: Vec<&str> = parent_slice.iter().map(String::as_str).collect();
                let strict_parent = self.open_dir_components_strict_openat2(&parent_refs)?;
                let c_leaf = CString::new(leaf_name.as_str())
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
                let verify_fd = openat2_strict_no_symlinks(
                    strict_parent.as_raw_fd(),
                    c_leaf.as_c_str(),
                    libc::O_PATH,
                )?;
                let verify_stat = fstat_fd(verify_fd.as_raw_fd())?;
                if (verify_stat.st_mode & libc::S_IFMT) != libc::S_IFREG
                    || verify_stat.st_nlink > 1
                    || verify_stat.st_dev != probe_stat.st_dev
                    || verify_stat.st_ino != probe_stat.st_ino
                {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "resolved target identity proof failed under concurrent mutation",
                    ));
                }
                let resolved_path = resolved_components.join("/");
                let entry = entry_from_stat(leaf_name, resolved_path.clone(), &verify_stat);
                let was_symlink = !resolution_paths.is_empty() || requested_norm != resolved_path;
                Ok(ResolvedEntry {
                    was_symlink,
                    entry,
                    resolved_path,
                    resolution_paths,
                })
            }
            libc::S_IFDIR => {
                let (resolved_components, resolution_paths) =
                    self.derive_resolved_components(&initial_components)?;
                if resolved_components.is_empty() {
                    let verify_root =
                        openat2_strict_no_symlinks(self.root_fd.as_raw_fd(), c".", libc::O_PATH)?;
                    let verify_stat = fstat_fd(verify_root.as_raw_fd())?;
                    if (verify_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                        || verify_stat.st_dev != probe_stat.st_dev
                        || verify_stat.st_ino != probe_stat.st_ino
                    {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "resolved root directory identity proof failed",
                        ));
                    }
                    return Ok(ResolvedEntry {
                        entry: Entry {
                            name: String::new(),
                            path: String::new(),
                            kind: "directory".to_string(),
                            size: 0,
                            modified: format_mtime(&verify_stat),
                        },
                        resolved_path: String::new(),
                        resolution_paths,
                        was_symlink: true,
                    });
                }
                let resolved_refs: Vec<&str> =
                    resolved_components.iter().map(String::as_str).collect();
                let verify_dir = self.open_dir_components_strict_openat2(&resolved_refs)?;
                let verify_stat = fstat_fd(verify_dir.as_raw_fd())?;
                if (verify_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                    || verify_stat.st_dev != probe_stat.st_dev
                    || verify_stat.st_ino != probe_stat.st_ino
                {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "resolved directory identity proof failed under concurrent mutation",
                    ));
                }
                let leaf_name = resolved_components.last().cloned().unwrap_or_default();
                let resolved_path = resolved_components.join("/");
                let entry = entry_from_stat(&leaf_name, resolved_path.clone(), &verify_stat);
                let was_symlink = !resolution_paths.is_empty() || requested_norm != resolved_path;
                Ok(ResolvedEntry {
                    was_symlink,
                    entry,
                    resolved_path,
                    resolution_paths,
                })
            }
            _ => Err(Error::new(
                ErrorKind::PermissionDenied,
                "special files are not permitted",
            )),
        }
    }

    pub fn list_with_trace_resolving_internal_links(
        &self,
        path: &str,
    ) -> io::Result<ResolvedDirListing> {
        let resolved_dir = self.scoped_resolving_internal_links(path)?;
        let entries = read_dir_entries_bounded(
            &resolved_dir.fs.root_fd,
            &resolved_dir.resolved_path,
            MAX_LIST_ENTRIES,
        )?;
        Ok(ResolvedDirListing {
            entries,
            resolved_path: resolved_dir.resolved_path,
            resolution_paths: resolved_dir.resolution_paths,
            entry: resolved_dir.entry,
        })
    }

    pub fn list_resolving_internal_links(&self, path: &str) -> io::Result<(Vec<Entry>, String)> {
        let listing = self.list_with_trace_resolving_internal_links(path)?;
        Ok((listing.entries, listing.resolved_path))
    }

    fn resolve_internal_target(
        &self,
        path: &str,
        allow_root: bool,
        expected_kind: InternalTargetKind,
    ) -> io::Result<VerifiedInternalTarget> {
        let initial_components = parse_relative_path(path, allow_root)?;
        if initial_components.is_empty() {
            if matches!(expected_kind, InternalTargetKind::File) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "operation not allowed on root directory",
                ));
            }
            let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
            let root_dup = openat2_beneath_internal(self.root_fd.as_raw_fd(), c".", dir_flags)?;
            let root_stat = fstat_fd(root_dup.as_raw_fd())?;
            if (root_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "root path is not a directory",
                ));
            }
            let entry = Entry {
                name: String::new(),
                path: String::new(),
                kind: "directory".to_string(),
                size: 0,
                modified: format_mtime(&root_stat),
            };
            let scoped_fs = Self::from_directory(root_dup)?;
            return Ok(VerifiedInternalTarget::Directory(ResolvedDir {
                fs: scoped_fs,
                resolved_path: String::new(),
                resolution_paths: Vec::new(),
                entry,
            }));
        }

        let normalized_request = initial_components.join("/");
        let c_request = CString::new(normalized_request.as_str())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
        let probe_fd =
            openat2_beneath_internal(self.root_fd.as_raw_fd(), c_request.as_c_str(), libc::O_PATH)?;
        let probe_stat = fstat_fd(probe_fd.as_raw_fd())?;
        let probe_mode = probe_stat.st_mode & libc::S_IFMT;

        match (expected_kind, probe_mode) {
            (InternalTargetKind::File, libc::S_IFREG) => {
                if probe_stat.st_nlink > 1 {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "hardlinked regular files are not permitted",
                    ));
                }
                let (resolved_components, resolution_paths) =
                    self.derive_resolved_components(&initial_components)?;
                let (leaf_name, parent_slice) =
                    resolved_components.split_last().ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "resolved file path cannot be root")
                    })?;
                let parent_refs: Vec<&str> = parent_slice.iter().map(String::as_str).collect();
                let strict_parent = self.open_dir_components_strict_openat2(&parent_refs)?;
                let c_leaf = CString::new(leaf_name.as_str())
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
                let verify_path_fd = openat2_strict_no_symlinks(
                    strict_parent.as_raw_fd(),
                    c_leaf.as_c_str(),
                    libc::O_PATH,
                )?;
                let verify_path_stat = fstat_fd(verify_path_fd.as_raw_fd())?;
                if (verify_path_stat.st_mode & libc::S_IFMT) != libc::S_IFREG
                    || verify_path_stat.st_nlink > 1
                    || verify_path_stat.st_dev != probe_stat.st_dev
                    || verify_path_stat.st_ino != probe_stat.st_ino
                {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "resolved target identity proof failed under concurrent mutation",
                    ));
                }
                let readable_flags =
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
                let readable_fd = openat2_strict_no_symlinks(
                    strict_parent.as_raw_fd(),
                    c_leaf.as_c_str(),
                    readable_flags,
                )?;
                let readable_stat = fstat_fd(readable_fd.as_raw_fd())?;
                if (readable_stat.st_mode & libc::S_IFMT) != libc::S_IFREG
                    || readable_stat.st_nlink > 1
                    || readable_stat.st_dev != probe_stat.st_dev
                    || readable_stat.st_ino != probe_stat.st_ino
                {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "resolved target identity proof failed under concurrent mutation",
                    ));
                }
                clear_nonblock(readable_fd.as_raw_fd())?;
                let after_stat = fstat_fd(readable_fd.as_raw_fd())?;
                if (after_stat.st_mode & libc::S_IFMT) != libc::S_IFREG
                    || after_stat.st_nlink > 1
                    || after_stat.st_dev != probe_stat.st_dev
                    || after_stat.st_ino != probe_stat.st_ino
                {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "file identity changed during open validation",
                    ));
                }
                let resolved_path = resolved_components.join("/");
                let entry = entry_from_stat(leaf_name, resolved_path.clone(), &after_stat);
                Ok(VerifiedInternalTarget::File(ResolvedFile {
                    file: File::from(readable_fd),
                    resolved_path,
                    resolution_paths,
                    entry,
                }))
            }
            (InternalTargetKind::Directory, libc::S_IFDIR) => {
                let (resolved_components, resolution_paths) =
                    self.derive_resolved_components(&initial_components)?;
                if resolved_components.is_empty() {
                    let verify_flags =
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
                    let verify_root =
                        openat2_strict_no_symlinks(self.root_fd.as_raw_fd(), c".", verify_flags)?;
                    let verify_stat = fstat_fd(verify_root.as_raw_fd())?;
                    if (verify_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                        || verify_stat.st_dev != probe_stat.st_dev
                        || verify_stat.st_ino != probe_stat.st_ino
                    {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "resolved root directory identity proof failed",
                        ));
                    }
                    let entry = Entry {
                        name: String::new(),
                        path: String::new(),
                        kind: "directory".to_string(),
                        size: 0,
                        modified: format_mtime(&verify_stat),
                    };
                    let scoped_fs = Self::from_directory(verify_root)?;
                    return Ok(VerifiedInternalTarget::Directory(ResolvedDir {
                        fs: scoped_fs,
                        resolved_path: String::new(),
                        resolution_paths,
                        entry,
                    }));
                }

                let resolved_refs: Vec<&str> =
                    resolved_components.iter().map(String::as_str).collect();
                let verify_dir = self.open_dir_components_strict_openat2(&resolved_refs)?;
                let verify_stat = fstat_fd(verify_dir.as_raw_fd())?;
                if (verify_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                    || verify_stat.st_dev != probe_stat.st_dev
                    || verify_stat.st_ino != probe_stat.st_ino
                {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "resolved directory identity proof failed under concurrent mutation",
                    ));
                }
                let leaf_name = resolved_components.last().cloned().unwrap_or_default();
                let resolved_path = resolved_components.join("/");
                let entry = entry_from_stat(&leaf_name, resolved_path.clone(), &verify_stat);
                let scoped_fs = Self::from_directory(verify_dir)?;
                Ok(VerifiedInternalTarget::Directory(ResolvedDir {
                    fs: scoped_fs,
                    resolved_path,
                    resolution_paths,
                    entry,
                }))
            }
            (InternalTargetKind::File, libc::S_IFDIR) => Err(Error::new(
                ErrorKind::InvalidInput,
                "path is a directory, not a regular file",
            )),
            (InternalTargetKind::Directory, libc::S_IFREG) => Err(Error::new(
                ErrorKind::InvalidInput,
                "path is not a directory",
            )),
            (_, _) => Err(Error::new(
                ErrorKind::PermissionDenied,
                "special files are not permitted",
            )),
        }
    }

    fn open_dir_components_strict_openat2(&self, components: &[&str]) -> io::Result<OwnedFd> {
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let mut current = openat2_strict_no_symlinks(self.root_fd.as_raw_fd(), c".", flags)?;
        for &comp in components {
            let c_comp = CString::new(comp)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
            current = openat2_strict_no_symlinks(current.as_raw_fd(), c_comp.as_c_str(), flags)?;
        }
        Ok(current)
    }

    fn derive_resolved_components(
        &self,
        initial_components: &[&str],
    ) -> io::Result<(Vec<String>, Vec<String>)> {
        let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let root_dup = openat2_strict_no_symlinks(self.root_fd.as_raw_fd(), c".", dir_flags)?;

        let mut dir_stack: Vec<OwnedFd> = vec![root_dup];
        let mut name_stack: Vec<String> = Vec::new();
        let mut pending: Vec<String> = initial_components
            .iter()
            .rev()
            .map(|segment| (*segment).to_string())
            .collect();
        let mut symlink_expansions = 0usize;
        let mut resolution_paths: Vec<String> = Vec::new();

        while let Some(segment) = pending.pop() {
            if segment.is_empty() || segment == "." {
                continue;
            }
            if segment == ".." {
                if name_stack.pop().is_none() {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "symlink traversal outside root is not permitted",
                    ));
                }
                dir_stack.pop();
                if symlink_expansions > 0 {
                    push_clean_trace_path(&mut resolution_paths, &name_stack, None, &pending);
                }
                continue;
            }
            if is_internal_upload_temp(&segment) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "reserved temporary filename is not allowed",
                ));
            }
            if segment.len() > 255 || name_stack.len() >= MAX_PATH_COMPONENTS {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "path component limit exceeded",
                ));
            }

            let current_dir_fd = dir_stack
                .last()
                .expect("dir_stack always retains root_fd")
                .as_raw_fd();
            let c_segment = CString::new(segment.as_str())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
            let entry_stat = fstatat_nofollow(current_dir_fd, c_segment.as_c_str())?;
            let mode_type = entry_stat.st_mode & libc::S_IFMT;

            match mode_type {
                libc::S_IFLNK => {
                    symlink_expansions += 1;
                    if symlink_expansions > MAX_SYMLINK_EXPANSIONS {
                        return Err(Error::from_raw_os_error(libc::ELOOP));
                    }
                    push_symlink_alias_trace(
                        &mut resolution_paths,
                        &name_stack,
                        segment.as_str(),
                        &pending,
                    );
                    push_clean_trace_path(
                        &mut resolution_paths,
                        &name_stack,
                        Some(segment.as_str()),
                        &pending,
                    );
                    let link_target = readlink_at_utf8(current_dir_fd, c_segment.as_c_str())?;
                    let target_segments = parse_symlink_target_segments(&link_target)?;
                    if pending.len().saturating_add(target_segments.len())
                        > MAX_PATH_COMPONENTS * MAX_SYMLINK_EXPANSIONS
                    {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "symlink expansion exceeded path component budget",
                        ));
                    }
                    for target_seg in target_segments.into_iter().rev() {
                        pending.push(target_seg);
                    }
                    push_clean_trace_path(&mut resolution_paths, &name_stack, None, &pending);
                }
                libc::S_IFDIR => {
                    let next_dir = openat2_strict_no_symlinks(
                        current_dir_fd,
                        c_segment.as_c_str(),
                        dir_flags,
                    )?;
                    dir_stack.push(next_dir);
                    name_stack.push(segment);
                }
                libc::S_IFREG => {
                    if !pending.is_empty() {
                        return Err(Error::from_raw_os_error(libc::ENOTDIR));
                    }
                    if entry_stat.st_nlink > 1 {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "hardlinked regular files are not permitted",
                        ));
                    }
                    name_stack.push(segment);
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "special files are not permitted",
                    ));
                }
            }
        }

        if symlink_expansions > 0 {
            let final_path = name_stack.join("/");
            if resolution_paths.last() != Some(&final_path) {
                resolution_paths.push(final_path);
            }
        }

        Ok((name_stack, resolution_paths))
    }
}
