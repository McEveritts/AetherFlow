use crate::path::{is_internal_upload_temp, parse_relative_path};
use crate::syscall::{
    format_mtime, fstat_fd, fstatat_nofollow, open_dir_stream, openat_no_symlinks,
};
use crate::{BrowserFs, Entry};
use std::cmp::Ordering;
use std::ffi::{CStr, CString};
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, OwnedFd};

pub(crate) const MAX_LIST_ENTRIES: usize = 10_000;

impl BrowserFs {
    pub fn metadata(&self, path: &str) -> io::Result<Entry> {
        let components = parse_relative_path(path, true)?;
        if components.is_empty() {
            let st = fstat_fd(self.root_fd.as_raw_fd())?;
            if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "root path is not a directory",
                ));
            }
            return Ok(Entry {
                name: String::new(),
                path: String::new(),
                kind: "directory".to_string(),
                size: 0,
                modified: format_mtime(&st),
            });
        }

        let (leaf_str, parent_components) = components
            .split_last()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid empty path"))?;
        let parent_fd = self.open_dir_components(parent_components)?;
        let leaf = CString::new(*leaf_str)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
        let st = fstatat_nofollow(parent_fd.as_raw_fd(), leaf.as_c_str())?;
        Ok(entry_from_stat(leaf_str, components.join("/"), &st))
    }

    pub fn list(&self, path: &str) -> io::Result<Vec<Entry>> {
        let components = parse_relative_path(path, true)?;
        let normalized_dir = components.join("/");
        let dir_fd = self.open_dir_components(&components)?;
        read_dir_entries_bounded(&dir_fd, &normalized_dir, MAX_LIST_ENTRIES)
    }

    pub fn walk(&self, path: &str, max_entries: usize) -> io::Result<Vec<Entry>> {
        let components = parse_relative_path(path, true)?;
        let normalized_dir = components.join("/");
        let start_fd = self.open_dir_components(&components)?;

        struct WalkFrame {
            dir_fd: OwnedFd,
            iter: std::vec::IntoIter<Entry>,
        }

        let initial_entries = read_dir_entries_bounded(&start_fd, &normalized_dir, max_entries)?;
        let mut total_discovered = initial_entries.len();
        let mut stack = vec![WalkFrame {
            dir_fd: start_fd,
            iter: initial_entries.into_iter(),
        }];
        let mut results = Vec::with_capacity(total_discovered);

        let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        while let Some(frame) = stack.last_mut() {
            if let Some(entry) = frame.iter.next() {
                let is_dir = entry.kind == "directory";
                let entry_name = entry.name.clone();
                let entry_path = entry.path.clone();
                let parent_raw_fd = frame.dir_fd.as_raw_fd();
                results.push(entry);

                if is_dir {
                    let c_name = CString::new(entry_name.as_str())
                        .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
                    match openat_no_symlinks(parent_raw_fd, c_name.as_c_str(), dir_flags, 0) {
                        Ok(child_fd) => {
                            let remaining = max_entries.saturating_sub(total_discovered);
                            let child_entries =
                                read_dir_entries_bounded(&child_fd, &entry_path, remaining)?;
                            total_discovered += child_entries.len();
                            stack.push(WalkFrame {
                                dir_fd: child_fd,
                                iter: child_entries.into_iter(),
                            });
                        }
                        Err(err) if err.kind() == ErrorKind::NotFound => {}
                        Err(err) => return Err(err),
                    }
                }
            } else {
                stack.pop();
            }
        }

        Ok(results)
    }

    pub fn walk_for_search(
        &self,
        path: &str,
        max_scan_entries: usize,
    ) -> io::Result<(Vec<Entry>, bool)> {
        let components = parse_relative_path(path, true)?;
        let normalized_dir = components.join("/");
        let start_fd = self.open_dir_components(&components)?;

        const SKIPPED_DEEP_DIRS: &[&str] = &[
            ".git",
            "node_modules",
            ".next",
            "target",
            ".cache",
            "__pycache__",
            ".venv",
        ];

        struct SearchDirItem {
            dir_fd: OwnedFd,
            dir_path: String,
            depth: usize,
        }

        let mut queue = std::collections::VecDeque::new();
        queue.push_back(SearchDirItem {
            dir_fd: start_fd,
            dir_path: normalized_dir,
            depth: 0,
        });

        let mut results = Vec::new();
        let mut truncated = false;
        let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;

        while let Some(item) = queue.pop_front() {
            if results.len() >= max_scan_entries {
                truncated = true;
                break;
            }
            let remaining = max_scan_entries.saturating_sub(results.len());
            let (dir_entries, dir_truncated) =
                match read_dir_entries_truncating(&item.dir_fd, &item.dir_path, remaining) {
                    Ok(pair) => pair,
                    Err(err)
                        if item.depth > 0
                            && matches!(
                                err.kind(),
                                ErrorKind::NotFound
                                    | ErrorKind::PermissionDenied
                                    | ErrorKind::InvalidData
                            ) =>
                    {
                        continue;
                    }
                    Err(err) => return Err(err),
                };
            if dir_truncated {
                truncated = true;
            }
            let parent_raw_fd = item.dir_fd.as_raw_fd();
            for entry in dir_entries {
                let is_dir = entry.kind == "directory";
                let entry_name = entry.name.clone();
                let entry_path = entry.path.clone();
                results.push(entry);

                if is_dir {
                    if item.depth >= 1 && SKIPPED_DEEP_DIRS.contains(&entry_name.as_str()) {
                        continue;
                    }
                    if let Ok(c_name) = CString::new(entry_name.as_str()) {
                        if let Ok(child_fd) =
                            openat_no_symlinks(parent_raw_fd, c_name.as_c_str(), dir_flags, 0)
                        {
                            queue.push_back(SearchDirItem {
                                dir_fd: child_fd,
                                dir_path: entry_path,
                                depth: item.depth + 1,
                            });
                        }
                    }
                }
            }
        }

        Ok((results, truncated))
    }
}

pub(crate) fn entry_from_stat(name: &str, path: String, st: &libc::stat) -> Entry {
    let mode_type = st.st_mode & libc::S_IFMT;
    let (kind, size) = match mode_type {
        libc::S_IFREG => ("file".to_string(), st.st_size.max(0) as u64),
        libc::S_IFDIR => ("directory".to_string(), 0),
        libc::S_IFLNK => ("symlink".to_string(), st.st_size.max(0) as u64),
        _ => ("other".to_string(), 0),
    };
    Entry {
        name: name.to_string(),
        path,
        kind,
        size,
        modified: format_mtime(st),
    }
}

fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| match (a.kind.as_str(), b.kind.as_str()) {
        ("directory", "directory") => a.name.cmp(&b.name),
        ("directory", _) => Ordering::Less,
        (_, "directory") => Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });
}

pub(crate) fn read_dir_entries_bounded(
    dir_fd: &OwnedFd,
    normalized_dir: &str,
    max_entries: usize,
) -> io::Result<Vec<Entry>> {
    let (guard, dir_raw_fd) = open_dir_stream(dir_fd.as_raw_fd())?;
    let mut entries = Vec::new();
    let effective_limit = max_entries.min(MAX_LIST_ENTRIES);

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
        let Ok(name_str) = std::str::from_utf8(name_bytes) else {
            tracing::warn!(
                dir = normalized_dir,
                lossy_name = %String::from_utf8_lossy(name_bytes),
                "skipping non-UTF-8 directory entry"
            );
            continue;
        };
        if is_internal_upload_temp(name_str) {
            continue;
        }
        if entries.len() >= effective_limit {
            return Err(Error::other("directory entry limit exceeded"));
        }
        let st = match fstatat_nofollow(dir_raw_fd, c_name) {
            Ok(st) => st,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let entry_path = if normalized_dir.is_empty() {
            name_str.to_string()
        } else {
            format!("{normalized_dir}/{name_str}")
        };
        entries.push(entry_from_stat(name_str, entry_path, &st));
    }

    sort_entries(&mut entries);
    Ok(entries)
}

fn read_dir_entries_truncating(
    dir_fd: &OwnedFd,
    normalized_dir: &str,
    max_entries: usize,
) -> io::Result<(Vec<Entry>, bool)> {
    let (guard, dir_raw_fd) = open_dir_stream(dir_fd.as_raw_fd())?;
    let mut entries = Vec::new();
    let effective_limit = max_entries.min(MAX_LIST_ENTRIES);
    let mut truncated = false;

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
        let Ok(name_str) = std::str::from_utf8(name_bytes) else {
            tracing::warn!(
                dir = normalized_dir,
                lossy_name = %String::from_utf8_lossy(name_bytes),
                "skipping non-UTF-8 directory entry during search walk"
            );
            continue;
        };
        if is_internal_upload_temp(name_str) {
            continue;
        }
        if entries.len() >= effective_limit {
            truncated = true;
            break;
        }
        let st = match fstatat_nofollow(dir_raw_fd, c_name) {
            Ok(st) => st,
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::NotFound | ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(err) => return Err(err),
        };
        let entry_path = if normalized_dir.is_empty() {
            name_str.to_string()
        } else {
            format!("{normalized_dir}/{name_str}")
        };
        entries.push(entry_from_stat(name_str, entry_path, &st));
    }

    sort_entries(&mut entries);
    Ok((entries, truncated))
}
