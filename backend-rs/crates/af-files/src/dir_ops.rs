use crate::path::{is_internal_upload_temp, parse_relative_path, MAX_PATH_COMPONENTS};
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

    /// Bounded depth-first walk. Fails closed when more than `max_entries`
    /// entries exist or when the tree is deeper than `MAX_PATH_COMPONENTS`
    /// (entries past that depth could never be addressed through the API).
    /// At most `MAX_PATH_COMPONENTS + 1` directory descriptors are open at once.
    pub fn walk(&self, path: &str, max_entries: usize) -> io::Result<Vec<Entry>> {
        let components = parse_relative_path(path, true)?;
        let normalized_dir = components.join("/");
        let start_fd = self.open_dir_components(&components)?;

        struct WalkFrame {
            dir_fd: OwnedFd,
            depth: usize,
            iter: std::vec::IntoIter<Entry>,
        }

        let initial_entries = read_dir_entries_bounded(&start_fd, &normalized_dir, max_entries)?;
        if !initial_entries.is_empty() && components.len() >= MAX_PATH_COMPONENTS {
            return Err(depth_limit_error());
        }
        let mut total_discovered = initial_entries.len();
        let mut stack = vec![WalkFrame {
            dir_fd: start_fd,
            depth: components.len(),
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
                // Depth (component count) of `entry` itself.
                let entry_depth = frame.depth + 1;
                results.push(entry);

                if is_dir {
                    let c_name = CString::new(entry_name.as_str())
                        .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
                    match openat_no_symlinks(parent_raw_fd, c_name.as_c_str(), dir_flags, 0) {
                        Ok(child_fd) => {
                            let remaining = max_entries.saturating_sub(total_discovered);
                            let child_entries =
                                read_dir_entries_bounded(&child_fd, &entry_path, remaining)?;
                            if !child_entries.is_empty() && entry_depth >= MAX_PATH_COMPONENTS {
                                return Err(depth_limit_error());
                            }
                            total_discovered += child_entries.len();
                            stack.push(WalkFrame {
                                dir_fd: child_fd,
                                depth: entry_depth,
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

    /// Truncating breadth-first search walk.
    ///
    /// The BFS queue holds only relative path strings, never live descriptors,
    /// so arbitrarily wide trees cannot exhaust the process FD table
    /// (`EMFILE`). Each directory is re-opened from the browser root strictly
    /// through [`BrowserFs::open_dir_components`] (`openat2` with
    /// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` per component) only while it is
    /// being scanned, and its descriptor is dropped before the next directory
    /// is opened. Directories whose children would exceed
    /// `MAX_PATH_COMPONENTS` are not descended and mark the result truncated.
    pub fn walk_for_search(
        &self,
        path: &str,
        max_scan_entries: usize,
    ) -> io::Result<(Vec<Entry>, bool)> {
        let components = parse_relative_path(path, true)?;
        let normalized_dir = components.join("/");

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
            /// Root-relative path (`/`-joined validated components).
            dir_path: String,
            /// Depth relative to the search start (0 == start directory).
            depth: usize,
            /// Absolute component count of `dir_path` below the browser root.
            components: usize,
        }

        if components.len() >= MAX_PATH_COMPONENTS {
            let dir_fd = self.open_search_dir(&normalized_dir)?;
            let (probe, dir_truncated) = read_dir_entries_truncating(&dir_fd, &normalized_dir, 1)?;
            drop(dir_fd);
            let truncated = dir_truncated || !probe.is_empty();
            return Ok((Vec::new(), truncated));
        }

        let mut queue = std::collections::VecDeque::new();
        queue.push_back(SearchDirItem {
            dir_path: normalized_dir,
            depth: 0,
            components: components.len(),
        });

        let mut results = Vec::new();
        let mut truncated = false;

        while let Some(item) = queue.pop_front() {
            if results.len() >= max_scan_entries {
                truncated = true;
                break;
            }
            let dir_fd = match self.open_search_dir(&item.dir_path) {
                Ok(fd) => fd,
                Err(err) if item.depth > 0 && !is_resource_exhaustion(&err) => {
                    // Vanished, replaced by a symlink, or otherwise unreadable
                    // since discovery: skip it, never follow it.
                    continue;
                }
                Err(err) => return Err(err),
            };
            let remaining = max_scan_entries.saturating_sub(results.len());
            let read = read_dir_entries_truncating(&dir_fd, &item.dir_path, remaining);
            drop(dir_fd);
            let (dir_entries, dir_truncated) = match read {
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
            for entry in dir_entries {
                let is_dir = entry.kind == "directory";
                if is_dir && !(item.depth >= 1 && SKIPPED_DEEP_DIRS.contains(&entry.name.as_str()))
                {
                    let child_components = item.components + 1;
                    if child_components >= MAX_PATH_COMPONENTS {
                        // Its children would exceed the addressable depth.
                        truncated = true;
                    } else {
                        queue.push_back(SearchDirItem {
                            dir_path: entry.path.clone(),
                            depth: item.depth + 1,
                            components: child_components,
                        });
                    }
                }
                results.push(entry);
            }
        }

        Ok((results, truncated))
    }

    /// Re-opens a root-relative directory for one search scan step.
    fn open_search_dir(&self, dir_path: &str) -> io::Result<OwnedFd> {
        let components: Vec<&str> = if dir_path.is_empty() {
            Vec::new()
        } else {
            dir_path.split('/').collect()
        };
        if components.len() > MAX_PATH_COMPONENTS {
            return Err(depth_limit_error());
        }
        self.open_dir_components(&components)
    }
}

fn depth_limit_error() -> Error {
    Error::new(ErrorKind::InvalidInput, "path component limit exceeded")
}

fn is_resource_exhaustion(err: &Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOMEM)
    )
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

#[cfg(test)]
mod tests {
    use crate::path::MAX_PATH_COMPONENTS;
    use crate::tests::TempDir;
    use crate::BrowserFs;
    use std::fs;
    use std::io::ErrorKind;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    const WIDE_TREE_TEST: &str = "dir_ops::tests::wide_tree_search_holds_bounded_descriptors";
    const WIDE_TREE_ENV: &str = "AF_FILES_WIDE_TREE_TEST_CHILD";

    fn open_fd_count() -> usize {
        fs::read_dir("/proc/self/fd").unwrap().count()
    }

    fn deep_chain(root: &Path, depth: usize) -> PathBuf {
        let mut path = root.to_path_buf();
        for _ in 0..depth {
            path.push("d");
        }
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Runs in a re-executed child so lowering `RLIMIT_NOFILE` cannot disturb
    /// sibling tests sharing this process.
    #[test]
    fn wide_tree_search_holds_bounded_descriptors() {
        if std::env::var(WIDE_TREE_ENV).as_deref() != Ok(WIDE_TREE_TEST) {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", WIDE_TREE_TEST, "--nocapture", "--test-threads=1"])
                .env(WIDE_TREE_ENV, WIDE_TREE_TEST)
                .status()
                .unwrap();
            assert!(status.success(), "wide-tree child failed: {status:?}");
            return;
        }

        const WIDTH: usize = 400;
        let tmp = TempDir::new();
        for index in 0..WIDTH {
            let dir = tmp.path().join(format!("dir{index:04}"));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("leaf.txt"), b"x").unwrap();
        }
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        // Allow only a small, fixed number of descriptors beyond what is open
        // now: far fewer than the tree's width. Queuing a live FD per
        // discovered directory would hit EMFILE (and silently lose subtrees).
        let headroom = 24;
        let limit = (open_fd_count() + headroom) as libc::rlim_t;
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) },
            0
        );
        assert!(limit < WIDTH as libc::rlim_t);
        rlim.rlim_cur = limit.min(rlim.rlim_max);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) }, 0);

        let before = open_fd_count();
        let (entries, truncated) = bfs.walk_for_search("", 10_000).unwrap();
        assert!(!truncated);
        assert_eq!(entries.len(), WIDTH * 2);
        let leaves = entries
            .iter()
            .filter(|entry| entry.name == "leaf.txt")
            .count();
        assert_eq!(leaves, WIDTH, "every subtree must be scanned");
        assert_eq!(open_fd_count(), before, "search walk leaked descriptors");

        let walked = bfs.walk("", 10_000).unwrap();
        assert_eq!(walked.len(), WIDTH * 2);
        assert_eq!(open_fd_count(), before, "walk leaked descriptors");
    }

    #[test]
    fn search_reopen_rejects_symlinked_components_and_never_follows_them() {
        let tmp = TempDir::new();
        let outside = TempDir::new();
        fs::write(outside.path().join("outside-secret.txt"), b"secret").unwrap();
        fs::create_dir_all(tmp.path().join("real/sub")).unwrap();
        fs::write(tmp.path().join("real/sub/inside.txt"), b"ok").unwrap();
        symlink(outside.path(), tmp.path().join("escape")).unwrap();
        // Even a symlink whose target stays beneath the root is refused.
        symlink("sub", tmp.path().join("real/alias")).unwrap();

        let bfs = BrowserFs::open(tmp.path()).unwrap();
        for path in ["escape", "real/alias", "real/alias/../sub"] {
            assert!(
                bfs.open_search_dir(path).is_err(),
                "re-open must refuse symlinked component in {path:?}"
            );
        }
        assert!(bfs.open_search_dir("real/sub").is_ok());

        let (entries, truncated) = bfs.walk_for_search("", 100).unwrap();
        assert!(!truncated);
        let paths: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
        assert!(paths.contains(&"real/sub/inside.txt"));
        assert!(paths.contains(&"escape"));
        assert!(paths.contains(&"real/alias"));
        assert!(!paths.iter().any(|path| path.contains("outside-secret")));
        assert!(!paths.iter().any(|path| path.starts_with("real/alias/")));
        let kind = |p: &str| entries.iter().find(|e| e.path == p).unwrap().kind.clone();
        assert_eq!(kind("escape"), "symlink");
        assert_eq!(kind("real/alias"), "symlink");

        // A directory swapped for a symlink after discovery is skipped, not followed.
        fs::rename(tmp.path().join("real/sub"), tmp.path().join("real/moved")).unwrap();
        symlink(outside.path(), tmp.path().join("real/sub")).unwrap();
        assert!(bfs.open_search_dir("real/sub").is_err());
        let (entries, _) = bfs.walk_for_search("real", 100).unwrap();
        assert!(!entries
            .iter()
            .any(|entry| entry.path.contains("outside-secret")));
    }

    #[test]
    fn depth_beyond_component_limit_truncates_search_and_fails_walk_closed() {
        let tmp = TempDir::new();
        let bottom = deep_chain(tmp.path(), MAX_PATH_COMPONENTS + 6);
        fs::write(bottom.join("deep.txt"), b"deep").unwrap();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        let (entries, truncated) = bfs.walk_for_search("", 10_000).unwrap();
        assert!(truncated, "unreachable depth must be reported as truncated");
        let max_components = entries
            .iter()
            .map(|entry| entry.path.split('/').count())
            .max()
            .unwrap();
        assert_eq!(max_components, MAX_PATH_COMPONENTS);
        assert!(!entries.iter().any(|entry| entry.name == "deep.txt"));

        let err = bfs.walk("", 10_000).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        // Starting at the deepest addressable directory with children also fails.
        let start = vec!["d"; MAX_PATH_COMPONENTS].join("/");
        assert_eq!(
            bfs.walk(&start, 10_000).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        let (from_deep, deep_truncated) = bfs.walk_for_search(&start, 10_000).unwrap();
        assert!(
            from_deep.is_empty(),
            "children past MAX_PATH_COMPONENTS are unaddressable and must not be emitted"
        );
        assert!(deep_truncated);

        // An empty directory at MAX_PATH_COMPONENTS has no unaddressable children.
        let empty_deep = TempDir::new();
        deep_chain(empty_deep.path(), MAX_PATH_COMPONENTS);
        let empty_bfs = BrowserFs::open(empty_deep.path()).unwrap();
        let (empty_entries, empty_truncated) = empty_bfs.walk_for_search(&start, 10_000).unwrap();
        assert!(empty_entries.is_empty());
        assert!(!empty_truncated);
    }

    #[test]
    fn exactly_max_depth_tree_is_fully_walked() {
        let tmp = TempDir::new();
        deep_chain(tmp.path(), MAX_PATH_COMPONENTS);
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        let walked = bfs.walk("", 10_000).unwrap();
        assert_eq!(walked.len(), MAX_PATH_COMPONENTS);
        let (searched, truncated) = bfs.walk_for_search("", 10_000).unwrap();
        assert_eq!(searched.len(), MAX_PATH_COMPONENTS);
        // The deepest directory cannot be descended, so the search conservatively
        // reports possible truncation even though it happens to be empty.
        assert!(truncated);
        assert!(searched
            .iter()
            .all(|entry| entry.path.split('/').count() <= MAX_PATH_COMPONENTS));
    }
}
