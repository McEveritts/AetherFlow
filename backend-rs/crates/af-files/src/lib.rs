//! Confinement-hardened filesystem primitives for AetherFlow's `McBrowser`.
//!
//! # Security Guarantees
//! - **Rooted descriptor traversal**: All relative paths are resolved component-by-component
//!   beneath an open `O_DIRECTORY | O_NOFOLLOW` root file descriptor using Linux `openat2`
//!   (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`), with an `openat`
//!   (`O_NOFOLLOW | O_CLOEXEC`) fallback when the host kernel does not support `openat2`.
//! - **No symlink or hardlink traversal**: Regular file opens, copies, deletions, and atomic
//!   replacements reject symlinks, special files (FIFOs, sockets, device nodes), and
//!   multiply-linked regular files (`st_nlink > 1`).
//! - **Opt-in internal symlink resolution**: Explicit opt-in APIs (`open_file_resolving_internal_links`,
//!   `scoped_resolving_internal_links`, `list_resolving_internal_links`,
//!   `metadata_resolving_internal_links`) resolve relative symlinks strictly inside `root_fd`
//!   without weakening strict default primitives (`open_file`, `scoped`, `list`, `metadata`, `walk`).
//!   Every step of resolution uses Linux `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`
//!   directly against `self.root_fd` (no fallback on kernels missing `openat2`; fails closed)
//!   combined with bounded component-by-component `readlinkat` stack expansion to derive a
//!   normalized root-relative target path. The kernel-opened descriptor is then bound to the
//!   derived target path by opening the derived path strictly with `RESOLVE_NO_SYMLINKS` and
//!   verifying exact `(st_dev, st_ino)` identity, guaranteeing race-safe agreement between the
//!   returned capability (`File` or `BrowserFs`) and the proven `resolved_path` suitable for
//!   parent policy authorization on both alias and target.
//! - **Safe leaf symlink rename and unlink**: Explicit leaf-link mutation methods
//!   (`rename_allowing_leaf_symlink`, `remove_allowing_leaf_symlink`,
//!   `remove_with_size_allowing_leaf_symlink`, `remove_tree_with_size_allowing_symlinks`)
//!   resolve ancestor directories strictly with `RESOLVE_NO_SYMLINKS`, operate on the symlink
//!   inode itself (never its target), enforce `RENAME_NOREPLACE`, and report `0` quota bytes
//!   when unlinking symlinks.
//! - **Hidden staging namespace**: Temporary upload files and recursive-copy staging directories
//!   use the reserved `.af-upload-tmp.` prefix, which is hidden from directory listings and walks
//!   and rejected by relative path parsing.
//! - **No-clobber and verified replacement**: `BrowserFs::begin_upload`, `PendingUpload::commit`,
//!   `BrowserFs::rename`, and `BrowserFs::copy` refuse to clobber existing targets and publish via
//!   `renameat2(..., RENAME_NOREPLACE)` with no overwrite fallback. `BrowserFs::begin_replace`
//!   stages replacements only for existing single-link regular files, and
//!   `PendingUpload::commit_replace` atomically replaces the target only after verifying that both
//!   the caller's previously opened [`std::fs::File`] and the current directory entry are
//!   single-link regular files sharing the exact same `(st_dev, st_ino)` identity.
//! - **Scoped capability derivation**: `BrowserFs::scoped` opens an existing subdirectory under the
//!   current root with full no-symlink traversal protections (or duplicates an independent root
//!   descriptor when empty), returning an isolated `BrowserFs` capability confined to that subtree.
//!
//! # Trusted Host & Parent Path Limitations
//! - **Parent path trust boundary**: [`BrowserFs::open`] opens the leaf root directory with
//!   `O_NOFOLLOW` and verifies it via `fstat`, confining all subsequent operations relative to
//!   that descriptor. However, callers must ensure that parent/ancestor directories above the root
//!   path on the host filesystem are owned by trusted accounts (e.g., `root` or the service UID)
//!   and are not writable by untrusted local principals during root initialization.
//! - **Trusted local process assumption**: `BrowserFs` enforces confinement against untrusted
//!   client/API inputs. It assumes the host kernel and local processes running with permission to
//!   mutate the underlying storage directory directly on the host are trusted and do not mount
//!   concurrent out-of-band filesystem race attacks against active `BrowserFs` operations.

#[cfg(not(target_os = "linux"))]
compile_error!("af-files is only supported on Linux");

use chrono::{DateTime, TimeZone, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const MAX_LIST_ENTRIES: usize = 10_000;
const MAX_PATH_COMPONENTS: usize = 64;
const MAX_SYMLINK_EXPANSIONS: usize = 40;
const UPLOAD_TEMP_PREFIX: &str = ".af-upload-tmp.";
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub modified: Option<String>,
}

#[derive(Debug)]
pub struct ResolvedFile {
    pub file: File,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub entry: Entry,
}

#[derive(Debug)]
pub struct ResolvedDir {
    pub fs: BrowserFs,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub entry: Entry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEntry {
    pub entry: Entry,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub was_symlink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDirListing {
    pub entries: Vec<Entry>,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub entry: Entry,
}

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

/// Error returned by [`BrowserFs::remove_tree_with_size`], carrying the total regular-file bytes
/// already unlinked before the failure occurred so callers can accurately adjust storage quotas.
#[derive(Debug)]
pub struct RemovalError {
    pub removed_bytes: u64,
    pub error: io::Error,
}

impl std::fmt::Display for RemovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (after removing {} bytes)",
            self.error, self.removed_bytes
        )
    }
}

impl std::error::Error for RemovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
pub struct BrowserFs {
    root_fd: OwnedFd,
}

#[derive(Debug)]
pub struct PendingUpload {
    parent_fd: OwnedFd,
    temp_name: CString,
    target_name: CString,
    file: File,
    committed: bool,
}

impl BrowserFs {
    pub fn open(root: &Path) -> io::Result<Self> {
        let bytes = root.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid root path"));
        }
        let c_root = CString::new(bytes)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "root path contains NUL"))?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let fd = unsafe { libc::open(c_root.as_ptr(), flags) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        let root_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::from_directory(root_fd)
    }

    pub fn from_directory(root_fd: OwnedFd) -> io::Result<Self> {
        let st = fstat_fd(root_fd.as_raw_fd())?;
        if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "root path is not a directory",
            ));
        }
        Ok(Self { root_fd })
    }

    pub fn scoped(&self, path: &str) -> io::Result<Self> {
        let components = parse_relative_path(path, true)?;
        let dir_fd = self.open_dir_components(&components)?;
        Self::from_directory(dir_fd)
    }

    pub fn directory_metadata(&self) -> io::Result<std::fs::Metadata> {
        File::from(self.root_fd.try_clone()?).metadata()
    }

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
                        Error::new(
                            ErrorKind::InvalidInput,
                            "resolved file path cannot be root",
                        )
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
                let was_symlink =
                    !resolution_paths.is_empty() || requested_norm != resolved_path;
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
                let leaf_name = resolved_components
                    .last()
                    .cloned()
                    .unwrap_or_default();
                let resolved_path = resolved_components.join("/");
                let entry = entry_from_stat(&leaf_name, resolved_path.clone(), &verify_stat);
                let was_symlink =
                    !resolution_paths.is_empty() || requested_norm != resolved_path;
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
            return Err(Error::last_os_error());
        }
        Ok(if mode_type == libc::S_IFREG {
            st.st_size.max(0) as u64
        } else {
            0
        })
    }

    pub fn remove_tree_with_size(&self, path: &str) -> Result<u64, RemovalError> {
        self.remove_tree_with_size_policy(path, false)
    }

    pub fn remove_tree_with_size_allowing_symlinks(&self, path: &str) -> Result<u64, RemovalError> {
        self.remove_tree_with_size_policy(path, true)
    }

    fn remove_tree_with_size_policy(
        &self,
        path: &str,
        allow_symlinks: bool,
    ) -> Result<u64, RemovalError> {
        let (parent_fd, leaf) = self
            .resolve_parent_and_leaf(path)
            .map_err(|error| RemovalError {
                removed_bytes: 0,
                error,
            })?;
        let mut removed_bytes = 0u64;
        remove_entry_recursive(
            parent_fd.as_raw_fd(),
            leaf.as_c_str(),
            &mut removed_bytes,
            0,
            allow_symlinks,
        )
        .map_err(|error| RemovalError {
            removed_bytes,
            error,
        })?;
        Ok(removed_bytes)
    }

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

    fn open_dir_components(&self, components: &[&str]) -> io::Result<OwnedFd> {
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let mut current = openat_no_symlinks(self.root_fd.as_raw_fd(), c".", flags, 0)?;
        for &comp in components {
            let c_comp = CString::new(comp)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
            current = openat_no_symlinks(current.as_raw_fd(), c_comp.as_c_str(), flags, 0)?;
        }
        Ok(current)
    }

    fn resolve_parent_and_leaf(&self, path: &str) -> io::Result<(OwnedFd, CString)> {
        let components = parse_relative_path(path, false)?;
        let (leaf_str, parent_components) = components
            .split_last()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "root path not allowed"))?;
        let parent_fd = self.open_dir_components(parent_components)?;
        let leaf = CString::new(*leaf_str)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
        Ok((parent_fd, leaf))
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
            let dir_flags =
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
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
                        Error::new(
                            ErrorKind::InvalidInput,
                            "resolved file path cannot be root",
                        )
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
                    let verify_root = openat2_strict_no_symlinks(
                        self.root_fd.as_raw_fd(),
                        c".",
                        verify_flags,
                    )?;
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
                let leaf_name = resolved_components
                    .last()
                    .cloned()
                    .unwrap_or_default();
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

    fn commit_with_directory_sync(
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

    fn commit_replace_with_directory_sync(
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

struct DirGuard(*mut libc::DIR);

impl Drop for DirGuard {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn open_dir_stream(dir_fd: libc::c_int) -> io::Result<(DirGuard, libc::c_int)> {
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

fn entry_from_stat(name: &str, path: String, st: &libc::stat) -> Entry {
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

fn read_dir_entries_bounded(
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
        let name_str = std::str::from_utf8(name_bytes).map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                "directory contains non-UTF-8 entry name",
            )
        })?;
        if is_internal_upload_temp(name_str) {
            continue;
        }
        if entries.len() >= effective_limit {
            return Err(Error::new(
                ErrorKind::Other,
                "directory entry limit exceeded",
            ));
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

fn open_regular_file_at(dirfd: libc::c_int, leaf: &CStr) -> io::Result<File> {
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

fn allocate_pending_upload(parent_fd: OwnedFd, target_name: CString) -> io::Result<PendingUpload> {
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
                    total_bytes = total_bytes.checked_add(copied).ok_or_else(|| {
                        Error::new(ErrorKind::Other, "copied byte count overflow")
                    })?;
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
            if stack.is_empty() {
                if unsafe { libc::fchmod(finished.dst_fd.as_raw_fd(), 0o755) } < 0 {
                    return Err(Error::last_os_error());
                }
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
            return Err(Error::new(
                ErrorKind::Other,
                "directory entry limit exceeded",
            ));
        }
        names.push(c_name.to_owned());
    }
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

fn cleanup_staging_tree(parent_fd: libc::c_int, staging_name: &CStr) {
    let mut ignored = 0u64;
    let _ = remove_entry_recursive(parent_fd, staging_name, &mut ignored, 0, false);
}

fn remove_entry_recursive(
    parent_fd: libc::c_int,
    name: &CStr,
    removed_bytes: &mut u64,
    depth: usize,
    allow_symlinks: bool,
) -> io::Result<()> {
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
            *removed_bytes = removed_bytes.saturating_add(size);
            Ok(())
        }
        libc::S_IFDIR => {
            let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
            let dir_fd = openat_no_symlinks(parent_fd, name, dir_flags, 0)?;
            let (guard, dir_raw_fd) = open_dir_stream(dir_fd.as_raw_fd())?;

            let mut regular_files: Vec<(CString, u64)> = Vec::new();
            let mut symlinks: Vec<CString> = Vec::new();
            let mut subdirs: Vec<CString> = Vec::new();
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
                if let Ok(s) = std::str::from_utf8(child_bytes) {
                    if is_internal_upload_temp(s) {
                        continue;
                    }
                }
                let child_st = match fstatat_nofollow(dir_raw_fd, c_child) {
                    Ok(st) => st,
                    Err(err) if err.kind() == ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                };
                match child_st.st_mode & libc::S_IFMT {
                    libc::S_IFREG if child_st.st_nlink == 1 => {
                        regular_files.push((c_child.to_owned(), child_st.st_size.max(0) as u64));
                    }
                    libc::S_IFLNK if allow_symlinks => {
                        symlinks.push(c_child.to_owned());
                    }
                    libc::S_IFDIR => {
                        subdirs.push(c_child.to_owned());
                    }
                    _ => {
                        invalid_entries.push(c_child.to_owned());
                    }
                }
            }
            drop(guard);

            regular_files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            symlinks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            subdirs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
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
                *removed_bytes = removed_bytes.saturating_add(size);
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

            for subdir_name in subdirs {
                remove_entry_recursive(
                    dir_fd.as_raw_fd(),
                    subdir_name.as_c_str(),
                    removed_bytes,
                    depth + 1,
                    allow_symlinks,
                )?;
            }

            for invalid_name in invalid_entries {
                remove_entry_recursive(
                    dir_fd.as_raw_fd(),
                    invalid_name.as_c_str(),
                    removed_bytes,
                    depth + 1,
                    allow_symlinks,
                )?;
            }

            drop(dir_fd);
            let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
            if rc < 0 {
                return Err(Error::last_os_error());
            }
            Ok(())
        }
        libc::S_IFLNK if allow_symlinks => {
            let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
            if rc < 0 {
                return Err(Error::last_os_error());
            }
            Ok(())
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

fn is_internal_upload_temp(name: &str) -> bool {
    name.starts_with(UPLOAD_TEMP_PREFIX)
}

fn parse_relative_path(path: &str, allow_root: bool) -> io::Result<Vec<&str>> {
    if path.len() > 4096 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path length exceeds limit",
        ));
    }
    if path.as_bytes().contains(&0) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path contains NUL byte",
        ));
    }
    if path.is_empty() {
        if allow_root {
            return Ok(Vec::new());
        }
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "operation not allowed on root directory",
        ));
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "absolute or backslash paths are not allowed",
        ));
    }

    let mut components = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        if segment == "." || segment == ".." {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "traversal segments are not allowed",
            ));
        }
        if is_internal_upload_temp(segment) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "reserved temporary filename is not allowed",
            ));
        }
        if segment.len() > 255 || components.len() >= MAX_PATH_COMPONENTS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "path component limit exceeded",
            ));
        }
        components.push(segment);
    }

    if components.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid empty path"));
    }

    Ok(components)
}

fn parse_symlink_target_segments(target: &str) -> io::Result<Vec<String>> {
    if target.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "empty symlink target is not allowed",
        ));
    }
    if target.len() > 4096 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "symlink target length exceeds limit",
        ));
    }
    if target.as_bytes().contains(&0) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "symlink target contains NUL byte",
        ));
    }
    if target.starts_with('/') || target.contains('\\') {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "absolute or backslash symlink targets are not permitted",
        ));
    }
    let mut segments = Vec::new();
    for segment in target.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if is_internal_upload_temp(segment) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "symlink target referencing reserved temporary filename is not permitted",
            ));
        }
        if segment.len() > 255 || segments.len() >= MAX_PATH_COMPONENTS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "symlink target component limit exceeded",
            ));
        }
        segments.push(segment.to_string());
    }
    Ok(segments)
}

fn push_symlink_alias_trace(
    resolution_paths: &mut Vec<String>,
    name_stack: &[String],
    segment: &str,
    pending: &[String],
) {
    let has_parent_traversal = pending.iter().any(|s| s == "..");
    if !has_parent_traversal {
        return;
    }
    let path = if name_stack.is_empty() {
        segment.to_string()
    } else {
        format!("{}/{segment}", name_stack.join("/"))
    };
    if resolution_paths.last() != Some(&path) {
        resolution_paths.push(path);
    }
}

fn push_clean_trace_path(
    resolution_paths: &mut Vec<String>,
    name_stack: &[String],
    current_segment: Option<&str>,
    pending: &[String],
) {
    let mut stack_prefix: Vec<&str> = name_stack.iter().map(String::as_str).collect();
    let mut suffix: Vec<&str> = Vec::new();
    let mut seen_non_parent = false;

    for s in current_segment
        .into_iter()
        .chain(pending.iter().rev().map(String::as_str))
    {
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." {
            if seen_non_parent {
                return;
            }
            if stack_prefix.pop().is_none() {
                return;
            }
        } else {
            seen_non_parent = true;
            suffix.push(s);
        }
    }

    stack_prefix.extend(suffix);
    let path = stack_prefix.join("/");
    if resolution_paths.last() != Some(&path) {
        resolution_paths.push(path);
    }
}

fn readlink_at_utf8(dirfd: libc::c_int, name: &CStr) -> io::Result<String> {
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

fn openat2_beneath_internal(
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

fn openat2_strict_no_symlinks(
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
    Err(Error::last_os_error())
}

fn openat_no_symlinks(
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
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {}
        _ => return Err(err),
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

fn dup_cloexec(fd: libc::c_int) -> io::Result<OwnedFd> {
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new_fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

fn fstat_fd(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc < 0 {
        return Err(Error::last_os_error());
    }
    Ok(st)
}

fn fstatat_nofollow(dirfd: libc::c_int, name: &CStr) -> io::Result<libc::stat> {
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

fn clear_nonblock(fd: libc::c_int) -> io::Result<()> {
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

fn renameat_noreplace(
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

fn sync_dir(dirfd: libc::c_int) -> io::Result<()> {
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

fn format_mtime(st: &libc::stat) -> Option<String> {
    let nsec = u32::try_from(st.st_mtime_nsec).ok()?;
    let dt: DateTime<Utc> = Utc.timestamp_opt(st.st_mtime, nsec).single()?;
    Some(dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let mut rng = rand::thread_rng();
            for _ in 0..64 {
                let token: u128 = rng.gen();
                let path = std::env::temp_dir().join(format!("af-files-test-{token:032x}"));
                if fs::create_dir(&path).is_ok() {
                    return Self { path };
                }
            }
            panic!("failed to create test tempdir");
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn nested_upload_directories_are_idempotent_and_confined() {
        let tmp = TempDir::new();
        let outside = TempDir::new();
        let filesystem = BrowserFs::open(tmp.path()).unwrap();
        filesystem
            .create_directory_all("albums/live/disc1")
            .unwrap();
        filesystem
            .create_directory_all("albums/live/disc1")
            .unwrap();
        let mut upload = filesystem
            .begin_upload("albums/live/disc1/track.txt")
            .unwrap();
        upload.write_all(b"track").unwrap();
        upload.commit().unwrap();
        assert_eq!(
            filesystem
                .begin_upload("albums/live/disc1/track.txt")
                .unwrap_err()
                .kind(),
            ErrorKind::AlreadyExists
        );
        symlink(outside.path(), tmp.path().join("external")).unwrap();
        assert!(filesystem.create_directory_all("external/escape").is_err());
        assert!(!outside.path().join("escape").exists());
        fs::write(tmp.path().join("plain-file"), b"unchanged").unwrap();
        assert!(filesystem.create_directory_all("plain-file/child").is_err());
        assert_eq!(
            fs::read(tmp.path().join("plain-file")).unwrap(),
            b"unchanged"
        );
        assert!(filesystem.create_directory_all("valid/../invalid").is_err());
        assert!(!tmp.path().join("valid").exists());
    }

    #[test]
    fn removal_reports_bytes_and_rejects_hardlinked_files() {
        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("file.txt"), b"payload").unwrap();
        assert_eq!(bfs.remove_with_size("file.txt").unwrap(), 7);
        bfs.create_directory("empty").unwrap();
        assert_eq!(bfs.remove_with_size("empty").unwrap(), 0);
        std::fs::write(tmp.path().join("linked.txt"), b"data").unwrap();
        std::fs::hard_link(tmp.path().join("linked.txt"), tmp.path().join("alias.txt")).unwrap();
        assert_eq!(
            bfs.remove_with_size("linked.txt").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert!(tmp.path().join("linked.txt").exists());
    }

    #[test]
    fn open_rejects_non_directory_and_symlink_root() {
        let tmp = TempDir::new();
        let file_path = tmp.path().join("file.txt");
        fs::write(&file_path, b"hello").unwrap();
        assert!(BrowserFs::open(&file_path).is_err());

        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let symlink_root = tmp.path().join("link_root");
        symlink(&real_dir, &symlink_root).unwrap();
        assert!(BrowserFs::open(&symlink_root).is_err());
    }

    #[test]
    fn invalid_paths_and_traversal_are_rejected() {
        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        for bad in [
            "..",
            "../etc/passwd",
            "a/../b",
            "a/../../b",
            ".",
            "./a",
            "a/./b",
            "/abs",
            "/etc/passwd",
            "/",
            "//",
            "a\\b",
            "\\root",
            "a\0b",
            ".af-upload-tmp.1234",
            "nested/.af-upload-tmp.1234",
        ] {
            assert!(bfs.scoped(bad).is_err(), "scoped should reject {bad:?}");
            assert!(bfs.list(bad).is_err(), "list should reject {bad:?}");
            assert!(bfs.metadata(bad).is_err(), "metadata should reject {bad:?}");
            assert!(bfs.walk(bad, 100).is_err(), "walk should reject {bad:?}");
            assert!(
                bfs.create_directory(bad).is_err(),
                "create_directory should reject {bad:?}"
            );
            assert!(bfs.remove(bad).is_err(), "remove should reject {bad:?}");
            assert!(
                bfs.remove_tree_with_size(bad).is_err(),
                "remove_tree_with_size should reject {bad:?}"
            );
            assert!(
                bfs.open_file(bad).is_err(),
                "open_file should reject {bad:?}"
            );
            assert!(
                bfs.begin_upload(bad).is_err(),
                "begin_upload should reject {bad:?}"
            );
            assert!(
                bfs.begin_replace(bad).is_err(),
                "begin_replace should reject {bad:?}"
            );
            assert!(
                bfs.rename(bad, "valid.txt").is_err(),
                "rename from should reject {bad:?}"
            );
            assert!(
                bfs.rename("valid.txt", bad).is_err(),
                "rename to should reject {bad:?}"
            );
            assert!(
                bfs.copy(bad, "valid.txt").is_err(),
                "copy from should reject {bad:?}"
            );
            assert!(
                bfs.copy("valid.txt", bad).is_err(),
                "copy to should reject {bad:?}"
            );
        }

        assert!(bfs.create_directory("").is_err());
        assert!(bfs.remove("").is_err());
        assert_eq!(bfs.remove_tree_with_size("").unwrap_err().removed_bytes, 0);
        assert!(bfs.open_file("").is_err());
        assert!(bfs.begin_upload("").is_err());
        assert!(bfs.begin_replace("").is_err());
        assert!(bfs.rename("", "dest").is_err());
        assert!(bfs.rename("src", "").is_err());
        assert!(bfs.copy("", "dest").is_err());
        assert!(bfs.copy("src", "").is_err());
    }

    #[test]
    fn mkdir_upload_open_rename_remove_roundtrip() {
        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        assert!(bfs.list("").unwrap().is_empty());

        bfs.create_directory("media").unwrap();
        bfs.create_directory("media/movies").unwrap();
        assert_eq!(
            bfs.create_directory("media").unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );

        let upload = bfs.begin_upload("media/movies/clip.bin").unwrap();
        let mut writer = upload.file().unwrap();
        writer.write_all(b"streamed-payload-123").unwrap();
        writer.flush().unwrap();
        drop(writer);

        assert!(bfs.list("media/movies").unwrap().is_empty());
        upload.commit().unwrap();

        let entries = bfs.list("media/movies").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "clip.bin");
        assert_eq!(entries[0].path, "media/movies/clip.bin");
        assert_eq!(entries[0].kind, "file");
        assert_eq!(entries[0].size, 20);
        assert!(entries[0].modified.as_deref().unwrap().contains('T'));

        let serialized = serde_json::to_value(&entries[0]).unwrap();
        assert_eq!(serialized["name"], "clip.bin");
        assert_eq!(serialized["path"], "media/movies/clip.bin");
        assert_eq!(serialized["kind"], "file");
        assert_eq!(serialized["size"], 20);
        assert!(serialized["modified"].is_string());

        let mut reader = bfs.open_file("media/movies/clip.bin").unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"streamed-payload-123");

        bfs.rename("media/movies/clip.bin", "media/clip-renamed.bin")
            .unwrap();
        assert!(bfs.list("media/movies").unwrap().is_empty());

        let media_entries = bfs.list("media").unwrap();
        assert_eq!(media_entries.len(), 2);
        assert_eq!(media_entries[0].name, "movies");
        assert_eq!(media_entries[0].kind, "directory");
        assert_eq!(media_entries[0].path, "media/movies");
        assert_eq!(media_entries[1].name, "clip-renamed.bin");
        assert_eq!(media_entries[1].kind, "file");
        assert_eq!(media_entries[1].path, "media/clip-renamed.bin");

        assert!(bfs.remove("media").is_err());
        bfs.remove("media/movies").unwrap();
        bfs.remove("media/clip-renamed.bin").unwrap();
        bfs.remove("media").unwrap();
        assert!(bfs.list("").unwrap().is_empty());
    }

    #[test]
    fn symlinks_in_ancestor_and_leaf_and_dangling_are_handled_safely() {
        let outside = TempDir::new();
        let outside_secret = outside.path().join("secret.txt");
        fs::write(&outside_secret, b"top-secret").unwrap();

        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        let ancestor_link = tmp.path().join("escape_dir");
        symlink(outside.path(), &ancestor_link).unwrap();

        let leaf_link = tmp.path().join("escape_file.txt");
        symlink(&outside_secret, &leaf_link).unwrap();

        let dangling_link = tmp.path().join("dangling.txt");
        symlink(outside.path().join("nonexistent"), &dangling_link).unwrap();

        let root_entries = bfs.list("").unwrap();
        assert_eq!(root_entries.len(), 3);
        for entry in &root_entries {
            assert_eq!(entry.kind, "symlink");
        }

        assert!(bfs.scoped("escape_dir").is_err());
        assert!(bfs.scoped("escape_dir/sub").is_err());
        assert!(bfs.list("escape_dir").is_err());
        assert!(bfs.metadata("escape_dir/secret.txt").is_err());
        assert!(bfs.walk("escape_dir", 100).is_err());
        assert!(bfs.walk("escape_dir/sub", 100).is_err());
        assert!(bfs.open_file("escape_dir/secret.txt").is_err());
        assert!(bfs.create_directory("escape_dir/new_dir").is_err());
        assert!(bfs.begin_upload("escape_dir/injected.txt").is_err());
        assert!(bfs.begin_replace("escape_dir/secret.txt").is_err());
        assert!(bfs.remove("escape_dir/secret.txt").is_err());
        assert!(bfs.remove_tree_with_size("escape_dir/secret.txt").is_err());
        assert!(bfs.remove_tree_with_size("escape_dir").is_err());
        assert!(bfs.rename("escape_dir/secret.txt", "stolen.txt").is_err());
        assert!(bfs.copy("escape_dir/secret.txt", "stolen.txt").is_err());

        assert!(bfs.scoped("escape_file.txt").is_err());
        assert!(bfs.scoped("dangling.txt").is_err());
        assert!(bfs.open_file("escape_file.txt").is_err());
        assert!(bfs.open_file("dangling.txt").is_err());
        assert!(bfs.begin_upload("escape_file.txt").is_err());
        assert!(bfs.begin_upload("dangling.txt").is_err());
        assert!(bfs.begin_replace("escape_file.txt").is_err());
        assert!(bfs.begin_replace("dangling.txt").is_err());
        assert!(bfs.remove("escape_file.txt").is_err());
        assert!(bfs.remove("dangling.txt").is_err());
        assert!(bfs.remove_tree_with_size("escape_file.txt").is_err());
        assert!(bfs.remove_tree_with_size("dangling.txt").is_err());
        assert!(bfs.rename("escape_file.txt", "moved.txt").is_err());
        assert!(bfs.copy("escape_file.txt", "copied.txt").is_err());
        assert!(bfs.copy("dangling.txt", "copied.txt").is_err());

        fs::write(tmp.path().join("real.txt"), b"real").unwrap();
        assert!(bfs.rename("real.txt", "escape_file.txt").is_err());
        assert!(bfs.rename("real.txt", "dangling.txt").is_err());
        assert!(bfs.rename("real.txt", "escape_dir/real.txt").is_err());
        assert!(bfs.copy("real.txt", "escape_file.txt").is_err());
        assert!(bfs.copy("real.txt", "dangling.txt").is_err());
        assert!(bfs.copy("real.txt", "escape_dir/real.txt").is_err());

        assert_eq!(fs::read(&outside_secret).unwrap(), b"top-secret");
    }

    #[test]
    fn fifo_is_listed_as_other_and_open_file_rejects_without_blocking() {
        let tmp = TempDir::new();
        let fifo_path = tmp.path().join("pipe.fifo");
        let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
        assert_eq!(rc, 0);

        let bfs = BrowserFs::open(tmp.path()).unwrap();
        let entries = bfs.list("").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "pipe.fifo");
        assert_eq!(entries[0].kind, "other");

        let err = bfs.open_file("pipe.fifo").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        assert!(bfs.scoped("pipe.fifo").is_err());
        assert_eq!(
            bfs.begin_replace("pipe.fifo").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert!(bfs.remove("pipe.fifo").is_err());
        assert!(bfs.remove_tree_with_size("pipe.fifo").is_err());
        assert!(bfs.rename("pipe.fifo", "renamed.fifo").is_err());
        assert!(bfs.copy("pipe.fifo", "copied.fifo").is_err());
    }

    #[test]
    fn open_file_and_rename_reject_hardlinked_regular_files() {
        let outside = TempDir::new();
        let external_file = outside.path().join("control_plane.db");
        fs::write(&external_file, b"sensitive-control-plane-data").unwrap();

        let tmp = TempDir::new();
        let injected_hardlink = tmp.path().join("exposed.db");
        fs::hard_link(&external_file, &injected_hardlink).unwrap();

        let bfs = BrowserFs::open(tmp.path()).unwrap();
        let err = bfs.open_file("exposed.db").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(
            bfs.rename("exposed.db", "renamed_exposed.db")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(tmp.path().join("exposed.db").exists());
        assert!(!tmp.path().join("renamed_exposed.db").exists());

        let up = bfs.begin_upload("normal.txt").unwrap();
        up.file().unwrap().write_all(b"single-link").unwrap();
        up.commit().unwrap();

        let mut buf = String::new();
        bfs.open_file("normal.txt")
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        assert_eq!(buf, "single-link");

        fs::hard_link(
            tmp.path().join("normal.txt"),
            tmp.path().join("normal_link.txt"),
        )
        .unwrap();
        assert_eq!(
            bfs.open_file("normal.txt").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            bfs.open_file("normal_link.txt").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            bfs.rename("normal.txt", "normal_moved.txt")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            bfs.rename("normal_link.txt", "normal_link_moved.txt")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            bfs.begin_upload("normal.txt").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            bfs.begin_replace("normal.txt").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn rename_and_upload_refuse_to_clobber_existing_targets() {
        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        let up1 = bfs.begin_upload("a.txt").unwrap();
        up1.file().unwrap().write_all(b"first").unwrap();
        up1.commit().unwrap();

        let up2 = bfs.begin_upload("b.txt").unwrap();
        up2.file().unwrap().write_all(b"second").unwrap();
        up2.commit().unwrap();

        let err = bfs.rename("a.txt", "b.txt").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);

        let mut content_b = String::new();
        bfs.open_file("b.txt")
            .unwrap()
            .read_to_string(&mut content_b)
            .unwrap();
        assert_eq!(content_b, "second");

        let err = bfs.begin_upload("a.txt").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);

        let mut content_a = String::new();
        bfs.open_file("a.txt")
            .unwrap()
            .read_to_string(&mut content_a)
            .unwrap();
        assert_eq!(content_a, "first");

        let race_up1 = bfs.begin_upload("race.txt").unwrap();
        race_up1.file().unwrap().write_all(b"winner").unwrap();

        let race_up2 = bfs.begin_upload("race.txt").unwrap();
        race_up2.file().unwrap().write_all(b"loser").unwrap();

        race_up1.commit().unwrap();
        let err = race_up2.commit().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);

        let mut winner_content = String::new();
        bfs.open_file("race.txt")
            .unwrap()
            .read_to_string(&mut winner_content)
            .unwrap();
        assert_eq!(winner_content, "winner");

        let raw_names: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!raw_names.iter().any(|n| n.starts_with(UPLOAD_TEMP_PREFIX)));
    }

    #[test]
    fn dropped_upload_removes_only_its_own_temp_file_and_keeps_stranger_files() {
        let tmp = TempDir::new();
        let stranger = tmp.path().join(".stranger-temp.part");
        let fake_internal = tmp.path().join(format!("{UPLOAD_TEMP_PREFIX}foreign"));
        fs::write(&stranger, b"keep-me").unwrap();
        fs::write(&fake_internal, b"keep-foreign").unwrap();

        let bfs = BrowserFs::open(tmp.path()).unwrap();
        {
            let up = bfs.begin_upload("aborted.txt").unwrap();
            up.file().unwrap().write_all(b"partial").unwrap();

            let listed = bfs.list("").unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].name, ".stranger-temp.part");
        }

        assert!(!tmp.path().join("aborted.txt").exists());
        assert_eq!(fs::read(&stranger).unwrap(), b"keep-me");
        assert_eq!(fs::read(&fake_internal).unwrap(), b"keep-foreign");

        let remaining_temps: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(UPLOAD_TEMP_PREFIX))
            .collect();
        assert_eq!(
            remaining_temps,
            vec![format!("{UPLOAD_TEMP_PREFIX}foreign")]
        );
    }

    #[test]
    fn non_utf8_filenames_are_rejected_without_lossy_collision() {
        let tmp = TempDir::new();
        let invalid_name = std::ffi::OsString::from_vec(vec![b'b', b'a', b'd', 0xff, 0xfe]);
        fs::write(tmp.path().join(invalid_name), b"bad").unwrap();

        let bfs = BrowserFs::open(tmp.path()).unwrap();
        let err = bfs.list("").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        let walk_err = bfs.walk("", 100).unwrap_err();
        assert_eq!(walk_err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn published_upload_remains_successful_when_directory_sync_fails() {
        let tmp = TempDir::new();
        let browser = BrowserFs::open(tmp.path()).unwrap();
        let upload = browser.begin_upload("published.txt").unwrap();
        upload
            .file()
            .unwrap()
            .write_all(b"accounted content")
            .unwrap();
        upload
            .commit_with_directory_sync(|_| Err(Error::from_raw_os_error(libc::EIO)))
            .unwrap();
        assert_eq!(
            fs::read(tmp.path().join("published.txt")).unwrap(),
            b"accounted content"
        );
        assert_eq!(browser.list("").unwrap().len(), 1);
    }

    #[test]
    fn oversized_or_excessively_deep_paths_are_rejected_before_io() {
        assert!(parse_relative_path(&"x".repeat(4097), false).is_err());
        assert!(parse_relative_path(&"x".repeat(256), false).is_err());
        assert!(parse_relative_path(&vec!["x"; 65].join("/"), false).is_err());
        assert_eq!(
            parse_relative_path(&vec!["x"; 64].join("/"), false)
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn repeated_and_concurrent_root_listings_and_walks_have_independent_offsets() {
        let tmp = TempDir::new();
        fs::create_dir_all(tmp.path().join("sub/deep")).unwrap();
        fs::write(tmp.path().join("visible.txt"), b"data").unwrap();
        fs::write(tmp.path().join("sub/deep/leaf.txt"), b"leaf").unwrap();
        let browser = BrowserFs::open(tmp.path()).unwrap();
        for _ in 0..3 {
            assert_eq!(browser.list("").unwrap().len(), 2);
            assert_eq!(browser.walk("", 100).unwrap().len(), 4);
        }
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    assert_eq!(browser.list("").unwrap().len(), 2);
                    assert_eq!(browser.walk("", 100).unwrap().len(), 4);
                });
            }
        });
    }

    #[test]
    fn list_enforces_10000_entry_limit() {
        let tmp = TempDir::new();
        for i in 0..=MAX_LIST_ENTRIES {
            let p = tmp.path().join(format!("f_{i:05}"));
            File::create(p).unwrap();
        }

        let bfs = BrowserFs::open(tmp.path()).unwrap();
        let err = bfs.list("").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
    }

    #[test]
    fn metadata_supports_root_and_entries_without_following_symlinks() {
        let outside = TempDir::new();
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside-payload").unwrap();

        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        let root_meta = bfs.metadata("").unwrap();
        assert_eq!(root_meta.name, "");
        assert_eq!(root_meta.path, "");
        assert_eq!(root_meta.kind, "directory");
        assert_eq!(root_meta.size, 0);
        assert!(root_meta.modified.is_some());

        bfs.create_directory_all("docs/guides").unwrap();
        let mut up = bfs.begin_upload("docs/guides/intro.md").unwrap();
        up.write_all(b"# Welcome").unwrap();
        up.commit().unwrap();

        let dir_meta = bfs.metadata("docs//guides/").unwrap();
        assert_eq!(dir_meta.name, "guides");
        assert_eq!(dir_meta.path, "docs/guides");
        assert_eq!(dir_meta.kind, "directory");
        assert_eq!(dir_meta.size, 0);

        let file_meta = bfs.metadata("docs/guides/intro.md").unwrap();
        assert_eq!(file_meta.name, "intro.md");
        assert_eq!(file_meta.path, "docs/guides/intro.md");
        assert_eq!(file_meta.kind, "file");
        assert_eq!(file_meta.size, 9);

        symlink(&outside_file, tmp.path().join("docs/leaf_link")).unwrap();
        symlink(outside.path(), tmp.path().join("docs/dir_link")).unwrap();

        let sym_meta = bfs.metadata("docs/leaf_link").unwrap();
        assert_eq!(sym_meta.name, "leaf_link");
        assert_eq!(sym_meta.path, "docs/leaf_link");
        assert_eq!(sym_meta.kind, "symlink");

        assert!(bfs.metadata("docs/dir_link/outside.txt").is_err());
        assert_eq!(
            bfs.metadata("docs/missing.txt").unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn walk_returns_descendants_with_full_relative_paths_and_enforces_bounds_and_no_symlink_traversal()
    {
        let outside = TempDir::new();
        fs::write(outside.path().join("secret.txt"), b"classified").unwrap();

        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        assert!(bfs.walk("", 0).unwrap().is_empty());

        bfs.create_directory_all("alpha/beta").unwrap();
        bfs.create_directory_all("gamma").unwrap();
        fs::write(tmp.path().join("root.txt"), b"r").unwrap();
        fs::write(tmp.path().join("alpha/a.txt"), b"aa").unwrap();
        fs::write(tmp.path().join("alpha/beta/b.txt"), b"bbb").unwrap();
        fs::write(
            tmp.path().join(format!("{UPLOAD_TEMP_PREFIX}hidden")),
            b"temp",
        )
        .unwrap();
        symlink(outside.path(), tmp.path().join("alpha/escape_dir")).unwrap();
        symlink(
            outside.path().join("secret.txt"),
            tmp.path().join("alpha/escape_file"),
        )
        .unwrap();

        let all = bfs.walk("", 100).unwrap();
        let paths: Vec<&str> = all.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "alpha",
                "alpha/beta",
                "alpha/beta/b.txt",
                "alpha/a.txt",
                "alpha/escape_dir",
                "alpha/escape_file",
                "gamma",
                "root.txt",
            ]
        );
        assert!(!paths.iter().any(|p| p.contains("secret.txt")));
        assert!(!paths.iter().any(|p| p.contains(UPLOAD_TEMP_PREFIX)));

        let sub = bfs.walk("alpha", 100).unwrap();
        let sub_paths: Vec<&str> = sub.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            sub_paths,
            vec![
                "alpha/beta",
                "alpha/beta/b.txt",
                "alpha/a.txt",
                "alpha/escape_dir",
                "alpha/escape_file",
            ]
        );
        assert_eq!(sub[1].name, "b.txt");
        assert_eq!(sub[1].size, 3);

        assert_eq!(bfs.walk("alpha", 5).unwrap().len(), 5);
        for limit in 0..5 {
            let err = bfs.walk("alpha", limit).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Other);
            assert_eq!(err.to_string(), "directory entry limit exceeded");
        }

        assert!(bfs.walk("root.txt", 10).is_err());
        assert!(bfs.walk("alpha/escape_dir", 10).is_err());
        assert!(bfs.walk("alpha/escape_dir/secret.txt", 10).is_err());
    }

    #[test]
    fn copy_files_and_recursive_directories_enforces_no_overwrite_and_cleans_up_failures() {
        let outside = TempDir::new();
        fs::write(outside.path().join("external.txt"), b"external").unwrap();

        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        bfs.create_directory_all("src/nested/empty_dir").unwrap();
        fs::write(tmp.path().join("src/top.txt"), b"hello").unwrap();
        fs::write(tmp.path().join("src/nested/deep.bin"), b"0123456789").unwrap();
        fs::write(
            tmp.path().join(format!("src/{UPLOAD_TEMP_PREFIX}ignored")),
            b"ignore-staging",
        )
        .unwrap();

        let file_bytes = bfs.copy("src/top.txt", "top_copy.txt").unwrap();
        assert_eq!(file_bytes, 5);
        assert_eq!(fs::read(tmp.path().join("top_copy.txt")).unwrap(), b"hello");

        let dir_bytes = bfs.copy("src", "dst").unwrap();
        assert_eq!(dir_bytes, 15);
        assert_eq!(fs::read(tmp.path().join("dst/top.txt")).unwrap(), b"hello");
        assert_eq!(
            fs::read(tmp.path().join("dst/nested/deep.bin")).unwrap(),
            b"0123456789"
        );
        assert!(tmp.path().join("dst/nested/empty_dir").is_dir());
        assert_eq!(bfs.walk("dst", 100).unwrap().len(), 4);

        // No overwrite of existing file or directory
        assert_eq!(
            bfs.copy("src/top.txt", "top_copy.txt").unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        assert_eq!(
            bfs.copy("src", "dst").unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        assert_eq!(
            bfs.copy("src", "src").unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );

        // Reject copying a directory into itself or any descendant
        assert_eq!(
            bfs.copy("src", "src/sub_copy").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            bfs.copy("src", "src/nested/sub_copy").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert!(!tmp.path().join("src/sub_copy").exists());

        // Failure inside recursive directory copy (symlink) must be all-or-nothing and clean up staging
        bfs.create_directory_all("bad_symlink_tree/sub").unwrap();
        fs::write(tmp.path().join("bad_symlink_tree/good.txt"), b"valid-data").unwrap();
        symlink(
            outside.path().join("external.txt"),
            tmp.path().join("bad_symlink_tree/sub/link.txt"),
        )
        .unwrap();
        assert_eq!(
            bfs.copy("bad_symlink_tree", "failed_dst_1")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(!tmp.path().join("failed_dst_1").exists());

        // Failure inside recursive directory copy (hardlinked regular file) must clean up staging
        bfs.create_directory_all("bad_hardlink_tree/sub").unwrap();
        fs::write(tmp.path().join("bad_hardlink_tree/good.txt"), b"valid-data").unwrap();
        fs::hard_link(
            outside.path().join("external.txt"),
            tmp.path().join("bad_hardlink_tree/sub/hard.txt"),
        )
        .unwrap();
        assert_eq!(
            bfs.copy("bad_hardlink_tree", "failed_dst_2")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(!tmp.path().join("failed_dst_2").exists());

        let root_raw_names: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!root_raw_names
            .iter()
            .any(|n| n.starts_with(UPLOAD_TEMP_PREFIX)));
    }

    #[test]
    fn remove_tree_with_size_deletes_trees_and_reports_partial_bytes_on_error() {
        let outside = TempDir::new();
        let outside_secret = outside.path().join("keep.txt");
        fs::write(&outside_secret, b"must-survive").unwrap();

        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        // Single regular file and full directory tree deletion
        fs::write(tmp.path().join("single.txt"), b"123456").unwrap();
        assert_eq!(bfs.remove_tree_with_size("single.txt").unwrap(), 6);
        assert!(!tmp.path().join("single.txt").exists());

        bfs.create_directory_all("tree/a/b").unwrap();
        bfs.create_directory_all("tree/empty").unwrap();
        fs::write(tmp.path().join("tree/root_file.bin"), b"1234").unwrap();
        fs::write(tmp.path().join("tree/a/mid.bin"), b"12345").unwrap();
        fs::write(tmp.path().join("tree/a/b/leaf.bin"), b"1234567").unwrap();
        assert_eq!(bfs.remove_tree_with_size("tree").unwrap(), 16);
        assert!(!tmp.path().join("tree").exists());

        // Partial deletion accounting when a directory contains valid files and a symlink
        bfs.create_directory_all("partial_sym/sub").unwrap();
        fs::write(tmp.path().join("partial_sym/top.txt"), b"12345").unwrap();
        fs::write(tmp.path().join("partial_sym/sub/nested.txt"), b"12345678").unwrap();
        symlink(&outside_secret, tmp.path().join("partial_sym/sub/a_link")).unwrap();

        let rem_err = bfs.remove_tree_with_size("partial_sym").unwrap_err();
        assert_eq!(rem_err.error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(rem_err.removed_bytes, 13);
        assert!(!tmp.path().join("partial_sym/top.txt").exists());
        assert!(!tmp.path().join("partial_sym/sub/nested.txt").exists());
        assert!(tmp
            .path()
            .join("partial_sym/sub/a_link")
            .symlink_metadata()
            .is_ok());
        assert_eq!(fs::read(&outside_secret).unwrap(), b"must-survive");

        // Partial deletion accounting when a directory contains valid files and a hardlink
        bfs.create_directory_all("partial_hard/sub").unwrap();
        fs::write(tmp.path().join("partial_hard/file1.txt"), b"abcdef").unwrap();
        fs::write(
            tmp.path().join("partial_hard/sub/file2.txt"),
            b"0123456789",
        )
        .unwrap();
        fs::hard_link(
            &outside_secret,
            tmp.path().join("partial_hard/sub/a_hardlink.txt"),
        )
        .unwrap();

        let hard_err = bfs.remove_tree_with_size("partial_hard").unwrap_err();
        assert_eq!(hard_err.error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(hard_err.removed_bytes, 16);
        assert!(tmp.path().join("partial_hard/sub/a_hardlink.txt").exists());
        assert_eq!(fs::read(&outside_secret).unwrap(), b"must-survive");
    }

    #[test]
    fn commit_replace_verifies_identity_preserves_offsets_and_maintains_publication_semantics() {
        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        assert_eq!(
            bfs.begin_replace("missing.json").unwrap_err().kind(),
            ErrorKind::NotFound
        );
        bfs.create_directory("dir_target").unwrap();
        assert_eq!(
            bfs.begin_replace("dir_target").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );

        let mut initial = bfs.begin_upload("config.json").unwrap();
        initial.write_all(b"{\"v\":1,\"mode\":\"old\"}").unwrap();
        initial.commit().unwrap();

        assert_eq!(
            bfs.begin_upload("config.json").unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );

        let mut expected_file = bfs.open_file("config.json").unwrap();
        let mut prefix = [0u8; 7];
        expected_file.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"{\"v\":1,");

        // Atomic replacement with matching dev/ino succeeds
        let mut replacement = bfs.begin_replace("config.json").unwrap();
        replacement.write_all(b"{\"v\":2,\"mode\":\"new\"}").unwrap();
        replacement.commit_replace(&expected_file).unwrap();

        // Previously opened file handle retains its own inode and descriptor offset
        let mut rest_of_old = String::new();
        expected_file.read_to_string(&mut rest_of_old).unwrap();
        assert_eq!(rest_of_old, "\"mode\":\"old\"}");

        // Newly opened handle sees the replaced file content
        let mut new_content = String::new();
        bfs.open_file("config.json")
            .unwrap()
            .read_to_string(&mut new_content)
            .unwrap();
        assert_eq!(new_content, "{\"v\":2,\"mode\":\"new\"}");

        // Identity mismatch: expected_file still points to v1 inode while config.json is now v2
        let mut stale_replace = bfs.begin_replace("config.json").unwrap();
        stale_replace.write_all(b"stale-overwrite").unwrap();
        let mismatch_err = stale_replace.commit_replace(&expected_file).unwrap_err();
        assert_eq!(mismatch_err.kind(), ErrorKind::AlreadyExists);

        let mut unchanged = String::new();
        bfs.open_file("config.json")
            .unwrap()
            .read_to_string(&mut unchanged)
            .unwrap();
        assert_eq!(unchanged, "{\"v\":2,\"mode\":\"new\"}");

        // Identity mismatch against a different file's handle
        fs::write(tmp.path().join("other.txt"), b"other").unwrap();
        let other_handle = bfs.open_file("other.txt").unwrap();
        let mut wrong_handle_up = bfs.begin_replace("config.json").unwrap();
        wrong_handle_up.write_all(b"wrong").unwrap();
        assert_eq!(
            wrong_handle_up
                .commit_replace(&other_handle)
                .unwrap_err()
                .kind(),
            ErrorKind::AlreadyExists
        );

        // Target deleted before commit_replace fails with NotFound
        let v2_handle = bfs.open_file("config.json").unwrap();
        let mut deleted_target_up = bfs.begin_replace("config.json").unwrap();
        deleted_target_up.write_all(b"after-delete").unwrap();
        bfs.remove("config.json").unwrap();
        assert_eq!(
            deleted_target_up
                .commit_replace(&v2_handle)
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        assert!(!tmp.path().join("config.json").exists());

        // Hardlinked target before commit_replace is rejected with PermissionDenied
        fs::write(tmp.path().join("hard_target.txt"), b"initial").unwrap();
        let hard_expected = bfs.open_file("hard_target.txt").unwrap();
        let mut hard_replace = bfs.begin_replace("hard_target.txt").unwrap();
        hard_replace.write_all(b"replaced").unwrap();
        fs::hard_link(
            tmp.path().join("hard_target.txt"),
            tmp.path().join("hard_alias.txt"),
        )
        .unwrap();
        assert_eq!(
            bfs.begin_replace("hard_target.txt").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            hard_replace
                .commit_replace(&hard_expected)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            fs::read(tmp.path().join("hard_target.txt")).unwrap(),
            b"initial"
        );
        fs::remove_file(tmp.path().join("hard_alias.txt")).unwrap();

        // Publication semantics: directory sync failure after renameat must still return Ok(())
        let sync_expected = bfs.open_file("hard_target.txt").unwrap();
        let mut sync_replace = bfs.begin_replace("hard_target.txt").unwrap();
        sync_replace.write_all(b"published-despite-dir-eio").unwrap();
        sync_replace
            .commit_replace_with_directory_sync(&sync_expected, |_| {
                Err(Error::from_raw_os_error(libc::EIO))
            })
            .unwrap();
        assert_eq!(
            fs::read(tmp.path().join("hard_target.txt")).unwrap(),
            b"published-despite-dir-eio"
        );

        // Ensure no leftover staging files remain
        let raw_names: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!raw_names.iter().any(|n| n.starts_with(UPLOAD_TEMP_PREFIX)));
    }

    #[test]
    fn scoped_opens_confined_subdirectory_and_duplicates_root_when_empty() {
        let outside = TempDir::new();
        fs::write(outside.path().join("outside.txt"), b"outside").unwrap();

        let tmp = TempDir::new();
        let bfs = BrowserFs::open(tmp.path()).unwrap();

        bfs.create_directory_all("tenants/alpha/docs").unwrap();
        bfs.create_directory_all("tenants/beta").unwrap();
        fs::write(tmp.path().join("root_secret.txt"), b"root-only").unwrap();
        fs::write(tmp.path().join("tenants/beta/beta.txt"), b"beta-only").unwrap();
        fs::write(tmp.path().join("tenants/alpha/hello.txt"), b"alpha-v1").unwrap();

        // Empty scope duplicates an independent root descriptor that survives dropping the original
        let root_dup = {
            let temp_root = BrowserFs::open(tmp.path()).unwrap();
            let dup = temp_root.scoped("").unwrap();
            assert_ne!(dup.root_fd.as_raw_fd(), temp_root.root_fd.as_raw_fd());
            dup
        };
        assert_eq!(root_dup.metadata("root_secret.txt").unwrap().size, 9);

        // Scoped subdirectory capability is isolated to `tenants/alpha`
        let alpha_fs = bfs.scoped("tenants//alpha/").unwrap();
        let root_meta = alpha_fs.metadata("").unwrap();
        assert_eq!(root_meta.kind, "directory");
        assert_eq!(root_meta.name, "");
        assert_eq!(root_meta.path, "");

        let entries = alpha_fs.list("").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["docs", "hello.txt"]);

        // Cannot access parent or sibling entries from scoped capability
        assert_eq!(
            alpha_fs.open_file("root_secret.txt").unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            alpha_fs.open_file("beta/beta.txt").unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            alpha_fs.open_file("../beta/beta.txt").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            alpha_fs.scoped("../beta").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );

        // Create and replace inside scoped root affects only the scoped subtree
        let mut up = alpha_fs.begin_upload("docs/guide.md").unwrap();
        up.write_all(b"initial-guide").unwrap();
        up.commit().unwrap();
        assert_eq!(
            fs::read(tmp.path().join("tenants/alpha/docs/guide.md")).unwrap(),
            b"initial-guide"
        );

        let expected = alpha_fs.open_file("hello.txt").unwrap();
        let mut rep = alpha_fs.begin_replace("hello.txt").unwrap();
        rep.write_all(b"alpha-v2").unwrap();
        rep.commit_replace(&expected).unwrap();
        assert_eq!(
            fs::read(tmp.path().join("tenants/alpha/hello.txt")).unwrap(),
            b"alpha-v2"
        );

        // Nested scoping from an already-scoped BrowserFs
        let docs_fs = alpha_fs.scoped("docs").unwrap();
        let docs_list = docs_fs.list("").unwrap();
        assert_eq!(docs_list.len(), 1);
        assert_eq!(docs_list[0].name, "guide.md");
        assert_eq!(docs_list[0].path, "guide.md");

        // Reject missing directories, regular files, and symlinks (leaf or ancestor)
        assert_eq!(
            bfs.scoped("tenants/missing").unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert!(bfs.scoped("tenants/alpha/hello.txt").is_err());

        symlink(outside.path(), tmp.path().join("tenants/alpha/sym_dir")).unwrap();
        assert!(bfs.scoped("tenants/alpha/sym_dir").is_err());
        assert!(bfs.scoped("tenants/alpha/sym_dir/child").is_err());
        assert!(alpha_fs.scoped("sym_dir").is_err());
        assert!(alpha_fs.scoped("sym_dir/child").is_err());
    }

    #[test]
    fn internal_symlink_resolution_supports_nested_directory_and_file_links_with_proven_target_paths()
    {
        let temp_root = TempDir::new();
        let browser = BrowserFs::open(temp_root.path()).unwrap();

        browser
            .create_directory_all("real/albums/2026/live")
            .unwrap();
        browser.create_directory_all("aliases/music").unwrap();
        fs::write(
            temp_root.path().join("real/albums/2026/live/track01.flac"),
            b"lossless-audio-stream",
        )
        .unwrap();
        fs::write(
            temp_root.path().join("real/albums/2026/notes.txt"),
            b"liner-notes",
        )
        .unwrap();

        symlink(
            "../../real/albums/2026",
            temp_root.path().join("aliases/music/year_link"),
        )
        .unwrap();
        symlink(
            "live/track01.flac",
            temp_root.path().join("real/albums/2026/featured.flac"),
        )
        .unwrap();
        symlink(
            "year_link/featured.flac",
            temp_root.path().join("aliases/music/top_pick.flac"),
        )
        .unwrap();

        assert!(browser
            .open_file("aliases/music/top_pick.flac")
            .is_err());
        assert!(browser
            .open_file("aliases/music/year_link/notes.txt")
            .is_err());
        assert!(browser.scoped("aliases/music/year_link").is_err());
        assert!(browser.list("aliases/music/year_link").is_err());

        let mut resolved_file = browser
            .open_file_resolving_internal_links("aliases/music/top_pick.flac")
            .unwrap();
        assert_eq!(
            resolved_file.resolved_path,
            "real/albums/2026/live/track01.flac"
        );
        assert_eq!(resolved_file.entry.name, "track01.flac");
        assert_eq!(
            resolved_file.entry.path,
            "real/albums/2026/live/track01.flac"
        );
        assert_eq!(resolved_file.entry.kind, "file");
        assert_eq!(resolved_file.entry.size, 21);
        let mut payload = Vec::new();
        resolved_file.file.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, b"lossless-audio-stream");

        let resolved_meta = browser
            .metadata_resolving_internal_links("aliases/music/top_pick.flac")
            .unwrap();
        assert!(resolved_meta.was_symlink);
        assert_eq!(
            resolved_meta.resolved_path,
            "real/albums/2026/live/track01.flac"
        );
        assert_eq!(resolved_meta.entry.kind, "file");
        assert_eq!(resolved_meta.entry.size, 21);

        let direct_meta = browser
            .metadata_resolving_internal_links("real/albums/2026/notes.txt")
            .unwrap();
        assert!(!direct_meta.was_symlink);
        assert_eq!(direct_meta.resolved_path, "real/albums/2026/notes.txt");
        assert_eq!(direct_meta.entry.kind, "file");
        let redundant_separator_meta = browser
            .metadata_resolving_internal_links("real//albums/2026/notes.txt")
            .unwrap();
        assert!(!redundant_separator_meta.was_symlink);
        assert_eq!(redundant_separator_meta.resolved_path, direct_meta.resolved_path);

        let resolved_dir = browser
            .scoped_resolving_internal_links("aliases/music/year_link/live")
            .unwrap();
        assert_eq!(resolved_dir.resolved_path, "real/albums/2026/live");
        assert_eq!(resolved_dir.entry.name, "live");
        assert_eq!(resolved_dir.entry.path, "real/albums/2026/live");
        assert_eq!(resolved_dir.entry.kind, "directory");

        let scoped_entries = resolved_dir.fs.list("").unwrap();
        assert_eq!(scoped_entries.len(), 1);
        assert_eq!(scoped_entries[0].name, "track01.flac");
        assert_eq!(scoped_entries[0].path, "track01.flac");

        let (listed_via_link, list_target_path) = browser
            .list_resolving_internal_links("aliases/music/year_link")
            .unwrap();
        assert_eq!(list_target_path, "real/albums/2026");
        let listed_paths: Vec<&str> = listed_via_link
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        assert_eq!(
            listed_paths,
            vec![
                "real/albums/2026/live",
                "real/albums/2026/featured.flac",
                "real/albums/2026/notes.txt",
            ]
        );
    }

    #[test]
    fn internal_symlink_resolution_rejects_escapes_absolute_links_magiclinks_broken_and_loops() {
        let outside_dir = TempDir::new();
        let outside_file = outside_dir.path().join("outside_secret.txt");
        fs::write(&outside_file, b"external-secret").unwrap();

        let temp_root = TempDir::new();
        let browser = BrowserFs::open(temp_root.path()).unwrap();
        browser.create_directory_all("nested/inner").unwrap();
        fs::write(
            temp_root.path().join("nested/inner/internal.txt"),
            b"internal-ok",
        )
        .unwrap();

        symlink(
            &outside_file,
            temp_root.path().join("nested/abs_outside_file"),
        )
        .unwrap();
        symlink(
            outside_dir.path(),
            temp_root.path().join("nested/abs_outside_dir"),
        )
        .unwrap();

        let internal_abs_target = temp_root.path().join("nested/inner/internal.txt");
        symlink(
            &internal_abs_target,
            temp_root.path().join("nested/abs_in_tree_file"),
        )
        .unwrap();
        symlink(
            temp_root.path().join("nested/inner"),
            temp_root.path().join("nested/abs_in_tree_dir"),
        )
        .unwrap();

        symlink(
            "../../../outside_secret.txt",
            temp_root.path().join("nested/inner/rel_escape_file"),
        )
        .unwrap();
        symlink(
            "../../..",
            temp_root.path().join("nested/inner/rel_escape_dir"),
        )
        .unwrap();
        symlink(
            "../../../nested/inner/internal.txt",
            temp_root.path().join("nested/inner/bounce_outside_root"),
        )
        .unwrap();

        symlink("/proc/self/fd/0", temp_root.path().join("nested/magic_fd0")).unwrap();
        symlink(
            "/proc/self/root",
            temp_root.path().join("nested/magic_root"),
        )
        .unwrap();
        symlink(
            "/proc/self/cwd",
            temp_root.path().join("nested/magic_cwd"),
        )
        .unwrap();

        symlink(
            "missing_target.txt",
            temp_root.path().join("nested/broken_leaf"),
        )
        .unwrap();
        symlink(
            "missing_dir/sub",
            temp_root.path().join("nested/broken_dir"),
        )
        .unwrap();

        symlink("loop_b", temp_root.path().join("nested/loop_a")).unwrap();
        symlink("loop_a", temp_root.path().join("nested/loop_b")).unwrap();

        for rejected_file in [
            "nested/abs_outside_file",
            "nested/abs_outside_dir/outside_secret.txt",
            "nested/abs_in_tree_file",
            "nested/abs_in_tree_dir/internal.txt",
            "nested/inner/rel_escape_file",
            "nested/inner/rel_escape_dir/outside_secret.txt",
            "nested/inner/bounce_outside_root",
            "nested/magic_fd0",
            "nested/magic_root/etc/passwd",
            "nested/magic_cwd",
            "nested/broken_leaf",
            "nested/broken_dir/file.txt",
            "nested/loop_a",
            "nested/loop_b",
        ] {
            assert!(
                browser
                    .open_file_resolving_internal_links(rejected_file)
                    .is_err(),
                "open_file_resolving_internal_links must reject {rejected_file}"
            );
            assert!(
                browser
                    .metadata_resolving_internal_links(rejected_file)
                    .is_err(),
                "metadata_resolving_internal_links must reject {rejected_file}"
            );
        }

        for rejected_dir in [
            "nested/abs_outside_dir",
            "nested/abs_in_tree_dir",
            "nested/inner/rel_escape_dir",
            "nested/magic_root",
            "nested/magic_cwd",
            "nested/broken_dir",
            "nested/loop_a",
        ] {
            assert!(
                browser
                    .scoped_resolving_internal_links(rejected_dir)
                    .is_err(),
                "scoped_resolving_internal_links must reject {rejected_dir}"
            );
            assert!(
                browser
                    .list_resolving_internal_links(rejected_dir)
                    .is_err(),
                "list_resolving_internal_links must reject {rejected_dir}"
            );
        }

        assert_eq!(
            browser
                .open_file_resolving_internal_links("nested/broken_leaf")
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            browser
                .open_file_resolving_internal_links("nested/loop_a")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ELOOP)
        );
        assert_eq!(fs::read(&outside_file).unwrap(), b"external-secret");
    }

    #[test]
    fn scoped_capability_preserves_confinement_and_supports_parent_policy_target_authorization() {
        let temp_root = TempDir::new();
        let root_fs = BrowserFs::open(temp_root.path()).unwrap();

        root_fs
            .create_directory_all("tenants/alpha/public")
            .unwrap();
        root_fs
            .create_directory_all("tenants/alpha/private")
            .unwrap();
        root_fs
            .create_directory_all("tenants/beta/shared")
            .unwrap();

        fs::write(
            temp_root.path().join("tenants/alpha/public/readme.txt"),
            b"public-doc",
        )
        .unwrap();
        fs::write(
            temp_root.path().join("tenants/alpha/private/secret.txt"),
            b"alpha-private-secret",
        )
        .unwrap();
        fs::write(
            temp_root.path().join("tenants/beta/shared/beta.txt"),
            b"beta-data",
        )
        .unwrap();

        symlink(
            "../private/secret.txt",
            temp_root
                .path()
                .join("tenants/alpha/public/sneaky_private_link.txt"),
        )
        .unwrap();
        symlink(
            "../../beta/shared/beta.txt",
            temp_root
                .path()
                .join("tenants/alpha/public/cross_tenant_link.txt"),
        )
        .unwrap();

        let alpha_fs = root_fs.scoped("tenants/alpha").unwrap();

        assert!(alpha_fs
            .open_file_resolving_internal_links("public/cross_tenant_link.txt")
            .is_err());

        let resolved_in_alpha = alpha_fs
            .open_file_resolving_internal_links("public/sneaky_private_link.txt")
            .unwrap();
        assert_eq!(resolved_in_alpha.resolved_path, "private/secret.txt");

        let is_allowed_by_mock_policy =
            |candidate_path: &str| !candidate_path.starts_with("private");
        assert!(is_allowed_by_mock_policy("public/sneaky_private_link.txt"));
        assert!(!is_allowed_by_mock_policy(&resolved_in_alpha.resolved_path));

        let public_only_fs = alpha_fs.scoped("public").unwrap();
        assert!(public_only_fs
            .open_file_resolving_internal_links("sneaky_private_link.txt")
            .is_err());
    }

    #[test]
    fn concurrent_symlink_retarget_race_preserves_scope_confinement_and_target_proof() {
        let outside_dir = TempDir::new();
        fs::write(outside_dir.path().join("escape.txt"), b"outside-escape").unwrap();

        let temp_root = TempDir::new();
        let browser = BrowserFs::open(temp_root.path()).unwrap();
        browser.create_directory_all("allowed").unwrap();
        browser.create_directory_all("restricted").unwrap();
        browser.create_directory_all("links").unwrap();

        fs::write(temp_root.path().join("allowed/doc.txt"), b"allowed-payload").unwrap();
        fs::write(
            temp_root.path().join("restricted/secret.txt"),
            b"restricted-payload",
        )
        .unwrap();

        let active_link = temp_root.path().join("links/race_link.txt");
        symlink("../allowed/doc.txt", &active_link).unwrap();

        let stop_flag = std::sync::atomic::AtomicBool::new(false);
        let root_path_clone = temp_root.path().to_path_buf();
        let outside_file_path = outside_dir.path().join("escape.txt");

        std::thread::scope(|scope| {
            let writer_handle = scope.spawn(|| {
                let link_path = root_path_clone.join("links/race_link.txt");
                let staging_link = root_path_clone.join("links/swap_link.tmp");
                let mut iteration = 0usize;
                while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    let target_str = match iteration % 3 {
                        0 => "../allowed/doc.txt".to_string(),
                        1 => "../restricted/secret.txt".to_string(),
                        _ => outside_file_path.to_string_lossy().into_owned(),
                    };
                    let _ = fs::remove_file(&staging_link);
                    if symlink(&target_str, &staging_link).is_ok() {
                        let _ = fs::rename(&staging_link, &link_path);
                    }
                    iteration += 1;
                }
                let _ = fs::remove_file(&staging_link);
            });

            for _ in 0..120 {
                if let Ok(mut resolved) =
                    browser.open_file_resolving_internal_links("links/race_link.txt")
                {
                    let mut data = Vec::new();
                    resolved.file.read_to_end(&mut data).unwrap();
                    assert_ne!(data, b"outside-escape");
                    match resolved.resolved_path.as_str() {
                        "allowed/doc.txt" => assert_eq!(data, b"allowed-payload"),
                        "restricted/secret.txt" => assert_eq!(data, b"restricted-payload"),
                        unexpected => panic!("unexpected resolved_path: {unexpected}"),
                    }
                }
            }

            stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            writer_handle.join().unwrap();
        });
    }

    #[test]
    fn leaf_symlink_rename_and_unlink_operate_on_link_itself_with_zero_quota_and_preserve_targets()
    {
        let outside_dir = TempDir::new();
        let external_target = outside_dir.path().join("external_keep.txt");
        fs::write(&external_target, b"external-untouched").unwrap();

        let temp_root = TempDir::new();
        let browser = BrowserFs::open(temp_root.path()).unwrap();
        browser.create_directory_all("dir_a").unwrap();
        browser.create_directory_all("dir_b").unwrap();

        fs::write(
            temp_root.path().join("dir_a/target.txt"),
            b"internal-target-7777777",
        )
        .unwrap();
        fs::write(temp_root.path().join("dir_b/existing.txt"), b"do-not-clobber").unwrap();

        symlink("target.txt", temp_root.path().join("dir_a/internal_sym")).unwrap();
        symlink(&external_target, temp_root.path().join("dir_a/external_sym")).unwrap();
        symlink(
            "nonexistent.txt",
            temp_root.path().join("dir_a/dangling_sym"),
        )
        .unwrap();
        symlink(outside_dir.path(), temp_root.path().join("dir_a/dir_sym")).unwrap();

        assert_eq!(
            browser
                .rename("dir_a/internal_sym", "dir_b/moved_sym")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            browser
                .remove_with_size("dir_a/internal_sym")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );

        browser
            .rename_allowing_leaf_symlink("dir_a/internal_sym", "dir_b/moved_internal_sym")
            .unwrap();
        assert!(!temp_root
            .path()
            .join("dir_a/internal_sym")
            .symlink_metadata()
            .is_ok());
        assert!(temp_root
            .path()
            .join("dir_b/moved_internal_sym")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(temp_root.path().join("dir_a/target.txt")).unwrap(),
            b"internal-target-7777777"
        );

        assert_eq!(
            browser
                .rename_allowing_leaf_symlink("dir_b/moved_internal_sym", "dir_b/existing.txt")
                .unwrap_err()
                .kind(),
            ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(temp_root.path().join("dir_b/existing.txt")).unwrap(),
            b"do-not-clobber"
        );

        assert!(browser
            .rename_allowing_leaf_symlink("dir_a/dir_sym/external_keep.txt", "dir_b/stolen.txt")
            .is_err());
        assert!(browser
            .rename_allowing_leaf_symlink("dir_b/moved_internal_sym", "dir_a/dir_sym/placed.txt")
            .is_err());
        assert!(browser
            .remove_with_size_allowing_leaf_symlink("dir_a/dir_sym/external_keep.txt")
            .is_err());

        let quota_delta_internal = browser
            .remove_with_size_allowing_leaf_symlink("dir_b/moved_internal_sym")
            .unwrap();
        assert_eq!(quota_delta_internal, 0);
        assert_eq!(
            fs::read(temp_root.path().join("dir_a/target.txt")).unwrap(),
            b"internal-target-7777777"
        );

        let quota_delta_external = browser
            .remove_with_size_allowing_leaf_symlink("dir_a/external_sym")
            .unwrap();
        assert_eq!(quota_delta_external, 0);
        assert_eq!(fs::read(&external_target).unwrap(), b"external-untouched");

        let quota_delta_dangling = browser
            .remove_with_size_allowing_leaf_symlink("dir_a/dangling_sym")
            .unwrap();
        assert_eq!(quota_delta_dangling, 0);

        browser
            .remove_allowing_leaf_symlink("dir_a/dir_sym")
            .unwrap();
        assert!(outside_dir.path().exists());
        assert_eq!(fs::read(&external_target).unwrap(), b"external-untouched");

        browser.create_directory_all("mixed_tree/sub").unwrap();
        fs::write(temp_root.path().join("mixed_tree/file1.bin"), b"12345").unwrap();
        fs::write(
            temp_root.path().join("mixed_tree/sub/file2.bin"),
            b"123456789",
        )
        .unwrap();
        symlink(
            &external_target,
            temp_root.path().join("mixed_tree/sub/ext_link"),
        )
        .unwrap();
        symlink(
            "../file1.bin",
            temp_root.path().join("mixed_tree/sub/int_link"),
        )
        .unwrap();

        let removed_tree_bytes = browser
            .remove_tree_with_size_allowing_symlinks("mixed_tree")
            .unwrap();
        assert_eq!(removed_tree_bytes, 14);
        assert!(!temp_root.path().join("mixed_tree").exists());
        assert_eq!(fs::read(&external_target).unwrap(), b"external-untouched");
    }

    #[test]
    fn replace_file_by_rename_atomically_replaces_verified_target_and_returns_replaced_bytes() {
        let temp_root = TempDir::new();
        let browser = BrowserFs::open(temp_root.path()).unwrap();
        browser.create_directory_all("source").unwrap();
        browser.create_directory_all("target").unwrap();

        fs::write(temp_root.path().join("source/new.txt"), b"replacement-15b").unwrap();
        fs::write(temp_root.path().join("target/old.txt"), b"old-7b!").unwrap();
        fs::write(temp_root.path().join("target/other.txt"), b"other").unwrap();

        let other_handle = browser.open_file("target/other.txt").unwrap();
        assert_eq!(
            browser
                .replace_file_by_rename("source/new.txt", "target/old.txt", &other_handle)
                .unwrap_err()
                .kind(),
            ErrorKind::AlreadyExists
        );
        assert!(temp_root.path().join("source/new.txt").exists());
        assert_eq!(
            fs::read(temp_root.path().join("target/old.txt")).unwrap(),
            b"old-7b!"
        );

        let expected_handle = browser.open_file("target/old.txt").unwrap();
        let replaced_bytes = browser
            .replace_file_by_rename("source/new.txt", "target/old.txt", &expected_handle)
            .unwrap();
        assert_eq!(replaced_bytes, 7);
        assert!(!temp_root.path().join("source/new.txt").exists());
        assert_eq!(
            fs::read(temp_root.path().join("target/old.txt")).unwrap(),
            b"replacement-15b"
        );

        symlink("old.txt", temp_root.path().join("source/sym.txt")).unwrap();
        let current_handle = browser.open_file("target/old.txt").unwrap();
        assert_eq!(
            browser
                .replace_file_by_rename("source/sym.txt", "target/old.txt", &current_handle)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn internal_link_resolution_rejects_fifo_and_hardlinked_targets_via_o_path_without_opening_special_files(
    ) {
        let temp_root = TempDir::new();
        let browser = BrowserFs::open(temp_root.path()).unwrap();
        browser.create_directory_all("dir").unwrap();

        let fifo_path = temp_root.path().join("dir/pipe.fifo");
        let fifo_cstring =
            CString::new(fifo_path.as_os_str().as_bytes()).expect("fifo path should not have NUL");
        let mkfifo_rc = unsafe { libc::mkfifo(fifo_cstring.as_ptr(), 0o600) };
        assert_eq!(mkfifo_rc, 0);

        symlink("pipe.fifo", temp_root.path().join("dir/fifo_link")).unwrap();
        assert_eq!(
            browser
                .metadata_resolving_internal_links("dir/fifo_link")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            browser
                .open_file_resolving_internal_links("dir/fifo_link")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            browser
                .scoped_resolving_internal_links("dir/fifo_link")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );

        let hardlink_source = temp_root.path().join("dir/hard_a.txt");
        let hardlink_alias = temp_root.path().join("dir/hard_b.txt");
        fs::write(&hardlink_source, b"hardlinked-payload").unwrap();
        fs::hard_link(&hardlink_source, &hardlink_alias).unwrap();
        symlink("hard_a.txt", temp_root.path().join("dir/hard_link")).unwrap();

        assert_eq!(
            browser
                .metadata_resolving_internal_links("dir/hard_link")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            browser
                .open_file_resolving_internal_links("dir/hard_link")
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn internal_symlink_resolution_traces_every_intermediate_hop_and_preserves_descendant_carveouts(
    ) {
        let temp_root = TempDir::new();
        let browser = BrowserFs::open(temp_root.path()).unwrap();

        browser.create_directory_all("docs").unwrap();
        browser.create_directory_all("public_dir/sub").unwrap();
        fs::write(temp_root.path().join("public.txt"), b"public-content").unwrap();
        fs::write(
            temp_root.path().join("public_dir/sub/item.txt"),
            b"item-content",
        )
        .unwrap();

        // Multi-hop chain:
        // folder-link -> docs
        // docs/secret-link -> ../public.txt
        // docs/dir-hop -> ../public_dir
        symlink("docs", temp_root.path().join("folder-link")).unwrap();
        symlink("../public.txt", temp_root.path().join("docs/secret-link")).unwrap();
        symlink("../public_dir", temp_root.path().join("docs/dir-hop")).unwrap();

        let expected_file_trace = vec![
            "folder-link/secret-link".to_string(),
            "docs/secret-link".to_string(),
            "public.txt".to_string(),
        ];

        let mut resolved_file = browser
            .open_file_resolving_internal_links("folder-link/secret-link")
            .unwrap();
        assert_eq!(resolved_file.resolved_path, "public.txt");
        assert_eq!(resolved_file.resolution_paths, expected_file_trace);
        let mut content = Vec::new();
        resolved_file.file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"public-content");

        let resolved_meta = browser
            .metadata_resolving_internal_links("folder-link/secret-link")
            .unwrap();
        assert!(resolved_meta.was_symlink);
        assert_eq!(resolved_meta.resolved_path, "public.txt");
        assert_eq!(resolved_meta.resolution_paths, expected_file_trace);

        // Policy simulation: deny `docs/secret-link`, allow `folder-link/**` and `public.txt`.
        // Checking `resolution_paths` catches the denied intermediate hop `docs/secret-link`
        // without requiring read permission on every ordinary parent directory.
        let is_allowed = |candidate: &str| candidate != "docs/secret-link";
        assert!(is_allowed("folder-link/secret-link"));
        assert!(is_allowed(&resolved_file.resolved_path));
        assert!(!resolved_file
            .resolution_paths
            .iter()
            .all(|hop| is_allowed(hop)));

        // Directory chain with trailing descendant:
        // folder-link/dir-hop/sub -> docs/dir-hop/sub -> public_dir/sub
        let expected_dir_trace = vec![
            "folder-link/dir-hop/sub".to_string(),
            "docs/dir-hop/sub".to_string(),
            "public_dir/sub".to_string(),
        ];
        let resolved_dir = browser
            .scoped_resolving_internal_links("folder-link/dir-hop/sub")
            .unwrap();
        assert_eq!(resolved_dir.resolved_path, "public_dir/sub");
        assert_eq!(resolved_dir.resolution_paths, expected_dir_trace);

        let dir_meta = browser
            .metadata_resolving_internal_links("folder-link/dir-hop/sub")
            .unwrap();
        assert!(dir_meta.was_symlink);
        assert_eq!(dir_meta.resolved_path, "public_dir/sub");
        assert_eq!(dir_meta.resolution_paths, expected_dir_trace);

        let traced_listing = browser
            .list_with_trace_resolving_internal_links("folder-link/dir-hop/sub")
            .unwrap();
        assert_eq!(traced_listing.resolved_path, "public_dir/sub");
        assert_eq!(traced_listing.resolution_paths, expected_dir_trace);
        assert_eq!(traced_listing.entries.len(), 1);
        assert_eq!(traced_listing.entries[0].path, "public_dir/sub/item.txt");

        let (tuple_entries, tuple_resolved) = browser
            .list_resolving_internal_links("folder-link/dir-hop/sub")
            .unwrap();
        assert_eq!(tuple_resolved, "public_dir/sub");
        assert_eq!(tuple_entries, traced_listing.entries);

        // Direct non-symlink access has empty resolution_paths (ordinary parent directories are not added)
        let direct_file = browser
            .open_file_resolving_internal_links("public_dir/sub/item.txt")
            .unwrap();
        assert_eq!(direct_file.resolved_path, "public_dir/sub/item.txt");
        assert!(direct_file.resolution_paths.is_empty());

        let direct_meta = browser
            .metadata_resolving_internal_links("public_dir/sub/item.txt")
            .unwrap();
        assert!(!direct_meta.was_symlink);
        assert_eq!(direct_meta.resolved_path, "public_dir/sub/item.txt");
        assert!(direct_meta.resolution_paths.is_empty());

        // Regression 1: `deep-link -> real/sub`, `entry-link -> deep-link/../target.txt`
        // Must resolve `real/target.txt`, never record phantom root `target.txt`, and still
        // record `deep-link` so denying `deep-link` blocks traversal.
        browser.create_directory_all("real/sub").unwrap();
        fs::write(temp_root.path().join("real/target.txt"), b"real-target").unwrap();
        symlink("real/sub", temp_root.path().join("deep-link")).unwrap();
        symlink(
            "deep-link/../target.txt",
            temp_root.path().join("entry-link"),
        )
        .unwrap();

        let mut deep1 = browser
            .open_file_resolving_internal_links("entry-link")
            .unwrap();
        assert_eq!(deep1.resolved_path, "real/target.txt");
        assert!(!deep1
            .resolution_paths
            .iter()
            .any(|p| p == "target.txt" || p.contains("..")));
        assert_eq!(
            deep1.resolution_paths,
            vec![
                "entry-link".to_string(),
                "deep-link".to_string(),
                "real/target.txt".to_string(),
            ]
        );
        let mut deep1_bytes = Vec::new();
        deep1.file.read_to_end(&mut deep1_bytes).unwrap();
        assert_eq!(deep1_bytes, b"real-target");

        let deep1_meta = browser
            .metadata_resolving_internal_links("entry-link")
            .unwrap();
        assert_eq!(deep1_meta.resolved_path, "real/target.txt");
        assert_eq!(deep1_meta.resolution_paths, deep1.resolution_paths);

        // Regression 2: `deep-link-2 -> a/b/c`, `entry-link-2 -> deep-link-2/../../file.txt`
        // Must succeed (not fail with false outside-root error) and resolve `a/file.txt`.
        browser.create_directory_all("a/b/c").unwrap();
        fs::write(temp_root.path().join("a/file.txt"), b"a-file").unwrap();
        symlink("a/b/c", temp_root.path().join("deep-link-2")).unwrap();
        symlink(
            "deep-link-2/../../file.txt",
            temp_root.path().join("entry-link-2"),
        )
        .unwrap();

        let mut deep2 = browser
            .open_file_resolving_internal_links("entry-link-2")
            .unwrap();
        assert_eq!(deep2.resolved_path, "a/file.txt");
        assert!(!deep2.resolution_paths.iter().any(|p| p.contains("..")));
        assert_eq!(
            deep2.resolution_paths,
            vec![
                "entry-link-2".to_string(),
                "deep-link-2".to_string(),
                "a/file.txt".to_string(),
            ]
        );
        let mut deep2_bytes = Vec::new();
        deep2.file.read_to_end(&mut deep2_bytes).unwrap();
        assert_eq!(deep2_bytes, b"a-file");

        let deep2_meta = browser
            .metadata_resolving_internal_links("entry-link-2")
            .unwrap();
        assert_eq!(deep2_meta.resolved_path, "a/file.txt");
        assert_eq!(deep2_meta.resolution_paths, deep2.resolution_paths);
    }
}
