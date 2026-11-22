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

mod dir_ops;
mod internal_links;
mod mutation;
mod path;
mod syscall;
mod types;
mod upload;

#[cfg(test)]
mod tests;

pub use types::{
    Entry, RemovalError, ResolvedDir, ResolvedDirListing, ResolvedEntry, ResolvedFile,
};
pub use upload::PendingUpload;

use crate::path::parse_relative_path;
use crate::syscall::{fstat_fd, openat_no_symlinks, sync_dir};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Debug)]
pub struct BrowserFs {
    pub(crate) root_fd: OwnedFd,
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

    /// Inspect a leaf without reading its contents or following a symlink.
    pub fn entry_metadata(&self, path: &str) -> io::Result<std::fs::Metadata> {
        let (parent, leaf) = self.resolve_parent_and_leaf(path)?;
        let fd = openat_no_symlinks(
            parent.as_raw_fd(),
            leaf.as_c_str(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        File::from(fd).metadata()
    }

    pub fn sync_directory(&self) -> io::Result<()> {
        sync_dir(self.root_fd.as_raw_fd())
    }

    pub(crate) fn open_dir_components(&self, components: &[&str]) -> io::Result<OwnedFd> {
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let mut current = openat_no_symlinks(self.root_fd.as_raw_fd(), c".", flags, 0)?;
        for &comp in components {
            let c_comp = CString::new(comp)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
            current = openat_no_symlinks(current.as_raw_fd(), c_comp.as_c_str(), flags, 0)?;
        }
        Ok(current)
    }

    pub(crate) fn resolve_parent_and_leaf(&self, path: &str) -> io::Result<(OwnedFd, CString)> {
        let components = parse_relative_path(path, false)?;
        let (leaf_str, parent_components) = components
            .split_last()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "root path not allowed"))?;
        let parent_fd = self.open_dir_components(parent_components)?;
        let leaf = CString::new(*leaf_str)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
        Ok((parent_fd, leaf))
    }
}
