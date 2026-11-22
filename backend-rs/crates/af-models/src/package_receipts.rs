//! Shared root-aware discovery and validation for package installation receipts.
//!
//! Canonical installation receipts live at the configured `package.lock_file`
//! (typically `/install/.<pkg>.lock`) rebased under the active filesystem root.
//! Legacy Swizzin receipts (`/etc/Swizzin/.<pkg>.lock`) are treated strictly as
//! upgrade/migration input rather than authoritative live installation state.

use std::env;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};

/// Maximum receipt file size read when extracting metadata such as legacy ports.
pub const MAX_PACKAGE_RECEIPT_BYTES: usize = 64 * 1024;

/// Resolves the canonical package lockfile stem for supported legacy aliases.
pub fn resolve_package_lock_name(pkg_id: &str) -> &str {
    let trimmed = pkg_id.trim();
    match trimmed {
        "autodl" => "autodlirssi",
        "transmission-daemon" => "transmission",
        _ => trimmed,
    }
}

/// Resolves the active isolated filesystem root, honoring an explicit root first,
/// then `AETHERFLOW_FS_ROOT`, then `AETHERFLOW_INSTALL_ROOT`.
pub fn resolve_package_fs_root(explicit_root: Option<&Path>) -> Option<PathBuf> {
    if let Some(root) = explicit_root {
        let raw = root.to_string_lossy();
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed != "/" {
            return Some(PathBuf::from(trimmed));
        }
        return None;
    }

    for env_key in ["AETHERFLOW_FS_ROOT", "AETHERFLOW_INSTALL_ROOT"] {
        if let Ok(value) = env::var(env_key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() && trimmed != "/" {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    None
}

/// Rebases a logical or already-rooted filesystem path under `fs_root` without
/// double-prefixing paths that are already rooted under `fs_root`.
pub fn resolve_path_for_fs_root(path_str: &str, fs_root: Option<&Path>) -> PathBuf {
    let trimmed = path_str.trim();
    if trimmed.is_empty() {
        return PathBuf::new();
    }
    if let Some(root) = fs_root {
        let raw = Path::new(trimmed);
        if raw.starts_with(root) {
            return raw.to_path_buf();
        }
        let rel = trimmed.trim_start_matches(['/', '\\']);
        return root.join(rel);
    }
    PathBuf::from(trimmed)
}

/// Resolved canonical, retained-removal, and optional legacy Swizzin receipt
/// paths for a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageLockPaths {
    pub canonical: PathBuf,
    pub retained: PathBuf,
    pub legacy_swizzin: Option<PathBuf>,
}

/// Derives the companion retained-removal receipt path alongside a canonical
/// installation lock (e.g. `/install/.rclone.lock` -> `/install/.rclone.retained`).
pub fn retained_receipt_path_for_canonical(canonical: &Path) -> PathBuf {
    if canonical.as_os_str().is_empty() {
        return PathBuf::new();
    }
    let Some(file_name) = canonical.file_name().and_then(|name| name.to_str()) else {
        return PathBuf::new();
    };
    let retained_name = match file_name.strip_suffix(".lock") {
        Some(stem) if !stem.is_empty() => format!("{stem}.retained"),
        _ => format!("{file_name}.retained"),
    };
    canonical.with_file_name(retained_name)
}

/// Formats the canonical retained-removal receipt payload written after an
/// ordinary (non-purge) removal that preserves managed configuration/data.
pub fn format_retained_package_receipt(pkg_id: &str, updated_at: &str) -> String {
    let pkg = pkg_id.trim().to_ascii_lowercase();
    let ts = updated_at.trim();
    if ts.is_empty() {
        format!("package={pkg}\nstate=retained\n")
    } else {
        format!("package={pkg}\nstate=retained\nupdated_at={ts}\n")
    }
}

fn legacy_swizzin_filename_for_canonical(
    canonical: &Path,
    fs_root: Option<&Path>,
) -> Option<String> {
    let expected_install_dir = resolve_path_for_fs_root("/install", fs_root);
    if canonical.parent() != Some(expected_install_dir.as_path()) {
        return None;
    }
    let file_name = canonical.file_name()?.to_str()?;
    let stem = file_name.strip_prefix('.')?.strip_suffix(".lock")?;
    if stem.is_empty() || stem.contains('/') || stem.contains('\\') {
        return None;
    }
    Some(file_name.to_string())
}

/// Resolves the canonical lockfile path, its companion retained-removal receipt
/// path, and (when the canonical lock uses the standard `/install/.<pkg>.lock`
/// layout) the matching legacy `/etc/Swizzin` upgrade-input receipt path.
///
/// Explicit custom catalog lock paths outside `/install/` are preserved as-is
/// without synthesizing a `/etc/Swizzin` fallback.
pub fn resolve_package_lock_paths(
    pkg_id: &str,
    explicit_lock_file: Option<&str>,
    explicit_root: Option<&Path>,
) -> PackageLockPaths {
    let fs_root = resolve_package_fs_root(explicit_root);
    let canonical = match explicit_lock_file.map(str::trim).filter(|s| !s.is_empty()) {
        Some(lock_file) => resolve_path_for_fs_root(lock_file, fs_root.as_deref()),
        None => {
            let lock_name = resolve_package_lock_name(pkg_id);
            resolve_path_for_fs_root(&format!("/install/.{lock_name}.lock"), fs_root.as_deref())
        }
    };
    let retained = retained_receipt_path_for_canonical(&canonical);

    let legacy_swizzin =
        legacy_swizzin_filename_for_canonical(&canonical, fs_root.as_deref()).map(|file_name| {
            resolve_path_for_fs_root(&format!("/etc/Swizzin/{file_name}"), fs_root.as_deref())
        });

    PackageLockPaths {
        canonical,
        retained,
        legacy_swizzin,
    }
}

fn check_ancestor_dir(ancestor: &Path, leaf_path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(ancestor) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "installation lock ancestor is not a regular directory (symlink): {}",
            ancestor.display()
        )),
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(format!(
            "installation lock ancestor is not a directory: {}",
            ancestor.display()
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "cannot inspect installation lock {}: {}",
            leaf_path.display(),
            err
        )),
    }
}

/// Validates that `path` and its managed ancestors are free of symlinks and
/// non-regular lock types. Returns `Ok(true)` iff `path` exists as a regular
/// non-symlink file, `Ok(false)` when absent, and `Err(...)` for unsafe lock
/// types or I/O inspection failures.
pub fn inspect_receipt_file(path: &Path, fs_root: Option<&Path>) -> Result<bool, String> {
    if path.as_os_str().is_empty() {
        return Ok(false);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "installation lock path contains forbidden parent traversal: {}",
            path.display()
        ));
    }

    if fs_root.is_some_and(|root| !path.starts_with(root)) {
        return Err(format!(
            "installation lock is outside the filesystem root: {}",
            path.display()
        ));
    }
    let ancestors: Vec<_> = path
        .ancestors()
        .skip(1)
        .filter(|parent| !parent.as_os_str().is_empty())
        .collect();
    for ancestor in ancestors.into_iter().rev() {
        if !check_ancestor_dir(ancestor, path)? {
            return Ok(false);
        }
    }

    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "installation lock is not a regular file (symlink): {}",
            path.display()
        )),
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(format!(
            "installation lock is not a regular file: {}",
            path.display()
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "cannot inspect installation lock {}: {}",
            path.display(),
            err
        )),
    }
}

/// Validates a retained-removal receipt file for `pkg_id`, enforcing symlink,
/// confinement, regular-file, bounded-read, and package-ownership invariants.
/// Returns `Ok(true)` iff the file exists and proves retained ownership for
/// `pkg_id`, `Ok(false)` when absent, and `Err(...)` for unsafe or mismatched
/// retained receipt files.
pub fn inspect_retained_receipt_file(
    path: &Path,
    pkg_id: &str,
    fs_root: Option<&Path>,
) -> Result<bool, String> {
    let Some(raw) = read_receipt_file_bounded(path, fs_root, MAX_PACKAGE_RECEIPT_BYTES)? else {
        return Ok(false);
    };

    let expected_pkg = pkg_id.trim().to_ascii_lowercase();
    let expected_lock = resolve_package_lock_name(pkg_id).to_ascii_lowercase();
    if expected_pkg.is_empty() {
        return Err(format!(
            "cannot validate retained package receipt {} without package id",
            path.display()
        ));
    }

    let mut seen_pkg: Option<String> = None;
    let mut seen_state: Option<String> = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            return Err(format!(
                "retained package receipt {} contains malformed line",
                path.display()
            ));
        };
        let key = lhs.trim();
        let value = rhs.trim().trim_matches('"').trim_matches('\'').trim();
        match key {
            "package" => {
                if seen_pkg.is_some() {
                    return Err(format!(
                        "retained package receipt {} declares duplicate package field",
                        path.display()
                    ));
                }
                seen_pkg = Some(value.to_ascii_lowercase());
            }
            "state" => {
                if seen_state.is_some() {
                    return Err(format!(
                        "retained package receipt {} declares duplicate state field",
                        path.display()
                    ));
                }
                seen_state = Some(value.to_ascii_lowercase());
            }
            _ => {}
        }
    }

    let Some(actual_pkg) = seen_pkg else {
        return Err(format!(
            "retained package receipt {} is missing package ownership metadata",
            path.display()
        ));
    };
    if actual_pkg != expected_pkg && actual_pkg != expected_lock {
        return Err(format!(
            "retained package receipt {} belongs to package '{}', not '{}'",
            path.display(),
            actual_pkg,
            expected_pkg
        ));
    }
    if seen_state.as_deref() != Some("retained") {
        return Err(format!(
            "retained package receipt {} has unexpected state (expected 'retained')",
            path.display()
        ));
    }
    Ok(true)
}

/// Inspected canonical, retained-removal, and legacy receipt status for a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageReceiptStatus {
    pub canonical_path: PathBuf,
    pub retained_path: PathBuf,
    pub legacy_path: Option<PathBuf>,
    pub canonical_installed: bool,
    pub retained_receipt_present: bool,
    pub legacy_receipt_present: bool,
}

impl PackageReceiptStatus {
    /// Returns `true` iff the authoritative canonical installation receipt is present.
    pub fn is_installed(&self) -> bool {
        self.canonical_installed
    }

    /// Returns `true` iff only a legacy `/etc/Swizzin` upgrade-input receipt exists.
    pub fn has_legacy_upgrade_receipt(&self) -> bool {
        !self.canonical_installed && self.legacy_receipt_present
    }

    /// Returns `true` iff either the canonical receipt or a legacy receipt exists.
    pub fn has_any_receipt(&self) -> bool {
        self.canonical_installed || self.legacy_receipt_present
    }

    /// Returns `true` iff a verified AetherFlow retained-removal receipt is present.
    pub fn has_retained_receipt(&self) -> bool {
        self.retained_receipt_present
    }

    /// Returns `true` iff no active or legacy install receipt exists, but a verified
    /// retained-removal receipt is present.
    pub fn is_retained_only(&self) -> bool {
        !self.has_any_receipt() && self.retained_receipt_present
    }
}

/// Inspects only the canonical installation receipt for a package.
///
/// When `explicit_lock_file` is `Some("")` (an explicit empty catalog lock),
/// returns `Ok(false)` rather than synthesizing a `/install` path.
pub fn inspect_canonical_package_receipt(
    pkg_id: &str,
    explicit_lock_file: Option<&str>,
    explicit_root: Option<&Path>,
) -> Result<bool, String> {
    if let Some(raw) = explicit_lock_file {
        if raw.trim().is_empty() {
            return Ok(false);
        }
    }
    let fs_root = resolve_package_fs_root(explicit_root);
    let paths = resolve_package_lock_paths(pkg_id, explicit_lock_file, explicit_root);
    inspect_receipt_file(&paths.canonical, fs_root.as_deref())
}

/// Inspects canonical, retained-removal, and (when applicable) legacy
/// `/etc/Swizzin` receipts for a package, rejecting unsafe lock types or
/// mismatched retained ownership on any path.
pub fn inspect_package_receipts(
    pkg_id: &str,
    explicit_lock_file: Option<&str>,
    explicit_root: Option<&Path>,
) -> Result<PackageReceiptStatus, String> {
    let fs_root = resolve_package_fs_root(explicit_root);
    if let Some(raw) = explicit_lock_file {
        if raw.trim().is_empty() {
            return Ok(PackageReceiptStatus {
                canonical_path: PathBuf::new(),
                retained_path: PathBuf::new(),
                legacy_path: None,
                canonical_installed: false,
                retained_receipt_present: false,
                legacy_receipt_present: false,
            });
        }
    }

    let paths = resolve_package_lock_paths(pkg_id, explicit_lock_file, explicit_root);
    let canonical_installed = inspect_receipt_file(&paths.canonical, fs_root.as_deref())?;
    let retained_receipt_present =
        inspect_retained_receipt_file(&paths.retained, pkg_id, fs_root.as_deref())?;
    let legacy_receipt_present = match &paths.legacy_swizzin {
        Some(legacy_path) => inspect_receipt_file(legacy_path, fs_root.as_deref())?,
        None => false,
    };

    Ok(PackageReceiptStatus {
        canonical_path: paths.canonical,
        retained_path: paths.retained,
        legacy_path: paths.legacy_swizzin,
        canonical_installed,
        retained_receipt_present,
        legacy_receipt_present,
    })
}

/// Safely reads a bounded regular receipt file without following symlinks or
/// opening non-regular files (such as FIFOs or directories).
pub fn read_receipt_file_bounded(
    path: &Path,
    fs_root: Option<&Path>,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    if !inspect_receipt_file(path, fs_root)? {
        return Ok(None);
    }
    let lstat = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "cannot inspect installation lock {}: {}",
            path.display(),
            err
        )
    })?;
    if lstat.file_type().is_symlink() || !lstat.is_file() {
        return Err(format!(
            "installation lock is not a regular file: {}",
            path.display()
        ));
    }
    if lstat.len() > max_bytes as u64 {
        return Err(format!(
            "installation lock {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|err| format!("cannot open installation lock {}: {}", path.display(), err))?;
    let fstat = file
        .metadata()
        .map_err(|err| format!("cannot stat installation lock {}: {}", path.display(), err))?;
    if !fstat.is_file() {
        return Err(format!(
            "installation lock is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fstat.dev() != lstat.dev() || fstat.ino() != lstat.ino() {
            return Err(format!(
                "installation lock changed while reading: {}",
                path.display()
            ));
        }
    }
    if fstat.len() > max_bytes as u64 {
        return Err(format!(
            "installation lock {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    let mut buf = Vec::new();
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|err| format!("cannot read installation lock {}: {}", path.display(), err))?;
    if buf.len() > max_bytes {
        return Err(format!(
            "installation lock {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Parses a configured application port (`1024..=65535`) from a receipt file's text.
pub fn parse_port_from_receipt_content(raw: &str) -> Option<i32> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Ok(p) = trimmed.parse::<i32>() {
            if (1024..=65535).contains(&p) {
                return Some(p);
            }
        }
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let key = lhs.trim();
            if matches!(
                key,
                "PORT" | "AF_APP_PORT" | "AETHERFLOW_APP_PORT" | "listen_port" | "port"
            ) {
                let clean_rhs = rhs.trim().trim_matches('"').trim_matches('\'').trim();
                if let Ok(p) = clean_rhs.parse::<i32>() {
                    if (1024..=65535).contains(&p) {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Reads a port hint from the canonical receipt first, falling back to a legacy
/// `/etc/Swizzin` upgrade receipt when present. Rejects unsafe lock types.
pub fn read_package_receipt_port(
    pkg_id: &str,
    explicit_lock_file: Option<&str>,
    explicit_root: Option<&Path>,
) -> Result<Option<i32>, String> {
    let fs_root = resolve_package_fs_root(explicit_root);
    let status = inspect_package_receipts(pkg_id, explicit_lock_file, explicit_root)?;
    if status.canonical_installed {
        if let Some(raw) = read_receipt_file_bounded(
            &status.canonical_path,
            fs_root.as_deref(),
            MAX_PACKAGE_RECEIPT_BYTES,
        )? {
            if let Some(port) = parse_port_from_receipt_content(&raw) {
                return Ok(Some(port));
            }
        }
    }
    if status.legacy_receipt_present {
        if let Some(ref legacy_path) = status.legacy_path {
            if let Some(raw) = read_receipt_file_bounded(
                legacy_path,
                fs_root.as_deref(),
                MAX_PACKAGE_RECEIPT_BYTES,
            )? {
                if let Some(port) = parse_port_from_receipt_content(&raw) {
                    return Ok(Some(port));
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_root(label: &str) -> PathBuf {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("af-receipts-{label}-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn canonical_aliases_and_explicit_catalog_locks_resolve_coherently() {
        let root = temp_root("aliases");
        let autodl = resolve_package_lock_paths("autodl", None, Some(&root));
        assert_eq!(autodl.canonical, root.join("install/.autodlirssi.lock"));
        assert_eq!(
            autodl.legacy_swizzin,
            Some(root.join("etc/Swizzin/.autodlirssi.lock"))
        );

        let transmission = resolve_package_lock_paths("transmission-daemon", None, Some(&root));
        assert_eq!(
            transmission.canonical,
            root.join("install/.transmission.lock")
        );
        assert_eq!(
            transmission.legacy_swizzin,
            Some(root.join("etc/Swizzin/.transmission.lock"))
        );

        // Explicit non-/install catalog lock is preserved without synthesizing /etc/Swizzin
        let custom = resolve_package_lock_paths(
            "sonarr",
            Some("/custom/locks/.sonarr.receipt"),
            Some(&root),
        );
        assert_eq!(custom.canonical, root.join("custom/locks/.sonarr.receipt"));
        assert_eq!(custom.legacy_swizzin, None);

        // Already-rooted canonical lock is not double-prefixed
        let already_rooted = root.join("install/.sonarr.lock");
        let rooted_str = already_rooted.to_string_lossy().into_owned();
        let resolved = resolve_package_lock_paths("sonarr", Some(&rooted_str), Some(&root));
        assert_eq!(resolved.canonical, already_rooted);
        assert_eq!(
            resolved.legacy_swizzin,
            Some(root.join("etc/Swizzin/.sonarr.lock"))
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_swizzin_receipt_is_upgrade_input_not_canonical_install() {
        let root = temp_root("legacy-upgrade");
        let swizzin = root.join("etc/Swizzin");
        fs::create_dir_all(&swizzin).unwrap();
        fs::write(swizzin.join(".sonarr.lock"), b"PORT=18989\n").unwrap();

        assert!(!inspect_canonical_package_receipt(
            "sonarr",
            Some("/install/.sonarr.lock"),
            Some(&root)
        )
        .unwrap());
        let status =
            inspect_package_receipts("sonarr", Some("/install/.sonarr.lock"), Some(&root)).unwrap();
        assert!(!status.is_installed());
        assert!(status.has_legacy_upgrade_receipt());
        assert!(status.has_any_receipt());
        assert_eq!(
            read_package_receipt_port("sonarr", Some("/install/.sonarr.lock"), Some(&root))
                .unwrap(),
            Some(18989)
        );

        // Once canonical lock exists, canonical takes precedence for installed state & port
        fs::create_dir_all(root.join("install")).unwrap();
        fs::write(root.join("install/.sonarr.lock"), b"PORT=19001\n").unwrap();
        let canonical =
            inspect_package_receipts("sonarr", Some("/install/.sonarr.lock"), Some(&root)).unwrap();
        assert!(canonical.is_installed());
        assert!(!canonical.has_legacy_upgrade_receipt());
        assert_eq!(
            read_package_receipt_port("sonarr", Some("/install/.sonarr.lock"), Some(&root))
                .unwrap(),
            Some(19001)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_lock_types_and_symlink_ancestors_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = temp_root("unsafe");
        fs::create_dir_all(root.join("install")).unwrap();
        fs::create_dir_all(root.join("etc/Swizzin")).unwrap();

        let outside = root.join("outside.txt");
        fs::write(&outside, b"PORT=18989\n").unwrap();

        // Symlink canonical lock rejected
        let sym_canonical = root.join("install/.sonarr.lock");
        symlink(&outside, &sym_canonical).unwrap();
        let err =
            inspect_canonical_package_receipt("sonarr", Some("/install/.sonarr.lock"), Some(&root))
                .unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        fs::remove_file(&sym_canonical).unwrap();

        // Directory canonical lock rejected
        fs::create_dir(&sym_canonical).unwrap();
        let err =
            inspect_canonical_package_receipt("sonarr", Some("/install/.sonarr.lock"), Some(&root))
                .unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        fs::remove_dir(&sym_canonical).unwrap();

        // Symlink legacy lock rejected
        let sym_legacy = root.join("etc/Swizzin/.sonarr.lock");
        symlink(&outside, &sym_legacy).unwrap();
        assert!(
            inspect_package_receipts("sonarr", Some("/install/.sonarr.lock"), Some(&root)).is_err()
        );
        assert!(
            read_package_receipt_port("sonarr", Some("/install/.sonarr.lock"), Some(&root))
                .is_err()
        );
        fs::remove_file(&sym_legacy).unwrap();

        // Symlinked /etc/Swizzin directory rejected
        fs::remove_dir(root.join("etc/Swizzin")).unwrap();
        let decoy_dir = root.join("decoy-swizzin");
        fs::create_dir_all(&decoy_dir).unwrap();
        fs::write(decoy_dir.join(".sonarr.lock"), b"PORT=18989\n").unwrap();
        symlink(&decoy_dir, root.join("etc/Swizzin")).unwrap();
        let err = inspect_package_receipts("sonarr", Some("/install/.sonarr.lock"), Some(&root))
            .unwrap_err();
        assert!(err.contains("symlink"), "{err}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_explicit_lock_and_parent_traversal_are_handled_safely() {
        let root = temp_root("empty-and-traversal");
        assert!(!inspect_canonical_package_receipt("sonarr", Some(""), Some(&root)).unwrap());
        let status = inspect_package_receipts("sonarr", Some(""), Some(&root)).unwrap();
        assert!(!status.is_installed());
        assert!(!status.has_any_receipt());

        let traversal_err = inspect_canonical_package_receipt(
            "sonarr",
            Some("/install/../../etc/passwd"),
            Some(&root),
        )
        .unwrap_err();
        assert!(
            traversal_err.contains("parent traversal"),
            "{traversal_err}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn retained_receipt_paths_and_ownership_validation_work_and_fail_closed() {
        let root = temp_root("retained");
        let rclone = resolve_package_lock_paths("rclone", None, Some(&root));
        assert_eq!(rclone.canonical, root.join("install/.rclone.lock"));
        assert_eq!(rclone.retained, root.join("install/.rclone.retained"));

        let custom = resolve_package_lock_paths(
            "sonarr",
            Some("/custom/locks/.sonarr.receipt"),
            Some(&root),
        );
        assert_eq!(
            custom.retained,
            root.join("custom/locks/.sonarr.receipt.retained")
        );

        let install_dir = root.join("install");
        fs::create_dir_all(&install_dir).unwrap();
        let payload = format_retained_package_receipt("rclone", "2026-11-22T00:00:00Z");
        fs::write(&rclone.retained, payload).unwrap();

        let status =
            inspect_package_receipts("rclone", Some("/install/.rclone.lock"), Some(&root)).unwrap();
        assert!(!status.is_installed());
        assert!(!status.has_any_receipt());
        assert!(status.has_retained_receipt());
        assert!(status.is_retained_only());

        // Alias lock stem is accepted (e.g. Bash writing lock stem autodlirssi for autodl)
        let autodl = resolve_package_lock_paths("autodl", None, Some(&root));
        fs::write(
            &autodl.retained,
            format_retained_package_receipt("autodlirssi", "2026-11-22T00:00:00Z"),
        )
        .unwrap();
        let autodl_status = inspect_package_receipts("autodl", None, Some(&root)).unwrap();
        assert!(autodl_status.is_retained_only());

        // Mismatched package ownership fails closed
        fs::write(
            &rclone.retained,
            format_retained_package_receipt("sonarr", "2026-11-22T00:00:00Z"),
        )
        .unwrap();
        let err = inspect_package_receipts("rclone", Some("/install/.rclone.lock"), Some(&root))
            .unwrap_err();
        assert!(err.contains("belongs to package 'sonarr'"), "{err}");

        // Unexpected state fails closed
        fs::write(&rclone.retained, "package=rclone\nstate=purged\n").unwrap();
        let err = inspect_package_receipts("rclone", Some("/install/.rclone.lock"), Some(&root))
            .unwrap_err();
        assert!(err.contains("unexpected state"), "{err}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            fs::remove_file(&rclone.retained).unwrap();
            let outside = root.join("outside-retained");
            fs::write(
                &outside,
                format_retained_package_receipt("rclone", "2026-11-22T00:00:00Z"),
            )
            .unwrap();
            symlink(&outside, &rclone.retained).unwrap();
            let err =
                inspect_package_receipts("rclone", Some("/install/.rclone.lock"), Some(&root))
                    .unwrap_err();
            assert!(err.contains("not a regular file"), "{err}");
        }

        let _ = fs::remove_dir_all(&root);
    }
}
