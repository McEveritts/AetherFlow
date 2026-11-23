use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeFilter {
    None,
    Plex,
    MediaServer,
    Nextcloud,
    Paperless,
    Calibre,
}

impl RuntimeFilter {
    pub(super) fn for_target(package: &str, target: &Path, root: Option<&Path>) -> Self {
        let logical = target
            .strip_prefix(root.unwrap_or(Path::new("/")))
            .unwrap_or(target)
            .to_str();
        match (package, logical) {
            ("plex", Some("var/lib/plexmediaserver")) => Self::Plex,
            ("jellyfin", Some("var/lib/jellyfin"))
            | ("emby", Some("var/lib/emby" | "var/lib/emby-server")) => Self::MediaServer,
            ("nextcloud", Some("var/www/nextcloud" | "var/www/html/nextcloud")) => Self::Nextcloud,
            ("paperless-ngx", Some("var/lib/paperless")) => Self::Paperless,
            ("calibreweb", Some("var/lib/calibre-library")) => Self::Calibre,
            _ => Self::None,
        }
    }

    pub(super) fn excludes(self, relative: &Path, meta: &std::fs::Metadata) -> bool {
        let name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        match self {
            Self::None => false,
            Self::Plex => {
                relative.parent()
                    == Some(Path::new("Library/Application Support/Plex Media Server"))
                    && matches!(
                        name,
                        "Cache"
                            | "Media"
                            | "Metadata"
                            | "Codecs"
                            | "Crash Reports"
                            | "Diagnostics"
                            | "Logs"
                            | "Updates"
                    )
            }
            Self::MediaServer => matches!(
                name.to_ascii_lowercase().as_str(),
                "cache" | "transcodes" | "metadata" | "log" | "logs"
            ),
            Self::Nextcloud => {
                relative.components().count() == 1
                    && (name == "data" || name.starts_with("updater-"))
            }
            Self::Paperless => {
                relative == Path::new("media") || relative == Path::new("data/index")
            }
            Self::Calibre => {
                !meta.is_dir()
                    && !is_receipt_file_name(name)
                    && !matches!(
                        relative
                            .extension()
                            .and_then(|ext| ext.to_str())
                            .map(str::to_ascii_lowercase)
                            .as_deref(),
                        Some(
                            "db" | "db-wal"
                                | "db-shm"
                                | "json"
                                | "conf"
                                | "ini"
                                | "yaml"
                                | "yml"
                                | "toml"
                                | "cfg"
                        )
                    )
            }
        }
    }
}

pub(crate) const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const SNAPSHOT_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn configured_max_snapshot_bytes() -> Result<u64, String> {
    std::env::var("AETHERFLOW_MAX_SNAPSHOT_BYTES")
        .ok()
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|_| "Invalid AETHERFLOW_MAX_SNAPSHOT_BYTES".to_owned())
        })
        .transpose()
        .map(|opt| opt.unwrap_or(DEFAULT_MAX_SNAPSHOT_BYTES))
}

pub(crate) fn snapshot_filesystem_capacity(path: &Path) -> Result<(u64, u64), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mut check_path = path.to_path_buf();
        while std::fs::symlink_metadata(&check_path).is_err() {
            let Some(parent) = check_path.parent() else {
                break;
            };
            if parent.as_os_str().is_empty() {
                break;
            }
            check_path = parent.to_path_buf();
        }
        let dev = std::fs::metadata(&check_path)
            .map(|meta| meta.dev())
            .map_err(|err| {
                format!(
                    "Cannot inspect snapshot staging filesystem {}: {err}",
                    check_path.display()
                )
            })?;
        let c_path = std::ffi::CString::new(check_path.as_os_str().as_bytes())
            .map_err(|err| err.to_string())?;
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } != 0 {
            return Err(format!(
                "Cannot check snapshot staging filesystem: {}",
                std::io::Error::last_os_error()
            ));
        }
        #[allow(clippy::unnecessary_cast)]
        let block_size = if vfs.f_frsize > 0 {
            vfs.f_frsize as u64
        } else {
            vfs.f_bsize as u64
        };
        #[allow(clippy::unnecessary_cast)]
        let available = (vfs.f_bavail as u64).saturating_mul(block_size);
        #[cfg(test)]
        let available = if std::env::var_os("AETHERFLOW_TEST_FORCE_DISK_FULL").is_some() {
            0
        } else {
            available
        };
        Ok((dev, available))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok((0, u64::MAX))
    }
}

pub(crate) fn ensure_snapshot_free_space(needed_bytes: u64, available: u64) -> Result<(), String> {
    if needed_bytes.saturating_add(SNAPSHOT_RESERVE_BYTES) > available {
        return Err(format!(
            "Insufficient disk space to snapshot: need {needed_bytes} bytes plus {SNAPSHOT_RESERVE_BYTES} bytes reserved, available {available} bytes"
        ));
    }
    Ok(())
}

pub(super) fn preflight_runtime_snapshot(
    package: &str,
    root: Option<&Path>,
    staging: &Path,
    targets: &[(PathBuf, RuntimeTargetKind)],
) -> Result<SnapshotBudget, String> {
    let limit = configured_max_snapshot_bytes()?;

    fn scan(
        path: &Path,
        target: &Path,
        filter: RuntimeFilter,
        bytes: &mut u64,
        limit: u64,
    ) -> Result<(), String> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("Failed to stat {}: {e}", path.display()))?;
        if path != target
            && filter.excludes(
                path.strip_prefix(target).expect("child is beneath target"),
                &meta,
            )
        {
            return Ok(());
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)
                .map_err(|e| format!("Failed to read dir {}: {e}", path.display()))?
            {
                let entry = entry
                    .map_err(|e| format!("Failed to read entry in {}: {e}", path.display()))?;
                if !entry.file_name().to_string_lossy().contains(".af-backup.") {
                    scan(&entry.path(), target, filter, bytes, limit)?;
                }
            }
        } else if meta.is_file() {
            // Charge logical size, counting sparse and reflinkable files conservatively.
            *bytes = bytes.saturating_add(meta.len());
            if *bytes > limit {
                return Err(format!("Runtime snapshot exceeds the {limit}-byte copy ceiling (at least {bytes} bytes)"));
            }
        }
        Ok(())
    }

    let mut bytes = 0_u64;
    for (target, _) in targets {
        verify_no_symlink_ancestors_with_root(target, root)?;
        if !matches!(std::fs::symlink_metadata(target), Err(err) if err.kind() == std::io::ErrorKind::NotFound)
        {
            scan(
                target,
                target,
                RuntimeFilter::for_target(package, target, root),
                &mut bytes,
                limit,
            )?;
        }
    }

    #[cfg(unix)]
    let limit = {
        let (_dev, available) = snapshot_filesystem_capacity(staging)?;
        ensure_snapshot_free_space(bytes, available)?;
        limit.min(available - SNAPSHOT_RESERVE_BYTES)
    };
    Ok(SnapshotBudget::new(limit))
}

pub(crate) struct SnapshotBudget {
    remaining: u64,
}

impl SnapshotBudget {
    pub(crate) fn new(remaining: u64) -> Self {
        Self { remaining }
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.remaining
    }

    pub(crate) fn charge(&mut self, path: &Path, size: u64) -> Result<(), String> {
        self.remaining = self.remaining.checked_sub(size).ok_or_else(|| {
            format!(
                "Runtime data changed after snapshot preflight and exceeded the copy budget at {}",
                path.display()
            )
        })?;
        Ok(())
    }
}

impl CommittedSwap {
    pub(super) fn retain_exclusions(&mut self, filter: RuntimeFilter) -> std::io::Result<()> {
        fn walk(
            old: &Path,
            swap: &mut CommittedSwap,
            relative: &Path,
            filter: RuntimeFilter,
        ) -> std::io::Result<()> {
            for entry in std::fs::read_dir(old.join(relative))? {
                let entry = entry?;
                let child = relative.join(entry.file_name());
                let meta = std::fs::symlink_metadata(entry.path())?;
                if filter.excludes(&child, &meta) {
                    let destination = swap.target_path.join(&child);
                    verify_no_symlink_ancestors_with_root(&destination, None)
                        .map_err(std::io::Error::other)?;
                    std::fs::create_dir_all(
                        destination.parent().expect("destination has a parent"),
                    )?;
                    if destination.symlink_metadata().is_ok() {
                        return Err(std::io::Error::other(format!(
                            "Conflicting snapshot payload at {}",
                            destination.display()
                        )));
                    }
                    std::fs::rename(entry.path(), destination)?;
                    swap.retained.push(child);
                } else if meta.is_dir() {
                    walk(old, swap, &child, filter)?;
                }
            }
            Ok(())
        }

        if filter != RuntimeFilter::None {
            if let Some(old) = self
                .old_path
                .clone()
                .filter(|path| path.symlink_metadata().is_ok_and(|meta| meta.is_dir()))
            {
                walk(&old, self, Path::new(""), filter)?;
            }
        }
        Ok(())
    }

    pub(super) fn revert(self) -> std::io::Result<()> {
        if let Some(old) = &self.old_path {
            for path in &self.retained {
                std::fs::rename(self.target_path.join(path), old.join(path))?;
            }
        }
        if self.target_path.symlink_metadata()?.is_dir() {
            std::fs::remove_dir_all(&self.target_path)?;
        } else {
            std::fs::remove_file(&self.target_path)?;
        }
        if let Some(old) = self.old_path {
            std::fs::rename(old, self.target_path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, crate::PackageExecutionEnv) {
        let root = std::env::temp_dir().join(format!("af-runtime-filter-{}", uuid::Uuid::new_v4()));
        let env = crate::PackageExecutionEnv {
            fs_root: Some(root.join("host")),
            temp_dir: root.join("staging"),
            recovery_root: Some(root.join("recovery")),
            ..Default::default()
        };
        (root, env)
    }

    #[tokio::test]
    async fn capture_runs_off_runtime_thread_and_restore_preserves_excluded_payloads() {
        let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
        for (package, logical, kept, excluded) in [
            ("plex", "var/lib/plexmediaserver",
             &["Library/Application Support/Plex Media Server/Preferences.xml",
               "Library/Application Support/Plex Media Server/Plug-in Support/Databases/library.db"][..],
             &["Library/Application Support/Plex Media Server/Cache/data",
               "Library/Application Support/Plex Media Server/Metadata/poster"][..]),
            ("jellyfin", "var/lib/jellyfin", &["data/library.db"], &["cache/data", "data/transcodes/stream", "logs/log"]),
            ("emby", "var/lib/emby-server", &["config/system.xml"], &["metadata/poster", "log/log"]),
            ("nextcloud", "var/www/nextcloud", &["config/config.php", "apps/example/appinfo/info.xml"], &["data/user/file", "updater-123/archive"]),
            ("paperless-ngx", "var/lib/paperless", &["data/db.sqlite3"], &["media/archive.pdf", "data/index/data"]),
            ("calibreweb", "var/lib/calibre-library", &["metadata.db", "app.db", "gdrive.db", "app.json"], &["Author/Title/book.epub", "Author/Title/book.pdf"]),
        ] {
            let (root, env) = fixture();
            let live = env.fs_root.as_ref().unwrap().join(logical);
            for path in kept.iter().chain(excluded) {
                let path = live.join(path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, "original").unwrap();
            }
            let mut snapshot = PackageRuntimeSnapshot::capture_blocking(package.into(), Vec::new(), env)
                .await.unwrap();
            assert_ne!(*SNAPSHOT_CAPTURE_THREAD.lock().unwrap(), Some(std::thread::current().id()));
            let backup = snapshot.entries.iter().find_map(|entry| match entry {
                RuntimeSnapshotEntry::Directory { target_path, backup_path, .. } if *target_path == live => Some(backup_path),
                _ => None,
            }).unwrap();
            for path in kept {
                assert!(backup.join(path).is_file(), "{package}: {path}");
            }
            for path in excluded {
                assert!(!backup.join(path).exists(), "{package}: {path}");
            }
            for path in kept.iter().chain(excluded) {
                std::fs::write(live.join(path), "changed").unwrap();
            }
            tokio::task::spawn_blocking(move || snapshot.restore()).await.unwrap().unwrap();
            for path in kept {
                assert_eq!(std::fs::read_to_string(live.join(path)).unwrap(), "original");
            }
            for path in excluded {
                assert_eq!(std::fs::read_to_string(live.join(path)).unwrap(), "changed");
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn cumulative_preflight_rejects_before_copy() {
        let _env_guard = crate::ENV_TEST_MUTEX.blocking_lock();
        let (root, env) = fixture();
        let live = env.fs_root.as_ref().unwrap().join("var/lib/sonarr");
        std::fs::create_dir_all(&live).unwrap();
        for name in ["first.db", "second.db"] {
            // Each sparse file is below the default ceiling, but together they exceed it.
            std::fs::File::create(live.join(name))
                .unwrap()
                .set_len(1100 * 1024 * 1024)
                .unwrap();
        }
        let error = PackageRuntimeSnapshot::capture("sonarr", &[], &env, false)
            .err()
            .unwrap();
        assert!(error.contains("2147483648-byte copy ceiling"), "{error}");
        let recovery_root = env.recovery_root.as_ref().unwrap();
        assert_eq!(std::fs::read_dir(recovery_root).unwrap().count(), 0);
        assert!(
            !env.temp_dir.exists(),
            "runtime snapshot capture must not write into disposable temp_dir"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
