//! Durable storage cleanup for deleted accounts. Callers serialize FileShare
//! publications and account storage operations with the existing mutation locks.
use af_files::BrowserFs;
use anyhow::{ensure, Context};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::Metadata;
use std::io::{self, ErrorKind};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::SystemTime;
use tokio::sync::OwnedMutexGuard;

#[derive(Debug, Serialize, Deserialize)]
struct EntryIdentity {
    device: u64,
    inode: u64,
    created: Option<SystemTime>,
    size: u64,
    modified: (i64, i64),
}

impl From<&Metadata> for EntryIdentity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            created: metadata.created().ok(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
        }
    }
}

struct Target {
    shared: bool,
    root: String,
    directory: String,
    filename: String,
}

impl Target {
    fn open_parent(&self, require_private: bool) -> io::Result<BrowserFs> {
        let root = Path::new(&self.root);
        if !root.is_absolute()
            || root.parent().is_none()
            || self.filename.contains('/')
            || matches!(self.filename.as_str(), "" | "." | "..")
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Invalid cleanup path",
            ));
        }
        let browser = if self.shared {
            // FileShare ownership rows store a canonical root. Refuse
            // symlinks in all its components when replaying the durable path.
            let relative = self.root.trim_start_matches('/');
            BrowserFs::open(Path::new("/"))?.scoped(relative)?
        } else {
            // A configured McBrowser root may have operator-owned aliases in
            // its ancestors. BrowserFs refuses a symlink at the root itself.
            let browser = BrowserFs::open(root)?;
            if require_private {
                check_private_directory(&browser.directory_metadata()?)?;
            }
            browser
        };
        browser.scoped(&self.directory)
    }

    fn matches_type(&self, metadata: &Metadata) -> bool {
        if self.shared {
            metadata.is_file()
        } else {
            metadata.is_dir()
        }
    }

    fn queue(&self, conn: &Connection, user_id: i64) -> anyhow::Result<usize> {
        let observed = self
            .open_parent(false)
            .and_then(|parent| parent.entry_metadata(&self.filename));
        let (identity, error) = match observed {
            Ok(metadata) if self.matches_type(&metadata) => (
                Some(serde_json::to_string(&EntryIdentity::from(&metadata))?),
                String::new(),
            ),
            Ok(_) => (None, "Cleanup path has an unexpected entry type".into()),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
            Err(error) => (None, error.to_string()),
        };
        Ok(conn.execute(
            "INSERT OR IGNORE INTO account_storage_cleanup
             (user_id, shared, storage_root, directory, filename, identity, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                user_id,
                self.shared,
                self.root,
                self.directory,
                self.filename,
                identity,
                error,
            ],
        )?)
    }

    fn still_referenced(&self, conn: &Connection, user_id: i64) -> rusqlite::Result<bool> {
        if self.shared {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM fileshare_objects
                 WHERE storage_root = ?1 AND directory = ?2 AND filename = ?3)",
                params![self.root, self.directory, self.filename],
                |row| row.get(0),
            )
        } else {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?1)",
                [user_id],
                |row| row.get(0),
            )
        }
    }

    fn remove(&self, user_id: i64, identity: Option<&str>) -> anyhow::Result<()> {
        if !self.shared {
            ensure!(
                self.filename == format!("user-{user_id}")
                    && matches!(self.directory.as_str(), "" | ".af-upload-staging"),
                "Invalid private account cleanup path"
            );
        }
        let parent = match self.open_parent(true) {
            Ok(parent) => parent,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let actual = match parent.entry_metadata(&self.filename) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return parent.sync_directory().map_err(Into::into);
            }
            Err(error) => return Err(error.into()),
        };
        let expected: EntryIdentity =
            serde_json::from_str(identity.context("Original storage identity was unavailable")?)?;
        let observed = EntryIdentity::from(&actual);
        let same_inode = expected.device == observed.device
            && expected.inode == observed.inode
            && !matches!((expected.created, observed.created), (Some(a), Some(b)) if a != b);
        if !same_inode {
            tracing::warn!(
                user_id, root = %self.root, directory = %self.directory,
                filename = %self.filename, "Preserved a replacement at the account cleanup path"
            );
            return Ok(());
        }
        ensure!(self.matches_type(&actual), "Cleanup entry type changed");
        if self.shared {
            ensure!(
                expected.size == observed.size && expected.modified == observed.modified,
                "Shared file changed after account deletion"
            );
            parent.remove(&self.filename)?;
        } else {
            check_private_directory(&actual)?;
            let outcome = parent.remove_tree_with_outcome_allowing_symlinks(&self.filename)?;
            self.record_mount_skips(user_id, &outcome);
        }
        parent.sync_directory()?;
        Ok(())
    }

    fn record_mount_skips(&self, user_id: i64, outcome: &af_files::RemoveTreeOutcome) {
        if outcome.skipped_mount_paths.is_empty() {
            return;
        }
        let preserved: Vec<String> = outcome
            .skipped_mount_paths
            .iter()
            .map(|p| {
                if self.directory.is_empty() {
                    p.to_string_lossy().into_owned()
                } else {
                    format!("{}/{}", self.directory, p.to_string_lossy())
                }
            })
            .collect();
        tracing::warn!(
            user_id,
            root = %self.root,
            directory = %self.directory,
            filename = %self.filename,
            skipped_mount_paths = ?preserved,
            removed_bytes = outcome.removed_bytes,
            "Account storage cleanup skipped mounted paths at filesystem boundary"
        );
        let target_label = if self.directory.is_empty() {
            self.filename.clone()
        } else {
            format!("{}/{}", self.directory, self.filename)
        };
        let detail = format!(
            "Account storage cleanup preserved mounted path(s) under {}/{}: {}",
            self.root.trim_end_matches('/'),
            target_label,
            preserved.join(", ")
        );
        af_db::record_audit(
            0,
            "system:account_cleanup",
            "account_storage_cleanup_mount_skipped",
            "account_storage",
            &format!("user-{user_id}"),
            &detail,
            "127.0.0.1",
            "aetherflow-api/account_cleanup",
        );
    }
}

fn check_private_directory(metadata: &Metadata) -> io::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "Unsafe private account storage directory",
        ));
    }
    Ok(())
}

pub(crate) fn queue_private(
    conn: &Connection,
    user_id: i64,
    configured_root: Option<&str>,
) -> anyhow::Result<usize> {
    let root = match crate::mcbrowser::resolve_configured_base_root(configured_root) {
        Ok(root) => root.to_string_lossy().into_owned(),
        // Keep the attempted path in the journal if the current configuration
        // cannot be interpreted safely.
        Err(_) => configured_root.unwrap_or_default().to_owned(),
    };
    let mut count = 0;
    for directory in ["", ".af-upload-staging"] {
        let target = Target {
            shared: false,
            root: root.clone(),
            directory: directory.to_owned(),
            filename: format!("user-{user_id}"),
        };
        count += target.queue(conn, user_id)?;
    }
    Ok(count)
}

pub(crate) fn queue_shared(conn: &Connection, user_id: i64) -> anyhow::Result<usize> {
    let mut statement = conn.prepare(
        "SELECT DISTINCT f.storage_root, f.directory, f.filename
         FROM fileshare_objects AS f WHERE f.user_id = ?1
         AND NOT EXISTS (
             SELECT 1 FROM fileshare_objects AS remaining
             WHERE remaining.user_id != ?1 AND remaining.storage_root = f.storage_root
               AND remaining.directory = f.directory AND remaining.filename = f.filename
         )",
    )?;
    let targets = statement.query_map([user_id], |row| {
        Ok(Target {
            shared: true,
            root: row.get(0)?,
            directory: row.get(1)?,
            filename: row.get(2)?,
        })
    })?;
    let mut count = 0;
    for target in targets {
        count += target?.queue(conn, user_id)?;
    }
    Ok(count)
}

pub(crate) fn pending_shared_names(
    conn: &Connection,
    root: &str,
    directory: &str,
) -> rusqlite::Result<HashSet<String>> {
    let mut statement = conn.prepare(
        "SELECT filename FROM account_storage_cleanup
         WHERE shared = 1 AND storage_root = ?1 AND directory = ?2",
    )?;
    let names = statement.query_map(params![root, directory], |row| row.get(0))?;
    names.collect()
}

pub(crate) fn shared_path_pending(
    conn: &Connection,
    root: &str,
    directory: &str,
    filename: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM account_storage_cleanup
         WHERE shared = 1 AND storage_root = ?1 AND directory = ?2 AND filename = ?3)",
        params![root, directory, filename],
        |row| row.get(0),
    )
}

pub(crate) fn pending_count(conn: &Connection, user_id: i64) -> rusqlite::Result<usize> {
    conn.query_row(
        "SELECT COUNT(*) FROM account_storage_cleanup WHERE user_id = ?1",
        [user_id],
        |row| row.get(0),
    )
}

struct PendingTarget {
    id: i64,
    target: Target,
    identity: Option<String>,
}

fn pending_targets(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<PendingTarget>> {
    let mut statement = conn.prepare(
        "SELECT id, shared, storage_root, directory, filename, identity
         FROM account_storage_cleanup WHERE user_id = ?1 ORDER BY id",
    )?;
    let targets = statement.query_map([user_id], |row| {
        Ok(PendingTarget {
            id: row.get(0)?,
            target: Target {
                shared: row.get(1)?,
                root: row.get(2)?,
                directory: row.get(3)?,
                filename: row.get(4)?,
            },
            identity: row.get(5)?,
        })
    })?;
    targets.collect()
}

pub(crate) fn settle(user_id: i64, shared_guard: OwnedMutexGuard<()>) -> anyhow::Result<usize> {
    let (shared, private) = {
        let conn = af_db::get_read_conn()?;
        pending_targets(&conn, user_id)?
            .into_iter()
            .partition(|pending| pending.target.shared)
    };
    let shared_remaining = settle_targets(user_id, shared)?;
    // A private tree can take time to remove. The account's mutation lock
    // protects it while shared reads and publications proceed.
    drop(shared_guard);
    Ok(shared_remaining + settle_targets(user_id, private)?)
}

fn settle_targets(user_id: i64, targets: Vec<PendingTarget>) -> anyhow::Result<usize> {
    let mut remaining = 0;
    for pending in targets {
        let target = &pending.target;
        let live = {
            let conn = af_db::get_read_conn()?;
            target.still_referenced(&conn, user_id)?
        };
        let result = if live {
            Ok(())
        } else {
            target.remove(user_id, pending.identity.as_deref())
        };
        let conn = af_db::get_conn()?;
        match result {
            Ok(()) => {
                conn.execute(
                    "DELETE FROM account_storage_cleanup WHERE id = ?1",
                    [pending.id],
                )?;
            }
            Err(error) => {
                remaining += 1;
                tracing::warn!(
                    %error, user_id, root = %target.root, directory = %target.directory,
                    filename = %target.filename, "Account storage cleanup remains pending"
                );
                conn.execute(
                    "UPDATE account_storage_cleanup SET last_error = ?1 WHERE id = ?2",
                    params![error.to_string(), pending.id],
                )?;
            }
        }
    }
    Ok(remaining)
}

fn pending_users() -> anyhow::Result<Vec<i64>> {
    let conn = af_db::get_read_conn()?;
    let mut statement =
        conn.prepare("SELECT DISTINCT user_id FROM account_storage_cleanup ORDER BY user_id")?;
    let rows = statement.query_map([], |row| row.get(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub(crate) async fn recover() {
    let users = match tokio::task::spawn_blocking(pending_users).await {
        Ok(Ok(users)) => users,
        Ok(Err(error)) => {
            tracing::warn!(%error, "Could not read pending account storage cleanups");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "Account storage cleanup lookup worker failed");
            return;
        }
    };
    for user_id in users {
        let shared = crate::storage::lock_fileshare_mutations().await;
        let user = crate::mcbrowser::user_mutation_stripe(user_id)
            .lock_owned()
            .await;
        let result = tokio::task::spawn_blocking(move || {
            let _user = user;
            settle(user_id, shared)
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
        if let Err(error) = result {
            tracing::warn!(%error, user_id, "Could not reconcile account storage cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    #[tokio::test]
    async fn mount_boundary_skip_records_audit_and_deletes_cleanup_row_without_retry_loop() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let db_path = crate::plugins::tests::ensure_shared_test_db();
        let root = db_path.parent().unwrap().join("mcbrowser-cleanup-root");
        let user_dir = root.join("user-77");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&user_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(user_dir.join("local.txt"), b"remove-me").unwrap();

        let target = Target {
            shared: false,
            root: root.to_string_lossy().into_owned(),
            directory: String::new(),
            filename: "user-77".to_string(),
        };
        let outcome = af_files::RemoveTreeOutcome {
            removed_bytes: 9,
            skipped_mount_paths: vec![PathBuf::from("user-77/Media")],
        };
        target.record_mount_skips(77, &outcome);

        {
            let conn = af_db::get_conn().unwrap();
            let queued = queue_private(&conn, 77, Some(&target.root)).unwrap();
            assert_eq!(queued, 1);
            assert_eq!(pending_count(&conn, 77).unwrap(), 1);
        }

        let shared_guard = crate::storage::lock_fileshare_mutations().await;
        let remaining = settle(77, shared_guard).unwrap();
        assert_eq!(
            remaining, 0,
            "completed cleanup row must be deleted without leaving a 15m retry loop"
        );

        let reader = af_db::get_read_conn().unwrap();
        assert_eq!(pending_count(&reader, 77).unwrap(), 0);
        let audit_detail: String = reader
            .query_row(
                "SELECT detail FROM admin_audit_log \
                 WHERE action = 'account_storage_cleanup_mount_skipped' AND target_id = 'user-77' \
                 ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            audit_detail.contains("user-77/Media"),
            "audit entry must name skipped mount paths: {audit_detail}"
        );
    }
}
