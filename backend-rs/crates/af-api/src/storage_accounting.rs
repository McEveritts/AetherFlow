//! Shared storage accounting. Host scans and publications serialize with mutations;
//! durable reservations precede publishing a shared file.
use super::*;

pub(super) static MUTATIONS: Lazy<Arc<tokio::sync::Mutex<()>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(())));
static QUOTA_WORKERS: Lazy<Arc<tokio::sync::Semaphore>> =
    Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(4)));

fn transaction<T>(
    conn: &rusqlite::Connection,
    work: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    match work().and_then(|value| {
        conn.execute_batch("COMMIT")?;
        Ok(value)
    }) {
        Ok(value) => Ok(value),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

#[derive(Debug)]
pub(super) struct QuotaExceeded;
impl std::fmt::Display for QuotaExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Storage quota exceeded. Free up space or contact an administrator.")
    }
}
impl std::error::Error for QuotaExceeded {}

fn reserve(conn: &rusqlite::Connection, user_id: i64, bytes: u64) -> anyhow::Result<()> {
    crate::mcbrowser::reserve_user_quota_conn(conn, user_id, bytes).map_err(|error| match error {
        crate::mcbrowser::McBrowserError::QuotaExceeded(_) => anyhow::Error::new(QuotaExceeded),
        other => anyhow::anyhow!("Storage quota reservation failed: {other:?}"),
    })
}
fn release(conn: &rusqlite::Connection, user_id: i64, bytes: u64) -> anyhow::Result<()> {
    crate::mcbrowser::release_user_quota_conn(conn, user_id, bytes)
        .map_err(|error| anyhow::anyhow!("Storage quota release failed: {error:?}"))
}

pub(super) fn object_key(root: &StdPath, directory: &str) -> anyhow::Result<(String, String)> {
    let root = fs::canonicalize(root)?.to_string_lossy().into_owned();
    let directory = directory.trim().trim_matches('/');
    let directory = if directory == "." {
        String::new()
    } else {
        directory
            .split('/')
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    };
    Ok((root, directory))
}

pub(super) const MAX_ALIGNED_QUOTA_BYTES: i64 = i64::MAX - (i64::MAX % 1024);

pub(super) fn align_quota_bytes_to_kib(bytes: i64) -> anyhow::Result<i64> {
    anyhow::ensure!(bytes > 0, "Quota must be positive");
    bytes
        .checked_add(1023)
        .map(|sum| sum & !1023)
        .filter(|&aligned| aligned > 0 && aligned <= MAX_ALIGNED_QUOTA_BYTES)
        .ok_or_else(|| anyhow::anyhow!("Quota is too large"))
}

fn inspect_confined_shared_file_size(
    root: &str,
    directory: &str,
    filename: &str,
) -> std::io::Result<Option<u64>> {
    let root_path = StdPath::new(root);
    if !root_path.is_absolute()
        || root_path.parent().is_none()
        || filename.contains('/')
        || matches!(filename, "" | "." | "..")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid shared storage path",
        ));
    }
    let relative_root = root.trim_start_matches('/');
    let browser = match af_files::BrowserFs::open(StdPath::new("/"))
        .and_then(|fs_root| fs_root.scoped(relative_root))
        .and_then(|root_fs| root_fs.scoped(directory))
    {
        Ok(browser) => browser,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    match browser.open_file(filename) {
        Ok(file) => Ok(Some(file.metadata()?.len())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) struct ReservedPublish {
    root_key: String,
    directory: String,
    previous: Option<(i64, i64)>,
    old_size: u64,
    new_size: u64,
    growth: u64,
}

pub(super) fn reserve_publish(
    conn: &rusqlite::Connection,
    root: &StdPath,
    user_id: i64,
    directory: &str,
    filename: &str,
    new_size: u64,
) -> anyhow::Result<ReservedPublish> {
    let (root_key, directory) = object_key(root, directory)?;
    anyhow::ensure!(
        !crate::account_cleanup::shared_path_pending(conn, &root_key, &directory, filename)?,
        "This path is awaiting account storage cleanup"
    );
    let previous: Option<(i64, i64)> = conn
        .query_row(
            "SELECT user_id, size_bytes FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![root_key, directory, filename],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((owner, _)) = previous {
        anyhow::ensure!(
            owner == user_id,
            "Only the file owner can replace an existing shared file"
        );
    }
    let old_size = previous.map(|(_, size)| size.max(0) as u64).unwrap_or(0);
    let growth = new_size.saturating_sub(old_size);
    let prev_user = previous.map(|(owner, _)| owner);
    let prev_size = previous.map(|(_, size)| size);
    let new_size_i64 = i64::try_from(new_size)?;
    let growth_i64 = i64::try_from(growth)?;
    transaction(conn, || {
        reserve(conn, user_id, growth)?;
        conn.execute(
            "INSERT INTO fileshare_objects(storage_root,directory,filename,user_id,size_bytes)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(storage_root,directory,filename) DO UPDATE
             SET user_id=excluded.user_id,size_bytes=excluded.size_bytes",
            params![root_key, directory, filename, user_id, new_size_i64],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO fileshare_pending_publishes(
                 storage_root, directory, filename, user_id, new_size_bytes, growth_bytes,
                 previous_user_id, previous_size_bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                root_key,
                directory,
                filename,
                user_id,
                new_size_i64,
                growth_i64,
                prev_user,
                prev_size
            ],
        )?;
        Ok(())
    })?;
    Ok(ReservedPublish {
        root_key,
        directory,
        previous,
        old_size,
        new_size,
        growth,
    })
}

pub(super) fn publish(
    conn: &rusqlite::Connection,
    root: &StdPath,
    user_id: i64,
    session: FileshareUpload,
) -> anyhow::Result<()> {
    let reserved = reserve_publish(
        conn,
        root,
        user_id,
        &session.directory,
        &session.filename,
        session.size as u64,
    )?;
    // Keep the quota charged and durable pending-publish intent recorded if the
    // process stops here. Startup reconciliation and quota refresh reconcile
    // the ledger with disk and release phantom ownership rows.
    let published = if let Some(original) = session.original {
        session.pending.commit_replace(&original)
    } else {
        session.pending.commit()
    };
    if let Err(error) = published {
        transaction(conn, || {
            release(conn, user_id, reserved.growth)?;
            if let Some((owner, size)) = reserved.previous {
                conn.execute(
                    "UPDATE fileshare_objects SET user_id=?4,size_bytes=?5 WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                    params![
                        reserved.root_key,
                        reserved.directory,
                        session.filename,
                        owner,
                        size
                    ],
                )?;
            } else {
                conn.execute(
                    "DELETE FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                    params![reserved.root_key, reserved.directory, session.filename],
                )?;
            }
            conn.execute(
                "DELETE FROM fileshare_pending_publishes WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                params![reserved.root_key, reserved.directory, session.filename],
            )?;
            Ok(())
        })?;
        return Err(error.into());
    }
    transaction(conn, || {
        release(
            conn,
            user_id,
            reserved.old_size.saturating_sub(reserved.new_size),
        )?;
        conn.execute(
            "DELETE FROM fileshare_pending_publishes WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![reserved.root_key, reserved.directory, session.filename],
        )?;
        Ok(())
    })?;
    Ok(())
}

pub(super) fn delete(
    conn: &rusqlite::Connection,
    root: &StdPath,
    directory: &str,
    filename: &str,
) -> anyhow::Result<()> {
    let browser = fileshare_directory(root, directory)?;
    anyhow::ensure!(
        browser.metadata(filename)?.kind == "file",
        "Cannot delete directory via file endpoint"
    );
    let (root_key, directory) = object_key(root, directory)?;
    let previous: Option<(i64, i64)> = conn
        .query_row(
            "SELECT user_id,size_bytes FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![root_key, directory, filename],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    browser.remove(filename)?;
    if crate::account_cleanup::shared_path_pending(conn, &root_key, &directory, filename)? {
        browser.sync_directory()?;
    }
    transaction(conn, || {
        if let Some((owner, size)) = previous {
            release(conn, owner, size.max(0) as u64)?;
        }
        conn.execute(
            "DELETE FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![root_key, directory, filename],
        )?;
        conn.execute(
            "DELETE FROM fileshare_pending_publishes WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![root_key, directory, filename],
        )?;
        conn.execute(
            "DELETE FROM account_storage_cleanup
             WHERE shared = 1 AND storage_root = ?1 AND directory = ?2 AND filename = ?3",
            params![root_key, directory, filename],
        )?;
        Ok(())
    })
}

struct PendingFilesharePublish {
    storage_root: String,
    directory: String,
    filename: String,
    user_id: i64,
    new_size_bytes: i64,
    growth_bytes: i64,
    previous_user_id: Option<i64>,
    previous_size_bytes: Option<i64>,
}

fn has_pending_publishes_table(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='fileshare_pending_publishes')",
        [],
        |row| row.get(0),
    )
}

fn load_pending_publishes(
    conn: &rusqlite::Connection,
    user_filter: Option<i64>,
) -> anyhow::Result<Vec<PendingFilesharePublish>> {
    if !has_pending_publishes_table(conn)? {
        return Ok(Vec::new());
    }
    let mut rows_out = Vec::new();
    let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<PendingFilesharePublish> {
        Ok(PendingFilesharePublish {
            storage_root: row.get(0)?,
            directory: row.get(1)?,
            filename: row.get(2)?,
            user_id: row.get(3)?,
            new_size_bytes: row.get(4)?,
            growth_bytes: row.get(5)?,
            previous_user_id: row.get(6)?,
            previous_size_bytes: row.get(7)?,
        })
    };
    if let Some(uid) = user_filter {
        let mut stmt = conn.prepare(
            "SELECT storage_root, directory, filename, user_id, new_size_bytes, growth_bytes,
                    previous_user_id, previous_size_bytes
             FROM fileshare_pending_publishes
             WHERE user_id = ?1
             ORDER BY storage_root, directory, filename",
        )?;
        for item in stmt.query_map([uid], map_row)? {
            rows_out.push(item?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT storage_root, directory, filename, user_id, new_size_bytes, growth_bytes,
                    previous_user_id, previous_size_bytes
             FROM fileshare_pending_publishes
             ORDER BY user_id, storage_root, directory, filename",
        )?;
        for item in stmt.query_map([], map_row)? {
            rows_out.push(item?);
        }
    }
    Ok(rows_out)
}

fn reconcile_one_pending_publish_in_tx(
    conn: &rusqlite::Connection,
    pending: &PendingFilesharePublish,
) -> anyhow::Result<()> {
    let existing: Option<(i64, i64)> = conn
        .query_row(
            "SELECT user_id, size_bytes FROM fileshare_objects
             WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![pending.storage_root, pending.directory, pending.filename],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let Some((current_owner, _)) = existing else {
        conn.execute(
            "DELETE FROM fileshare_pending_publishes WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![pending.storage_root, pending.directory, pending.filename],
        )?;
        return Ok(());
    };
    if current_owner != pending.user_id {
        conn.execute(
            "DELETE FROM fileshare_pending_publishes WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![pending.storage_root, pending.directory, pending.filename],
        )?;
        return Ok(());
    }

    let old_size = pending.previous_size_bytes.unwrap_or(0).max(0) as u64;
    let growth = pending.growth_bytes.max(0) as u64;
    let charged = old_size.saturating_add(growth);

    match inspect_confined_shared_file_size(
        &pending.storage_root,
        &pending.directory,
        &pending.filename,
    )? {
        None => {
            conn.execute(
                "DELETE FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                params![pending.storage_root, pending.directory, pending.filename],
            )?;
            if let Some(prev_uid) = pending.previous_user_id.filter(|&id| id != pending.user_id) {
                release(conn, pending.user_id, growth)?;
                release(conn, prev_uid, old_size)?;
            } else {
                release(conn, pending.user_id, charged)?;
            }
        }
        Some(actual_size) => {
            let actual_i64 = i64::try_from(actual_size)?;
            if let Some(prev_uid) = pending.previous_user_id.filter(|&id| {
                id != pending.user_id
                    && pending.previous_size_bytes == Some(actual_i64)
                    && pending.new_size_bytes != actual_i64
            }) {
                conn.execute(
                    "UPDATE fileshare_objects SET user_id=?4, size_bytes=?5
                     WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                    params![
                        pending.storage_root,
                        pending.directory,
                        pending.filename,
                        prev_uid,
                        actual_i64
                    ],
                )?;
                release(conn, pending.user_id, growth)?;
            } else {
                conn.execute(
                    "UPDATE fileshare_objects SET size_bytes=?4
                     WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                    params![
                        pending.storage_root,
                        pending.directory,
                        pending.filename,
                        actual_i64
                    ],
                )?;
                release(conn, pending.user_id, charged.saturating_sub(actual_size))?;
            }
        }
    }

    conn.execute(
        "DELETE FROM fileshare_pending_publishes WHERE storage_root=?1 AND directory=?2 AND filename=?3",
        params![pending.storage_root, pending.directory, pending.filename],
    )?;
    Ok(())
}

pub(super) fn reconcile_pending_fileshare_publishes_in_tx(
    conn: &rusqlite::Connection,
    user_filter: Option<i64>,
) -> anyhow::Result<usize> {
    let entries = load_pending_publishes(conn, user_filter)?;
    let count = entries.len();
    for entry in &entries {
        reconcile_one_pending_publish_in_tx(conn, entry)?;
    }
    Ok(count)
}

fn reconcile_pending_fileshare_publishes_for_user(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> anyhow::Result<usize> {
    let entries = load_pending_publishes(conn, Some(user_id))?;
    let mut reconciled = 0usize;
    for entry in &entries {
        match transaction(conn, || reconcile_one_pending_publish_in_tx(conn, entry)) {
            Ok(()) => reconciled += 1,
            Err(error) => {
                tracing::warn!(
                    %error,
                    user_id,
                    root = %entry.storage_root,
                    directory = %entry.directory,
                    filename = %entry.filename,
                    "Pending FileShare publish reconciliation remains pending"
                );
            }
        }
    }
    Ok(reconciled)
}

pub(crate) async fn recover_fileshare_pending_publishes() {
    let pending_users = tokio::task::spawn_blocking(|| -> anyhow::Result<Vec<i64>> {
        let conn = af_db::get_conn()?;
        if !has_pending_publishes_table(&conn)? {
            return Ok(Vec::new());
        }
        let mut stmt = conn
            .prepare("SELECT DISTINCT user_id FROM fileshare_pending_publishes ORDER BY user_id")?;
        let ids = stmt.query_map([], |row| row.get(0))?;
        Ok(ids.collect::<Result<_, _>>()?)
    })
    .await;
    let user_ids = match pending_users {
        Ok(Ok(ids)) => ids,
        Ok(Err(error)) => {
            tracing::warn!(%error, "Could not read pending FileShare publications");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "Pending FileShare publication lookup worker failed");
            return;
        }
    };
    for user_id in user_ids {
        let _shared = MUTATIONS.lock().await;
        let _user = crate::mcbrowser::user_mutation_stripe(user_id)
            .lock_owned()
            .await;
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let conn = af_db::get_conn()?;
            reconcile_pending_fileshare_publishes_for_user(&conn, user_id)
        })
        .await;
        match res {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, user_id, "Pending FileShare publication recovery failed");
            }
            Err(error) => {
                tracing::warn!(%error, user_id, "Pending FileShare publication recovery worker failed");
            }
        }
    }
}

// Reconcile durable reservations after an interrupted publication or an
// operator's out-of-band removal; never follow a stored path through symlinks.
fn shared_usage(
    conn: &rusqlite::Connection,
    user_id: i64,
    scanned: &[PathBuf],
) -> anyhow::Result<u64> {
    reconcile_pending_fileshare_publishes_in_tx(conn, Some(user_id))?;
    let mut stmt = conn.prepare(
        "SELECT storage_root,directory,filename FROM fileshare_objects WHERE user_id=?1",
    )?;
    let entries = stmt
        .query_map([user_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let mut total = 0u64;
    for (root, directory, filename) in entries {
        let actual = inspect_confined_shared_file_size(&root, &directory, &filename)?;
        let Some(size) = actual else {
            let pending_cleanup =
                crate::account_cleanup::shared_path_pending(conn, &root, &directory, &filename)?;
            if !pending_cleanup {
                conn.execute(
                    "DELETE FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                    params![root, directory, filename],
                )?;
                if has_pending_publishes_table(conn)? {
                    conn.execute(
                        "DELETE FROM fileshare_pending_publishes WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                        params![root, directory, filename],
                    )?;
                }
            } else {
                conn.execute(
                    "UPDATE fileshare_objects SET size_bytes=0 WHERE storage_root=?1 AND directory=?2 AND filename=?3",
                    params![root, directory, filename],
                )?;
            }
            continue;
        };
        conn.execute(
            "UPDATE fileshare_objects SET size_bytes=?4 WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![root, directory, filename, i64::try_from(size)?],
        )?;
        let full = StdPath::new(&root).join(&directory).join(&filename);
        if !scanned.iter().any(|base| full.starts_with(base)) {
            total = total
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("Storage usage overflow"))?;
        }
    }
    Ok(total)
}

fn ensure_no_reserved_uploads(conn: &rusqlite::Connection, user_id: i64) -> anyhow::Result<()> {
    let table: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='mcbrowser_uploads')", [], |row| row.get(0))?;
    if table {
        let busy: bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM mcbrowser_uploads WHERE user_id=?1 AND status IN ('uploading','publishing'))",[user_id],|row|row.get(0))?;
        anyhow::ensure!(
            !busy,
            "Finish or cancel active McBrowser uploads before scanning or changing quotas"
        );
    }
    Ok(())
}

// The caller holds the storage and per-user mutation locks. A receipt means
// the host may have changed while SQLite still holds the last committed limit.
async fn restore_committed_quota(user_id: i64) -> anyhow::Result<()> {
    let rollback = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<(String, i64)>> {
        let conn = af_db::get_conn()?;
        let pending: Option<(String, String, i64)> = conn
            .query_row(
                "SELECT r.username, u.username, COALESCE(q.quota_bytes, 0)
                 FROM quota_rollbacks r JOIN users u ON u.id = r.user_id
                 LEFT JOIN user_quotas q ON q.user_id = r.user_id
                 WHERE r.user_id = ?1",
                [user_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((username, current_username, bytes)) = pending else {
            return Ok(None);
        };
        anyhow::ensure!(
            username == current_username,
            "Pending quota change belongs to a different host account"
        );
        Ok(Some((username, bytes.max(0))))
    })
    .await??;
    if let Some((username, bytes)) = rollback {
        af_runner::dispatch_set_quota(&username, &format!("{bytes}B")).await?;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let conn = af_db::get_conn()?;
            conn.execute(
                "DELETE FROM quota_rollbacks WHERE user_id = ?1 AND username = ?2",
                params![user_id, username],
            )?;
            Ok(())
        })
        .await??;
    }
    Ok(())
}

pub(crate) async fn recover_quota_rollbacks() {
    let pending = tokio::task::spawn_blocking(|| -> anyhow::Result<Vec<i64>> {
        let conn = af_db::get_conn()?;
        let mut stmt = conn.prepare("SELECT user_id FROM quota_rollbacks ORDER BY user_id")?;
        let ids = stmt.query_map([], |row| row.get(0))?;
        Ok(ids.collect::<Result<_, _>>()?)
    })
    .await;
    let ids = match pending {
        Ok(Ok(ids)) => ids,
        Ok(Err(error)) => {
            tracing::warn!(%error, "Could not read pending host quota rollbacks");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "Quota rollback lookup failed");
            return;
        }
    };
    for user_id in ids {
        let _shared = MUTATIONS.lock().await;
        let _user = crate::mcbrowser::user_mutation_stripe(user_id)
            .lock_owned()
            .await;
        if let Err(error) = restore_committed_quota(user_id).await {
            tracing::warn!(%error, user_id, "Host quota rollback remains pending");
        }
    }
}

async fn run_quota_operation(
    user_id: i64,
    requested: Option<i64>,
) -> anyhow::Result<UserQuotaRecord> {
    let _shared = MUTATIONS.clone().lock_owned().await;
    let _user = crate::mcbrowser::user_mutation_stripe(user_id)
        .lock_owned()
        .await;
    restore_committed_quota(user_id).await?;
    let effective = requested.map(align_quota_bytes_to_kib).transpose()?;
    let username = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let conn = af_db::get_conn()?;
        ensure_no_reserved_uploads(&conn, user_id)?;
        reconcile_pending_fileshare_publishes_for_user(&conn, user_id)?;
        let user_sql = if crate::auth::column_exists(&conn, "users", "account_type")? {
            "SELECT username FROM users WHERE id = ?1 AND COALESCE(account_type, 'human') = 'human'"
        } else {
            "SELECT username FROM users WHERE id = ?1"
        };
        Ok(conn.query_row(user_sql, [user_id], |row| row.get(0))?)
    })
    .await??;
    let usage = af_runner::quota::dispatch(&af_runner::quota::UsageRequest {
        username: username.clone(),
        user_id,
    })
    .await?;
    if effective.is_some() {
        let username = username.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let conn = af_db::get_conn()?;
            conn.execute(
                "INSERT INTO quota_rollbacks (user_id, username) VALUES (?1, ?2)",
                params![user_id, username],
            )?;
            Ok(())
        })
        .await??;
    }

    let result: anyhow::Result<UserQuotaRecord> = async {
        if let Some(bytes) = effective {
            af_runner::dispatch_set_quota(&username, &format!("{bytes}B")).await?;
        }
        tokio::task::spawn_blocking(move || {
            let conn = af_db::get_conn()?;
            transaction(&conn, || {
                let used = usage
                    .used_bytes
                    .checked_add(shared_usage(&conn, user_id, &usage.scanned_roots)?)
                    .ok_or_else(|| anyhow::anyhow!("Storage usage overflow"))?;
                conn.execute(
                    "INSERT INTO user_quotas(user_id,username,quota_bytes,used_bytes,status,source,updated_at)
                     VALUES(?1,?2,COALESCE(?3,0),?4,'active','manual',CURRENT_TIMESTAMP)
                     ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,
                     quota_bytes=COALESCE(?3,user_quotas.quota_bytes),used_bytes=?4,updated_at=CURRENT_TIMESTAMP",
                    params![user_id, username, effective, i64::try_from(used)?],
                )?;
                if effective.is_some() {
                    conn.execute("DELETE FROM quota_rollbacks WHERE user_id = ?1", [user_id])?;
                }
                crate::storage::query_user_quota_record_conn(&conn, user_id)
            })
        })
        .await?
    }
    .await;

    match result {
        Err(error) if effective.is_some() => match restore_committed_quota(user_id).await {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(error.context(format!(
                "Quota update failed and host quota rollback remains pending: {rollback_error}"
            ))),
        },
        result => result,
    }
}

pub(super) async fn quota_operation(user_id: i64, requested: Option<i64>) -> Response {
    if let Some(bytes) = requested {
        if let Err(err) = align_quota_bytes_to_kib(bytes) {
            return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", err.to_string());
        }
    }
    let Ok(permit) = QUOTA_WORKERS.clone().try_acquire_owned() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "BUSY",
            "Quota workers busy; retry shortly",
        );
    };
    // The owned task continues to hold serialization if the HTTP client leaves.
    match tokio::spawn(async move {let _permit=permit;run_quota_operation(user_id,requested).await}).await {
        Ok(Ok(record))=>Json(serde_json::json!({"message":if requested.is_some(){"Filesystem quota applied and usage scanned"}else{"Storage usage scanned"},"quota":record})).into_response(),
        Ok(Err(error))=> {
            let status=if matches!(error.downcast_ref::<rusqlite::Error>(),Some(rusqlite::Error::QueryReturnedNoRows)){StatusCode::NOT_FOUND}else{StatusCode::BAD_GATEWAY};
            tracing::warn!(%error, user_id, "Quota operation did not complete");
            api_error(status,"QUOTA_OPERATION_FAILED",error.to_string())
        }
        Err(_)=>api_error(StatusCode::INTERNAL_SERVER_ERROR,"INTERNAL_ERROR","Quota worker failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_do_not_overwrite_live_mcbrowser_reservations() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE mcbrowser_uploads(user_id INTEGER, status TEXT);
             INSERT INTO mcbrowser_uploads VALUES(7, 'uploading');",
        )
        .unwrap();
        for status in ["uploading", "publishing"] {
            conn.execute("UPDATE mcbrowser_uploads SET status=?1", [status])
                .unwrap();
            assert!(ensure_no_reserved_uploads(&conn, 7).is_err());
            assert!(ensure_no_reserved_uploads(&conn, 8).is_ok());
        }
        for status in ["completed", "cancelled"] {
            conn.execute("UPDATE mcbrowser_uploads SET status=?1", [status])
                .unwrap();
            assert!(ensure_no_reserved_uploads(&conn, 7).is_ok());
        }
    }

    #[test]
    fn align_quota_bytes_to_kib_uses_checked_arithmetic_and_rejects_overflow() {
        assert_eq!(align_quota_bytes_to_kib(1).unwrap(), 1024);
        assert_eq!(align_quota_bytes_to_kib(1024).unwrap(), 1024);
        assert_eq!(align_quota_bytes_to_kib(1537).unwrap(), 2048);
        assert_eq!(
            align_quota_bytes_to_kib(MAX_ALIGNED_QUOTA_BYTES).unwrap(),
            MAX_ALIGNED_QUOTA_BYTES
        );
        assert_eq!(MAX_ALIGNED_QUOTA_BYTES % 1024, 0);
        for invalid in [
            i64::MIN,
            -1024,
            -1,
            0,
            MAX_ALIGNED_QUOTA_BYTES + 1,
            i64::MAX - 1,
            i64::MAX,
        ] {
            assert!(
                align_quota_bytes_to_kib(invalid).is_err(),
                "expected alignment rejection for {invalid}"
            );
        }
    }
}
