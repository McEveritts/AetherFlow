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

fn object_key(root: &StdPath, directory: &str) -> anyhow::Result<(String, String)> {
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

pub(super) fn publish(
    conn: &rusqlite::Connection,
    root: &StdPath,
    user_id: i64,
    session: FileshareUpload,
) -> anyhow::Result<()> {
    let (root_key, directory) = object_key(root, &session.directory)?;
    let previous: Option<(i64, i64)> = conn.query_row(
        "SELECT user_id, size_bytes FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
        params![root_key, directory, session.filename], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
    if let Some((owner, _)) = previous {
        anyhow::ensure!(
            owner == user_id,
            "Only the file owner can replace an existing shared file"
        );
    }
    let old_size = previous.map(|(_, size)| size.max(0) as u64).unwrap_or(0);
    let new_size = session.size as u64;
    let growth = new_size.saturating_sub(old_size);
    transaction(conn, || {
        reserve(conn, user_id, growth)?;
        conn.execute("INSERT INTO fileshare_objects(storage_root,directory,filename,user_id,size_bytes) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(storage_root,directory,filename) DO UPDATE SET user_id=excluded.user_id,size_bytes=excluded.size_bytes", params![root_key,directory,session.filename,user_id,new_size as i64])?;
        Ok(())
    })?;
    // Keep the quota charged if the process stops here. A refresh reconciles
    // the ledger with disk. A failed publication refunds only its own reserve.
    let published = if let Some(original) = session.original {
        session.pending.commit_replace(&original)
    } else {
        session.pending.commit()
    };
    if let Err(error) = published {
        transaction(conn, || {
            release(conn, user_id, growth)?;
            if let Some((owner, size)) = previous {
                conn.execute("UPDATE fileshare_objects SET user_id=?4,size_bytes=?5 WHERE storage_root=?1 AND directory=?2 AND filename=?3", params![root_key,directory,session.filename,owner,size])?;
            } else {
                conn.execute("DELETE FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3", params![root_key,directory,session.filename])?;
            }
            Ok(())
        })?;
        return Err(error.into());
    }
    release(conn, user_id, old_size.saturating_sub(new_size))?;
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
    let previous: Option<(i64,i64)> = conn.query_row("SELECT user_id,size_bytes FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3", params![root_key,directory,filename], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
    browser.remove(filename)?;
    transaction(conn, || {
        if let Some((owner, size)) = previous {
            release(conn, owner, size.max(0) as u64)?;
        }
        conn.execute(
            "DELETE FROM fileshare_objects WHERE storage_root=?1 AND directory=?2 AND filename=?3",
            params![root_key, directory, filename],
        )?;
        Ok(())
    })
}

// Reconcile durable reservations after an interrupted publication or an
// operator's out-of-band removal; never follow a stored path through symlinks.
fn shared_usage(
    conn: &rusqlite::Connection,
    user_id: i64,
    scanned: &[PathBuf],
) -> anyhow::Result<u64> {
    let mut stmt = conn.prepare(
        "SELECT storage_root,directory,filename FROM fileshare_objects WHERE user_id=?1",
    )?;
    let entries = stmt.query_map([user_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut total = 0u64;
    for entry in entries {
        let (root, directory, filename) = entry?;
        let actual = (|| -> std::io::Result<u64> {
            let browser = af_files::BrowserFs::open(StdPath::new(&root))?.scoped(&directory)?;
            Ok(browser.open_file(&filename)?.metadata()?.len())
        })();
        let size = match actual {
            Ok(size) => size,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        conn.execute("UPDATE fileshare_objects SET size_bytes=?4 WHERE storage_root=?1 AND directory=?2 AND filename=?3",params![root,directory,filename,i64::try_from(size)?])?;
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

async fn run_quota_operation(
    user_id: i64,
    requested: Option<i64>,
) -> anyhow::Result<UserQuotaRecord> {
    let _shared = MUTATIONS.clone().lock_owned().await;
    let _user = crate::mcbrowser::user_mutation_stripe(user_id)
        .lock_owned()
        .await;
    let username = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let conn = af_db::get_conn()?;
        ensure_no_reserved_uploads(&conn, user_id)?;
        Ok(
            conn.query_row("SELECT username FROM users WHERE id=?1", [user_id], |row| {
                row.get(0)
            })?,
        )
    })
    .await??;
    let usage = af_runner::quota::dispatch(&af_runner::quota::UsageRequest {
        username: username.clone(),
        user_id,
    })
    .await?;
    let effective = requested.map(|bytes| ((bytes as u64).div_ceil(1024) * 1024) as i64);
    if let Some(bytes) = effective {
        af_runner::dispatch_set_quota(&username, &format!("{bytes}B")).await?;
    }
    tokio::task::spawn_blocking(move || -> anyhow::Result<UserQuotaRecord> {
        let conn=af_db::get_conn()?;
        let used=usage.used_bytes.checked_add(shared_usage(&conn,user_id,&usage.scanned_roots)?).ok_or_else(||anyhow::anyhow!("Storage usage overflow"))?;
        let used=i64::try_from(used)?;
        conn.execute("INSERT INTO user_quotas(user_id,username,quota_bytes,used_bytes,status,source,updated_at) VALUES(?1,?2,COALESCE(?3,0),?4,'active','manual',CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,quota_bytes=COALESCE(?3,user_quotas.quota_bytes),used_bytes=?4,updated_at=CURRENT_TIMESTAMP",params![user_id,username,effective,used])?;
        drop(conn);
        query_user_quota_record(user_id)
    }).await?
}

pub(super) async fn quota_operation(user_id: i64, requested: Option<i64>) -> Response {
    if requested.is_some_and(|bytes| bytes > i64::MAX - 1023) {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Quota is too large");
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
            tracing::warn!(%error,user_id,"Quota operation did not complete; host application may require reconciliation");
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
}
