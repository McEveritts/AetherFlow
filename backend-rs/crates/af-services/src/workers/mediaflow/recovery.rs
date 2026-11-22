use super::*;

pub(in crate::workers) fn cleanup_stranded_mediaflow_temps(dir: &Path, job_id: i64) {
    let Ok(dmeta) = fs::symlink_metadata(dir) else {
        return;
    };
    if !dmeta.is_dir() {
        return;
    }

    #[cfg(unix)]
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    };
    #[cfg(unix)]
    let pinned_dir = {
        let Ok(pinned) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(dir)
        else {
            return;
        };
        if !pinned
            .metadata()
            .is_ok_and(|meta| meta.dev() == dmeta.dev() && meta.ino() == dmeta.ino())
        {
            return;
        }
        pinned
    };
    #[cfg(unix)]
    let owner = unsafe { libc::geteuid() };

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let basename = entry.file_name();
        let Some(name) = basename.to_str() else {
            continue;
        };
        if !is_mediaflow_temp_name(name, job_id) {
            continue;
        }

        #[cfg(unix)]
        {
            let dirfd = pinned_dir.as_raw_fd();
            if fstatat_nofollow(dirfd, name).is_ok_and(|meta| {
                meta.st_mode & libc::S_IFMT == libc::S_IFREG
                    && meta.st_uid == owner
                    && meta.st_nlink == 1
            }) {
                unlinkat_entry(dirfd, name);
            }
        }
        #[cfg(not(unix))]
        if entry.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

pub(in crate::workers) fn is_mediaflow_temp_name(name: &str, job_id: i64) -> bool {
    // Support the ID-only name and the simple UUID suffix used by the current writer.
    let prefix = format!(".tmp_mediaflow_{job_id}");
    name.strip_prefix(&prefix)
        .and_then(|tail| tail.strip_suffix(".mkv"))
        .is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.strip_prefix('_').is_some_and(|nonce| {
                    nonce.len() == 32
                        && nonce
                            .bytes()
                            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                })
        })
}

pub(in crate::workers) fn prune_mediaflow_trash_dir(trash_dir: &Path, retention: Duration) {
    let Ok(tmeta) = fs::symlink_metadata(trash_dir) else {
        return;
    };
    if tmeta.file_type().is_symlink() || !tmeta.is_dir() {
        return;
    }
    let now_unix = Utc::now().timestamp();
    let retention_secs = retention.as_secs();
    let Ok(entries) = fs::read_dir(trash_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if fname.starts_with(".publish_intent_") || fname.starts_with(".tmp_meta_") {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            continue;
        }
        if let Some(base_entry) = fname.strip_suffix(".meta.json") {
            let companion_media = trash_dir.join(base_entry);
            if fs::symlink_metadata(&companion_media).is_err() {
                let _ = fs::remove_file(&path);
            }
            continue;
        }

        let meta_path = trash_dir.join(trash_meta_filename(fname));
        let Some(meta_rec) = read_regular_json_bounded::<MediaflowTrashMeta>(&meta_path) else {
            // Never prune a trashed media original without a verified trashed_at_unix record!
            continue;
        };
        if meta_rec.trashed_at_unix <= 0 || now_unix < meta_rec.trashed_at_unix {
            continue;
        }
        let age_secs = (now_unix - meta_rec.trashed_at_unix) as u64;
        if age_secs >= retention_secs {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(&meta_path);
        }
    }
}

pub(super) async fn persist_mediaflow_completion_with_retry(
    job_id: i64,
    out_str: &str,
    new_size: i64,
) -> Result<(), String> {
    let mut backoff_ms = 20u64;
    let mut last_err = String::new();
    for attempt in 0..5 {
        match af_db::get_conn() {
            Ok(conn) => {
                match conn.execute(
                    "UPDATE mediaflow_queue SET status = 'COMPLETED', file_path = ?1, new_codec = 'hevc', new_size = ?2, error_log = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?3 AND status = 'PROCESSING'",
                    params![out_str, new_size, job_id],
                ) {
                    Ok(1) => return Ok(()),
                    Ok(0) => {
                        return Err(
                            "Job row was no longer in PROCESSING state during completion commit"
                                .to_string(),
                        )
                    }
                    Ok(_) => return Ok(()),
                    Err(err) => last_err = err.to_string(),
                }
            }
            Err(err) => last_err = err.to_string(),
        }
        if attempt < 4 {
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = backoff_ms.saturating_mul(2);
        }
    }
    Err(last_err)
}

#[cfg(unix)]
pub(in crate::workers) fn rollback_interrupted_publication(
    raw_path: &str,
    roots: &[PathBuf],
    expected_source: &str,
    intent: &MediaflowPublishIntent,
    output: &MediaflowPublishedOutput,
) -> Result<bool, String> {
    use std::io::ErrorKind;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    if expected_source.is_empty() || intent.source_fingerprint != expected_source {
        return Ok(false);
    }
    let Ok(source) = open_and_pin_mediaflow_source_in_roots(raw_path, roots) else {
        return Ok(false);
    };
    let output_name = mediaflow_output_name(&source.canon_src);
    if source.identity.fingerprint != expected_source
        || Path::new(&intent.published_path) != source.canon_parent.join(&output_name)
        || !is_mediaflow_temp_name(&output.temp_name, intent.job_id)
    {
        return Ok(false);
    }
    let dirfd = source.parent_dir.as_raw_fd();
    let published = match fstatat_nofollow(dirfd, &output_name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            // A previous recovery may have unlinked the output before persisting it.
            source
                .parent_dir
                .sync_all()
                .map_err(|err| err.to_string())?;
            return Ok(true);
        }
        Err(error) => return Err(error.to_string()),
    };
    if published.st_nlink != 2
        || !output.matches_entry(&published)
        || !fstatat_nofollow(dirfd, &output.temp_name).is_ok_and(|stat| output.matches_entry(&stat))
    {
        return Ok(false);
    }

    let output_c = cstring_from_os_name(&output_name, "published output")?;
    let fd = unsafe {
        libc::openat(
            dirfd,
            output_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    if MediaflowPublishedOutput::capture(&file, output.temp_name.clone())? != *output
        || source.verify_still_matches_live().is_err()
        || !fstatat_nofollow(dirfd, &output_name)
            .is_ok_and(|stat| output.matches_entry(&stat) && stat.st_nlink == 2)
        || !fstatat_nofollow(dirfd, &output.temp_name).is_ok_and(|stat| output.matches_entry(&stat))
    {
        return Ok(false);
    }

    // The still-pinned original and both links prove this file belongs to the
    // interrupted attempt. Remove the visible link before clearing its intent.
    if unsafe { libc::unlinkat(dirfd, output_c.as_ptr(), 0) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    source
        .parent_dir
        .sync_all()
        .map_err(|err| err.to_string())?;
    cleanup_stranded_mediaflow_temps(&source.canon_parent, intent.job_id);
    Ok(true)
}

pub(in crate::workers) fn mediaflow_output_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("output");
    format!("{stem}_hevc.mkv")
}

/// Reconciles any `PROCESSING` MediaFlow jobs stranded by a prior crash/restart:
/// - If a durable `.publish_intent_<job_id>.json` exists and both the published output and
///   trashed original exist on disk, finalizes the SQLite row to `COMPLETED` and removes the intent.
/// - Rolls back proven partial publications and moves the job to `NEEDS_RESCAN` for approval again.
/// - Otherwise marks stranded `PROCESSING` rows as `FAILED`.
/// - Marks legacy `PENDING_APPROVAL` / `APPROVED` rows missing persisted source identity as
///   `NEEDS_RESCAN` so operators re-scan and re-approve safely.
/// - Removes scratch files for interrupted jobs and genuinely expired `.mediaflow_trash` entries.
pub fn reconcile_mediaflow_startup() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let mut candidate_dirs: HashSet<PathBuf> = HashSet::new();
    if let Ok(mut stmt) = conn.prepare("SELECT file_path FROM mediaflow_queue") {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            for path_str in rows.flatten() {
                if let Some(parent) = Path::new(&path_str).parent() {
                    if parent.is_absolute() {
                        candidate_dirs.insert(parent.to_path_buf());
                    }
                }
            }
        }
    }

    let roots = mediaflow_allowed_roots();
    let mut processing_rows = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, file_path, COALESCE(source_fingerprint, '') FROM mediaflow_queue WHERE status = 'PROCESSING'",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        }) {
            processing_rows.extend(rows.flatten());
        }
    }

    let now_unix = Utc::now().timestamp();
    #[allow(unused_mut)]
    let mut deferred = Vec::<i64>::new();
    for (job_id, raw_path, _source_fingerprint) in processing_rows {
        let Some(parent) = Path::new(&raw_path).parent() else {
            continue;
        };
        if !parent.is_absolute() {
            continue;
        }
        let Ok(canon_dir) = fs::canonicalize(parent) else {
            continue;
        };
        if !is_path_within_allowed_mediaflow_roots(&canon_dir, &roots) {
            continue;
        }
        if parent == canon_dir.as_path() {
            cleanup_stranded_mediaflow_temps(&canon_dir, job_id);
        }
        let trash_dir = canon_dir.join(".mediaflow_trash");
        let intent_path = trash_dir.join(publish_intent_filename(job_id));
        let Some(intent) = read_regular_json_bounded::<MediaflowPublishIntent>(&intent_path) else {
            continue;
        };
        if intent.job_id != job_id
            || intent.trash_entry_name.contains('/')
            || intent.trash_entry_name.is_empty()
        {
            let _ = fs::remove_file(&intent_path);
            continue;
        }

        #[cfg(unix)]
        if let Some(output) = &intent.output {
            match rollback_interrupted_publication(
                &raw_path,
                &roots,
                &_source_fingerprint,
                &intent,
                output,
            ) {
                Ok(true) => {
                    let persisted = conn.execute(
                        "UPDATE mediaflow_queue SET status = 'NEEDS_RESCAN',
                         error_log = 'Publication was interrupted. Rescan to approve another attempt.',
                         updated_at = CURRENT_TIMESTAMP WHERE id = ?1 AND status = 'PROCESSING'",
                        params![job_id],
                    );
                    if persisted.is_ok_and(|affected| affected == 1) {
                        let _ = fs::remove_file(&intent_path);
                    } else {
                        deferred.push(job_id);
                    }
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(job_id, %error, "MediaFlow publication recovery needs a retry");
                    deferred.push(job_id);
                    continue;
                }
            }
        }

        let pub_path = Path::new(&intent.published_path);
        let pub_valid = pub_path.parent() == Some(canon_dir.as_path())
            && fs::symlink_metadata(pub_path)
                .ok()
                .is_some_and(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0);
        let trashed_path = trash_dir.join(&intent.trash_entry_name);
        let trash_valid = fs::symlink_metadata(&trashed_path)
            .ok()
            .is_some_and(|m| !m.file_type().is_symlink() && m.is_file());

        if pub_valid && trash_valid {
            let actual_size = fs::symlink_metadata(pub_path)
                .map(|m| m.len() as i64)
                .unwrap_or(intent.new_size)
                .max(intent.new_size);
            if conn
                .execute(
                    "UPDATE mediaflow_queue SET status = 'COMPLETED', file_path = ?1, new_codec = 'hevc', new_size = ?2, error_log = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?3 AND status = 'PROCESSING'",
                    params![intent.published_path, actual_size, job_id],
                )
                .is_ok_and(|affected| affected == 1)
            {
                let meta_path = trash_dir.join(trash_meta_filename(&intent.trash_entry_name));
                if read_regular_json_bounded::<MediaflowTrashMeta>(&meta_path).is_none() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::ffi::OsStrExt;
                        use std::os::unix::io::{AsRawFd, FromRawFd};
                        if let Ok(c_trash) =
                            std::ffi::CString::new(trash_dir.as_os_str().as_bytes())
                        {
                            let raw_fd = unsafe {
                                libc::open(
                                    c_trash.as_ptr(),
                                    libc::O_RDONLY
                                        | libc::O_DIRECTORY
                                        | libc::O_NOFOLLOW
                                        | libc::O_CLOEXEC,
                                )
                            };
                            if raw_fd >= 0 {
                                let tf = unsafe { fs::File::from_raw_fd(raw_fd) };
                                let orig_name = Path::new(&raw_path)
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("");
                                let _ = persist_trash_entry_metadata_dirfd(
                                    tf.as_raw_fd(),
                                    &intent.trash_entry_name,
                                    job_id,
                                    orig_name,
                                    now_unix,
                                );
                            }
                        }
                    }
                }
                let _ = fs::remove_file(&intent_path);
                tracing::info!(
                    job_id = job_id,
                    published_path = %intent.published_path,
                    "mediaflow: reconciled completed transcode from durable publish intent on startup"
                );
            }
        } else {
            let _ = fs::remove_file(&intent_path);
        }
    }

    let stranded = conn
        .execute(
            "UPDATE mediaflow_queue SET status = 'FAILED', error_log = 'Interrupted by service restart', updated_at = CURRENT_TIMESTAMP
             WHERE status = 'PROCESSING' AND id NOT IN (SELECT value FROM json_each(?1))",
            params![serde_json::json!(deferred).to_string()],
        )
        .unwrap_or(0);
    if stranded > 0 {
        tracing::warn!(
            stranded_jobs = stranded,
            "mediaflow: marked stranded PROCESSING job(s) as FAILED after service restart"
        );
    }

    let legacy_invalidated = conn
        .execute(
            "UPDATE mediaflow_queue
             SET status = 'NEEDS_RESCAN',
                 error_log = ?1,
                 updated_at = CURRENT_TIMESTAMP
             WHERE status IN ('PENDING_APPROVAL', 'APPROVED')
               AND (
                   source_dev IS NULL
                   OR source_ino IS NULL
                   OR source_size IS NULL
                   OR source_mtime_sec IS NULL
                   OR source_mtime_nsec IS NULL
                   OR COALESCE(source_fingerprint, '') = ''
               )",
            params![MEDIAFLOW_MISSING_IDENTITY_MSG],
        )
        .unwrap_or(0);
    if legacy_invalidated > 0 {
        tracing::warn!(
            legacy_jobs = legacy_invalidated,
            "mediaflow: transitioned legacy identity-less queue job(s) to NEEDS_RESCAN on startup"
        );
    }

    let retention = mediaflow_trash_retention();
    for dir in candidate_dirs {
        let Ok(canon_dir) = fs::canonicalize(&dir) else {
            continue;
        };
        if !is_path_within_allowed_mediaflow_roots(&canon_dir, &roots) {
            continue;
        }
        prune_mediaflow_trash_dir(&canon_dir.join(".mediaflow_trash"), retention);
    }
}

/// Spawns the background MediaFlow worker poller (10-second interval) that picks up
/// `APPROVED` items in `mediaflow_queue`, transitions them to `PROCESSING`, invokes
/// `ffmpeg` with hardware transcode flags from [`af_hardware::get_gpu_transcode_flags()`],
/// and updates the row to `COMPLETED`, `FAILED`, `CANCELLED`, or `NEEDS_RESCAN`.
pub fn start_mediaflow_poller() {
    if MEDIAFLOW_POLLER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    tokio::spawn(async move {
        reconcile_mediaflow_startup();
        tracing::info!(
            interval_secs = 10,
            "mediaflow autonomous transcode poller initialized"
        );

        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let _ = process_next_mediaflow_job().await;
        }
    });
}
