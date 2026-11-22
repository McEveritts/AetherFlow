use super::*;

struct ClaimedMediaflowJob {
    id: i64,
    file_path: String,
    expected_identity: Option<MediaflowSourceIdentity>,
}

struct AbortOnDrop(Option<tokio::task::AbortHandle>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

struct TempOutputGuard<'a> {
    #[cfg(unix)]
    dirfd: std::os::unix::io::RawFd,
    #[cfg(unix)]
    temp_fname: &'a str,
    #[cfg(not(unix))]
    temp_output: &'a Path,
    active: bool,
}

impl<'a> TempOutputGuard<'a> {
    fn cleanup_now(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        #[cfg(unix)]
        unlinkat_entry(self.dirfd, self.temp_fname);
        #[cfg(not(unix))]
        let _ = fs::remove_file(self.temp_output);
    }
}

impl Drop for TempOutputGuard<'_> {
    fn drop(&mut self) {
        self.cleanup_now();
    }
}

fn is_job_still_processing(job_id: i64) -> bool {
    af_db::get_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row(
                "SELECT status FROM mediaflow_queue WHERE id = ?1",
                params![job_id],
                |r| r.get::<_, String>(0),
            )
            .ok()
        })
        .is_some_and(|status| status == "PROCESSING")
}

/// Processes a single `APPROVED` job from `mediaflow_queue` if one exists and no job
/// is currently running. Returns `true` if a job was picked up and processed.
pub async fn process_next_mediaflow_job() -> bool {
    use tokio::io::{AsyncBufReadExt, BufReader};

    if MEDIAFLOW_PROCESSING.swap(true, Ordering::SeqCst) {
        return false;
    }

    struct ProcessingGuard;
    impl Drop for ProcessingGuard {
        fn drop(&mut self) {
            MEDIAFLOW_PROCESSING.store(false, Ordering::SeqCst);
        }
    }
    let _guard = ProcessingGuard;

    let job_opt: Option<ClaimedMediaflowJob> = {
        let Ok(conn) = af_db::get_conn() else {
            return false;
        };
        let Ok(row) = conn.query_row(
            "SELECT id, file_path, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, COALESCE(source_fingerprint, '')
             FROM mediaflow_queue
             WHERE status = 'APPROVED'
             ORDER BY created_at ASC, id ASC
             LIMIT 1",
            [],
            |r| {
                let id = r.get::<_, i64>(0)?;
                let file_path = r.get::<_, String>(1)?;
                let expected_identity = parse_stored_mediaflow_identity(
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, Option<String>>(7)?.as_deref(),
                );
                Ok(ClaimedMediaflowJob {
                    id,
                    file_path,
                    expected_identity,
                })
            },
        ) else {
            return false;
        };
        match conn.execute(
            "UPDATE mediaflow_queue SET status = 'PROCESSING', updated_at = CURRENT_TIMESTAMP WHERE id = ?1 AND status = 'APPROVED'",
            params![row.id],
        ) {
            Ok(1) => Some(row),
            _ => None,
        }
    };

    let Some(job) = job_opt else {
        return false;
    };
    let job_id = job.id;
    let file_path = job.file_path;

    let (_active_job_guard, mut cancel_rx) = register_active_mediaflow_job(job_id);

    let Some(expected_identity) = job.expected_identity else {
        record_mediaflow_needs_rescan(job_id, MEDIAFLOW_MISSING_IDENTITY_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "needs_rescan",
            "file": file_path,
            "progress": 0,
            "message": MEDIAFLOW_MISSING_IDENTITY_MSG,
        }));
        return true;
    };

    let pinned = match open_and_pin_mediaflow_source(&file_path) {
        Ok(valid) => valid,
        Err(reason) => {
            let needs_rescan = reason.contains("does not exist")
                || reason.contains("symlink")
                || reason.contains("hard-linked")
                || reason.contains("regular file")
                || reason.contains("changed concurrently");
            if needs_rescan {
                let msg = format!("{reason}; re-scan and re-approve before transcoding");
                record_mediaflow_needs_rescan(job_id, &msg);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "needs_rescan",
                    "file": file_path,
                    "progress": 0,
                    "message": msg,
                }));
            } else {
                record_mediaflow_failure(job_id, &reason);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "failed",
                    "file": file_path,
                    "progress": 0,
                    "message": reason,
                }));
            }
            return true;
        }
    };

    if pinned.identity != expected_identity {
        record_mediaflow_needs_rescan(job_id, MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "needs_rescan",
            "file": file_path,
            "progress": 0,
            "message": MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG,
        }));
        return true;
    }

    if *cancel_rx.borrow() || !is_job_still_processing(job_id) {
        record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "cancelled",
            "file": file_path,
            "progress": 0,
            "message": "Transcode cancelled",
        }));
        return true;
    }

    let src_path = &pinned.canon_src;
    let parent_dir = &pinned.canon_parent;

    let flags = af_hardware::get_gpu_transcode_flags();
    let out_fname = mediaflow_output_name(src_path);
    let out_path = parent_dir.join(&out_fname);
    if fs::symlink_metadata(&out_path).is_ok() {
        let msg = format!(
            "Refusing to clobber existing output file: {}",
            out_path.display()
        );
        record_mediaflow_failure(job_id, &msg);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "failed",
            "file": file_path,
            "progress": 0,
            "message": msg,
        }));
        return true;
    }

    let temp_fname = format!(
        ".tmp_mediaflow_{}_{}.mkv",
        job_id,
        uuid::Uuid::new_v4().simple()
    );
    let temp_output = parent_dir.join(&temp_fname);

    #[cfg(unix)]
    let (temp_dev, temp_ino) = {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let temp_cstr = match cstring_from_os_name(&temp_fname, "temporary output filename") {
            Ok(c) => c,
            Err(msg) => {
                record_mediaflow_failure(job_id, &msg);
                return true;
            }
        };
        let tfd = unsafe {
            libc::openat(
                pinned.parent_dir.as_raw_fd(),
                temp_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if tfd < 0 {
            let msg = format!(
                "Failed to create exclusive temporary output file: {}",
                std::io::Error::last_os_error()
            );
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
            return true;
        }
        let temp_file = unsafe { fs::File::from_raw_fd(tfd) };
        match temp_file.metadata() {
            Ok(meta) => (meta.dev(), meta.ino()),
            Err(err) => {
                drop(temp_file);
                unlinkat_entry(pinned.parent_dir.as_raw_fd(), &temp_fname);
                let msg = format!("Failed to inspect temporary output file: {err}");
                record_mediaflow_failure(job_id, &msg);
                return true;
            }
        }
    };

    #[cfg(not(unix))]
    if let Err(err) = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_output)
    {
        let msg = format!("Failed to create exclusive temporary output file: {err}");
        record_mediaflow_failure(job_id, &msg);
        return true;
    }

    #[cfg(unix)]
    let mut temp_guard = {
        use std::os::unix::io::AsRawFd;
        TempOutputGuard {
            dirfd: pinned.parent_dir.as_raw_fd(),
            temp_fname: &temp_fname,
            active: true,
        }
    };
    #[cfg(not(unix))]
    let mut temp_guard = TempOutputGuard {
        temp_output: &temp_output,
        active: true,
    };

    let mut args: Vec<String> = vec!["-nostdin".to_string(), "-y".to_string()];
    if !flags.hw_accel.is_empty() && flags.hw_accel != "none" {
        args.push("-hwaccel".to_string());
        args.push(flags.hw_accel.clone());
        if !flags.hw_accel_device.is_empty() {
            args.push("-hwaccel_device".to_string());
            args.push(flags.hw_accel_device.clone());
        }
        if !flags.output_format.is_empty() {
            args.push("-hwaccel_output_format".to_string());
            args.push(flags.output_format.clone());
        }
    }

    let video_codec = if flags.video_codec.trim().is_empty() {
        "libx265"
    } else {
        flags.video_codec.trim()
    };

    #[cfg(unix)]
    let (input_uri, child_pinned_fd) = {
        use std::os::unix::io::AsRawFd;
        let raw_fd = pinned.source_file.as_raw_fd();
        if cfg!(target_os = "linux") && Path::new("/proc/self/fd").is_dir() {
            (format!("file:/proc/self/fd/{raw_fd}"), Some(raw_fd))
        } else {
            (format!("file:{}", src_path.to_string_lossy()), None)
        }
    };
    #[cfg(not(unix))]
    let input_uri = format!("file:{}", src_path.to_string_lossy());

    args.extend([
        "-i".to_string(),
        input_uri.clone(),
        "-map".to_string(),
        "0".to_string(),
        "-c:v".to_string(),
        video_codec.to_string(),
        "-b:v".to_string(),
        "5M".to_string(),
        "-c:a".to_string(),
        "copy".to_string(),
        "-c:s".to_string(),
        "copy".to_string(),
        "-nostats".to_string(),
        "-progress".to_string(),
        "pipe:1".to_string(),
        format!("file:{}", temp_output.to_string_lossy()),
    ]);

    tracing::info!(
        job_id = job_id,
        file_path = %file_path,
        codec = %video_codec,
        fingerprint = %pinned.identity.fingerprint,
        "mediaflow: starting transcode job"
    );
    publish_mediaflow_progress(&serde_json::json!({
        "status": "running",
        "file": file_path,
        "progress": 0,
        "message": "Starting transcode",
    }));

    #[cfg(unix)]
    let duration_secs = probe_mediaflow_duration_secs(&input_uri, child_pinned_fd).await;
    #[cfg(not(unix))]
    let duration_secs = probe_mediaflow_duration_secs(&input_uri).await;

    if *cancel_rx.borrow() || !is_job_still_processing(job_id) {
        temp_guard.cleanup_now();
        record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "cancelled",
            "file": file_path,
            "progress": 0,
            "message": "Transcode cancelled",
        }));
        return true;
    }

    let timeout = mediaflow_transcode_timeout();

    let mut cmd = Command::new("ffmpeg");
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    if let Some(raw_fd) = child_pinned_fd {
        unsafe {
            cmd.pre_exec(move || {
                let flags = libc::fcntl(raw_fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(raw_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            temp_guard.cleanup_now();
            let msg = format!("FFmpeg execution error: {}", err);
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
            return true;
        }
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let progress_file = file_path.clone();

    let stdout_task = tokio::spawn(async move {
        let Some(stdout) = stdout_pipe else {
            return;
        };
        let mut lines = BufReader::new(stdout).lines();
        let mut out_time_secs: f64 = 0.0;
        let mut last_pct: i32 = -1;
        let mut last_emit = Instant::now() - Duration::from_secs(10);
        while let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim();
            if let Some(val) = trimmed
                .strip_prefix("out_time_us=")
                .or_else(|| trimmed.strip_prefix("out_time_ms="))
            {
                if let Ok(us) = val.parse::<i64>() {
                    out_time_secs = (us.max(0) as f64) / 1_000_000.0;
                }
            } else if trimmed == "progress=continue" || trimmed == "progress=end" {
                let pct = duration_secs
                    .filter(|&d| d > 0.0)
                    .map(|d| ((out_time_secs / d) * 100.0).clamp(0.0, 99.0) as i32)
                    .unwrap_or(0);
                if pct != last_pct || last_emit.elapsed() >= Duration::from_secs(2) {
                    last_pct = pct;
                    last_emit = Instant::now();
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "running",
                        "file": progress_file,
                        "progress": pct,
                        "message": if duration_secs.is_some() {
                            format!("Transcoding ({pct}%)")
                        } else {
                            format!("Transcoding ({out_time_secs:.1}s)")
                        },
                    }));
                }
            }
        }
    });

    let stderr_task = tokio::spawn(async move {
        let Some(stderr) = stderr_pipe else {
            return String::new();
        };
        drain_stderr_bounded(stderr, 16 * 1024, 48 * 1024).await
    });

    let mut stdout_abort = AbortOnDrop(Some(stdout_task.abort_handle()));
    let mut stderr_abort = AbortOnDrop(Some(stderr_task.abort_handle()));

    enum WaitSignal {
        Exited(std::io::Result<std::process::ExitStatus>),
        Cancelled,
        TimedOut,
    }

    enum FfmpegOutcome {
        Exited(std::io::Result<std::process::ExitStatus>, String),
        Cancelled,
        TimedOut,
    }

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    let wait_signal = tokio::select! {
        biased;
        _ = wait_for_mediaflow_cancel(&mut cancel_rx) => WaitSignal::Cancelled,
        status = child.wait() => WaitSignal::Exited(status),
        _ = &mut deadline => WaitSignal::TimedOut,
    };

    let outcome = match wait_signal {
        WaitSignal::Exited(status) => {
            let _ = stdout_task.await;
            let stderr_text = stderr_task.await.unwrap_or_default();
            stdout_abort.0 = None;
            stderr_abort.0 = None;
            FfmpegOutcome::Exited(status, stderr_text)
        }
        WaitSignal::Cancelled => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            drop(stdout_abort);
            drop(stderr_abort);
            FfmpegOutcome::Cancelled
        }
        WaitSignal::TimedOut => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            drop(stdout_abort);
            drop(stderr_abort);
            FfmpegOutcome::TimedOut
        }
    };

    match outcome {
        FfmpegOutcome::Exited(Ok(status), _stderr_text) if status.success() => {
            #[cfg(unix)]
            let temp_size = {
                use std::os::unix::io::AsRawFd;
                let dirfd = pinned.parent_dir.as_raw_fd();
                match fstatat_nofollow(dirfd, &temp_fname) {
                    Ok(st)
                        if (st.st_mode & libc::S_IFMT) == libc::S_IFREG
                            && st.st_dev == temp_dev
                            && st.st_ino == temp_ino =>
                    {
                        st.st_size.max(0) as u64
                    }
                    _ => 0,
                }
            };
            #[cfg(not(unix))]
            let temp_size = fs::symlink_metadata(&temp_output)
                .ok()
                .filter(|m| !m.file_type().is_symlink() && m.file_type().is_file())
                .map(|m| m.len())
                .unwrap_or(0);

            if temp_size == 0 {
                temp_guard.cleanup_now();
                let msg = "FFmpeg exited cleanly but produced an empty or missing output file";
                record_mediaflow_failure(job_id, msg);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "failed",
                    "file": file_path,
                    "progress": 0,
                    "message": msg,
                }));
                return true;
            }

            if !try_begin_mediaflow_publication(job_id) || !is_job_still_processing(job_id) {
                temp_guard.cleanup_now();
                record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "cancelled",
                    "file": file_path,
                    "progress": 0,
                    "message": "Transcode cancelled",
                }));
                return true;
            }

            let new_size = temp_size as i64;
            let out_str = out_path.to_string_lossy().to_string();
            let intent_fname = publish_intent_filename(job_id);

            if let Err(conflict_msg) = pinned.verify_still_matches_live() {
                temp_guard.cleanup_now();
                record_mediaflow_failure(job_id, &conflict_msg);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "failed",
                    "file": file_path,
                    "progress": 0,
                    "message": conflict_msg,
                }));
                return true;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                use std::os::unix::io::{AsRawFd, FromRawFd};

                let dirfd = pinned.parent_dir.as_raw_fd();

                // Set published permissions (e.g. 0644 / 0664, never suid/sgid/exec) on the
                // verified temporary output inode before hard-linking it into the media library.
                let temp_c = std::ffi::CString::new(temp_fname.as_bytes()).unwrap();
                let output = {
                    let chmod_fd = unsafe {
                        libc::openat(
                            dirfd,
                            temp_c.as_ptr(),
                            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if chmod_fd < 0 {
                        temp_guard.cleanup_now();
                        let msg = format!(
                            "Failed opening temporary output for chmod: {}",
                            std::io::Error::last_os_error()
                        );
                        record_mediaflow_failure(job_id, &msg);
                        publish_mediaflow_progress(&serde_json::json!({
                            "status": "failed",
                            "file": file_path,
                            "progress": 0,
                            "message": msg,
                        }));
                        return true;
                    }
                    let chmod_file = unsafe { fs::File::from_raw_fd(chmod_fd) };
                    let meta_ok = chmod_file
                        .metadata()
                        .is_ok_and(|m| m.is_file() && m.dev() == temp_dev && m.ino() == temp_ino);
                    if !meta_ok {
                        drop(chmod_file);
                        temp_guard.cleanup_now();
                        let msg = "Temporary output inode changed unexpectedly before publication";
                        record_mediaflow_failure(job_id, msg);
                        publish_mediaflow_progress(&serde_json::json!({
                            "status": "failed",
                            "file": file_path,
                            "progress": 0,
                            "message": msg,
                        }));
                        return true;
                    }
                    let pub_mode = compute_published_media_mode(pinned.src_mode);
                    if unsafe { libc::fchmod(chmod_file.as_raw_fd(), pub_mode) } < 0 {
                        let err = std::io::Error::last_os_error();
                        drop(chmod_file);
                        temp_guard.cleanup_now();
                        let msg = format!("Failed applying permissions to output file: {err}");
                        record_mediaflow_failure(job_id, &msg);
                        publish_mediaflow_progress(&serde_json::json!({
                            "status": "failed",
                            "file": file_path,
                            "progress": 0,
                            "message": msg,
                        }));
                        return true;
                    }
                    match chmod_file
                        .sync_all()
                        .map_err(|error| error.to_string())
                        .and_then(|()| {
                            MediaflowPublishedOutput::capture(&chmod_file, temp_fname.clone())
                        }) {
                        Ok(output) => output,
                        Err(error) => {
                            temp_guard.cleanup_now();
                            record_mediaflow_failure(job_id, &error);
                            return true;
                        }
                    }
                };

                let trash_cstr = std::ffi::CString::new(".mediaflow_trash").unwrap();
                unsafe {
                    if libc::mkdirat(dirfd, trash_cstr.as_ptr(), 0o755) < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() != std::io::ErrorKind::AlreadyExists {
                            temp_guard.cleanup_now();
                            let msg = format!("Failed to create .mediaflow_trash directory: {err}");
                            record_mediaflow_failure(job_id, &msg);
                            publish_mediaflow_progress(&serde_json::json!({
                                "status": "failed",
                                "file": file_path,
                                "progress": 0,
                                "message": msg,
                            }));
                            return true;
                        }
                    }
                }
                let raw_trash_fd = unsafe {
                    libc::openat(
                        dirfd,
                        trash_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw_trash_fd < 0 {
                    temp_guard.cleanup_now();
                    let msg = "Refusing symlink or non-directory .mediaflow_trash";
                    record_mediaflow_failure(job_id, msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }
                let trash_dir_file = unsafe { fs::File::from_raw_fd(raw_trash_fd) };
                let trash_fd = trash_dir_file.as_raw_fd();

                let mut trash_entry_name = format!("{job_id}_{}", pinned.source_fname);
                if fstatat_nofollow(trash_fd, &trash_entry_name).is_ok() {
                    trash_entry_name = format!(
                        "{job_id}_{}_{}",
                        uuid::Uuid::new_v4().simple(),
                        pinned.source_fname
                    );
                }
                if fstatat_nofollow(trash_fd, &trash_entry_name).is_ok() {
                    temp_guard.cleanup_now();
                    let msg = "Refusing to clobber existing .mediaflow_trash entry";
                    record_mediaflow_failure(job_id, msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }

                // Persist durable publication intent BEFORE executing linkat/renameat swap
                let intent = MediaflowPublishIntent {
                    job_id,
                    published_path: out_str.clone(),
                    trash_entry_name: trash_entry_name.clone(),
                    new_size,
                    source_fingerprint: pinned.identity.fingerprint.clone(),
                    output: Some(output),
                };
                let intent_bytes = match serde_json::to_vec(&intent) {
                    Ok(b) => b,
                    Err(err) => {
                        temp_guard.cleanup_now();
                        let msg = format!("Failed serializing publish intent: {err}");
                        record_mediaflow_failure(job_id, &msg);
                        return true;
                    }
                };
                if let Err(msg) = write_dirfd_json_atomic(trash_fd, &intent_fname, &intent_bytes) {
                    temp_guard.cleanup_now();
                    record_mediaflow_failure(job_id, &msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }

                let out_c = std::ffi::CString::new(out_fname.as_bytes()).unwrap();
                let src_c = std::ffi::CString::new(pinned.source_fname.as_bytes()).unwrap();
                let trash_entry_c = std::ffi::CString::new(trash_entry_name.as_bytes()).unwrap();

                let publish_res = if unsafe {
                    libc::linkat(dirfd, temp_c.as_ptr(), dirfd, out_c.as_ptr(), 0)
                } < 0
                {
                    let err = std::io::Error::last_os_error();
                    Err(format!(
                        "Failed to publish transcoded output without clobbering target: {err}"
                    ))
                } else {
                    let source_still_matches = fstatat_nofollow(dirfd, &pinned.source_fname)
                        .map(|st| pinned.matches_live_stat(&st))
                        .unwrap_or(false);
                    if !source_still_matches {
                        unlinkat_entry(dirfd, &out_fname);
                        Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string())
                    } else if unsafe {
                        libc::renameat(dirfd, src_c.as_ptr(), trash_fd, trash_entry_c.as_ptr())
                    } < 0
                    {
                        let err = std::io::Error::last_os_error();
                        unlinkat_entry(dirfd, &out_fname);
                        Err(format!(
                            "Failed to move original media into .mediaflow_trash: {err}"
                        ))
                    } else {
                        Ok(())
                    }
                };
                temp_guard.cleanup_now();

                if let Err(msg) = publish_res {
                    unlinkat_entry(trash_fd, &intent_fname);
                    drop(trash_dir_file);
                    record_mediaflow_failure(job_id, &msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }

                let now_unix = Utc::now().timestamp();
                if let Err(err) = persist_trash_entry_metadata_dirfd(
                    trash_fd,
                    &trash_entry_name,
                    job_id,
                    &pinned.source_fname,
                    now_unix,
                ) {
                    tracing::warn!(
                        job_id = job_id,
                        trash_entry = %trash_entry_name,
                        error = %err,
                        "mediaflow: failed writing trash metadata sidecar; trashed original will be preserved from pruning"
                    );
                }
                unsafe {
                    let _ = libc::fsync(dirfd);
                }
                drop(trash_dir_file);
            }

            let trash_dir = parent_dir.join(".mediaflow_trash");

            match persist_mediaflow_completion_with_retry(job_id, &out_str, new_size).await {
                Ok(()) => {
                    let _ = fs::remove_file(trash_dir.join(&intent_fname));
                    prune_mediaflow_trash_dir(&trash_dir, mediaflow_trash_retention());
                    tracing::info!(
                        job_id = job_id,
                        output = %out_str,
                        new_size = new_size,
                        "mediaflow: transcode completed"
                    );
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "completed",
                        "file": out_str,
                        "progress": 100,
                        "message": "Transcode completed",
                    }));
                }
                Err(db_err) => {
                    tracing::error!(
                        job_id = job_id,
                        output = %out_str,
                        error = %db_err,
                        "mediaflow: filesystem publication succeeded but SQLite completion update failed after retries; retaining publish intent for startup reconciliation"
                    );
                }
            }
        }
        FfmpegOutcome::Exited(Ok(status), stderr_text) => {
            temp_guard.cleanup_now();
            let err_log = tail_error_log(&stderr_text, 1000);
            let msg = format!("FFmpeg error ({}): {}", status, err_log);
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
        }
        FfmpegOutcome::Exited(Err(err), _) => {
            temp_guard.cleanup_now();
            let msg = format!("FFmpeg execution error: {}", err);
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
        }
        FfmpegOutcome::Cancelled => {
            temp_guard.cleanup_now();
            record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "cancelled",
                "file": file_path,
                "progress": 0,
                "message": "Transcode cancelled",
            }));
        }
        FfmpegOutcome::TimedOut => {
            temp_guard.cleanup_now();
            let msg = format!("FFmpeg timed out after {}s", timeout.as_secs());
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
        }
    }

    drop(temp_guard);
    drop(pinned);
    true
}

pub(in crate::workers) fn tail_error_log(text: &str, max_len: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }
    let mut start = trimmed.len() - max_len;
    while start < trimmed.len() && !trimmed.is_char_boundary(start) {
        start += 1;
    }
    trimmed[start..].to_string()
}

pub(in crate::workers) fn record_mediaflow_failure(job_id: i64, reason: &str) {
    tracing::error!(job_id = job_id, error = %reason, "mediaflow: transcode job failed");
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'FAILED', error_log = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2 AND status = 'PROCESSING'",
            params![reason, job_id],
        );
    }
}

pub(in crate::workers) fn record_mediaflow_needs_rescan(job_id: i64, reason: &str) {
    tracing::warn!(job_id = job_id, reason = %reason, "mediaflow: transcode job requires re-scan/re-review");
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'NEEDS_RESCAN', error_log = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2 AND status = 'PROCESSING'",
            params![reason, job_id],
        );
    }
}

pub(in crate::workers) fn record_mediaflow_cancelled(job_id: i64, reason: &str) {
    tracing::info!(job_id = job_id, reason = %reason, "mediaflow: transcode job cancelled");
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'CANCELLED', error_log = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2 AND status = 'PROCESSING'",
            params![reason, job_id],
        );
    }
}
