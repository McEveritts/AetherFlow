#[cfg(test)]
use super::scan_cursor::{collect_matching_files_paged, run_auto_continuing_scan};
use super::scan_cursor::{
    commit_auto_continuing_scan, mediaflow_library_roots, prepare_auto_continuing_scan,
    validate_mediaflow_directory, PagedScanOutcome, MAX_SCAN_DEPTH, MAX_SCAN_FILES,
};
use crate::auth::api_error;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use rusqlite::{params, OptionalExtension as _};
use std::collections::HashMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Mutex;

pub(super) static MEDIAFLOW_SCAN_CURSORS: Lazy<Mutex<HashMap<PathBuf, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static MEDIAFLOW_SCANNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

static MEDIAFLOW_VIDEO_EXTS: &[&str] = &[".mkv", ".mp4", ".avi", ".mov", ".ts", ".m2ts"];

const MEDIAFLOW_FFPROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

struct MediaflowScanGuard;

impl Drop for MediaflowScanGuard {
    fn drop(&mut self) {
        MEDIAFLOW_SCANNING.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub async fn get_mediaflow_queue() -> Response {
    let conn = match af_db::get_read_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "Database unavailable while fetching MediaFlow queue");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Failed to fetch queue",
            );
        }
    };
    let mut stmt = match conn.prepare(
        "SELECT id, file_path, status, COALESCE(original_codec, ''), COALESCE(original_size, 0), \
         COALESCE(new_codec, ''), COALESCE(new_size, 0), COALESCE(error_log, ''), COALESCE(created_at, ''), \
         source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, COALESCE(source_fingerprint, '') \
         FROM mediaflow_queue WHERE status NOT IN ('DECLINED', 'SUPERSEDED') ORDER BY created_at DESC, id DESC LIMIT 100",
    ) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(%err, "Failed to prepare MediaFlow queue query");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to fetch queue",
            );
        }
    };
    let rows = match stmt.query_map([], |r| {
        let source_dev = r.get::<_, Option<i64>>(9)?;
        let source_ino = r.get::<_, Option<i64>>(10)?;
        let source_size = r.get::<_, Option<i64>>(11)?;
        let source_mtime_sec = r.get::<_, Option<i64>>(12)?;
        let source_mtime_nsec = r.get::<_, Option<i64>>(13)?;
        let source_fingerprint = r.get::<_, String>(14)?;
        let identity_bound = af_services::parse_stored_mediaflow_identity(
            source_dev,
            source_ino,
            source_size,
            source_mtime_sec,
            source_mtime_nsec,
            Some(source_fingerprint.as_str()),
        )
        .is_some();
        Ok(serde_json::json!({
            "id": r.get::<_, i64>(0)?,
            "filePath": r.get::<_, String>(1)?,
            "status": r.get::<_, String>(2)?,
            "originalCodec": r.get::<_, String>(3)?,
            "originalSize": r.get::<_, i64>(4)?,
            "newCodec": r.get::<_, String>(5)?,
            "newSize": r.get::<_, i64>(6)?,
            "errorLog": r.get::<_, String>(7)?,
            "createdAt": r.get::<_, String>(8)?,
            "sourceFingerprint": source_fingerprint,
            "sourceSize": source_size.unwrap_or(0),
            "sourceMtimeSec": source_mtime_sec.unwrap_or(0),
            "identityBound": identity_bound,
        }))
    }) {
        Ok(iter) => iter,
        Err(err) => {
            tracing::warn!(%err, "Failed to execute MediaFlow queue query");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to fetch queue",
            );
        }
    };
    let items: Vec<serde_json::Value> = match rows.collect::<rusqlite::Result<Vec<_>>>() {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(%err, "Failed to decode MediaFlow queue row");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to fetch queue",
            );
        }
    };
    Json(items).into_response()
}

async fn run_ffprobe_json_bounded_uri(
    ffprobe_bin: &str,
    input_arg: &std::ffi::OsStr,
    #[cfg(unix)] pinned_fd: Option<std::os::unix::io::RawFd>,
    timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut cmd = tokio::process::Command::new(ffprobe_bin);
    cmd.args([
        "-v",
        "quiet",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
    ])
    .arg(input_arg)
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::null())
    .kill_on_drop(true);
    #[cfg(unix)]
    if let Some(raw_fd) = pinned_fd {
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

    let mut child = cmd.spawn().ok()?;
    let mut stdout_pipe = child.stdout.take();
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(ref mut out) = stdout_pipe {
            let _ = out.take(2 * 1024 * 1024).read_to_end(&mut buf).await;
        }
        buf
    });

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) if status.success() => stdout_task.await.ok(),
        _ => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            stdout_task.abort();
            None
        }
    }
}

#[cfg(test)]
async fn run_ffprobe_json_bounded(
    ffprobe_bin: &str,
    file_path: &StdPath,
    timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        run_ffprobe_json_bounded_uri(ffprobe_bin, file_path.as_os_str(), None, timeout).await
    }
    #[cfg(not(unix))]
    {
        run_ffprobe_json_bounded_uri(ffprobe_bin, file_path.as_os_str(), timeout).await
    }
}

fn infer_video_codec_from_filename(fname: &str) -> String {
    let fname_lower = fname.to_lowercase();
    if fname_lower.contains("hevc")
        || fname_lower.contains("x265")
        || fname_lower.contains("h265")
        || fname_lower.contains("h.265")
    {
        "hevc".to_string()
    } else if fname_lower.contains("av1") {
        "av1".to_string()
    } else if fname_lower.contains("mpeg2") {
        "mpeg2video".to_string()
    } else if fname_lower.contains("vp9") {
        "vp9".to_string()
    } else {
        "h264".to_string()
    }
}

fn parse_ffprobe_video_codec_and_size(stdout: &[u8], fallback_size: i64) -> Option<(String, i64)> {
    let val = serde_json::from_slice::<serde_json::Value>(stdout).ok()?;
    let mut v_codec = String::new();
    if let Some(streams) = val.get("streams").and_then(|v| v.as_array()) {
        for s in streams {
            if s.get("codec_type").and_then(|v| v.as_str()) == Some("video") {
                v_codec = s
                    .get("codec_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                break;
            }
        }
    }
    let size = val
        .pointer("/format/size")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&sz| sz > 0)
        .unwrap_or(fallback_size);
    if v_codec.is_empty() {
        None
    } else {
        Some((v_codec, size))
    }
}

#[cfg(test)]
pub(super) async fn probe_video_codec_and_size_with_timeout(
    ffprobe_bin: &str,
    file_path: &StdPath,
    timeout: std::time::Duration,
) -> (String, i64) {
    let fallback_size = std::fs::metadata(file_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);

    if let Some(stdout) = run_ffprobe_json_bounded(ffprobe_bin, file_path, timeout).await {
        if let Some(parsed) = parse_ffprobe_video_codec_and_size(&stdout, fallback_size) {
            return parsed;
        }
    }

    let fname = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    (infer_video_codec_from_filename(fname), fallback_size)
}

async fn probe_video_codec_and_size_for_pinned(
    pinned: &af_services::PinnedMediaflowSource,
) -> (String, i64) {
    let exact_size = i64::try_from(pinned.identity.size).unwrap_or(i64::MAX);
    #[cfg(unix)]
    let (input_uri, child_pinned_fd) = {
        let raw_fd = pinned.source_raw_fd();
        if cfg!(target_os = "linux") && StdPath::new("/proc/self/fd").is_dir() {
            (format!("file:/proc/self/fd/{raw_fd}"), Some(raw_fd))
        } else {
            (format!("file:{}", pinned.canon_src.to_string_lossy()), None)
        }
    };
    #[cfg(not(unix))]
    let input_uri = format!("file:{}", pinned.canon_src.to_string_lossy());

    #[cfg(unix)]
    let probed = run_ffprobe_json_bounded_uri(
        "ffprobe",
        std::ffi::OsStr::new(&input_uri),
        child_pinned_fd,
        MEDIAFLOW_FFPROBE_TIMEOUT,
    )
    .await;
    #[cfg(not(unix))]
    let probed = run_ffprobe_json_bounded_uri(
        "ffprobe",
        std::ffi::OsStr::new(&input_uri),
        MEDIAFLOW_FFPROBE_TIMEOUT,
    )
    .await;

    if let Some(stdout) = probed {
        if let Some((codec, _)) = parse_ffprobe_video_codec_and_size(&stdout, exact_size) {
            return (codec, exact_size);
        }
    }

    (
        infer_video_codec_from_filename(&pinned.source_fname),
        exact_size,
    )
}

pub(super) fn is_mediaflow_extension(ext: &str) -> bool {
    MEDIAFLOW_VIDEO_EXTS
        .iter()
        .any(|allowed| allowed[1..].eq_ignore_ascii_case(ext))
}

#[cfg(test)]
pub(super) fn collect_mediaflow_files(
    directory: &StdPath,
    root: &StdPath,
    depth: usize,
    out: &mut Vec<PathBuf>,
) {
    let remaining = MAX_SCAN_FILES.saturating_sub(out.len());
    let max_depth = MAX_SCAN_DEPTH.saturating_sub(depth);
    let outcome = if directory == root && depth == 0 && out.is_empty() {
        run_auto_continuing_scan(
            root,
            None,
            false,
            &MEDIAFLOW_SCAN_CURSORS,
            remaining,
            max_depth,
            is_mediaflow_extension,
        )
    } else {
        collect_matching_files_paged(
            directory,
            None,
            remaining,
            max_depth,
            is_mediaflow_extension,
        )
    };
    out.extend(outcome.files);
}

pub(super) async fn scan_directory_for_mediaflow(
    root_dir: &StdPath,
    explicit_cursor: Option<&str>,
    reset_cursor: bool,
) -> anyhow::Result<PagedScanOutcome> {
    struct ExistingQueueSnapshot {
        status: String,
        original_size: i64,
        identity: Option<af_services::MediaflowSourceIdentity>,
    }

    let root_owned = root_dir.to_path_buf();
    let cursor_owned = explicit_cursor.map(str::to_owned);
    let (prepared, candidates) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let prepared = prepare_auto_continuing_scan(
            &root_owned,
            cursor_owned.as_deref(),
            reset_cursor,
            &MEDIAFLOW_SCAN_CURSORS,
            MAX_SCAN_FILES,
            MAX_SCAN_DEPTH,
            is_mediaflow_extension,
        );
        let mut candidates = Vec::new();
        if !prepared.outcome.files.is_empty() {
            let conn = af_db::get_read_conn()?;
            let scan_roots = vec![root_owned.clone()];
            let mut active_stmt = conn.prepare(
                "SELECT status, COALESCE(original_size, 0), source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, COALESCE(source_fingerprint, '')
                 FROM mediaflow_queue
                 WHERE file_path = ?1 AND status IN ('PENDING_APPROVAL', 'APPROVED', 'PROCESSING')
                 ORDER BY id DESC LIMIT 1",
            )?;
            let mut latest_stmt = conn.prepare(
                "SELECT status, COALESCE(original_size, 0), source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, COALESCE(source_fingerprint, '')
                 FROM mediaflow_queue
                 WHERE file_path = ?1
                 ORDER BY id DESC LIMIT 1",
            )?;
            let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<ExistingQueueSnapshot> {
                let status = row.get::<_, String>(0)?;
                let original_size = row.get::<_, i64>(1)?;
                let identity = af_services::parse_stored_mediaflow_identity(
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?.as_deref(),
                );
                Ok(ExistingQueueSnapshot {
                    status,
                    original_size,
                    identity,
                })
            };

            for path in &prepared.outcome.files {
                let raw_name = path.to_string_lossy();
                if raw_name.contains(".mediaflow_trash") {
                    continue;
                }
                let Ok(pinned) =
                    af_services::open_and_pin_mediaflow_source_in_roots(raw_name.as_ref(), &scan_roots)
                else {
                    continue;
                };
                let canon_name = pinned.canon_src.to_string_lossy().into_owned();
                if let Some(active) = active_stmt
                    .query_row(params![&canon_name], map_row)
                    .optional()?
                {
                    if active.status == "PROCESSING" {
                        continue;
                    }
                    if active.identity.as_ref() == Some(&pinned.identity) {
                        continue;
                    }
                    candidates.push(pinned);
                    continue;
                }

                if let Some(latest) = latest_stmt
                    .query_row(params![&canon_name], map_row)
                    .optional()?
                {
                    match latest.status.as_str() {
                        "NEEDS_RESCAN" | "SUPERSEDED" => {
                            candidates.push(pinned);
                        }
                        "DECLINED" => {
                            let same_identity = latest.identity.as_ref() == Some(&pinned.identity);
                            let legacy_same_size = latest.identity.is_none()
                                && latest.original_size
                                    == i64::try_from(pinned.identity.size).unwrap_or(-1);
                            if !same_identity && !legacy_same_size {
                                candidates.push(pinned);
                            }
                        }
                        "FAILED" | "CANCELLED" | "COMPLETED" => {
                            if latest.identity.as_ref() != Some(&pinned.identity) {
                                candidates.push(pinned);
                            }
                        }
                        _ => {
                            if latest.identity.as_ref() != Some(&pinned.identity) {
                                candidates.push(pinned);
                            }
                        }
                    }
                } else {
                    candidates.push(pinned);
                }
            }
        }
        Ok((prepared, candidates))
    })
    .await??;

    struct ProbedMediaflowCandidate {
        pinned: af_services::PinnedMediaflowSource,
        codec: String,
        size: i64,
    }

    let mut probed = Vec::new();
    for pinned in candidates {
        let (codec, size) = probe_video_codec_and_size_for_pinned(&pinned).await;
        if pinned.verify_still_matches_live().is_ok() {
            probed.push(ProbedMediaflowCandidate {
                pinned,
                codec,
                size,
            });
        }
    }

    if !probed.is_empty() {
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = af_db::get_conn()?;
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            for cand in probed {
                if cand.pinned.verify_still_matches_live().is_err() {
                    continue;
                }
                let file_path = cand.pinned.canon_src.to_string_lossy().into_owned();
                let active_row: Option<(i64, String, Option<af_services::MediaflowSourceIdentity>)> =
                    tx.query_row(
                        "SELECT id, status, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, COALESCE(source_fingerprint, '')
                         FROM mediaflow_queue
                         WHERE file_path = ?1 AND status IN ('PENDING_APPROVAL', 'APPROVED', 'PROCESSING')
                         ORDER BY id DESC LIMIT 1",
                        params![&file_path],
                        |r| {
                            let id = r.get::<_, i64>(0)?;
                            let status = r.get::<_, String>(1)?;
                            let identity = af_services::parse_stored_mediaflow_identity(
                                r.get::<_, Option<i64>>(2)?,
                                r.get::<_, Option<i64>>(3)?,
                                r.get::<_, Option<i64>>(4)?,
                                r.get::<_, Option<i64>>(5)?,
                                r.get::<_, Option<i64>>(6)?,
                                r.get::<_, Option<String>>(7)?.as_deref(),
                            );
                            Ok((id, status, identity))
                        },
                    )
                    .optional()?;

                let is_already_modern = cand.codec == "hevc" || cand.codec == "av1";
                if let Some((active_id, active_status, active_identity)) = active_row {
                    if active_status == "PROCESSING" {
                        continue;
                    }
                    if active_identity.as_ref() == Some(&cand.pinned.identity) {
                        continue;
                    }
                    let supersede_msg = if is_already_modern {
                        format!(
                            "Source file changed since prior scan and is already encoded as {}; prior candidate invalidated",
                            cand.codec
                        )
                    } else {
                        "Source file changed since prior scan; superseded by refreshed scan candidate"
                            .to_string()
                    };
                    let updated = tx.execute(
                        "UPDATE mediaflow_queue
                         SET status = 'SUPERSEDED',
                             error_log = ?1,
                             updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?2 AND status IN ('PENDING_APPROVAL', 'APPROVED')",
                        params![supersede_msg, active_id],
                    )?;
                    if updated != 1 {
                        continue;
                    }
                }

                let rescan_note = if is_already_modern {
                    format!("Re-scanned file is already encoded as {}", cand.codec)
                } else {
                    "Superseded by refreshed scan candidate".to_string()
                };
                tx.execute(
                    "UPDATE mediaflow_queue
                     SET status = 'SUPERSEDED',
                         error_log = CASE
                             WHEN COALESCE(error_log, '') = '' THEN ?1
                             ELSE error_log || ' (superseded by re-scan)'
                         END,
                         updated_at = CURRENT_TIMESTAMP
                     WHERE file_path = ?2 AND status = 'NEEDS_RESCAN'",
                    params![rescan_note, &file_path],
                )?;

                if !is_already_modern {
                    let id_rec = &cand.pinned.identity;
                    let src_size = i64::try_from(id_rec.size).unwrap_or(cand.size);
                    tx.execute(
                        "INSERT INTO mediaflow_queue (
                             file_path, original_codec, original_size, status,
                             source_dev, source_ino, source_size,
                             source_mtime_sec, source_mtime_nsec, source_fingerprint
                         ) VALUES (?1, ?2, ?3, 'PENDING_APPROVAL', ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            file_path,
                            cand.codec,
                            cand.size,
                            id_rec.dev as i64,
                            id_rec.ino as i64,
                            src_size,
                            id_rec.mtime_sec,
                            id_rec.mtime_nsec,
                            id_rec.fingerprint,
                        ],
                    )?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await??;
    }

    commit_auto_continuing_scan(&MEDIAFLOW_SCAN_CURSORS, &prepared);
    Ok(prepared.outcome)
}

pub async fn trigger_mediaflow_scan(Json(req): Json<serde_json::Value>) -> Response {
    let dir = req
        .get("directory")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if dir.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid payload" })),
        )
            .into_response();
    }
    let explicit_cursor = req
        .get("cursor")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let reset_cursor = req.get("reset").and_then(|v| v.as_bool()).unwrap_or(false);
    let directory = PathBuf::from(dir);
    let dir_buf = match tokio::task::spawn_blocking(move || {
        validate_mediaflow_directory(&directory, &mediaflow_library_roots())
    })
    .await
    {
        Ok(Ok(directory)) => directory,
        Ok(Err((status, message))) => return api_error(status, "INVALID_SCAN_PATH", message),
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                error.to_string(),
            )
        }
    };
    if MEDIAFLOW_SCANNING
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_err()
    {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "A MediaFlow scan is already in progress",
        );
    }
    let response_directory = dir_buf.to_string_lossy().into_owned();
    let pending_cursor = if reset_cursor {
        None
    } else {
        MEDIAFLOW_SCAN_CURSORS
            .lock()
            .ok()
            .and_then(|map| map.get(&dir_buf).cloned())
    };
    let explicit_cursor_for_task = explicit_cursor.clone();
    let stream_tx = crate::storage::ensure_or_reuse_deploy_stream("mediaflow_engine");
    if let Some(ref tx) = stream_tx {
        crate::storage::publish_deploy_json_event(
            "mediaflow_engine",
            tx,
            &serde_json::json!({
                "status": "running",
                "progress": 10,
                "message": format!("Scanning media library {}", response_directory),
            }),
        );
    }
    tokio::spawn(async move {
        let _guard = MediaflowScanGuard;
        let dir_for_scan = dir_buf.clone();
        let scan_res = scan_directory_for_mediaflow(
            &dir_for_scan,
            explicit_cursor_for_task.as_deref(),
            reset_cursor,
        )
        .await;

        let terminal_payload = match scan_res {
            Ok(outcome) => {
                if outcome.truncated {
                    tracing::info!(
                        directory = %dir_buf.display(),
                        batch_count = outcome.files.len(),
                        next_cursor = ?outcome.next_cursor,
                        "MediaFlow partial scan batch completed; cursor stored for continuation"
                    );
                }
                serde_json::json!({
                    "status": "completed",
                    "progress": 100,
                    "message": format!("MediaFlow scan completed ({} files scanned)", outcome.files.len()),
                    "truncated": outcome.truncated,
                })
            }
            Err(error) => {
                tracing::error!(%error, directory = %dir_buf.display(), "MediaFlow scan failed");
                serde_json::json!({
                    "status": "failed",
                    "progress": 100,
                    "message": "MediaFlow scan failed",
                })
            }
        };

        if let Some(tx) = stream_tx {
            crate::storage::publish_deploy_json_event("mediaflow_engine", &tx, &terminal_payload);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            crate::storage::release_deploy_stream_if_matching("mediaflow_engine", &tx);
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "message": "Scan initiated in background",
            "directory": response_directory,
            "resuming_from_cursor": explicit_cursor.or(pending_cursor),
        })),
    )
        .into_response()
}

pub async fn approve_mediaflow_item(Path(id): Path<String>, body: axum::body::Bytes) -> Response {
    let Ok(job_id) = id.trim().parse::<i64>() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_JOB_ID",
            "Invalid MediaFlow queue item id",
        );
    };
    let expected_fingerprint = if body.iter().all(|b| b.is_ascii_whitespace()) {
        None
    } else {
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_PAYLOAD",
                "Invalid JSON approval payload",
            );
        };
        payload
            .get("sourceFingerprint")
            .or_else(|| payload.get("source_fingerprint"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    let approval_result: Result<String, (StatusCode, &'static str, String)> =
        match tokio::task::spawn_blocking(move || {
            let conn = af_db::get_conn().map_err(|err| {
                tracing::warn!(%err, job_id, "Database unavailable while approving MediaFlow item");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "DATABASE_UNAVAILABLE",
                    "Failed to approve".to_string(),
                )
            })?;
            let row = conn
                .query_row(
                    "SELECT file_path, status, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, COALESCE(source_fingerprint, '')
                     FROM mediaflow_queue
                     WHERE id = ?1",
                    params![job_id],
                    |r| {
                        let file_path = r.get::<_, String>(0)?;
                        let status = r.get::<_, String>(1)?;
                        let identity = af_services::parse_stored_mediaflow_identity(
                            r.get::<_, Option<i64>>(2)?,
                            r.get::<_, Option<i64>>(3)?,
                            r.get::<_, Option<i64>>(4)?,
                            r.get::<_, Option<i64>>(5)?,
                            r.get::<_, Option<i64>>(6)?,
                            r.get::<_, Option<String>>(7)?.as_deref(),
                        );
                        Ok((file_path, status, identity))
                    },
                )
                .optional()
                .map_err(|err| {
                    tracing::warn!(%err, job_id, "Failed to inspect MediaFlow queue item for approval");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        "Failed to inspect queue item".to_string(),
                    )
                })?;

            let Some((file_path, status, stored_identity)) = row else {
                return Err((
                    StatusCode::NOT_FOUND,
                    "NOT_FOUND",
                    "Item not found".to_string(),
                ));
            };

            if status != "PENDING_APPROVAL" {
                let (code, msg) = if status == "NEEDS_RESCAN" {
                    (
                        "SOURCE_CHANGED",
                        "Source file changed or lacks verified scan identity; please re-scan before approving.".to_string(),
                    )
                } else {
                    (
                        "INVALID_STATE",
                        format!("Item cannot be approved from status {status}"),
                    )
                };
                return Err((StatusCode::CONFLICT, code, msg));
            }

            let Some(stored_identity) = stored_identity else {
                if let Err(err) = conn.execute(
                    "UPDATE mediaflow_queue
                     SET status = 'NEEDS_RESCAN',
                         error_log = ?1,
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?2 AND status = 'PENDING_APPROVAL'",
                    params![af_services::MEDIAFLOW_MISSING_IDENTITY_MSG, job_id],
                ) {
                    tracing::warn!(%err, job_id, "Failed to mark legacy MediaFlow item NEEDS_RESCAN");
                }
                return Err((
                    StatusCode::CONFLICT,
                    "NEEDS_RESCAN",
                    af_services::MEDIAFLOW_MISSING_IDENTITY_MSG.to_string(),
                ));
            };

            if let Some(ref client_fp) = expected_fingerprint {
                if client_fp != &stored_identity.fingerprint {
                    return Err((
                        StatusCode::CONFLICT,
                        "IDENTITY_MISMATCH",
                        "Queue item fingerprint no longer matches the reviewed candidate; refresh the queue and re-review before approving.".to_string(),
                    ));
                }
            }

            let pinned = match af_services::open_and_pin_mediaflow_source(&file_path) {
                Ok(p) => p,
                Err(reason) => {
                    let msg = format!(
                        "Source file is no longer valid for this scanned candidate ({reason}); re-scan before approving."
                    );
                    if let Err(err) = conn.execute(
                        "UPDATE mediaflow_queue
                         SET status = 'NEEDS_RESCAN',
                             error_log = ?1,
                             updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?2 AND status = 'PENDING_APPROVAL'",
                        params![&msg, job_id],
                    ) {
                        tracing::warn!(%err, job_id, "Failed to mark invalid MediaFlow source NEEDS_RESCAN");
                    }
                    return Err((StatusCode::CONFLICT, "SOURCE_CHANGED", msg));
                }
            };

            if pinned.identity != stored_identity {
                let msg = "Source file changed since scan; re-scan and review the updated file before approving.".to_string();
                if let Err(err) = conn.execute(
                    "UPDATE mediaflow_queue
                     SET status = 'NEEDS_RESCAN',
                         error_log = ?1,
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?2 AND status = 'PENDING_APPROVAL'",
                    params![&msg, job_id],
                ) {
                    tracing::warn!(%err, job_id, "Failed to mark drifted MediaFlow source NEEDS_RESCAN");
                }
                return Err((StatusCode::CONFLICT, "SOURCE_CHANGED", msg));
            }

            let affected = conn
                .execute(
                    "UPDATE mediaflow_queue
                     SET status = 'APPROVED',
                         error_log = '',
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?1
                       AND status = 'PENDING_APPROVAL'
                       AND source_fingerprint = ?2",
                    params![job_id, &stored_identity.fingerprint],
                )
                .map_err(|err| {
                    tracing::warn!(%err, job_id, "SQLite error while approving MediaFlow item");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        "Failed to approve queue item".to_string(),
                    )
                })?;
            if affected != 1 {
                return Err((
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Queue item state changed concurrently; refresh and try again.".to_string(),
                ));
            }
            Ok(stored_identity.fingerprint)
        })
        .await
        {
            Ok(res) => res,
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                err.to_string(),
            )),
        };

    let approved_fingerprint = match approval_result {
        Ok(fp) => fp,
        Err((status, code, msg)) => return api_error(status, code, msg),
    };

    if let Some(tx) = crate::storage::ensure_or_reuse_deploy_stream("mediaflow_engine") {
        crate::storage::publish_deploy_json_event(
            "mediaflow_engine",
            &tx,
            &serde_json::json!({
                "status": "running",
                "progress": 25,
                "message": format!("Transcode job #{} approved and queued.", job_id),
            }),
        );
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            crate::storage::publish_deploy_json_event(
                "mediaflow_engine",
                &tx,
                &serde_json::json!({
                    "status": "completed",
                    "progress": 100,
                    "message": format!("Transcode job #{} queued for MediaFlow Engine.", job_id),
                }),
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            crate::storage::release_deploy_stream_if_matching("mediaflow_engine", &tx);
        });
    }
    Json(serde_json::json!({
        "message": "Transcode queued. MediaFlow Engine assumes control.",
        "id": job_id,
        "status": "APPROVED",
        "sourceFingerprint": approved_fingerprint,
    }))
    .into_response()
}

pub async fn decline_mediaflow_item(Path(id): Path<String>) -> Response {
    let Ok(job_id) = id.trim().parse::<i64>() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_JOB_ID",
            "Invalid MediaFlow queue item id",
        );
    };

    let outcome: Result<(&'static str, &'static str), (StatusCode, &'static str, String)> =
        match tokio::task::spawn_blocking(move || {
            let conn = af_db::get_conn().map_err(|err| {
                tracing::warn!(%err, job_id, "Database unavailable while declining MediaFlow item");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "DATABASE_UNAVAILABLE",
                    "Failed to decline".to_string(),
                )
            })?;
            let declined = conn
                .execute(
                    "UPDATE mediaflow_queue
                     SET status = 'DECLINED',
                         error_log = CASE
                             WHEN status = 'APPROVED' THEN 'Cancelled before transcode started'
                             ELSE ''
                         END,
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?1 AND status IN ('PENDING_APPROVAL', 'APPROVED')",
                    params![job_id],
                )
                .map_err(|err| {
                    tracing::warn!(%err, job_id, "SQLite error while declining MediaFlow item");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        "Failed to decline queue item".to_string(),
                    )
                })?;
            if declined == 1 {
                return Ok(("DECLINED", "Transcode job declined."));
            }

            let status_opt: Option<String> = conn
                .query_row(
                    "SELECT status FROM mediaflow_queue WHERE id = ?1",
                    params![job_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|err| {
                    tracing::warn!(%err, job_id, "Failed to inspect MediaFlow queue item for decline");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        "Failed to inspect queue item".to_string(),
                    )
                })?;

            let Some(current_status) = status_opt else {
                return Err((
                    StatusCode::NOT_FOUND,
                    "NOT_FOUND",
                    "Item not found".to_string(),
                ));
            };

            if current_status == "PROCESSING" {
                match af_services::cancel_inflight_mediaflow_job(job_id) {
                    af_services::CancelInflightOutcome::AlreadyPublishing => {
                        return Err((
                            StatusCode::CONFLICT,
                            "ALREADY_PUBLISHING",
                            "Transcode job is finalizing publication and can no longer be cancelled.".to_string(),
                        ));
                    }
                    af_services::CancelInflightOutcome::CancelSignalled => {
                        if let Err(err) = conn.execute(
                            "UPDATE mediaflow_queue
                             SET status = 'CANCELLED',
                                 error_log = ?1,
                                 updated_at = CURRENT_TIMESTAMP
                             WHERE id = ?2 AND status = 'PROCESSING'",
                            params![af_services::MEDIAFLOW_CANCELLED_MSG, job_id],
                        ) {
                            tracing::warn!(
                                %err,
                                job_id,
                                "Failed to persist CANCELLED state after signalling in-flight transcode cancellation"
                            );
                        }
                        return Ok(("CANCELLED", "In-flight transcode cancelled."));
                    }
                    af_services::CancelInflightOutcome::NotRunning => {
                        let cancelled = conn
                            .execute(
                                "UPDATE mediaflow_queue
                                 SET status = 'CANCELLED',
                                     error_log = ?1,
                                     updated_at = CURRENT_TIMESTAMP
                                 WHERE id = ?2 AND status = 'PROCESSING'",
                                params![af_services::MEDIAFLOW_CANCELLED_MSG, job_id],
                            )
                            .map_err(|err| {
                                tracing::warn!(
                                    %err,
                                    job_id,
                                    "SQLite error while cancelling stale MediaFlow job"
                                );
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "INTERNAL_ERROR",
                                    "Failed to cancel queue item".to_string(),
                                )
                            })?;
                        if cancelled == 1 {
                            return Ok(("CANCELLED", "Transcode job cancelled."));
                        }
                        return Err((
                            StatusCode::CONFLICT,
                            "INVALID_STATE",
                            "Transcode job already finished.".to_string(),
                        ));
                    }
                }
            }

            Err((
                StatusCode::CONFLICT,
                "INVALID_STATE",
                format!("Item cannot be declined or cancelled from status {current_status}"),
            ))
        })
        .await
        {
            Ok(res) => res,
            Err(err) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                err.to_string(),
            )),
        };

    match outcome {
        Ok((status, message)) => Json(serde_json::json!({
            "message": message,
            "id": job_id,
            "status": status,
        }))
        .into_response(),
        Err((status, code, msg)) => api_error(status, code, msg),
    }
}
