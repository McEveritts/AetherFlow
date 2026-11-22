use super::backup_staging::{self, BackupStaging, StagingLimits};
use super::backups::{
    compute_file_sha256, get_active_db_path, get_backup_dir, is_valid_backup_filename,
    safe_backup_path, BACKUP_BLOCKING_LIMIT, VALID_UPLOAD_SESSION_ID_RE,
};
use super::updater::get_local_version;
use crate::auth::{api_error, AuthUser};
use axum::extract::{Path, Query, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path as StdPath, PathBuf};

const MAX_BACKUP_UPLOAD_CHUNK_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_BACKUP_UPLOAD_CHUNKS: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BackupUploadSessionMeta {
    pub(super) total_chunks: usize,
    #[serde(default)]
    pub(super) expected_sha256: Option<String>,
    pub(super) user_id: i64,
    pub(super) session_jti: String,
    pub(super) upload_id: String,
}

pub(super) type BackupUploadError = (StatusCode, &'static str, String);
pub(super) type BackupUploadResult = Result<serde_json::Value, BackupUploadError>;

fn sanitize_session_token_component(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .take(48)
        .collect();
    if filtered.is_empty() {
        "default".to_string()
    } else {
        filtered
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_backup_chunk_upload_in_dir(
    backup_dir: &StdPath,
    filename: &str,
    chunk_index: usize,
    total_chunks: usize,
    expected_checksum: Option<&str>,
    upload_id_param: Option<&str>,
    auth_session: Option<(i64, &str)>,
    bytes: &[u8],
) -> Result<serde_json::Value, (StatusCode, &'static str, String)> {
    process_backup_chunk_upload(
        backup_dir,
        filename,
        chunk_index,
        total_chunks,
        expected_checksum,
        upload_id_param,
        auth_session,
        bytes,
        StagingLimits::DEFAULT,
    )
}

fn backup_staging_error(error: impl std::fmt::Display) -> BackupUploadError {
    tracing::warn!(%error, "backup upload staging operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Backup upload staging operation failed".to_owned(),
    )
}

fn backup_staging_full() -> BackupUploadError {
    (
        StatusCode::INSUFFICIENT_STORAGE,
        "BACKUP_STAGING_FULL",
        "Backup upload staging is full; retry when another upload completes or expires".to_owned(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn process_backup_chunk_upload(
    backup_dir: &StdPath,
    filename: &str,
    chunk_index: usize,
    total_chunks: usize,
    expected_checksum: Option<&str>,
    upload_id_param: Option<&str>,
    auth_session: Option<(i64, &str)>,
    bytes: &[u8],
    limits: StagingLimits,
) -> BackupUploadResult {
    use backup_staging::{
        create_directory, open_staged_file, sync_directory, write_staged_file, SESSION_METADATA,
    };
    use std::time::SystemTime;

    if filename.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Filename required".to_string(),
        ));
    }
    if total_chunks == 0 || total_chunks > MAX_BACKUP_UPLOAD_CHUNKS {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!("total query must be between 1 and {MAX_BACKUP_UPLOAD_CHUNKS}"),
        ));
    }
    if chunk_index >= total_chunks {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!(
                "chunk index {} out of bounds for total_chunks {}",
                chunk_index, total_chunks
            ),
        ));
    }
    if bytes.is_empty() || bytes.len() > MAX_BACKUP_UPLOAD_CHUNK_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid chunk payload size".to_string(),
        ));
    }

    let upload_id =
        if let Some(raw_upload_id) = upload_id_param.map(str::trim).filter(|val| !val.is_empty()) {
            if !VALID_UPLOAD_SESSION_ID_RE.is_match(raw_upload_id) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid upload_id parameter".to_string(),
                ));
            }
            raw_upload_id.to_string()
        } else {
            "default".to_string()
        };

    let (user_id, session_jti) = match auth_session {
        Some((uid, jti)) => (uid, sanitize_session_token_component(jti)),
        None => (0, "anon".to_string()),
    };
    let session_key = format!("u{}-{}-{}", user_id, session_jti, upload_id);

    let Ok(final_path) = safe_backup_path(backup_dir, filename) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid filename".to_string(),
        ));
    };
    if !is_valid_backup_filename(filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Backup filename must end with .sqlite and contain only safe characters".to_string(),
        ));
    }
    let expected_sha256 = expected_checksum
        .map(str::trim)
        .filter(|val| !val.is_empty())
        .map(str::to_ascii_lowercase);
    if expected_sha256.as_ref().is_some_and(|checksum| {
        checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Backup checksum must be a SHA-256 hex digest".to_owned(),
        ));
    }

    let staging = BackupStaging::acquire(backup_dir, true)
        .map_err(backup_staging_error)?
        .expect("blocking staging lock acquisition returned without a lock");
    let upload_dir = staging.session_path(filename, &session_key);
    let usage = staging
        .scan(
            SystemTime::now(),
            limits.idle_for,
            Some((&upload_dir, total_chunks)),
        )
        .map_err(backup_staging_error)?;
    if usage.current.is_none() && usage.sessions >= limits.sessions {
        return Err(backup_staging_full());
    }

    // The scanner skips non-directory paths. Check the actual path before opening any leaves.
    if let Some(filename_dir) = upload_dir.parent() {
        for dir in [filename_dir, upload_dir.as_path()] {
            match fs::symlink_metadata(dir) {
                Ok(meta) if meta.is_dir() => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(backup_staging_error(format!(
                        "invalid staging directory {}",
                        dir.display()
                    )))
                }
            }
        }
    }

    let meta_path = upload_dir.join(SESSION_METADATA);
    let (session_meta, save_metadata) =
        match open_staged_file(&meta_path).map_err(backup_staging_error)? {
            Some(file) => {
                let mut stored: BackupUploadSessionMeta =
                    serde_json::from_reader(file.take(16 * 1024)).map_err(backup_staging_error)?;
                if stored.total_chunks != total_chunks
                    || stored.user_id != user_id
                    || stored.session_jti != session_jti
                    || stored.upload_id != upload_id
                {
                    return Err((
                        StatusCode::CONFLICT,
                        "CONFLICT",
                        "Upload session metadata mismatch; start a new upload_id".to_owned(),
                    ));
                }
                let save_metadata = stored.expected_sha256.is_none() && expected_sha256.is_some();
                if let Some(incoming) = expected_sha256 {
                    if stored
                        .expected_sha256
                        .as_ref()
                        .is_some_and(|existing| existing != &incoming)
                    {
                        return Err((
                            StatusCode::CONFLICT,
                            "CONFLICT",
                            "Upload session expected checksum mismatch".to_owned(),
                        ));
                    }
                    stored.expected_sha256 = Some(incoming);
                }
                (stored, save_metadata)
            }
            None => {
                // The writer commits session metadata before any part. A legacy part without
                // metadata has no declared chunk count or owner to validate on resume.
                if usage.current.as_ref().is_some_and(|parts| parts.bytes != 0) {
                    return Err(backup_staging_error(
                        "staged parts are missing session metadata",
                    ));
                }
                (
                    BackupUploadSessionMeta {
                        total_chunks,
                        expected_sha256,
                        user_id,
                        session_jti,
                        upload_id,
                    },
                    true,
                )
            }
        };

    let chunk_path = upload_dir.join(format!("{chunk_index:06}.part"));
    let mut existing = open_staged_file(&chunk_path).map_err(backup_staging_error)?;
    let old_len = existing
        .as_ref()
        .map(|file| file.metadata().map(|meta| meta.len()))
        .transpose()
        .map_err(backup_staging_error)?
        .unwrap_or(0);
    let incoming = bytes.len() as u64;
    let next_usage = usage
        .part_bytes
        .saturating_sub(old_len)
        .saturating_add(incoming);
    let parts = usage.current.unwrap_or_default();
    let received = parts.received + usize::from(old_len == 0);
    let complete = received == total_chunks;
    let assembly_size = parts.bytes.saturating_sub(old_len).saturating_add(incoming);
    let physical_limit = limits.part_bytes.saturating_mul(2);
    if (next_usage > limits.part_bytes && next_usage > usage.part_bytes)
        || (complete && next_usage.saturating_add(assembly_size) > physical_limit)
    {
        return Err(backup_staging_full());
    }

    let repeated = if let Some(file) = existing.as_mut().filter(|_| old_len == incoming) {
        staged_chunk_matches(file, bytes).map_err(backup_staging_error)?
    } else {
        false
    };
    if !repeated && usage.part_bytes.saturating_add(incoming) > physical_limit {
        return Err(backup_staging_full());
    }

    create_directory(upload_dir.parent().expect("upload session has a parent"))
        .and_then(|_| create_directory(&upload_dir))
        .map_err(backup_staging_error)?;
    if save_metadata {
        let serialized = serde_json::to_vec(&session_meta).map_err(backup_staging_error)?;
        write_staged_file(&meta_path, &upload_dir.join("meta.json.tmp"), &serialized)
            .map_err(backup_staging_error)?;
    }

    if let Some(file) = existing.filter(|_| repeated) {
        file.set_modified(SystemTime::now())
            .and_then(|_| file.sync_all())
            .and_then(|_| sync_directory(&upload_dir))
            .map_err(backup_staging_error)?;
    } else {
        write_staged_file(
            &chunk_path,
            &upload_dir.join(format!("{chunk_index:06}.part.tmp")),
            bytes,
        )
        .map_err(backup_staging_error)?;
    }

    if !complete {
        return Ok(serde_json::json!({
            "message": "Chunk received",
            "filename": filename,
            "upload_id": session_meta.upload_id,
            "received": received,
            "total": total_chunks,
            "progress": (received as f64 / total_chunks as f64) * 100.0,
            "complete": false,
        }));
    }

    let temp_final = upload_dir.join(format!("{filename}.uploading"));
    let result = assemble_backup_upload(
        backup_dir,
        &upload_dir,
        &temp_final,
        &final_path,
        filename,
        &session_meta,
    );
    let _ = fs::remove_file(&temp_final);
    // Keep the parts for a retry if assembly or publication fails transiently.
    if result.is_ok() || matches!(&result, Err((StatusCode::BAD_REQUEST, _, _))) {
        backup_staging::remove_session(&upload_dir);
    }
    result
}

fn staged_chunk_matches(file: &mut fs::File, bytes: &[u8]) -> std::io::Result<bool> {
    let mut buffer = [0; 64 * 1024];
    for block in bytes.chunks(buffer.len()) {
        let read = &mut buffer[..block.len()];
        file.read_exact(read)?;
        if read != block {
            return Ok(false);
        }
    }
    Ok(true)
}

fn assemble_backup_upload(
    backup_dir: &StdPath,
    upload_dir: &StdPath,
    temp_final: &StdPath,
    final_path: &StdPath,
    filename: &str,
    session: &BackupUploadSessionMeta,
) -> BackupUploadResult {
    use backup_staging::{create_staged_file, open_staged_file};

    let mut out = create_staged_file(temp_final).map_err(backup_staging_error)?;
    for index in 0..session.total_chunks {
        let mut part = open_staged_file(&upload_dir.join(format!("{index:06}.part")))
            .map_err(backup_staging_error)?
            .ok_or_else(|| backup_staging_error(format!("missing staged part {index}")))?;
        std::io::copy(&mut part, &mut out).map_err(backup_staging_error)?;
    }
    out.sync_all().map_err(backup_staging_error)?;
    drop(out);

    let checksum = compute_file_sha256(temp_final).map_err(backup_staging_error)?;
    if let Some(expected) = session
        .expected_sha256
        .as_ref()
        .filter(|expected| !expected.eq_ignore_ascii_case(&checksum))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "CHECKSUM_MISMATCH",
            format!("Checksum verification failed: expected {expected}, actual {checksum}"),
        ));
    }

    if let Err(err) = af_runner::af_host::verify_sqlite_snapshot_integrity(temp_final) {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!("Uploaded backup failed SQLite integrity verification: {err}"),
        ));
    }

    let size =
        finalize_assembled_backup_upload(backup_dir, filename, temp_final, final_path, &checksum)
            .map_err(backup_staging_error)?;

    Ok(serde_json::json!({
        "message": "Chunked upload completed",
        "filename": filename,
        "upload_id": session.upload_id,
        "size": size,
        "checksum": checksum,
        "received": session.total_chunks,
        "total": session.total_chunks,
        "progress": 100.0,
        "complete": true,
        "timestamp": Utc::now().to_rfc3339(),
    }))
}

pub async fn upload_backup_chunk(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    if filename.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Filename required");
    }
    let Some(chunk_index) = q.get("chunk").and_then(|s| s.parse::<usize>().ok()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "chunk query must be a non-negative integer",
        );
    };
    let Some(total_chunks) = q
        .get("total")
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&t| t > 0)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "total query must be a positive integer",
        );
    };
    if total_chunks > MAX_BACKUP_UPLOAD_CHUNKS || chunk_index >= total_chunks {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid chunk count or chunk index",
        );
    }

    let permit = match BACKUP_BLOCKING_LIMIT.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BUSY",
                "Backup workers busy; retry shortly",
            )
        }
    };
    let auth_user = req.extensions().get::<AuthUser>().cloned();
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), MAX_BACKUP_UPLOAD_CHUNK_BYTES).await
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to read chunk payload",
        );
    };

    let backup_dir = get_backup_dir();
    let expected_checksum = q.get("checksum").cloned();
    let upload_id = q.get("upload_id").or_else(|| q.get("session_id")).cloned();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let auth_pair = auth_user
            .as_ref()
            .map(|user| (user.user_id, user.jti.as_str()));
        process_backup_chunk_upload_in_dir(
            &backup_dir,
            &filename,
            chunk_index,
            total_chunks,
            expected_checksum.as_deref(),
            upload_id.as_deref(),
            auth_pair,
            &bytes,
        )
    })
    .await
    {
        Ok(Ok(payload)) => Json(payload).into_response(),
        Ok(Err((status, code, msg))) => {
            if code == "CHECKSUM_MISMATCH" {
                return (
                    status,
                    Json(
                        serde_json::json!({"error":"Checksum verification failed", "message": msg}),
                    ),
                )
                    .into_response();
            }
            api_error(status, code, msg)
        }
        Err(error) => api_error(StatusCode::SERVICE_UNAVAILABLE, "BUSY", error.to_string()),
    }
}

fn cleanup_backup_upload_artifacts(temp_final: &StdPath, final_path: &StdPath) {
    let _ = fs::remove_file(temp_final);
    let _ = fs::remove_file(final_path);
    let _ = fs::remove_file(format!("{}.sha256", final_path.display()));
    let _ = fs::remove_file(format!("{}.manifest.json", final_path.display()));
    let _ = fs::remove_file(format!("{}.manifest.json.sha256", final_path.display()));
}

pub(crate) fn finalize_assembled_backup_upload(
    backup_dir: &StdPath,
    clean_base: &str,
    temp_final: &StdPath,
    final_path: &StdPath,
    checksum: &str,
) -> anyhow::Result<i64> {
    let actual_checksum = compute_file_sha256(temp_final)
        .map_err(|err| anyhow::anyhow!("Failed to hash staged backup: {}", err))?;
    if !actual_checksum.eq_ignore_ascii_case(checksum.trim()) {
        let _ = fs::remove_file(temp_final);
        anyhow::bail!(
            "Staged backup checksum mismatch: expected {}, actual {}",
            checksum,
            actual_checksum
        );
    }

    let (user_version, journal_mode, integrity_check) =
        af_runner::af_host::verify_sqlite_snapshot_integrity(temp_final)
            .map_err(|err| anyhow::anyhow!("SQLite integrity verification failed: {}", err))?;

    let size_u64 = fs::metadata(temp_final)
        .map_err(|err| anyhow::anyhow!("Failed to stat staged backup: {}", err))?
        .len();

    let mut manifest = af_runner::af_host::BackupManifest::new(get_local_version(), clean_base)
        .map_err(|err| anyhow::anyhow!("Failed to initialize backup manifest: {}", err))?;

    manifest.sqlite_snapshot = Some(af_runner::af_host::SqliteSnapshotMetadata {
        snapshot_relative_path: clean_base.to_string(),
        capture_method: "vacuum_into".to_string(),
        sqlite_user_version: user_version,
        journal_mode,
        integrity_check,
        size_bytes: size_u64,
        sha256: actual_checksum.clone(),
    });
    manifest
        .add_file_from_disk(
            clean_base,
            temp_final,
            af_runner::af_host::BackupTargetKind::SqliteSnapshot,
            Some(get_active_db_path().to_string_lossy().into_owned()),
            true,
        )
        .map_err(|err| anyhow::anyhow!("Failed to record backup manifest entry: {}", err))?;

    let sha_path = PathBuf::from(format!("{}.sha256", final_path.display()));
    let manifest_path = PathBuf::from(format!("{}.manifest.json", final_path.display()));
    let manifest_sha_path = PathBuf::from(format!("{}.manifest.json.sha256", final_path.display()));

    let prev_tag = uuid::Uuid::new_v4().to_string();
    let prev_final = PathBuf::from(format!("{}.prev-{}", final_path.display(), prev_tag));
    let prev_sha = PathBuf::from(format!("{}.prev-{}", sha_path.display(), prev_tag));
    let prev_manifest = PathBuf::from(format!("{}.prev-{}", manifest_path.display(), prev_tag));
    let prev_manifest_sha =
        PathBuf::from(format!("{}.prev-{}", manifest_sha_path.display(), prev_tag));

    let artifact_paths = [
        (final_path.to_path_buf(), prev_final),
        (sha_path, prev_sha),
        (manifest_path.clone(), prev_manifest),
        (manifest_sha_path, prev_manifest_sha),
    ];
    // Validate every destination before moving any existing backup files.
    let previous_files = artifact_paths
        .into_iter()
        .filter_map(
            |(live_path, backup_path)| match backup_staging::open_staged_file(&live_path) {
                Ok(Some(_)) => Some(Ok((live_path, backup_path))),
                Ok(None) => None,
                Err(error) => Some(Err(error.context(format!(
                    "Inspecting backup artifact {} before replacement",
                    live_path.display()
                )))),
            },
        )
        .collect::<anyhow::Result<Vec<_>>>();
    let mut preserved_previous = Vec::<(PathBuf, PathBuf)>::new();
    for (live_path, backup_path) in previous_files.inspect_err(|_| {
        let _ = fs::remove_file(temp_final);
    })? {
        fs::rename(&live_path, &backup_path).map_err(|err| {
            for (orig_path, moved_path) in preserved_previous.iter().rev() {
                let _ = fs::rename(moved_path, orig_path);
            }
            anyhow::anyhow!(
                "Failed to stage existing backup artifact {} for safe replacement: {}",
                live_path.display(),
                err
            )
        })?;
        preserved_previous.push((live_path, backup_path));
    }

    let activate_result = (|| -> anyhow::Result<i64> {
        fs::rename(temp_final, final_path)
            .map_err(|err| anyhow::anyhow!("Failed to activate assembled backup file: {}", err))?;
        af_runner::af_host::write_sha256_sidecar(final_path)
            .map_err(|err| anyhow::anyhow!("Failed to write .sha256 sidecar: {}", err))?;
        manifest
            .save_atomic(&manifest_path)
            .map_err(|err| anyhow::anyhow!("Failed to write .manifest.json sidecar: {}", err))?;
        af_runner::af_host::verify_backup_artifact(backup_dir, clean_base)
            .map_err(|err| anyhow::anyhow!("Post-upload artifact verification failed: {}", err))?;
        let size = fs::metadata(final_path)
            .map_err(|err| anyhow::anyhow!("Failed to stat activated backup: {}", err))?
            .len() as i64;
        Ok(size)
    })();

    let activated_size = match activate_result {
        Ok(size) => size,
        Err(err) => {
            cleanup_backup_upload_artifacts(temp_final, final_path);
            for (orig_path, moved_path) in preserved_previous.into_iter().rev() {
                let _ = fs::rename(&moved_path, &orig_path);
            }
            return Err(err);
        }
    };

    for (_orig_path, moved_path) in preserved_previous {
        let _ = fs::remove_file(moved_path);
    }

    Ok(activated_size)
}
