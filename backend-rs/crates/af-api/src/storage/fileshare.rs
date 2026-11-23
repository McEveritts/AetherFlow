use super::accounting;
use super::backups::{percent_decode_header_utf8, VALID_UPLOAD_SESSION_ID_RE};
use super::stream_file;
use crate::auth::{api_error, AuthUser};
use axum::extract::{Multipart, Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

const MAX_UPLOAD_SIZE: usize = 50 * 1024 * 1024; // 50 MiB
const MAX_FILESHARE_CHUNK_BYTES: usize = 5 * 1024 * 1024;
const FILESHARE_UPLOAD_TTL: StdDuration = StdDuration::from_secs(10 * 60);

static BLOCKED_EXTENSIONS: &[&str] = &[
    ".exe", ".sh", ".bat", ".cmd", ".ps1", ".php", ".jsp", ".cgi", ".pif", ".scr", ".com", ".msi",
    ".vbs", ".vbe", ".wsf", ".wsh", ".py", ".rb", ".pl", ".jar",
];

pub(super) struct FileshareUpload {
    pub(super) filename: String,
    pub(super) directory: String,
    pub(super) total_chunks: usize,
    pub(super) next_chunk: usize,
    pub(super) size: usize,
    pub(super) prefix: Vec<u8>,
    pub(super) pending: af_files::PendingUpload,
    pub(super) original: Option<fs::File>,
    pub(super) updated: Instant,
}

pub(super) static FILESHARE_WORKERS: Lazy<Arc<tokio::sync::Semaphore>> =
    Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(4)));

static FILESHARE_UPLOADS: Lazy<Mutex<HashMap<(i64, String), FileshareUpload>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(super) fn upload_dir_from_config(upload: Option<&str>, state: Option<&str>) -> PathBuf {
    if let Some(path) = upload.filter(|p| !p.trim().is_empty()) {
        return PathBuf::from(path);
    }
    let state = state
        .and_then(|p| p.split(':').next())
        .filter(|p| !p.trim().is_empty())
        .unwrap_or("/var/lib/aetherflow");
    PathBuf::from(state).join("uploads")
}

fn get_upload_dir() -> PathBuf {
    upload_dir_from_config(
        env::var("AETHERFLOW_UPLOAD_DIR").ok().as_deref(),
        env::var("STATE_DIRECTORY").ok().as_deref(),
    )
}

pub(super) fn fileshare_directory(
    root: &StdPath,
    raw_sub_path: &str,
) -> std::io::Result<af_files::BrowserFs> {
    let browser = af_files::BrowserFs::open(root)?;
    let relative = raw_sub_path.trim().trim_start_matches('/');
    if relative.is_empty() || relative == "." {
        return Ok(browser);
    }
    browser.scoped(relative)
}

fn create_fileshare_directory(
    root: &StdPath,
    raw_sub_path: &str,
) -> std::io::Result<af_files::BrowserFs> {
    fs::create_dir_all(root)?;
    let browser = af_files::BrowserFs::open(root)?;
    let relative = raw_sub_path.trim().trim_start_matches('/');
    if relative.is_empty() || relative == "." {
        return Ok(browser);
    }
    browser.create_directory_all(relative)?;
    browser.scoped(relative)
}

pub(crate) async fn lock_fileshare_mutations() -> tokio::sync::OwnedMutexGuard<()> {
    accounting::MUTATIONS.clone().lock_owned().await
}

pub(crate) fn discard_fileshare_uploads(user_id: i64) {
    if let Ok(mut sessions) = FILESHARE_UPLOADS.lock() {
        sessions.retain(|(owner, _), _| *owner != user_id);
    }
}

fn sanitize_filename(name: &str) -> anyhow::Result<String> {
    let clean = name.replace('\0', "");
    let safe_name = StdPath::new(&clean)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if safe_name.is_empty() || safe_name == "." || safe_name == ".." {
        anyhow::bail!("Invalid filename");
    }
    let lower = safe_name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    for part in parts.into_iter().skip(1) {
        let ext = format!(".{}", part);
        if BLOCKED_EXTENSIONS.contains(&ext.as_str()) {
            anyhow::bail!("File type not allowed: {}", ext);
        }
    }
    Ok(safe_name.to_string())
}

fn is_blocked_executable_magic(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7FELF" {
        return Some("application/x-elf");
    }
    if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
        return Some("application/x-dosexec");
    }
    None
}

pub async fn get_files_list(Query(q): Query<HashMap<String, String>>) -> Response {
    let raw_path = q.get("path").cloned().unwrap_or_default();
    let shared = lock_fileshare_mutations().await;
    let listing = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<af_files::Entry>> {
        let _shared = shared;
        let root = get_upload_dir();
        let mut entries = fileshare_directory(&root, &raw_path)?.list("")?;
        if !entries.is_empty() {
            let (root, directory) = accounting::object_key(&root, &raw_path)?;
            let conn = af_db::get_read_conn()?;
            let pending = crate::account_cleanup::pending_shared_names(&conn, &root, &directory)?;
            entries.retain(|entry| !pending.contains(&entry.name));
        }
        Ok(entries)
    })
    .await;
    let entries = match listing {
        Ok(Ok(entries)) => entries,
        Ok(Err(error))
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Vec::new()
        }
        Ok(Err(error)) if error.is::<std::io::Error>() => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Unable to open files directory",
            )
        }
        _ => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Could not list shared files",
            )
        }
    };
    let mut list: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            matches!(entry.kind.as_str(), "file" | "directory")
                && !entry.name.starts_with(".af-upload-")
        })
        .map(|entry| {
            let is_dir = entry.kind == "directory";
            let extension = if is_dir {
                String::new()
            } else {
                StdPath::new(&entry.name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| format!(".{}", e))
                    .unwrap_or_default()
            };
            serde_json::json!({
                "name": entry.name, "size": entry.size, "modTime": entry.modified,
                "extension": extension, "isDir": is_dir,
            })
        })
        .collect();
    list.sort_by(|a, b| {
        b["isDir"]
            .as_bool()
            .cmp(&a["isDir"].as_bool())
            .then_with(|| {
                a["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .cmp(&b["name"].as_str().unwrap_or("").to_lowercase())
            })
    });
    Json(list).into_response()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_fileshare_chunk_with(
    sessions: &mut HashMap<(i64, String), FileshareUpload>,
    root: &StdPath,
    user_id: i64,
    upload_id: &str,
    directory: &str,
    filename: &str,
    chunk_index: usize,
    total_chunks: usize,
    data: &[u8],
    publish: impl FnOnce(FileshareUpload) -> anyhow::Result<()>,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        total_chunks > 0 && total_chunks <= 1024 && chunk_index < total_chunks,
        "Invalid chunk index or count"
    );
    anyhow::ensure!(
        VALID_UPLOAD_SESSION_ID_RE.is_match(upload_id),
        "Invalid upload session id"
    );
    anyhow::ensure!(
        data.len() <= MAX_FILESHARE_CHUNK_BYTES,
        "Upload chunk exceeds 5 MiB"
    );
    sessions.retain(|_, session| session.updated.elapsed() < FILESHARE_UPLOAD_TTL);
    let key = (user_id, upload_id.to_string());
    if chunk_index == 0 {
        anyhow::ensure!(
            !sessions.contains_key(&key),
            "Upload session already exists"
        );
        anyhow::ensure!(sessions.len() < 64, "Too many pending uploads");
        let browser = create_fileshare_directory(root, directory)?;
        let original = match browser.open_file(filename) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let pending = if original.is_some() {
            browser.begin_replace(filename)?
        } else {
            browser.begin_upload(filename)?
        };
        sessions.insert(
            key.clone(),
            FileshareUpload {
                filename: filename.to_string(),
                directory: directory.to_string(),
                total_chunks,
                next_chunk: 0,
                size: 0,
                prefix: Vec::new(),
                pending,
                original,
                updated: Instant::now(),
            },
        );
    }
    let session = sessions
        .get_mut(&key)
        .ok_or_else(|| anyhow::anyhow!("Upload session expired or missing"))?;
    anyhow::ensure!(
        session.filename == filename
            && session.directory == directory
            && session.total_chunks == total_chunks,
        "Upload session metadata changed"
    );
    anyhow::ensure!(
        session.next_chunk == chunk_index,
        "Upload chunk out of order"
    );
    if session.size.saturating_add(data.len()) > MAX_UPLOAD_SIZE {
        sessions.remove(&key);
        anyhow::bail!("File exceeds maximum allowed size of 50 MiB");
    }
    // Inspect the assembled prefix too, so splitting an executable's magic
    // bytes between requests cannot bypass the file content check.
    let mut file = session.pending.file()?;
    let mut prefix = session.prefix.clone();
    prefix.extend_from_slice(&data[..data.len().min(4 - prefix.len())]);
    if is_blocked_executable_magic(&prefix).is_some() {
        sessions.remove(&key);
        anyhow::bail!("File content type not allowed");
    }
    session.prefix = prefix;
    file.seek(SeekFrom::Start(session.size as u64))?;
    if let Err(error) = file.write_all(data) {
        sessions.remove(&key);
        return Err(error.into());
    }
    session.size += data.len();
    session.next_chunk += 1;
    session.updated = Instant::now();
    if session.next_chunk == total_chunks {
        let session = sessions.remove(&key).expect("session exists while locked");
        publish(session)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn append_fileshare_chunk(
    sessions: &mut HashMap<(i64, String), FileshareUpload>,
    root: &StdPath,
    user_id: i64,
    upload_id: &str,
    directory: &str,
    filename: &str,
    chunk_index: usize,
    total_chunks: usize,
    data: &[u8],
) -> anyhow::Result<bool> {
    append_fileshare_chunk_with(
        sessions,
        root,
        user_id,
        upload_id,
        directory,
        filename,
        chunk_index,
        total_chunks,
        data,
        |session| {
            if let Some(original) = session.original {
                session.pending.commit_replace(&original)?;
            } else {
                session.pending.commit()?;
            }
            Ok(())
        },
    )
}

pub async fn upload_file(
    axum::Extension(user): axum::Extension<AuthUser>,
    peer: Option<axum::Extension<crate::auth::PeerPrincipal>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    // Admission precedes multipart body collection. The blocking closure owns
    // this permit too, including when the requesting client disconnects.
    let permit = match FILESHARE_WORKERS.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BUSY",
                "Upload workers busy; retry shortly",
            )
        }
    };
    let header_value = |key: &str| {
        headers
            .get(key)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let encoded_filename = headers
        .get("X-File-Name-Encoded")
        .and_then(|value| value.to_str().ok())
        .and_then(percent_decode_header_utf8)
        .filter(|name| !name.is_empty());
    let header_filename = encoded_filename
        .clone()
        .unwrap_or_else(|| header_value("X-File-Name"));
    let directory = headers
        .get("X-Target-Path-Encoded")
        .and_then(|value| value.to_str().ok())
        .and_then(percent_decode_header_utf8)
        .unwrap_or_else(|| header_value("X-Target-Path"));
    let upload_id = header_value("X-Upload-ID");
    let chunk_index = header_value("X-Chunk-Index");
    let total_chunks = header_value("X-Total-Chunks");
    let chunked = !upload_id.is_empty() || !chunk_index.is_empty() || !total_chunks.is_empty();
    let (chunk_index, total_chunks) = if chunked {
        match (chunk_index.parse::<usize>(), total_chunks.parse::<usize>()) {
            (Ok(index), Ok(count)) if !upload_id.is_empty() => (index, count),
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Chunked uploads require a session id, index and total",
                )
            }
        }
    } else {
        (0, 1)
    };
    let limit = if chunked {
        MAX_FILESHARE_CHUNK_BYTES
    } else {
        MAX_UPLOAD_SIZE
    };
    while let Ok(Ok(Some(mut field))) =
        tokio::time::timeout(StdDuration::from_secs(120), multipart.next_field()).await
    {
        if field.name() != Some("file") {
            continue;
        }
        let raw_filename = encoded_filename
            .as_deref()
            .or_else(|| {
                field
                    .file_name()
                    .filter(|name| !name.is_empty() && *name != "blob")
            })
            .unwrap_or(&header_filename);
        let filename = match sanitize_filename(raw_filename) {
            Ok(name) => name,
            Err(error) => {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string())
            }
        };
        let mut data = Vec::new();
        loop {
            match tokio::time::timeout(StdDuration::from_secs(120), field.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    if data.len().saturating_add(bytes.len()) > limit {
                        return api_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "PAYLOAD_TOO_LARGE",
                            "Upload exceeds file or chunk size limit",
                        );
                    }
                    data.extend_from_slice(&bytes);
                }
                Ok(Ok(None)) => break,
                _ => {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Invalid or timed out upload stream",
                    )
                }
            }
        }
        if is_blocked_executable_magic(&data).is_some() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "File content type not allowed",
            );
        }
        let response_name = filename.clone();
        let peer_principal = peer.as_ref().map(|axum::Extension(p)| p.clone());
        let shared = accounting::MUTATIONS.clone().lock_owned().await;
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            let _permit = permit;
            let _shared = shared;
            let root = get_upload_dir();
            let conn = af_db::get_conn()?;
            crate::auth::load_active_subject_for_request(
                &conn,
                user.user_id,
                peer_principal.as_ref(),
            )
            .map_err(|_| anyhow::anyhow!("Fileshare account is no longer active"))?;
            if chunked {
                let mut sessions = FILESHARE_UPLOADS
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Upload state unavailable"))?;
                append_fileshare_chunk_with(
                    &mut sessions,
                    &root,
                    user.user_id,
                    &upload_id,
                    &directory,
                    &filename,
                    chunk_index,
                    total_chunks,
                    &data,
                    |session| accounting::publish(&conn, &root, user.user_id, session),
                )
            } else {
                let browser = create_fileshare_directory(&root, &directory)?;
                let original = match browser.open_file(&filename) {
                    Ok(file) => Some(file),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                let pending = if original.is_some() {
                    browser.begin_replace(&filename)?
                } else {
                    browser.begin_upload(&filename)?
                };
                pending.file()?.write_all(&data)?;
                accounting::publish(
                    &conn,
                    &root,
                    user.user_id,
                    FileshareUpload {
                        filename,
                        directory,
                        total_chunks: 1,
                        next_chunk: 1,
                        size: data.len(),
                        prefix: Vec::new(),
                        pending,
                        original,
                        updated: Instant::now(),
                    },
                )?;
                Ok(true)
            }
        })
        .await;
        return match result {
            Ok(Ok(complete)) => Json(serde_json::json!({ "message": if complete { "File uploaded successfully" } else { "Chunk received" }, "filename": response_name, "complete": complete })).into_response(),
            Ok(Err(error)) if error.is::<accounting::QuotaExceeded>() => api_error(StatusCode::PAYLOAD_TOO_LARGE, "QUOTA_EXCEEDED", error.to_string()),
            Ok(Err(error)) => api_error(StatusCode::CONFLICT, "UPLOAD_REJECTED", error.to_string()),
            Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Upload worker failed"),
        };
    }
    api_error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "No file uploaded or invalid payload",
    )
}

pub async fn download_file(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let filename = match sanitize_filename(&filename) {
        Ok(name) => name,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()),
    };
    let name = filename.clone();
    let directory = q.get("path").cloned().unwrap_or_default();
    let shared = lock_fileshare_mutations().await;
    let opened = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _shared = shared;
        let root = get_upload_dir();
        let file = fileshare_directory(&root, &directory)?.open_file(&name)?;
        let (root, directory) = accounting::object_key(&root, &directory)?;
        let conn = af_db::get_read_conn()?;
        if crate::account_cleanup::shared_path_pending(&conn, &root, &directory, &name)? {
            return Ok(None);
        }
        let size = file.metadata()?.len();
        Ok(Some((file, size)))
    })
    .await;
    let (file, size) = match opened {
        Ok(Ok(Some(pair))) => pair,
        Ok(Ok(None)) => return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "File not found"),
        Ok(Err(error)) if error.is::<std::io::Error>() => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "File not found");
        }
        _ => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Could not open shared file",
            )
        }
    };
    let mime = mime_guess::from_path(&filename).first_or_octet_stream();
    let mut resp = Response::new(stream_file(file, size));
    let h = resp.headers_mut();
    if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
        h.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"",
        filename.replace(['\"', '\\'], "_")
    )) {
        h.insert(header::CONTENT_DISPOSITION, value);
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    resp
}

enum DeleteSharedFileError {
    BadRequest,
    Internal(anyhow::Error),
}

pub async fn delete_shared_file(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let filename = match sanitize_filename(&filename) {
        Ok(name) => name,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()),
    };
    let response_name = filename.clone();
    let directory = q.get("path").cloned().unwrap_or_default();
    let shared = accounting::MUTATIONS.clone().lock_owned().await;
    let result = tokio::task::spawn_blocking(move || -> Result<(), DeleteSharedFileError> {
        let _shared = shared;
        let conn = af_db::get_conn().map_err(DeleteSharedFileError::Internal)?;
        accounting::delete(&conn, &get_upload_dir(), &directory, &filename).map_err(|error| {
            if error.downcast_ref::<rusqlite::Error>().is_some()
                || error
                    .to_string()
                    .starts_with("Storage quota release failed:")
            {
                DeleteSharedFileError::Internal(error)
            } else {
                DeleteSharedFileError::BadRequest
            }
        })
    })
    .await;
    match result {
        Ok(Ok(())) => {
            Json(serde_json::json!({"message": "File deleted", "filename": response_name}))
                .into_response()
        }
        Ok(Err(DeleteSharedFileError::BadRequest)) => api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Unable to delete shared file",
        ),
        Ok(Err(DeleteSharedFileError::Internal(error))) => {
            tracing::warn!(%error, "Failed to delete shared file due to storage ledger error");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to delete shared file",
            )
        }
        Err(error) => {
            tracing::warn!(%error, "Fileshare delete worker failed");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to delete shared file",
            )
        }
    }
}
