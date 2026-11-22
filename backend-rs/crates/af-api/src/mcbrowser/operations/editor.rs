use super::types::{ContentResponse, CreateFileRequest, PutContentRequest, PutContentResponse};
use super::{EDITOR_SEMAPHORE, MAX_EDITOR_CONTENT_BYTES};
use crate::auth::AuthUser;
use crate::mcbrowser::{
    check_fd_free_space, load_active_quota_conn, map_fs_io_error, normalize_relative_path,
    open_authorized_file_with_conn, open_configured_user_browser_fs_with_conn,
    release_user_quota_conn, reserve_user_quota_atomic, user_mutation_stripe,
    validate_mcbrowser_user, McBrowserError, MutationSuccessResponse, PathQuery,
};
use af_files::BrowserFs;
use axum::extract::{Extension, Query, Request};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;

pub(super) async fn limit_editor_requests(request: Request, next: Next) -> Response {
    let Ok(_permit) = EDITOR_SEMAPHORE.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::RETRY_AFTER, "1"),
            ],
            Json(serde_json::json!({
                "code": "EDITOR_BUSY",
                "message": "Editor capacity is busy; retry shortly"
            })),
        )
            .into_response();
    };
    next.run(request).await
}

pub fn compute_etag_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("\"{}\"", hex::encode(digest))
}

pub fn etag_matches(expected: &str, current: &str) -> bool {
    let clean_expected = expected
        .trim()
        .strip_prefix("W/")
        .unwrap_or_else(|| expected.trim())
        .trim_matches('"');
    let clean_current = current
        .trim()
        .strip_prefix("W/")
        .unwrap_or_else(|| current.trim())
        .trim_matches('"');
    !clean_expected.is_empty() && clean_expected.eq_ignore_ascii_case(clean_current)
}

pub fn read_utf8_editor_content_from_file(
    mut file: File,
    normalized_path: String,
) -> Result<(ContentResponse, File), McBrowserError> {
    let meta = file
        .metadata()
        .map_err(|_| McBrowserError::Internal("Failed to inspect file metadata".to_string()))?;
    if meta.len() > MAX_EDITOR_CONTENT_BYTES as u64 {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "File exceeds maximum editable size of {MAX_EDITOR_CONTENT_BYTES} bytes (10 MiB)"
        )));
    }

    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_EDITOR_CONTENT_BYTES));
    let mut chunk = [0u8; 8192];
    let max_read = MAX_EDITOR_CONTENT_BYTES + 1;

    while buf.len() < max_read {
        let to_read = (max_read - buf.len()).min(chunk.len());
        match file.read(&mut chunk[..to_read]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_fs_io_error(e, "Failed to read file content")),
        }
    }

    if buf.len() > MAX_EDITOR_CONTENT_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "File exceeds maximum editable size of {MAX_EDITOR_CONTENT_BYTES} bytes (10 MiB)"
        )));
    }

    if buf.contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Content editor only supports valid UTF-8 text files (binary content detected)"
                .to_string(),
        ));
    }

    let text = std::str::from_utf8(&buf).map_err(|_| {
        McBrowserError::BadRequest(
            "Content editor only supports valid UTF-8 text files".to_string(),
        )
    })?;

    let etag = compute_etag_bytes(&buf);
    Ok((
        ContentResponse {
            path: normalized_path,
            content: text.to_string(),
            etag,
        },
        file,
    ))
}

pub fn validate_editor_write_payload(content: &str) -> Result<&[u8], McBrowserError> {
    let bytes = content.as_bytes();
    if bytes.len() > MAX_EDITOR_CONTENT_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Content exceeds maximum editable size of {MAX_EDITOR_CONTENT_BYTES} bytes (10 MiB)"
        )));
    }
    if bytes.contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Content must not contain NUL bytes".to_string(),
        ));
    }
    Ok(bytes)
}

pub fn execute_create_file_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    content: Option<&str>,
    user_id: i64,
) -> Result<(), McBrowserError> {
    let payload_bytes = match content {
        Some(text) => validate_editor_write_payload(text)?,
        None => &[],
    };
    let byte_len = payload_bytes.len() as u64;

    load_active_quota_conn(conn, user_id, byte_len)?;

    let mut pending = bfs
        .begin_upload(normalized_path)
        .map_err(|e| map_fs_io_error(e, "Failed to create file"))?;
    let std_file = pending
        .file()
        .map_err(|e| map_fs_io_error(e, "Failed to prepare file handle"))?;
    check_fd_free_space(std_file.as_raw_fd(), byte_len.max(1))?;

    if !payload_bytes.is_empty() {
        pending
            .write_all(payload_bytes)
            .map_err(|e| map_fs_io_error(e, "Failed to write file content"))?;
        pending
            .flush()
            .map_err(|e| map_fs_io_error(e, "Failed to flush file content"))?;
    }

    if byte_len > 0 {
        reserve_user_quota_atomic(conn, user_id, byte_len)?;
    }

    if let Err(commit_err) = pending.commit() {
        if byte_len > 0 {
            release_user_quota_conn(conn, user_id, byte_len).map_err(|_| {
                McBrowserError::AccountingPending(
                    "File was not created; reserved quota requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(map_fs_io_error(commit_err, "Failed to finalize new file"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_put_content_with_loaded_target_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    resolved_target_path: &str,
    current_doc: &ContentResponse,
    expected_file: &File,
    content: &str,
    expected_etag: &str,
    user_id: i64,
) -> Result<(PutContentResponse, i64), McBrowserError> {
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }

    let new_bytes = validate_editor_write_payload(content)?;
    let new_size = new_bytes.len() as u64;
    let old_size = current_doc.content.len() as u64;

    if !etag_matches(expected_etag, &current_doc.etag) {
        return Err(McBrowserError::Conflict(
            "File content was modified by another request (ETag mismatch)".to_string(),
        ));
    }

    let additional_needed = new_size.saturating_sub(old_size);
    load_active_quota_conn(conn, user_id, additional_needed)?;

    let mut pending = bfs
        .begin_replace(resolved_target_path)
        .map_err(|e| map_fs_io_error(e, "Failed to stage content update"))?;
    let std_file = pending
        .file()
        .map_err(|e| map_fs_io_error(e, "Failed to access staging file"))?;
    check_fd_free_space(std_file.as_raw_fd(), new_size.max(1))?;

    if !new_bytes.is_empty() {
        pending
            .write_all(new_bytes)
            .map_err(|e| map_fs_io_error(e, "Failed to write updated content"))?;
        pending
            .flush()
            .map_err(|e| map_fs_io_error(e, "Failed to flush updated content"))?;
    }

    if additional_needed > 0 {
        reserve_user_quota_atomic(conn, user_id, additional_needed)?;
    }

    if let Err(commit_err) = pending.commit_replace(expected_file) {
        if additional_needed > 0 {
            release_user_quota_conn(conn, user_id, additional_needed).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Content was not saved; reserved quota requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(match commit_err.kind() {
            ErrorKind::AlreadyExists | ErrorKind::InvalidInput | ErrorKind::NotFound => {
                McBrowserError::Conflict(
                    "Target file changed concurrently during content update".to_string(),
                )
            }
            _ => map_fs_io_error(commit_err, "Failed to commit content update"),
        });
    }

    let released_bytes = old_size.saturating_sub(new_size);
    let accounting_pending = release_user_quota_conn(conn, user_id, released_bytes).is_err();
    crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, resolved_target_path);

    let byte_delta =
        (new_size.min(i64::MAX as u64) as i64).saturating_sub(old_size.min(i64::MAX as u64) as i64);

    Ok((
        PutContentResponse {
            success: true,
            etag: compute_etag_bytes(new_bytes),
            accounting_pending,
        },
        byte_delta,
    ))
}

#[cfg(test)]
pub(super) fn execute_put_content_for_pinned_target_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    resolved_target_path: &str,
    existing_file: File,
    content: &str,
    expected_etag: &str,
    user_id: i64,
) -> Result<(PutContentResponse, i64), McBrowserError> {
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }

    let _ = validate_editor_write_payload(content)?;

    let (current_doc, expected_file) =
        read_utf8_editor_content_from_file(existing_file, resolved_target_path.to_string())?;

    execute_put_content_with_loaded_target_conn(
        conn,
        bfs,
        resolved_target_path,
        &current_doc,
        &expected_file,
        content,
        expected_etag,
        user_id,
    )
}

#[cfg(test)]
pub fn execute_put_content_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    content: &str,
    expected_etag: &str,
    user_id: i64,
) -> Result<PutContentResponse, McBrowserError> {
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }

    let _ = validate_editor_write_payload(content)?;

    let existing_file = bfs
        .open_file(normalized_path)
        .map_err(|e| map_fs_io_error(e, "Failed to open existing file for update"))?;

    execute_put_content_for_pinned_target_conn(
        conn,
        bfs,
        normalized_path,
        existing_file,
        content,
        expected_etag,
        user_id,
    )
    .map(|(response, _)| response)
}

pub fn execute_get_content_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    path: &str,
) -> Result<ContentResponse, McBrowserError> {
    let normalized_path = crate::mcbrowser::policy::normalize_target_path(path, false)?;
    let file = open_authorized_file_with_conn(
        conn,
        auth_user,
        bfs,
        &normalized_path,
        crate::mcbrowser::policy::Permission::Read,
    )?;
    let (doc, _) = read_utf8_editor_content_from_file(file, normalized_path)?;
    Ok(doc)
}

pub(super) fn open_authorized_file_for_put_content_with_conn(
    conn: &rusqlite::Connection,
    auth_user: &AuthUser,
    bfs: &BrowserFs,
    normalized_path: &str,
) -> Result<(File, String), McBrowserError> {
    crate::mcbrowser::policy::authorize_with_conn(
        conn,
        auth_user,
        crate::mcbrowser::policy::Permission::Modify,
        normalized_path,
    )?;
    match bfs.open_file(normalized_path) {
        Ok(file) => Ok((file, normalized_path.to_string())),
        Err(_) => {
            let resolved = bfs
                .open_file_resolving_internal_links(normalized_path)
                .map_err(|error| {
                    map_fs_io_error(error, "Failed to open existing file for update")
                })?;
            for resolution_path in &resolved.resolution_paths {
                crate::mcbrowser::policy::authorize_with_conn(
                    conn,
                    auth_user,
                    crate::mcbrowser::policy::Permission::Modify,
                    resolution_path,
                )?;
            }
            crate::mcbrowser::policy::authorize_with_conn(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Modify,
                &resolved.resolved_path,
            )?;
            Ok((resolved.file, resolved.resolved_path))
        }
    }
}

#[cfg(test)]
pub fn execute_put_content_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    path: &str,
    content: &str,
    expected_etag: &str,
) -> Result<(PutContentResponse, i64), McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let normalized_path = crate::mcbrowser::policy::normalize_target_path(path, false)?;
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }
    let _ = validate_editor_write_payload(content)?;

    let (existing_file, resolved_target_path) =
        open_authorized_file_for_put_content_with_conn(conn, auth_user, bfs, &normalized_path)?;

    execute_put_content_for_pinned_target_conn(
        conn,
        bfs,
        &resolved_target_path,
        existing_file,
        content,
        expected_etag,
        user_id,
    )
}

pub(super) async fn get_content(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let user_for_task = auth_user;
    let res = tokio::task::spawn_blocking(move || -> Result<ContentResponse, McBrowserError> {
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for content read".to_string())
        })?;
        crate::mcbrowser::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::policy::Permission::Read,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        execute_get_content_for_user_with_conn(&conn, &bfs, &user_for_task, &normalized_path)
    })
    .await;

    match res {
        Ok(Ok(doc)) => {
            let etag_hdr = HeaderValue::from_str(&doc.etag).ok();
            let mut resp = Json(doc).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            if let Some(hv) = etag_hdr {
                resp.headers_mut().insert(header::ETAG, hv);
            }
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Read content task failed".to_string()).into_response(),
    }
}

pub(super) async fn put_content(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
    Json(req): Json<PutContentRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = validate_editor_write_payload(&req.content) {
        return e.into_response();
    }
    if req.etag.trim().is_empty() {
        return McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        )
        .into_response();
    }

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(move || -> Result<PutContentResponse, McBrowserError> {
        let _guard = guard;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for content update".to_string())
        })?;
        crate::mcbrowser::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::policy::Permission::Modify,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let (existing_file, resolved_target_path) = open_authorized_file_for_put_content_with_conn(
            &conn,
            &user_for_task,
            &bfs,
            &normalized_path,
        )?;
        let (current_doc, expected_file) =
            read_utf8_editor_content_from_file(existing_file, resolved_target_path.clone())?;
        let old_size = current_doc.content.len() as u64;
        let byte_delta = (req.content.len().min(i64::MAX as usize) as i64)
            .saturating_sub(old_size.min(i64::MAX as u64) as i64);
        crate::mcbrowser::events::execute_with_audit_intent_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::events::McBrowserEventTrigger::FileSaved,
            &normalized_path,
            None,
            byte_delta,
            |connection, _| {
                let (response, committed_delta) = execute_put_content_with_loaded_target_conn(
                    connection,
                    &bfs,
                    &resolved_target_path,
                    &current_doc,
                    &expected_file,
                    &req.content,
                    &req.etag,
                    user_id,
                )?;
                let accounting_complete = !response.accounting_pending;
                Ok((None, None, committed_delta, response, accounting_complete))
            },
        )
        .map(|(response, _)| response)
    })
    .await;

    match res {
        Ok(Ok(out)) => {
            let etag_hdr = HeaderValue::from_str(&out.etag).ok();
            let mut resp = Json(out).into_response();
            if let Some(hv) = etag_hdr {
                resp.headers_mut().insert(header::ETAG, hv);
            }
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Write content task failed".to_string()).into_response(),
    }
}

pub(super) async fn create_file(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<CreateFileRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&req.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if let Some(ref c) = req.content {
        if let Err(e) = validate_editor_write_payload(c) {
            return e.into_response();
        }
    }

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(move || -> Result<(), McBrowserError> {
        let _guard = guard;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for file creation".to_string())
        })?;
        crate::mcbrowser::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::policy::Permission::Create,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let byte_delta = req
            .content
            .as_ref()
            .map_or(0, |content| content.len() as i64);
        crate::mcbrowser::events::execute_with_audit_intent_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::events::McBrowserEventTrigger::FileSaved,
            &normalized_path,
            None,
            byte_delta,
            |connection, _pending| {
                execute_create_file_conn(
                    connection,
                    &bfs,
                    &normalized_path,
                    req.content.as_deref(),
                    user_id,
                )?;
                Ok((None, None, byte_delta, (), true))
            },
        )
        .map(|((), _audit_outcome)| ())
    })
    .await;

    match res {
        Ok(Ok(())) => (
            StatusCode::CREATED,
            Json(MutationSuccessResponse { success: true }),
        )
            .into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Create file task failed".to_string()).into_response(),
    }
}
