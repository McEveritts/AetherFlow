use super::db::ensure_uploads_schema;
use super::protocol::{
    configured_base_root, map_mcbrowser_err_tus, tus_error, validate_tus_version,
    validate_upload_id, with_tus_headers, ConflictPolicyQuery, DiscoverUploadsQuery,
    DiscoverUploadsResponse, UploadSessionRecord,
};
use super::session::{
    create_upload_session_at, delete_upload_at, discover_uploads_at, finalize_patch_upload_at,
    head_upload_at, prepare_patch_upload_at,
};
use super::{session_lock, CHUNK_STREAM_TIMEOUT, MAX_CHUNK_BYTES};
use crate::auth::AuthUser;
use crate::mcbrowser::{map_fs_io_error, user_mutation_stripe, validate_mcbrowser_user, McBrowserError};
use axum::body::Body;
use axum::extract::{Extension, Path as AxumPath, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use futures::StreamExt;
use std::fs::File;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

pub(super) async fn stream_patch_chunk_to_file(
    body: Body,
    std_file: File,
    start_offset: u64,
    remaining_upload_bytes: u64,
    declared_chunk_len: Option<u64>,
) -> Result<(File, u64), Response> {
    let mut async_file = tokio::fs::File::from_std(std_file);
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|_| {
            tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Failed to read upload chunk stream",
            )
        })?;
        let chunk_len = chunk.len() as u64;
        written = written.saturating_add(chunk_len);

        if written > MAX_CHUNK_BYTES {
            let _ = async_file.set_len(start_offset).await;
            return Err(map_mcbrowser_err_tus(McBrowserError::PayloadTooLarge(
                format!("PATCH chunk exceeds maximum allowed chunk size of {MAX_CHUNK_BYTES} bytes (4 MiB)"),
            )));
        }

        if written > remaining_upload_bytes {
            let _ = async_file.set_len(start_offset).await;
            return Err(tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "PATCH chunk exceeds declared Upload-Length",
            ));
        }

        if let Some(expected_cl) = declared_chunk_len {
            if written > expected_cl {
                let _ = async_file.set_len(start_offset).await;
                return Err(tus_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "PATCH body exceeded declared Content-Length",
                ));
            }
        }

        if let Err(e) = async_file.write_all(&chunk).await {
            let _ = async_file.set_len(start_offset).await;
            return Err(map_mcbrowser_err_tus(map_fs_io_error(
                e,
                "Failed to write upload chunk",
            )));
        }
    }

    if let Some(expected_cl) = declared_chunk_len {
        if written != expected_cl {
            let _ = async_file.set_len(start_offset).await;
            return Err(tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "PATCH body length did not match Content-Length header",
            ));
        }
    }

    if let Err(e) = async_file.flush().await {
        let _ = async_file.set_len(start_offset).await;
        return Err(map_mcbrowser_err_tus(map_fs_io_error(
            e,
            "Failed to flush upload chunk",
        )));
    }

    let std_file = async_file.into_std().await;
    Ok((std_file, written))
}

pub(super) fn parse_patch_headers(headers: &HeaderMap) -> Result<(u64, Option<u64>), Response> {
    validate_tus_version(headers)?;

    let Some(ct_hv) = headers.get(header::CONTENT_TYPE) else {
        return Err(tus_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Missing Content-Type: application/offset+octet-stream",
        ));
    };
    let Ok(ct_str) = ct_hv.to_str() else {
        return Err(tus_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Invalid Content-Type header",
        ));
    };
    let media_type = ct_str.split(';').next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("application/offset+octet-stream") {
        return Err(tus_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "PATCH Content-Type must be application/offset+octet-stream",
        ));
    }

    let Some(off_hv) = headers.get("Upload-Offset") else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Missing required Upload-Offset header",
        ));
    };
    let Ok(off_str) = off_hv.to_str() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid Upload-Offset header",
        ));
    };
    let Ok(client_offset) = off_str.trim().parse::<u64>() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Upload-Offset must be a non-negative integer",
        ));
    };

    let declared_cl = match headers.get(header::CONTENT_LENGTH) {
        Some(hv) => {
            let Ok(s) = hv.to_str() else {
                return Err(tus_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid Content-Length header",
                ));
            };
            let Ok(cl) = s.trim().parse::<u64>() else {
                return Err(tus_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid Content-Length header",
                ));
            };
            if cl > MAX_CHUNK_BYTES {
                return Err(map_mcbrowser_err_tus(McBrowserError::PayloadTooLarge(
                    format!("PATCH Content-Length {cl} exceeds maximum chunk size of {MAX_CHUNK_BYTES} bytes (4 MiB)"),
                )));
            }
            Some(cl)
        }
        None => None,
    };

    Ok((client_offset, declared_cl))
}

// ─────────────────────────────────────────────────────────────────────────────
// Axum Route Handlers
// ─────────────────────────────────────────────────────────────────────────────

pub(super) async fn create_upload(
    Extension(auth_user): Extension<AuthUser>,
    Query(policy_q): Query<ConflictPolicyQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_tus_version(&headers) {
        return resp;
    }
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let res = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload creation".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        let (_, resp) = create_upload_session_at(
            &conn,
            &base_root,
            &auth_user,
            &headers,
            policy_q.policy.as_deref(),
        )?;
        Ok::<Response, Response>(resp)
    })
    .await;

    match res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload creation task failed".to_string(),
        )),
    }
}

pub(super) async fn discover_uploads(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<DiscoverUploadsQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let res = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload discovery".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        let payload = discover_uploads_at(&conn, &base_root, &auth_user, &query)?;
        Ok::<DiscoverUploadsResponse, Response>(payload)
    })
    .await;

    match res {
        Ok(Ok(payload)) => with_tus_headers(Json(payload).into_response()),
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload discovery task failed".to_string(),
        )),
    }
}

pub(super) async fn head_upload(
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(raw_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_tus_version(&headers) {
        return resp;
    }
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };
    let upload_id = match validate_upload_id(&raw_id) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    // Canonical lock order: session_lock(&upload_id) -> user_mutation_stripe(user_id).
    // head_upload_at may finish an interrupted publish or cancel/release quota on missing staging.
    let sess_guard = session_lock(&upload_id).lock_owned().await;
    let user_guard = user_mutation_stripe(user_id).lock_owned().await;
    let res = tokio::task::spawn_blocking(move || {
        let _sess_guard = sess_guard;
        let _user_guard = user_guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload status check".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        head_upload_at(&conn, &base_root, &auth_user, &upload_id, &headers)
    })
    .await;

    match res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload HEAD task failed".to_string(),
        )),
    }
}

pub(super) async fn delete_upload(
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(raw_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_tus_version(&headers) {
        return resp;
    }
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };
    let upload_id = match validate_upload_id(&raw_id) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    let sess_guard = session_lock(&upload_id).lock_owned().await;
    let user_guard = user_mutation_stripe(user_id).lock_owned().await;

    let res = tokio::task::spawn_blocking(move || {
        let _sess_guard = sess_guard;
        let _user_guard = user_guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload cancellation".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        delete_upload_at(&conn, &base_root, &auth_user, &upload_id, &headers)
    })
    .await;

    match res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload DELETE task failed".to_string(),
        )),
    }
}

pub(super) async fn patch_upload(
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(raw_id): AxumPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (client_offset, declared_cl) = match parse_patch_headers(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };
    let upload_id = match validate_upload_id(&raw_id) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    // Acquire per-session lock (owned) so concurrent PATCH/HEAD/DELETE on the SAME upload serialize,
    // without holding the global per-user mutation stripe during network chunk streaming.
    let sess_guard = session_lock(&upload_id).lock_owned().await;

    // Acquire user mutation stripe strictly AFTER session_lock only for brief preparation
    // (which may reconcile an interrupted publish or cancel/release quota if staging is missing),
    // and release it before streaming the chunk body.
    let prep_user_guard = user_mutation_stripe(user_id).lock_owned().await;
    let id_for_prep = upload_id.clone();
    let auth_for_prep = auth_user.clone();
    let prep_res = tokio::task::spawn_blocking(move || {
        let _prep_user_guard = prep_user_guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload chunk".to_string(),
            ))
        })?;
        let (session, staging_file) = prepare_patch_upload_at(
            &conn,
            &base_root,
            &auth_for_prep,
            &id_for_prep,
            client_offset,
            declared_cl,
        )?;
        Ok::<(PathBuf, UploadSessionRecord, File), Response>((base_root, session, staging_file))
    })
    .await;

    let (base_root, session, staging_file) = match prep_res {
        Ok(Ok(tuple)) => tuple,
        Ok(Err(err_resp)) => return err_resp,
        Err(_) => {
            return map_mcbrowser_err_tus(McBrowserError::Internal(
                "Upload PATCH preparation failed".to_string(),
            ))
        }
    };

    let remaining = session.upload_length.saturating_sub(session.offset_bytes);
    let stream_res = tokio::time::timeout(
        CHUNK_STREAM_TIMEOUT,
        stream_patch_chunk_to_file(
            body,
            staging_file,
            session.offset_bytes,
            remaining,
            declared_cl,
        ),
    )
    .await;

    let (staging_file, written_bytes) = match stream_res {
        Ok(Ok(pair)) => pair,
        Ok(Err(err_resp)) => return err_resp,
        Err(_) => {
            return map_mcbrowser_err_tus(McBrowserError::RequestTimeout(
                "Upload timed out while streaming PATCH chunk".to_string(),
            ))
        }
    };

    let new_offset = session.offset_bytes.saturating_add(written_bytes);
    let reaches_completion = new_offset == session.upload_length;

    // If this chunk completes the upload, acquire the user mutation stripe only for the final atomic publication step.
    let user_guard_opt = if reaches_completion {
        Some(user_mutation_stripe(user_id).lock_owned().await)
    } else {
        None
    };

    let finalize_res = tokio::task::spawn_blocking(move || {
        let _sess_guard = sess_guard;
        let _user_guard = user_guard_opt;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for finalizing upload chunk".to_string(),
            ))
        })?;
        finalize_patch_upload_at(
            &conn,
            &base_root,
            user_id,
            &session,
            staging_file,
            new_offset,
        )
    })
    .await;

    match finalize_res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload PATCH finalization task failed".to_string(),
        )),
    }
}
