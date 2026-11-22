use super::approvals::{issue_approval, revoke_approval};
use super::planning::{inspect_restore, response_from_preview};
use super::restore::restore_connection;
use super::snapshot::build_archive;
use super::types::{
    PortabilityError, PortabilityResult, PreviewRequest, RestoreRequest, StreamingArchive,
};
use super::{
    HEADER_ARCHIVE_TELEMETRY, HEADER_OMITTED_BANDWIDTH_SAMPLES, HEADER_OMITTED_SESSION_SAMPLES,
    MAX_ARCHIVE_BYTES, MAX_BODY_BYTES, MAX_PORTABILITY_BODY_BYTES,
};
use crate::auth::AuthUser;
use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::http::{header, Request};
use axum::response::{IntoResponse, Response};
use chrono::Utc;

pub(super) async fn read_request_body(request: Request<Body>) -> PortabilityResult<Vec<u8>> {
    let bytes = to_bytes(request.into_body(), MAX_PORTABILITY_BODY_BYTES)
        .await
        .map_err(|_| PortabilityError::too_large())?;
    if bytes.len() > MAX_PORTABILITY_BODY_BYTES {
        return Err(PortabilityError::too_large());
    }
    Ok(bytes.to_vec())
}

pub(super) fn ensure_archive_within_byte_limit(
    archive: &StreamingArchive,
) -> PortabilityResult<()> {
    let encoded = serde_json::to_vec(archive).map_err(|_| PortabilityError::invalid())?;
    if encoded.len() > MAX_ARCHIVE_BYTES {
        return Err(PortabilityError::too_large());
    }
    Ok(())
}

pub(super) fn build_export_response(archive: &StreamingArchive) -> Response {
    let bytes = match serde_json::to_vec(archive) {
        Ok(bytes) => bytes,
        Err(_) => return PortabilityError::invalid().into_response(),
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"streaming-history-backup.json\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Body::from(bytes),
    )
        .into_response();
    let headers = response.headers_mut();
    if let Some(omitted) = &archive.manifest.omitted_samples {
        headers.insert(
            header::HeaderName::from_static(HEADER_ARCHIVE_TELEMETRY),
            header::HeaderValue::from_static("partial"),
        );
        if let Ok(value) = header::HeaderValue::from_str(&omitted.session_samples.to_string()) {
            headers.insert(
                header::HeaderName::from_static(HEADER_OMITTED_SESSION_SAMPLES),
                value,
            );
        }
        if let Ok(value) = header::HeaderValue::from_str(&omitted.bandwidth_samples.to_string()) {
            headers.insert(
                header::HeaderName::from_static(HEADER_OMITTED_BANDWIDTH_SAMPLES),
                value,
            );
        }
    } else {
        headers.insert(
            header::HeaderName::from_static(HEADER_ARCHIVE_TELEMETRY),
            header::HeaderValue::from_static("complete"),
        );
    }
    response
}

pub async fn export_handler(Extension(user): Extension<AuthUser>) -> Response {
    if user.role != "admin" {
        return PortabilityError::forbidden().into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| PortabilityError::unavailable())?;
        build_archive(&conn, Utc::now().timestamp())
    })
    .await;
    let archive = match result {
        Ok(Ok(archive)) => archive,
        Ok(Err(error)) => return error.into_response(),
        Err(_) => return PortabilityError::unavailable().into_response(),
    };
    build_export_response(&archive)
}

pub async fn preview_handler(
    Extension(user): Extension<AuthUser>,
    request: Request<Body>,
) -> Response {
    if user.role != "admin" {
        return PortabilityError::forbidden().into_response();
    }
    let bytes = match read_request_body(request).await {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let request: PreviewRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return PortabilityError::invalid().into_response(),
    };
    if let Err(error) = ensure_archive_within_byte_limit(&request.archive) {
        return error.into_response();
    }
    if let Err(error) = request.archive.validate() {
        return error.into_response();
    }
    let actor_id = user.user_id;
    let mode = request.mode;
    let archive = request.archive;
    let preview_result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| PortabilityError::unavailable())?;
        inspect_restore(&conn, &archive, mode)
    })
    .await;
    let preview = match preview_result {
        Ok(Ok(preview)) => preview,
        Ok(Err(error)) => return error.into_response(),
        Err(_) => return PortabilityError::unavailable().into_response(),
    };
    let now = Utc::now().timestamp();
    let (token, expires_at) = match issue_approval(
        actor_id,
        mode,
        &preview.archive_sha256,
        &preview.preview_sha256,
        now,
    ) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let body = response_from_preview(&preview, token, expires_at);
    let encoded = match serde_json::to_vec(&body) {
        Ok(encoded) => encoded,
        Err(_) => {
            revoke_approval(&body.approval_token);
            return PortabilityError::invalid().into_response();
        }
    };
    if encoded.len() > MAX_BODY_BYTES {
        revoke_approval(&body.approval_token);
        return PortabilityError::too_large().into_response();
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(body),
    )
        .into_response()
}

pub async fn restore_handler(
    Extension(user): Extension<AuthUser>,
    request: Request<Body>,
) -> Response {
    if user.role != "admin" {
        return PortabilityError::forbidden().into_response();
    }
    let bytes = match read_request_body(request).await {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let request: RestoreRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return PortabilityError::invalid().into_response(),
    };
    if let Err(error) = ensure_archive_within_byte_limit(&request.archive) {
        return error.into_response();
    }
    if let Err(error) = request.archive.validate() {
        return error.into_response();
    }
    let actor_id = user.user_id;
    let result = tokio::task::spawn_blocking(move || {
        let mut conn = af_db::get_conn().map_err(|_| PortabilityError::unavailable())?;
        let db_path = af_db::get_db_path();
        restore_connection(
            &mut conn,
            &db_path,
            actor_id,
            request.mode,
            &request.archive,
            &request.approval_token,
            Utc::now().timestamp(),
        )
    })
    .await;
    match result {
        Ok(Ok(response)) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            axum::Json(response),
        )
            .into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => PortabilityError::unavailable().into_response(),
    }
}
