use super::events::{evaluate_upstream_capability, get_import_status, import_events_batch};
use super::native_export::import_native_export_batch;
use super::policy::{
    delete_user_link, get_tracking_policy, list_user_links, update_tracking_policy,
    upsert_user_link,
};
use super::reconciliation::{
    apply_legacy_reconciliation_with_db_path, preview_legacy_reconciliation,
};
use super::types::{
    ensure_admin, DeleteStreamingUserLinkRequest, ImportEventsBatchRequest, ImportResult,
    ImportStatusQuery, NativeExportImportRequest, ReconciliationApplyRequest,
    ReconciliationPreviewRequest, StreamingImportError, UpdateTrackingPolicyRequest,
    UpsertStreamingUserLinkRequest, UpstreamProbeRequest,
};
use crate::auth::AuthUser;
use axum::extract::{Extension, Json, Query};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::Utc;

fn acquire_pool_conn(
    user: &AuthUser,
) -> ImportResult<r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>> {
    ensure_admin(user)?;
    af_db::get_conn().map_err(|_| {
        StreamingImportError::unavailable(
            "streaming_db_unavailable",
            "Streaming history database is temporarily unavailable",
        )
    })
}

/// `GET /api/v1/admin/streaming/imports/status`
pub async fn get_streaming_import_status_handler(
    Query(query): Query<ImportStatusQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        get_import_status(&conn, query, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Import status task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/imports/upstream-probe`
pub async fn probe_upstream_event_source_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<UpstreamProbeRequest>,
) -> Response {
    if let Err(err) = ensure_admin(&user) {
        return err.into_response();
    }
    match evaluate_upstream_capability(
        &request.provider,
        &request.server_id,
        &request.endpoint_path,
    ) {
        Ok(cap) => ([(header::CACHE_CONTROL, "no-store")], Json(cap)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/imports/events`
pub async fn import_streaming_events_handler(
    Extension(user): Extension<AuthUser>,
    Json(raw_body): Json<serde_json::Value>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        let now = Utc::now().timestamp();
        if raw_body.get("format").is_some() && raw_body.get("events").is_none() {
            let native_req: NativeExportImportRequest =
                serde_json::from_value(raw_body).map_err(|err| {
                    StreamingImportError::bad_request(
                        "invalid_import_request",
                        format!("Invalid native export import payload: {err}"),
                    )
                })?;
            import_native_export_batch(&conn, native_req, &user, now)
        } else {
            let batch_req: ImportEventsBatchRequest =
                serde_json::from_value(raw_body).map_err(|err| {
                    StreamingImportError::bad_request(
                        "invalid_import_request",
                        format!("Invalid event batch import payload: {err}"),
                    )
                })?;
            import_events_batch(&conn, batch_req, &user, now)
        }
    })
    .await
    .map_err(|_| StreamingImportError::internal("Event import task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `GET /api/v1/admin/streaming/policies`
pub async fn get_streaming_policy_handler(Extension(user): Extension<AuthUser>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        get_tracking_policy(&conn, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Get policy task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `PUT /api/v1/admin/streaming/policies`
pub async fn update_streaming_policy_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<UpdateTrackingPolicyRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        update_tracking_policy(&conn, request, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Update policy task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `GET /api/v1/admin/streaming/user-links`
pub async fn list_streaming_user_links_handler(Extension(user): Extension<AuthUser>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        list_user_links(&conn, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("List user links task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `PUT /api/v1/admin/streaming/user-links`
pub async fn upsert_streaming_user_link_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<UpsertStreamingUserLinkRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        upsert_user_link(&conn, request, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Upsert user link task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `DELETE /api/v1/admin/streaming/user-links`
pub async fn delete_streaming_user_link_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<DeleteStreamingUserLinkRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        delete_user_link(&conn, request, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Delete user link task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/reconciliation/preview`
pub async fn preview_legacy_reconciliation_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<ReconciliationPreviewRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        preview_legacy_reconciliation(&conn, request, &user, Utc::now().timestamp())
    })
    .await
    .map_err(|_| StreamingImportError::internal("Reconciliation preview task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/reconciliation/apply`
pub async fn apply_legacy_reconciliation_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<ReconciliationApplyRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        let db_path = af_db::get_db_path();
        apply_legacy_reconciliation_with_db_path(
            &conn,
            &db_path,
            request,
            &user,
            Utc::now().timestamp(),
        )
    })
    .await
    .map_err(|_| StreamingImportError::internal("Reconciliation apply task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}
