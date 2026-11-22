//! Phase 4: Streaming history bounded event import, tracking policies, explicit user-link
//! mapping, and guarded legacy reconciliation (preview + signed, backup-verified apply).
//!
//! All handlers in this module require an authenticated administrator (`AuthUser.role == "admin"`).
//! Every database operation is exposed both as a pure `&rusqlite::Connection` core function (for
//! isolated in-memory / temp-file unit tests without global pool state) and as an Axum HTTP handler.

mod events;
mod handlers;
mod native_export;
mod policy;
mod reconciliation;
mod types;
mod validation;

#[cfg(test)]
mod tests;

/// `GET /api/v1/admin/streaming/imports/status` — list import checkpoints & upstream capabilities.
pub const ROUTE_ADMIN_STREAMING_IMPORT_STATUS: &str = "/api/v1/admin/streaming/imports/status";
/// `POST /api/v1/admin/streaming/imports/events` — bounded real-event JSON batch import.
pub const ROUTE_ADMIN_STREAMING_IMPORT_EVENTS: &str = "/api/v1/admin/streaming/imports/events";
/// `POST /api/v1/admin/streaming/imports/upstream-probe` — capability-aware upstream source check.
pub const ROUTE_ADMIN_STREAMING_IMPORT_UPSTREAM_PROBE: &str =
    "/api/v1/admin/streaming/imports/upstream-probe";
/// `GET` / `PUT /api/v1/admin/streaming/policies` — read or update `streaming_tracking_policies`.
pub const ROUTE_ADMIN_STREAMING_POLICIES: &str = "/api/v1/admin/streaming/policies";
/// `GET` / `PUT` / `DELETE /api/v1/admin/streaming/user-links` — explicit user identity links.
pub const ROUTE_ADMIN_STREAMING_USER_LINKS: &str = "/api/v1/admin/streaming/user-links";
/// `POST /api/v1/admin/streaming/reconciliation/preview` — read-only legacy reconciliation preview.
pub const ROUTE_ADMIN_STREAMING_RECONCILIATION_PREVIEW: &str =
    "/api/v1/admin/streaming/reconciliation/preview";
/// `POST /api/v1/admin/streaming/reconciliation/apply` — verified-backup, token-bound apply.
pub const ROUTE_ADMIN_STREAMING_RECONCILIATION_APPLY: &str =
    "/api/v1/admin/streaming/reconciliation/apply";

/// Maximum events accepted in a single bounded JSON import batch.
pub const MAX_IMPORT_BATCH_EVENTS: usize = 500;
/// Approval token validity window in seconds (15 minutes).
pub const RECONCILIATION_TOKEN_TTL_SECS: i64 = 900;

pub use events::{
    evaluate_upstream_capability, get_import_status, import_events_batch,
    record_import_checkpoint_error,
};
pub use handlers::{
    apply_legacy_reconciliation_handler, delete_streaming_user_link_handler,
    get_streaming_import_status_handler, get_streaming_policy_handler,
    import_streaming_events_handler, list_streaming_user_links_handler,
    preview_legacy_reconciliation_handler, probe_upstream_event_source_handler,
    update_streaming_policy_handler, upsert_streaming_user_link_handler,
};
pub use native_export::{
    import_native_export_batch, parse_plex_csv_export, parse_plex_json_export,
};
pub use policy::{
    delete_user_link, get_tracking_policy, list_user_links, update_tracking_policy,
    upsert_user_link,
};
pub use reconciliation::{apply_legacy_reconciliation_with_db_path, preview_legacy_reconciliation};
pub use types::{
    DeleteStreamingUserLinkRequest, ImportCheckpointRecord, ImportEventOutcome,
    ImportEventsBatchRequest, ImportEventsBatchResponse, ImportLabelInput, ImportResult,
    ImportStatusQuery, ImportStatusResponse, ImportedEventInput, NativeExportImportRequest,
    PolicyScopeSemantics, PolicyScopeTarget, ReconciliationApplyRequest,
    ReconciliationApplyResponse, ReconciliationFieldChange, ReconciliationPreviewRequest,
    ReconciliationPreviewResponse, ReconciliationRowChange, ReconciliationRowState,
    StreamingImportError, StreamingUserLinkRecord, StreamingUserLinksResponse,
    TrackingPolicyResponse, UpdateTrackingPolicyRequest, UpsertStreamingUserLinkRequest,
    UpstreamEventCapability, UpstreamProbeRequest,
};
