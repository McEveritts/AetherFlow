#![allow(clippy::result_large_err)]
//! Resumable / chunked TUS 1.0.0 upload backend for McBrowser (`uploads.rs`).
//!
//! Owns:
//! - `POST /mcbrowser/uploads` (Creation with `Tus-Resumable: 1.0.0`, `Upload-Length`, `Upload-Metadata` path & fingerprint)
//! - `GET /mcbrowser/uploads` (Resumable session discovery by exact `(user_id, path, length, fingerprint)`)
//! - `HEAD /mcbrowser/uploads/:id` (Offset, length, `Upload-Status: uploading|completed`, and `Upload-Metadata` recovery)
//! - `PATCH /mcbrowser/uploads/:id` (`application/offset+octet-stream`, `Upload-Offset`, 4 MiB chunk cap, atomic publish on completion)
//! - `DELETE /mcbrowser/uploads/:id` (Cancel unfinished upload and release full reserved quota; `409 Conflict` if already completed)
//!
//! Security & Durability invariants:
//! - Staging files live in a private service-owned directory (`<base_root>/.af-upload-staging/user-<uid>/<id>.part`)
//!   with mode `0700` on directories and `0600` on regular files, completely outside browsable `user-<uid>` roots.
//! - Every directory hop and staging file open uses `O_NOFOLLOW` (and `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`
//!   when supported by the kernel) plus `fstat` ownership (`geteuid()`) and single-hardlink (`st_nlink == 1`) checks.
//! - Full `Upload-Length` quota is reserved upfront in SQLite inside the same `BEGIN IMMEDIATE` transaction that inserts
//!   the upload session row, enforcing max 32 active (`uploading` / `publishing`) sessions per user and 24-hour expiration.
//! - Per-user global lock is held only during brief metadata/commit/cancel sections; active chunk streaming holds a
//!   per-upload session lock so a slow chunk transfer does not block other operations for the user.
//! - On restart or reconnect, `HEAD` / `PATCH` reconciles SQLite `offset_bytes` with the actual staging file size on disk
//!   (truncating any uncommitted tail beyond `offset_bytes` or rolling `offset_bytes` back to disk size if smaller).
//! - Durable publication & crash-recovery reconciliation:
//!   - Before invoking `PendingUpload::commit()` (`renameat2(RENAME_NOREPLACE)`), the session transitions to
//!     `status = 'publishing'` (with `offset_bytes = upload_length`) in SQLite.
//!   - Once `PendingUpload::commit()` succeeds, the session transitions to `status = 'completed'` and retains its
//!     DB record for 24h so lost completion ACKs can be recovered via `HEAD`.
//!   - If a crash or DB error occurs after `status = 'publishing'` is recorded (or after the file rename succeeds
//!     before `status = 'completed'` is persisted), `reconcile_publishing_session_at` inspects the target path and
//!     private staging file to deterministically promote published uploads to `'completed'`, retry publication from
//!     the intact staging file on `HEAD`/`PATCH`, or CONSERVATIVELY retain the quota reservation when publication
//!     state is ambiguous. Expiry and cancellation NEVER release quota for a published or ambiguously-published file.


mod db;
mod handlers;
mod protocol;
mod session;
mod staging;

use axum::extract::DefaultBodyLimit;
use axum::routing::{head, post};
use axum::Router;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

// Preserve existing module-level public paths for crate callers and tests.
#[allow(unused_imports)]
pub use db::{cleanup_expired_uploads_at, ensure_uploads_schema};
#[allow(unused_imports)]
pub use protocol::{
    configured_max_upload_bytes, encode_upload_metadata_header, parse_upload_metadata,
    resolve_max_upload_bytes_from_str, validate_conflict_policy, validate_fingerprint_value,
    validate_tus_version, validate_upload_id, ConflictPolicy, ConflictPolicyQuery,
    DiscoverUploadsQuery, DiscoverUploadsResponse, ParsedUploadMetadata, UploadSessionSummary,
};
#[allow(unused_imports)]
pub(crate) use db::reconcile_publishing_session_at;
#[allow(unused_imports)]
pub(crate) use protocol::{
    authorize_conflict_policy_permissions_with_conn, authorize_create_permission_with_conn,
    authorize_modify_permission_with_conn, PublishingResolution, UploadSessionRecord,
};
#[allow(unused_imports)]
pub(crate) use session::{
    create_upload_session_at, delete_upload_at, discover_uploads_at, finalize_patch_upload_at,
    head_upload_at, prepare_patch_upload_at,
};

#[cfg(test)]
#[allow(unused_imports)]
use db::{discard_unpublished_session_conn, load_session_conn};
#[cfg(test)]
#[allow(unused_imports)]
use handlers::{parse_patch_headers, stream_patch_chunk_to_file};
#[cfg(test)]
#[allow(unused_imports)]
use protocol::now_unix_secs;
#[cfg(test)]
#[allow(unused_imports)]
use session::finish_unpublished_skip_conn;
#[cfg(test)]
#[allow(unused_imports)]
use staging::{
    commit_proven_upload_at, fstat_fd, open_existing_staging_file_at, open_user_staging_dir_at,
    prepare_publication_proof_at, publish_staging_file_to_browser_fs,
    publish_zero_byte_upload_conn, read_publication_proof_at, remove_publication_proof_at,
    remove_staging_file_at, write_publication_proof_at, UploadPublicationProof,
};
#[cfg(test)]
#[allow(unused_imports)]
use super::{open_user_browser_fs_at, release_user_quota_conn, McBrowserError};
#[cfg(test)]
#[allow(unused_imports)]
use axum::response::Response;
#[cfg(test)]
#[allow(unused_imports)]
use base64::Engine as _;
#[cfg(test)]
#[allow(unused_imports)]
use std::ffi::CString;
#[cfg(test)]
#[allow(unused_imports)]
use std::os::fd::AsRawFd;
#[cfg(test)]
#[allow(unused_imports)]
use uuid::Uuid;

pub const TUS_VERSION: &str = "1.0.0";
pub const MAX_CHUNK_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB per PATCH chunk
pub const DEFAULT_MAX_RESUMABLE_UPLOAD_BYTES: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB default max file size
pub const MAX_ACTIVE_UPLOADS_PER_USER: i64 = 32;
pub const UPLOAD_SESSION_EXPIRY_SECS: i64 = 24 * 3600; // 24 hours
pub const MAX_FINGERPRINT_LEN: usize = 512;
const CHUNK_STREAM_TIMEOUT: Duration = Duration::from_secs(120);
const STAGING_DIR_NAME: &str = ".af-upload-staging";

static SESSION_LOCKS: Lazy<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn session_lock(upload_id: &str) -> Arc<AsyncMutex<()>> {
    let mut map = SESSION_LOCKS.lock().unwrap();
    if map.len() > 4096 {
        map.retain(|_, v| Arc::strong_count(v) > 1);
    }
    Arc::clone(
        map.entry(upload_id.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
    )
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/mcbrowser/uploads",
            post(handlers::create_upload).get(handlers::discover_uploads),
        )
        .route(
            "/mcbrowser/uploads/:id",
            head(handlers::head_upload)
                .patch(handlers::patch_upload)
                .delete(handlers::delete_upload)
                .layer(DefaultBodyLimit::max((MAX_CHUNK_BYTES as usize) + 65_536)),
        )
}

#[cfg(test)]
#[path = "uploads_tests.rs"]
mod tests;
