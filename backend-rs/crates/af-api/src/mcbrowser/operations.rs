mod archive;
mod copy;
mod editor;
mod info_delete;
mod rename;
mod search;
mod types;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

// Preserve existing module-level public paths for crate callers and tests.
#[cfg(test)]
pub use archive::decode_tar_archive_entries;
#[allow(unused_imports)]
pub use archive::{
    collect_archive_plan_for_user_with_conn, collect_archive_plan_with_auth,
    compute_archive_download_filename, normalize_archive_selection,
    redeem_and_plan_archive_ticket_with, validate_archive_entry_name, write_archive_to_writer,
    ArchivePlanItem, ArchiveTicketEntry, ArchiveTicketStore,
};
#[allow(unused_imports)]
pub(crate) use archive::{
    write_zip_central_directory_and_eocd, ChannelChunkWriter, CountingWriter, ZipEntryRecord,
};
#[allow(unused_imports)]
pub use copy::{
    allocate_version_suffix_path, format_version_suffix_candidate,
    split_version_suffix_stem_and_ext,
};
#[cfg(test)]
#[allow(unused_imports)]
pub use copy::{execute_copy_conn, execute_copy_for_user_with_conn, execute_copy_with_policy_conn};
#[allow(unused_imports)]
pub use editor::{
    compute_etag_bytes, etag_matches, execute_create_file_conn,
    execute_get_content_for_user_with_conn, read_utf8_editor_content_from_file,
    validate_editor_write_payload,
};
#[cfg(test)]
#[allow(unused_imports)]
pub use editor::{execute_put_content_conn, execute_put_content_for_user_with_conn};
#[cfg(test)]
#[allow(unused_imports)]
pub use info_delete::execute_delete_recursive_conn;
#[allow(unused_imports)]
pub use info_delete::{
    collect_entry_info_with_auth, compute_checksums_from_reader,
    execute_delete_recursive_with_outcome_conn, parse_checksum_algorithms,
};
#[cfg(test)]
#[allow(unused_imports)]
pub use rename::execute_rename_for_user_with_conn;
pub(super) use rename::execute_rename_request;
#[allow(unused_imports)]
pub use search::{
    build_deterministic_nl_plan, filter_and_rank_entries_with_flowai, filter_walked_entries,
    parse_search_type_filter, FlowAiSearchPlan,
};
pub(super) use types::RenameMoveRequest;
#[allow(unused_imports)]
pub use types::{
    resolve_operation_conflict_policy, ArchiveFormat, ArchiveRequest, ArchiveTicketResponse,
    ChecksumAlgorithm, ContentResponse, CopyMoveResponse, CopyRequest, CreateFileRequest,
    DeleteRecursiveOutcome, DeleteRecursiveRequest, InfoQuery, InfoResponse,
    OperationConflictPolicy, PutContentRequest, PutContentResponse, SearchKindFilter, SearchQuery,
    SearchResponse,
};

#[cfg(test)]
#[allow(unused_imports)]
use crate::mcbrowser::McBrowserError;
#[cfg(test)]
#[allow(unused_imports)]
use af_models::md5::Md5Hasher;
#[cfg(test)]
#[allow(unused_imports)]
use archive::{
    collect_archive_plan_with_control, create_archive_ticket, download_archive,
    download_archive_by_ticket, open_planned_archive_file, ArchivePlanningControl,
    ArchivePlanningGuard, Crc32Hasher,
};
#[cfg(test)]
#[allow(unused_imports)]
use axum::body::Bytes;
#[cfg(test)]
#[allow(unused_imports)]
use axum::extract::{Extension, Path as AxumPath};
#[cfg(test)]
#[allow(unused_imports)]
use axum::http::{header, StatusCode};
#[cfg(test)]
#[allow(unused_imports)]
use axum::response::Json;
#[cfg(test)]
#[allow(unused_imports)]
use copy::{
    copy_pinned_file_new_with_quota, copy_single_file_new_with_quota,
    execute_copy_for_user_with_accounting_conn, execute_copy_with_accounting_conn,
    prepare_copy_source_plan, CopySourcePlan,
};
#[cfg(test)]
#[allow(unused_imports)]
use editor::{
    execute_put_content_with_loaded_target_conn, open_authorized_file_for_put_content_with_conn,
};
#[cfg(test)]
#[allow(unused_imports)]
use rename::execute_rename_with_accounting_conn;
#[cfg(test)]
#[allow(unused_imports)]
use std::collections::{BTreeMap, HashSet};
#[cfg(test)]
#[allow(unused_imports)]
use std::fs::File;
#[cfg(test)]
#[allow(unused_imports)]
use std::io::{self, ErrorKind, Write};
#[cfg(test)]
#[allow(unused_imports)]
use std::time::Instant;
#[cfg(test)]
#[allow(unused_imports)]
use tokio::sync::mpsc;

pub const MAX_SEARCH_ENTRIES: usize = 10_000;
pub const MAX_SEARCH_SCAN_ENTRIES: usize = 50_000;
pub const MAX_EDITOR_CONTENT_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_ARCHIVE_TICKETS: usize = 256;
pub const ARCHIVE_TICKET_TTL_SECS: u64 = 60;
pub const ARCHIVE_TICKET_TTL: Duration = Duration::from_secs(ARCHIVE_TICKET_TTL_SECS);
const CONTENT_BODY_LIMIT_BYTES: usize = (MAX_EDITOR_CONTENT_BYTES * 6) + 65_536;
const EDITOR_CONCURRENCY_LIMIT: usize = 4;
const CHECKSUM_CONCURRENCY_LIMIT: usize = 4;
const ARCHIVE_CONCURRENCY_LIMIT: usize = 4;
const ARCHIVE_CHANNEL_CAPACITY: usize = 8;
const ARCHIVE_CHUNK_BYTES: usize = 64 * 1024;
const ARCHIVE_PLANNING_TIMEOUT: Duration = Duration::from_secs(30);
const IO_BUF_BYTES: usize = 64 * 1024;

static CHECKSUM_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(CHECKSUM_CONCURRENCY_LIMIT)));

static EDITOR_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(EDITOR_CONCURRENCY_LIMIT));

static ARCHIVE_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(ARCHIVE_CONCURRENCY_LIMIT)));

static ARCHIVE_TICKET_STORE: Lazy<ArchiveTicketStore> =
    Lazy::new(|| ArchiveTicketStore::new(MAX_ARCHIVE_TICKETS, ARCHIVE_TICKET_TTL));

pub fn router() -> Router {
    let content_routes = Router::new()
        .route(
            "/mcbrowser/content",
            get(editor::get_content).put(editor::put_content),
        )
        .route("/mcbrowser/file", post(editor::create_file))
        .layer(DefaultBodyLimit::max(CONTENT_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(editor::limit_editor_requests));

    Router::new()
        .route("/mcbrowser/search", get(search::search_entries))
        .route("/mcbrowser/copy", post(copy::copy_entry))
        .route(
            "/mcbrowser/delete-recursive",
            post(info_delete::delete_recursive),
        )
        .route("/mcbrowser/info", get(info_delete::get_entry_info))
        .route("/mcbrowser/archive", post(archive::download_archive))
        .route(
            "/mcbrowser/archive-ticket",
            post(archive::create_archive_ticket),
        )
        .route(
            "/mcbrowser/archive/:ticket",
            get(archive::download_archive_by_ticket),
        )
        .merge(content_routes)
}

#[cfg(test)]
#[path = "operations_tests.rs"]
mod operations_tests;
