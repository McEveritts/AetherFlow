//! Storage, backup, fileshare, quota, self-update, and deployment stream routes.
//!
//! Cohesive domain implementations live under `storage/` while existing sibling
//! modules (`storage_backup_staging.rs`, `storage_accounting.rs`, and test suites)
//! stay mounted here and consume re-exported items through `super::*`.

use crate::auth::api_error;
#[cfg(test)]
use crate::auth::AuthUser;
use axum::body::Body;
#[cfg(test)]
use axum::extract::Path;
use axum::http::StatusCode;
#[cfg(test)]
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use rusqlite::{params, OptionalExtension};
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::env;
use std::fs;
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::Write;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::time::{Duration as StdDuration, Instant};
use tokio::io::AsyncReadExt;

#[path = "storage_backup_staging.rs"]
mod backup_staging;
pub(crate) use backup_staging::maintain_backup_upload_staging;

#[path = "storage_accounting.rs"]
mod accounting;
pub(crate) use accounting::{recover_fileshare_pending_publishes, recover_quota_rollbacks};

mod backup_uploads;
mod backups;
mod deploy;
mod deploy_rollback;
mod fileshare;
mod quotas;
mod updater;

#[cfg(test)]
mod backup_tests;
#[cfg(test)]
mod deploy_tests;
#[cfg(test)]
#[path = "storage_hillclimb_tests.rs"]
mod hillclimb_tests;
#[cfg(test)]
mod quota_fileshare_tests;
#[cfg(test)]
#[path = "storage_update_observability_tests.rs"]
mod update_observability_tests;
#[cfg(test)]
mod updater_tests;

pub use backup_uploads::upload_backup_chunk;
use backup_uploads::MAX_BACKUP_UPLOAD_CHUNKS;
#[allow(unused_imports)]
pub(crate) use backup_uploads::{
    finalize_assembled_backup_upload, process_backup_chunk_upload_in_dir,
};
#[cfg(test)]
use backup_uploads::{process_backup_chunk_upload, BackupUploadResult, BackupUploadSessionMeta};

use backups::is_valid_backup_filename;
#[cfg(test)]
use backups::{
    backup_download_chunk, compute_file_sha256, issue_backup_download_ticket, open_verified_backup,
    redeem_backup_download_ticket, BACKUP_DOWNLOAD_TICKETS, BACKUP_VERIFICATIONS,
    DEFAULT_BACKUP_CHUNK_SIZE,
};
pub use backups::{
    download_backup, get_active_db_path, get_backup_dir, get_backups_list,
    get_optimal_backup_window, perform_system_backup, prepare_backup_download, prune_old_backups,
    run_backup, set_backup_schedule, BackupFile,
};
#[allow(unused_imports)]
pub(crate) use backups::{
    extract_isolated_backup_ticket_cookie, is_canonical_backup_download_path,
    read_verified_backup_checksum, BackupTicketCookieError, BACKUP_DOWNLOAD_COOKIE,
    BACKUP_DOWNLOAD_COOKIE_PATH,
};

#[allow(unused_imports)]
pub(crate) use deploy::is_terminal_deploy_event;
#[cfg(test)]
pub use deploy::SSE_DEPLOY_TX;
pub use deploy::{af_common, handle_deploy_process, handle_deploy_stream};
#[cfg(test)]
use deploy::{deployment_restart_status, register_deployment, DEPLOY_STREAMS};
pub(crate) use deploy::{
    ensure_or_reuse_deploy_stream, publish_deploy_json_event, release_deploy_stream_if_matching,
};

#[cfg(test)]
use fileshare::{
    append_fileshare_chunk, append_fileshare_chunk_with, upload_dir_from_config, FILESHARE_WORKERS,
};
pub use fileshare::{delete_shared_file, download_file, get_files_list, upload_file};
pub(crate) use fileshare::{discard_fileshare_uploads, lock_fileshare_mutations};
use fileshare::{fileshare_directory, FileshareUpload};

#[cfg(test)]
use quotas::normalize_quota_record;
use quotas::query_user_quota_record_conn;
pub use quotas::{
    get_own_quota, list_user_quotas, parse_human_size, query_user_quota_record, refresh_user_quota,
    update_user_quota, UserQuotaRecord,
};

pub(crate) use updater::render_self_update_status_response;
#[allow(unused_imports)]
pub(crate) use updater::validate_runner_self_update_initiation_payload;
pub use updater::{
    check_update, compute_rate_limit_retry_at, get_system_update_status, github_update_token,
    is_newer_version, nightly_update_available, normalize_update_channel, run_update,
    sanitize_release_body, select_release_for_channel, GitHubReleaseAuthor, GitHubReleasePayload,
    GitHubUpdateCache, GitHubUpdateError,
};

// Each response owns an already-open file. Reads stay bounded, including for
// full downloads, and never occupy a runtime worker with filesystem I/O.
fn stream_file(file: fs::File, size: u64) -> Body {
    let stream = async_stream::stream! {
        let mut file = tokio::fs::File::from_std(file).take(size);
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let count = match file.read(&mut buffer).await {
                Ok(count) => count,
                Err(error) => { yield Err(error); break; }
            };
            if count == 0 {
                break;
            }
            yield Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(&buffer[..count]));
        }
    };
    Body::from_stream(stream)
}
