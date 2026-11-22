use super::types::{
    ChecksumAlgorithm, DeleteRecursiveOutcome, DeleteRecursiveRequest, InfoQuery, InfoResponse,
};
use super::{CHECKSUM_SEMAPHORE, IO_BUF_BYTES, MAX_SEARCH_ENTRIES};
use crate::auth::AuthUser;
use crate::mcbrowser::{
    load_active_quota_conn, map_fs_io_error, normalize_relative_path,
    open_configured_user_browser_fs_with_conn, release_user_quota_conn, user_mutation_stripe,
    validate_mcbrowser_user, McBrowserError,
};
use af_files::BrowserFs;
use af_models::md5::Md5Hasher;
use axum::extract::{Extension, Query};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Json, Response};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read};
use std::sync::Arc;

pub fn parse_checksum_algorithms(
    raw: Option<&str>,
) -> Result<Vec<ChecksumAlgorithm>, McBrowserError> {
    let Some(spec) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in spec.split(',') {
        let token = part.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        let alg = match token.as_str() {
            "md5" => ChecksumAlgorithm::Md5,
            "sha1" => ChecksumAlgorithm::Sha1,
            "sha256" => ChecksumAlgorithm::Sha256,
            "sha512" => ChecksumAlgorithm::Sha512,
            _ => {
                return Err(McBrowserError::BadRequest(format!(
                    "Unsupported checksum algorithm '{token}': allowed values are md5, sha1, sha256, sha512"
                )))
            }
        };
        if !out.contains(&alg) {
            out.push(alg);
        }
    }
    Ok(out)
}

pub fn compute_checksums_from_reader<R: Read>(
    mut reader: R,
    algorithms: &[ChecksumAlgorithm],
) -> io::Result<BTreeMap<String, String>> {
    if algorithms.is_empty() {
        return Ok(BTreeMap::new());
    }

    let want_md5 = algorithms.contains(&ChecksumAlgorithm::Md5);
    let want_sha1 = algorithms.contains(&ChecksumAlgorithm::Sha1);
    let want_sha256 = algorithms.contains(&ChecksumAlgorithm::Sha256);
    let want_sha512 = algorithms.contains(&ChecksumAlgorithm::Sha512);

    let mut md5_state = want_md5.then(Md5Hasher::new);
    let mut sha1_state = want_sha1.then(Sha1::new);
    let mut sha256_state = want_sha256.then(Sha256::new);
    let mut sha512_state = want_sha512.then(Sha512::new);

    let mut buf = vec![0u8; IO_BUF_BYTES];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let slice = &buf[..n];
                if let Some(h) = md5_state.as_mut() {
                    h.update(slice);
                }
                if let Some(h) = sha1_state.as_mut() {
                    h.update(slice);
                }
                if let Some(h) = sha256_state.as_mut() {
                    h.update(slice);
                }
                if let Some(h) = sha512_state.as_mut() {
                    h.update(slice);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let mut map = BTreeMap::new();
    if let Some(h) = md5_state {
        map.insert("md5".to_string(), hex::encode(h.finalize()));
    }
    if let Some(h) = sha1_state {
        map.insert("sha1".to_string(), hex::encode(h.finalize()));
    }
    if let Some(h) = sha256_state {
        map.insert("sha256".to_string(), hex::encode(h.finalize()));
    }
    if let Some(h) = sha512_state {
        map.insert("sha512".to_string(), hex::encode(h.finalize()));
    }
    Ok(map)
}

#[cfg(test)]
pub fn execute_delete_recursive_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    user_id: i64,
) -> Result<(), McBrowserError> {
    execute_delete_recursive_with_outcome_conn(conn, bfs, normalized_path, user_id).map(|_| ())
}

pub fn execute_delete_recursive_with_outcome_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    user_id: i64,
) -> Result<DeleteRecursiveOutcome, McBrowserError> {
    load_active_quota_conn(conn, user_id, 0)?;

    match bfs.remove_tree_with_size(normalized_path) {
        Ok(removed_bytes) => {
            crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, normalized_path);
            let accounting_pending = if removed_bytes > 0 {
                release_user_quota_conn(conn, user_id, removed_bytes).is_err()
            } else {
                false
            };
            Ok(DeleteRecursiveOutcome {
                removed_bytes,
                accounting_pending,
            })
        }
        Err(removal_err) => {
            crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, normalized_path);
            if removal_err.removed_bytes > 0 {
                release_user_quota_conn(conn, user_id, removal_err.removed_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Directory was only partially deleted; released quota requires reconciliation"
                            .to_string(),
                    )
                })?;
            }
            Err(map_fs_io_error(
                removal_err.error,
                "Failed to recursively delete entry",
            ))
        }
    }
}

pub fn collect_entry_info_with_auth<F>(
    bfs: &BrowserFs,
    normalized_path: &str,
    algorithms: &[ChecksumAlgorithm],
    mut can_read_path: F,
) -> Result<InfoResponse, McBrowserError>
where
    F: FnMut(&str, bool) -> bool,
{
    let resolved = bfs
        .metadata_resolving_internal_links(normalized_path)
        .map_err(|e| map_fs_io_error(e, "Failed to inspect entry metadata"))?;
    let mut authorize_resolution = |paths: &[String], target: &str| {
        if !can_read_path(normalized_path, false)
            || !paths
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(target))
                .all(|path| can_read_path(path, false))
        {
            return Err(McBrowserError::Forbidden(
                "Entry inspection is denied by user policy".to_string(),
            ));
        }
        Ok(())
    };
    authorize_resolution(&resolved.resolution_paths, &resolved.resolved_path)?;
    let mut entry = resolved.entry;

    let checksums = if algorithms.is_empty() {
        BTreeMap::new()
    } else {
        if entry.kind != "file" {
            return Err(McBrowserError::BadRequest(
                "Checksums can only be computed for regular files".to_string(),
            ));
        }
        let opened = bfs
            .open_file_resolving_internal_links(normalized_path)
            .map_err(|e| map_fs_io_error(e, "Failed to open file for checksum"))?;
        authorize_resolution(&opened.resolution_paths, &opened.resolved_path)?;
        entry = opened.entry;
        compute_checksums_from_reader(opened.file, algorithms)
            .map_err(|e| map_fs_io_error(e, "Failed to compute file checksums"))?
    };

    let (num_files, num_dirs) = if entry.kind == "directory" {
        match bfs.list_with_trace_resolving_internal_links(normalized_path) {
            Ok(listing) => {
                authorize_resolution(&listing.resolution_paths, &listing.resolved_path)?;
                entry = listing.entry;
                let mut files = 0usize;
                let mut dirs = 0usize;
                for child in listing.entries {
                    let is_dir = child.kind == "directory";
                    let visible_at_all_hops = listing
                        .resolution_paths
                        .iter()
                        .map(String::as_str)
                        .chain(std::iter::once(normalized_path))
                        .all(|parent| {
                            let child_alias = if parent.is_empty() {
                                child.name.clone()
                            } else {
                                format!("{parent}/{}", child.name)
                            };
                            can_read_path(&child_alias, is_dir)
                        });
                    if !visible_at_all_hops || !can_read_path(&child.path, is_dir) {
                        continue;
                    }
                    if is_dir {
                        dirs += 1;
                    } else if child.kind == "file" {
                        files += 1;
                    }
                }
                (Some(files), Some(dirs))
            }
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    entry.path = normalized_path.to_string();
    entry.name = normalized_path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    Ok(InfoResponse {
        entry,
        checksums,
        num_files,
        num_dirs,
    })
}

pub(super) async fn delete_recursive(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<DeleteRecursiveRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&req.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(
        move || -> Result<crate::mcbrowser::DeleteSuccessResponse, McBrowserError> {
            let _guard = guard;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for quota update".to_string())
            })?;
            crate::mcbrowser::policy::authorize_with_conn(
                &conn,
                &user_for_task,
                crate::mcbrowser::policy::Permission::Delete,
                &normalized_path,
            )?;
            let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
            let meta = bfs
                .metadata(&normalized_path)
                .map_err(|e| map_fs_io_error(e, "Failed to inspect entry for deletion"))?;
            if meta.kind == "directory" {
                crate::mcbrowser::policy::authorize_recursive_paths_with_conn(
                    &conn,
                    &user_for_task,
                    crate::mcbrowser::policy::Permission::Delete,
                    [normalized_path.as_str()],
                )?;
                let descendants = bfs
                    .walk(&normalized_path, MAX_SEARCH_ENTRIES)
                    .map_err(|e| map_fs_io_error(e, "Failed to inspect directory for deletion"))?;
                for d in &descendants {
                    crate::mcbrowser::policy::authorize_with_conn(
                        &conn,
                        &user_for_task,
                        crate::mcbrowser::policy::Permission::Delete,
                        &d.path,
                    )?;
                }
            }
            load_active_quota_conn(&conn, user_id, 0)?;
            let audit = crate::mcbrowser::events::record_pending_intent_with_conn(
                &conn,
                &user_for_task,
                crate::mcbrowser::events::McBrowserEventTrigger::EntryDeleted,
                &normalized_path,
                None,
                0,
            )?;
            let outcome =
                execute_delete_recursive_with_outcome_conn(&conn, &bfs, &normalized_path, user_id)?;
            if !outcome.accounting_pending {
                crate::mcbrowser::events::finalize_published_mutation_with_conn(
                    &conn,
                    &audit,
                    None,
                    None,
                    -(outcome.removed_bytes.min(i64::MAX as u64) as i64),
                );
            }
            Ok(crate::mcbrowser::DeleteSuccessResponse {
                success: true,
                accounting_pending: outcome.accounting_pending,
            })
        },
    )
    .await;

    match res {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => {
            McBrowserError::Internal("Recursive delete task failed".to_string()).into_response()
        }
    }
}

pub(super) async fn get_entry_info(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<InfoQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let algorithms = match parse_checksum_algorithms(query.checksum.as_deref()) {
        Ok(algs) => algs,
        Err(e) => return e.into_response(),
    };

    let permit = if !algorithms.is_empty() {
        let Ok(p) = Arc::clone(&CHECKSUM_SEMAPHORE).acquire_owned().await else {
            return McBrowserError::Internal("Checksum concurrency limiter closed".to_string())
                .into_response();
        };
        Some(p)
    } else {
        None
    };

    let user_for_task = auth_user;
    let res = tokio::task::spawn_blocking(move || -> Result<InfoResponse, McBrowserError> {
        let _permit = permit;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for entry info".to_string())
        })?;
        crate::mcbrowser::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::policy::Permission::Read,
            &normalized_path,
        )?;
        let policy = crate::mcbrowser::policy::load_user_policy_conn(&conn, user_id)?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        drop(conn);

        collect_entry_info_with_auth(&bfs, &normalized_path, &algorithms, |child_path, is_dir| {
            if is_dir {
                crate::mcbrowser::policy::is_entry_visible(&policy, child_path, true)
            } else {
                crate::mcbrowser::policy::authorize_with_policy(
                    &policy,
                    crate::mcbrowser::policy::Permission::Read,
                    child_path,
                )
                .is_ok()
            }
        })
    })
    .await;

    match res {
        Ok(Ok(info)) => {
            let mut resp = Json(info).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Entry info task failed".to_string()).into_response(),
    }
}
