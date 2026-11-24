use axum::http::StatusCode;
use std::collections::HashMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Mutex;

pub(super) const MAX_SCAN_DEPTH: usize = 32;
pub(super) const MAX_SCAN_FILES: usize = 10_000;
const DIR_SCAN_WINDOW_CAP: usize = 1024;

#[derive(Debug, Default, Clone)]
pub(super) struct PagedScanOutcome {
    pub(super) files: Vec<PathBuf>,
    pub(super) truncated: bool,
    pub(super) truncated_by_limit: bool,
    pub(super) next_cursor: Option<String>,
}

pub(super) struct PreparedAutoScan {
    canonical_root: PathBuf,
    pub(super) outcome: PagedScanOutcome,
}

pub(super) fn mediaflow_library_roots() -> Vec<PathBuf> {
    af_services::mediaflow_allowed_roots()
}

pub(super) fn validate_mediaflow_directory(
    directory: &StdPath,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, (StatusCode, String)> {
    let resolved = directory.canonicalize().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Directory does not exist or is not accessible".to_string(),
        )
    })?;
    if !resolved.is_dir() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Scan path must be a directory".to_string(),
        ));
    }
    if !allowed_roots.iter().any(|root| resolved.starts_with(root)) {
        return Err((
            StatusCode::FORBIDDEN,
            "Directory is outside configured library roots".to_string(),
        ));
    }
    if let Err(err) = crate::peers::storage::validate_media_library_path(&resolved) {
        return Err((StatusCode::BAD_REQUEST, err.to_string()));
    }
    Ok(resolved)
}

#[allow(clippy::too_many_arguments)]
fn collect_matching_files_paged_inner<F>(
    dir: &StdPath,
    root: &StdPath,
    cursor_parts: Option<&[&str]>,
    depth: usize,
    max_depth: usize,
    max_files: usize,
    ext_matches: &F,
    rel_parts: &mut Vec<String>,
    last_rel_key: &mut Option<String>,
    out: &mut PagedScanOutcome,
) where
    F: Fn(&str) -> bool,
{
    if out.truncated_by_limit {
        return;
    }
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return;
    }
    let Ok(resolved_dir) = dir.canonicalize() else {
        return;
    };
    if !resolved_dir.starts_with(root) {
        return;
    }

    let mut window_after: Option<String> = None;
    loop {
        if out.truncated_by_limit {
            return;
        }
        let Ok(read_dir) = std::fs::read_dir(&resolved_dir) else {
            return;
        };

        let mut heap: std::collections::BinaryHeap<(String, bool, PathBuf)> =
            std::collections::BinaryHeap::with_capacity(DIR_SCAN_WINDOW_CAP.min(256));
        let mut spilled = false;

        for entry in read_dir.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            // Skip hidden entries (including `.mediaflow_trash`).
            if file_name.starts_with('.') {
                continue;
            }
            if let Some(ref after_name) = window_after {
                if file_name <= *after_name {
                    continue;
                }
            }
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let is_dir = ft.is_dir();
            let is_file = ft.is_file();
            if !is_dir && !is_file {
                continue;
            }

            if window_after.is_none() {
                if let Some(c_parts) = cursor_parts {
                    if c_parts.len() > rel_parts.len() {
                        let min_name = c_parts[rel_parts.len()];
                        if is_dir && file_name.as_str() < min_name {
                            continue;
                        }
                        if is_file && file_name.as_str() <= min_name {
                            continue;
                        }
                    }
                }
            }

            if is_file
                && !StdPath::new(&file_name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(ext_matches)
            {
                continue;
            }

            if heap.len() < DIR_SCAN_WINDOW_CAP {
                heap.push((file_name, is_dir, entry.path()));
            } else if let Some(max_top) = heap.peek() {
                spilled = true;
                if file_name < max_top.0 {
                    heap.pop();
                    heap.push((file_name, is_dir, entry.path()));
                }
            }
        }

        if heap.is_empty() {
            break;
        }

        let batch = heap.into_sorted_vec();
        for (file_name, is_dir, path) in batch {
            if out.truncated_by_limit {
                return;
            }
            window_after = Some(file_name.clone());
            rel_parts.push(file_name);
            if is_dir {
                let mut next_cursor_slice = cursor_parts;
                let mut skip_dir = false;
                if let Some(c_parts) = cursor_parts {
                    let common_len = c_parts.len().min(rel_parts.len());
                    let rel_prefix = &rel_parts[..common_len];
                    let cur_prefix = &c_parts[..common_len];
                    let ord = rel_prefix
                        .iter()
                        .map(String::as_str)
                        .cmp(cur_prefix.iter().copied());
                    match ord {
                        std::cmp::Ordering::Less => {
                            skip_dir = true;
                        }
                        std::cmp::Ordering::Greater => {
                            next_cursor_slice = None;
                        }
                        std::cmp::Ordering::Equal => {
                            if c_parts.len() == rel_parts.len() {
                                next_cursor_slice = None;
                            }
                        }
                    }
                }
                if !skip_dir {
                    if depth >= max_depth {
                        out.truncated = true;
                    } else {
                        collect_matching_files_paged_inner(
                            &path,
                            root,
                            next_cursor_slice,
                            depth + 1,
                            max_depth,
                            max_files,
                            ext_matches,
                            rel_parts,
                            last_rel_key,
                            out,
                        );
                    }
                }
            } else {
                let after_cursor = match cursor_parts {
                    None => true,
                    Some(c_parts) => rel_parts
                        .iter()
                        .map(String::as_str)
                        .gt(c_parts.iter().copied()),
                };
                if after_cursor {
                    if let Ok(canonical_file) = path.canonicalize() {
                        if canonical_file.starts_with(root)
                            && canonical_file
                                .extension()
                                .and_then(|e| e.to_str())
                                .is_some_and(ext_matches)
                        {
                            if out.files.len() >= max_files {
                                out.truncated = true;
                                out.truncated_by_limit = true;
                                out.next_cursor = last_rel_key.clone();
                                rel_parts.pop();
                                return;
                            }
                            *last_rel_key = Some(rel_parts.join("/"));
                            out.files.push(canonical_file);
                        }
                    }
                }
            }
            rel_parts.pop();
        }

        if !spilled {
            break;
        }
    }
}

pub(super) fn collect_matching_files_paged<F>(
    root: &StdPath,
    after_cursor: Option<&str>,
    max_files: usize,
    max_depth: usize,
    ext_matches: F,
) -> PagedScanOutcome
where
    F: Fn(&str) -> bool,
{
    let Ok(canonical_root) = root.canonicalize() else {
        return PagedScanOutcome::default();
    };
    let cursor_vec: Option<Vec<&str>> = after_cursor
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.split('/').filter(|seg| !seg.is_empty()).collect())
        .filter(|v: &Vec<&str>| !v.is_empty());
    let mut outcome = PagedScanOutcome::default();
    let mut rel_parts = Vec::new();
    let mut last_rel_key = None;
    collect_matching_files_paged_inner(
        &canonical_root,
        &canonical_root,
        cursor_vec.as_deref(),
        0,
        max_depth,
        max_files,
        &ext_matches,
        &mut rel_parts,
        &mut last_rel_key,
        &mut outcome,
    );
    if outcome.truncated && outcome.next_cursor.is_none() {
        outcome.next_cursor = last_rel_key;
    }
    outcome
}

pub(super) fn prepare_auto_continuing_scan<F>(
    root: &StdPath,
    explicit_cursor: Option<&str>,
    reset_cursor: bool,
    cursor_store: &Mutex<HashMap<PathBuf, String>>,
    max_files: usize,
    max_depth: usize,
    ext_matches: F,
) -> PreparedAutoScan
where
    F: Fn(&str) -> bool,
{
    let Ok(canonical_root) = root.canonicalize() else {
        return PreparedAutoScan {
            canonical_root: PathBuf::new(),
            outcome: PagedScanOutcome::default(),
        };
    };
    let (effective_cursor, used_stored_cursor) = if reset_cursor {
        (None, false)
    } else if let Some(exp) = explicit_cursor {
        let trimmed = exp.trim();
        if trimmed.is_empty() {
            (None, false)
        } else {
            (Some(trimmed.to_string()), false)
        }
    } else {
        let stored = cursor_store
            .lock()
            .ok()
            .and_then(|map| map.get(&canonical_root).cloned());
        let has_stored = stored.is_some();
        (stored, has_stored)
    };

    let mut outcome = collect_matching_files_paged(
        &canonical_root,
        effective_cursor.as_deref(),
        max_files,
        max_depth,
        &ext_matches,
    );

    // If an auto-stored cursor hit EOF with 0 remaining files (e.g., tail files were removed),
    // wrap around immediately so repeated root scans never return an empty pass on a non-empty tree.
    if used_stored_cursor && outcome.files.is_empty() && !outcome.truncated {
        outcome =
            collect_matching_files_paged(&canonical_root, None, max_files, max_depth, &ext_matches);
    }

    PreparedAutoScan {
        canonical_root,
        outcome,
    }
}

pub(super) fn commit_auto_continuing_scan(
    cursor_store: &Mutex<HashMap<PathBuf, String>>,
    prepared: &PreparedAutoScan,
) {
    if prepared.canonical_root.as_os_str().is_empty() {
        return;
    }
    if let Ok(mut map) = cursor_store.lock() {
        if let (true, Some(next_cur)) = (
            prepared.outcome.truncated_by_limit,
            prepared.outcome.next_cursor.as_ref(),
        ) {
            map.insert(prepared.canonical_root.clone(), next_cur.clone());
        } else {
            map.remove(&prepared.canonical_root);
        }
    }
}

#[cfg(test)]
pub(super) fn run_auto_continuing_scan<F>(
    root: &StdPath,
    explicit_cursor: Option<&str>,
    reset_cursor: bool,
    cursor_store: &Mutex<HashMap<PathBuf, String>>,
    max_files: usize,
    max_depth: usize,
    ext_matches: F,
) -> PagedScanOutcome
where
    F: Fn(&str) -> bool,
{
    let prepared = prepare_auto_continuing_scan(
        root,
        explicit_cursor,
        reset_cursor,
        cursor_store,
        max_files,
        max_depth,
        ext_matches,
    );
    commit_auto_continuing_scan(cursor_store, &prepared);
    prepared.outcome
}
