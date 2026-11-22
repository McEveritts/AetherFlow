use super::ai_providers::{
    call_gemini_api, clean_json_fence, resolve_configured_gemini_model, resolve_provider_settings,
};
use super::scan_cursor::{
    commit_auto_continuing_scan, mediaflow_library_roots, prepare_auto_continuing_scan,
    validate_mediaflow_directory, PagedScanOutcome, MAX_SCAN_DEPTH, MAX_SCAN_FILES,
};
use crate::auth::api_error;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::params;
use std::collections::HashMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Mutex;

#[derive(Default, Clone)]
struct EnricherState {
    scanning: bool,
    progress: f64,
    total: usize,
    done: usize,
    processed: usize,
    results: Vec<serde_json::Value>,
    last_err: String,
    truncated: bool,
    next_cursor: Option<String>,
}

static ENRICHER_STATE: Lazy<Mutex<EnricherState>> =
    Lazy::new(|| Mutex::new(EnricherState::default()));

static METADATA_SCAN_CURSORS: Lazy<Mutex<HashMap<PathBuf, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static MEDIA_EXTENSIONS: &[&str] = &[
    ".mkv", ".mp4", ".avi", ".mov", ".m4v", ".wmv", ".flv", ".webm", ".ts", ".srt", ".ass", ".ssa",
    ".sub", ".vtt", ".flac", ".mp3", ".aac", ".ogg", ".opus",
];

struct EnricherScanGuard {
    keep_scanning: bool,
}

impl Drop for EnricherScanGuard {
    fn drop(&mut self) {
        if !self.keep_scanning {
            let mut st = ENRICHER_STATE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            st.scanning = false;
        }
    }
}

fn parse_filename_metadata(filename: &str) -> (String, String, String, String, Vec<String>) {
    static YEAR_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"\b(19\d{2}|20\d{2})\b").unwrap());
    static QUALITY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"(?i)\b(2160p|4k|1080p|720p|480p|bluray|blu-ray|web-dl|webdl|webrip|remux|hdtv)\b",
        )
        .unwrap()
    });
    static CODEC_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?i)\b(hevc|x265|h\.?265|av1|x264|h\.?264|10bit|hdr10|dv)\b").unwrap()
    });

    let stem = StdPath::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);

    let year = YEAR_RE
        .find(stem)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let mut quality_parts: Vec<String> = Vec::new();
    for m in QUALITY_RE.find_iter(stem) {
        let tok = m.as_str();
        let norm = match tok.to_lowercase().as_str() {
            "4k" | "2160p" => "2160p".to_string(),
            "1080p" => "1080p".to_string(),
            "720p" => "720p".to_string(),
            "480p" => "480p".to_string(),
            "bluray" | "blu-ray" => "BluRay".to_string(),
            "web-dl" | "webdl" => "WEB-DL".to_string(),
            "webrip" => "WEBRip".to_string(),
            "remux" => "Remux".to_string(),
            "hdtv" => "HDTV".to_string(),
            other => other.to_uppercase(),
        };
        if !quality_parts.contains(&norm) {
            quality_parts.push(norm);
        }
    }
    for m in CODEC_RE.find_iter(stem) {
        let tok = m.as_str().to_uppercase().replace('.', "");
        let norm = if tok == "X265" || tok == "H265" {
            "HEVC".to_string()
        } else if tok == "X264" {
            "H264".to_string()
        } else {
            tok
        };
        if !quality_parts.contains(&norm) {
            quality_parts.push(norm);
        }
    }
    let quality = if quality_parts.is_empty() {
        "Unknown".to_string()
    } else {
        quality_parts.join(" ")
    };

    // Extract clean title up to the year or quality token
    let mut cutoff_idx = stem.len();
    if let Some(m) = YEAR_RE.find(stem) {
        if m.start() > 0 {
            cutoff_idx = cutoff_idx.min(m.start());
        }
    }
    if let Some(m) = QUALITY_RE.find(stem) {
        if m.start() > 0 {
            cutoff_idx = cutoff_idx.min(m.start());
        }
    }
    let raw_title = &stem[..cutoff_idx];
    let cleaned_title = raw_title
        .replace(['.', '_', '-'], " ")
        .replace(['[', ']', '(', ')'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let title = if cleaned_title.is_empty() {
        stem.replace(['.', '_'], " ").trim().to_string()
    } else {
        cleaned_title
    };

    let lower = stem.to_lowercase();
    let language =
        if lower.contains("japanese") || lower.contains(".jpn.") || lower.contains("dual") {
            "ja".to_string()
        } else if lower.contains("spanish") || lower.contains(".spa.") {
            "es".to_string()
        } else if lower.contains("french") || lower.contains(".fre.") {
            "fr".to_string()
        } else if lower.contains("german") || lower.contains(".ger.") {
            "de".to_string()
        } else {
            "en".to_string()
        };

    let mut subs = Vec::new();
    if lower.contains("sub") || lower.contains("multi") {
        subs.push("en".to_string());
    }

    (title, year, language, quality, subs)
}

pub(super) fn upsert_media_metadata_row(
    file_path: &str,
    filename: &str,
    title: &str,
    year: &str,
    language: &str,
    quality: &str,
    subtitles: &[String],
) -> anyhow::Result<serde_json::Value> {
    let conn = af_db::get_conn()?;
    let subs_json = serde_json::to_string(subtitles).unwrap_or_else(|_| "[]".to_string());
    let now_str = Utc::now().to_rfc3339();

    let updated = conn.execute(
        "UPDATE media_metadata SET filename = ?2, title = ?3, year = ?4, language = ?5, quality = ?6, subtitles_json = ?7, enriched_at = ?8 WHERE file_path = ?1",
        params![file_path, filename, title, year, language, quality, subs_json, now_str],
    )?;

    if updated == 0 {
        conn.execute(
            "INSERT INTO media_metadata (file_path, filename, title, year, language, quality, subtitles_json, enriched_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![file_path, filename, title, year, language, quality, subs_json, now_str],
        )?;
    }

    let id = conn.query_row(
        "SELECT id FROM media_metadata WHERE file_path = ?1 ORDER BY id DESC LIMIT 1",
        params![file_path],
        |r| r.get::<_, i64>(0),
    )?;

    Ok(serde_json::json!({
        "id": id,
        "file_path": file_path,
        "filename": filename,
        "title": title,
        "year": year,
        "language": language,
        "quality": quality,
        "subtitles_json": subs_json,
        "enriched_at": now_str,
    }))
}

pub async fn metadata_scan(Json(req): Json<serde_json::Value>) -> Response {
    let raw_path = req
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if raw_path.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "path is required");
    }
    if raw_path.contains("..") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Path traversal not allowed",
        );
    }
    let raw_path_owned = raw_path.to_string();
    let check_path = PathBuf::from(&raw_path_owned);
    let clean_path = match tokio::task::spawn_blocking(move || {
        validate_mediaflow_directory(&check_path, &mediaflow_library_roots())
    })
    .await
    {
        Ok(Ok(path)) => path,
        Ok(Err((status, message))) => return api_error(status, "INVALID_SCAN_PATH", message),
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                error.to_string(),
            )
        }
    };

    {
        let mut st = ENRICHER_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if st.scanning {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "A scan is already in progress",
            );
        }
        st.scanning = true;
        st.progress = 0.0;
        st.total = 0;
        st.done = 0;
        st.processed = 0;
        st.results.clear();
        st.last_err.clear();
        st.truncated = false;
        st.next_cursor = None;
    }
    let mut scan_guard = EnricherScanGuard {
        keep_scanning: false,
    };

    let ps = resolve_provider_settings();
    let has_gemini_key = !ps.gemini_api_key.is_empty();
    let configured_gemini_model = resolve_configured_gemini_model();
    let explicit_cursor = req
        .get("cursor")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let reset_cursor = req.get("reset").and_then(|v| v.as_bool()).unwrap_or(false);

    let scan_root = clean_path.clone();
    let initial_result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(PagedScanOutcome, Vec<serde_json::Value>)> {
            let prepared = prepare_auto_continuing_scan(
                &scan_root,
                explicit_cursor.as_deref(),
                reset_cursor,
                &METADATA_SCAN_CURSORS,
                MAX_SCAN_FILES,
                MAX_SCAN_DEPTH,
                |ext| {
                    let dot_ext = format!(".{}", ext.to_ascii_lowercase());
                    MEDIA_EXTENSIONS.contains(&dot_ext.as_str())
                },
            );
            let total_files = prepared.outcome.files.len();
            {
                let mut st = ENRICHER_STATE
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                st.total = total_files;
                st.truncated = prepared.outcome.truncated;
                st.next_cursor = prepared.outcome.next_cursor.clone();
            }

            let mut enriched_items = Vec::with_capacity(total_files);
            if total_files > 0 {
                let mut conn = af_db::get_conn()?;
                let tx = conn.transaction()?;
                let now_str = Utc::now().to_rfc3339();
                for path in &prepared.outcome.files {
                    let file_path_str = path.to_string_lossy().to_string();
                    let filename = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    let (title, year, language, quality, subs) = parse_filename_metadata(&filename);
                    let subs_json =
                        serde_json::to_string(&subs).unwrap_or_else(|_| "[]".to_string());
                    let updated = tx.execute(
                        "UPDATE media_metadata SET filename = ?2, title = ?3, year = ?4, language = ?5, quality = ?6, subtitles_json = ?7, enriched_at = ?8 WHERE file_path = ?1",
                        params![file_path_str, filename, title, year, language, quality, subs_json, now_str],
                    )?;
                    if updated == 0 {
                        tx.execute(
                            "INSERT INTO media_metadata (file_path, filename, title, year, language, quality, subtitles_json, enriched_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![file_path_str, filename, title, year, language, quality, subs_json, now_str],
                        )?;
                    }
                    let id = tx.query_row(
                        "SELECT id FROM media_metadata WHERE file_path = ?1 ORDER BY id DESC LIMIT 1",
                        params![file_path_str],
                        |r| r.get::<_, i64>(0),
                    )?;
                    enriched_items.push(serde_json::json!({
                        "id": id,
                        "file_path": file_path_str,
                        "filename": filename,
                        "title": title,
                        "year": year,
                        "language": language,
                        "quality": quality,
                        "subtitles_json": subs_json,
                        "enriched_at": now_str,
                    }));
                }
                tx.commit()?;
            }
            commit_auto_continuing_scan(&METADATA_SCAN_CURSORS, &prepared);
            Ok((prepared.outcome, enriched_items))
        },
    )
    .await;

    let (scan_outcome, enriched_items) = match initial_result {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Metadata scan failed: {e}"),
            );
        }
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Metadata scan worker failed: {e}"),
            );
        }
    };
    let media_files = scan_outcome.files;
    let scan_truncated = scan_outcome.truncated;
    let scan_next_cursor = scan_outcome.next_cursor;
    let total_files = media_files.len();

    {
        let mut st = ENRICHER_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        st.done = total_files;
        st.processed = total_files;
        st.results = enriched_items;
        st.progress = 100.0;
        st.truncated = scan_truncated;
        st.next_cursor = scan_next_cursor.clone();
    }

    if has_gemini_key && !media_files.is_empty() {
        scan_guard.keep_scanning = true;
        let api_key = ps.gemini_api_key.clone();
        let gemini_model = configured_gemini_model;
        tokio::spawn(async move {
            let _async_guard = EnricherScanGuard {
                keep_scanning: false,
            };
            let batch_size = 10usize;
            let total = media_files.len();
            let mut updated_results = Vec::new();
            let mut last_persist_err = String::new();

            for (start, chunk) in media_files.chunks(batch_size).enumerate() {
                let filenames: Vec<String> = chunk
                    .iter()
                    .filter_map(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.to_string())
                    })
                    .collect();
                let prompt = format!(
                    "Parse these media filenames and extract structured metadata. Return a JSON array where each element has: \"filename\", \"title\", \"year\", \"language\" (ISO 639-1), \"quality\" (e.g., 1080p BluRay), \"subtitles\" (array of likely subtitle languages). Only return valid JSON, no markdown.\n\nFilenames:\n{}",
                    filenames.join("\n")
                );
                if let Ok(resp_text) =
                    call_gemini_api(&api_key, &gemini_model, "", &[], &prompt).await
                {
                    let cleaned = clean_json_fence(&resp_text);
                    if let Ok(parsed_arr) = serde_json::from_str::<Vec<serde_json::Value>>(&cleaned)
                    {
                        for (i, item) in parsed_arr.iter().enumerate() {
                            if let Some(full_path) = chunk.get(i) {
                                let fp_str = full_path.to_string_lossy().to_string();
                                let fname =
                                    full_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                                let (def_title, def_year, def_lang, def_qual, def_subs) =
                                    parse_filename_metadata(fname);
                                let title = item
                                    .get("title")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_title);
                                let year = item
                                    .get("year")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_year);
                                let language = item
                                    .get("language")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_lang);
                                let quality = item
                                    .get("quality")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_qual);
                                let subs: Vec<String> = item
                                    .get("subtitles")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or(def_subs);
                                match upsert_media_metadata_row(
                                    &fp_str, fname, title, year, language, quality, &subs,
                                ) {
                                    Ok(row) => updated_results.push(row),
                                    Err(err) => {
                                        tracing::warn!(
                                            %err,
                                            file_path = %fp_str,
                                            "Failed to persist AI-enriched metadata row"
                                        );
                                        last_persist_err =
                                            format!("Failed to persist enriched metadata: {err}");
                                    }
                                }
                            }
                        }
                    }
                }
                let done_count = ((start + 1) * batch_size).min(total);
                let mut st = ENRICHER_STATE
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                st.done = done_count;
                st.processed = done_count;
                st.progress = (done_count as f64 / total as f64) * 100.0;
                if !updated_results.is_empty() {
                    st.results = updated_results.clone();
                }
                if !last_persist_err.is_empty() {
                    st.last_err = last_persist_err.clone();
                }
            }

            let mut st = ENRICHER_STATE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            st.scanning = false;
            st.progress = 100.0;
        });
    }

    let scan_status = if scan_truncated {
        "partial"
    } else {
        "completed"
    };
    Json(serde_json::json!({
        "message": if scan_truncated {
            "Metadata enrichment partial batch scanned; invoke again or pass next_cursor to continue"
        } else {
            "Metadata enrichment scan started"
        },
        "path": raw_path,
        "total": total_files,
        "status": scan_status,
        "partial": scan_truncated,
        "truncated": scan_truncated,
        "next_cursor": scan_next_cursor,
    }))
    .into_response()
}

pub async fn metadata_status() -> Response {
    let st = ENRICHER_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let status = if st.scanning {
        "scanning"
    } else if !st.last_err.is_empty() {
        "error"
    } else if st.truncated {
        "partial"
    } else {
        "completed"
    };
    Json(serde_json::json!({
        "scanning": st.scanning,
        "status": status,
        "partial": st.truncated,
        "truncated": st.truncated,
        "next_cursor": st.next_cursor,
        "progress": st.progress,
        "total": st.total,
        "done": st.done,
        "processed": st.processed,
        "results": st.results,
        "error": st.last_err,
    }))
    .into_response()
}

pub async fn metadata_results() -> Response {
    let conn = match af_db::get_read_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "Database unavailable while fetching metadata results");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Metadata results are temporarily unavailable",
            );
        }
    };
    let mut stmt = match conn.prepare(
        "SELECT id, file_path, filename, COALESCE(title, ''), COALESCE(year, ''), \
         COALESCE(language, ''), COALESCE(quality, ''), COALESCE(subtitles_json, '[]'), COALESCE(enriched_at, '') \
         FROM media_metadata ORDER BY enriched_at DESC, id DESC LIMIT 200",
    ) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(%err, "Failed to prepare metadata results query");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to load metadata results",
            );
        }
    };
    let rows = match stmt.query_map([], |r| {
        Ok(serde_json::json!({
            "id": r.get::<_, i64>(0)?,
            "file_path": r.get::<_, String>(1)?,
            "filename": r.get::<_, String>(2)?,
            "title": r.get::<_, String>(3)?,
            "year": r.get::<_, String>(4)?,
            "language": r.get::<_, String>(5)?,
            "quality": r.get::<_, String>(6)?,
            "subtitles_json": r.get::<_, String>(7)?,
            "enriched_at": r.get::<_, String>(8)?,
        }))
    }) {
        Ok(iter) => iter,
        Err(err) => {
            tracing::warn!(%err, "Failed to query metadata results");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to load metadata results",
            );
        }
    };
    let results: Vec<serde_json::Value> = match rows.collect::<rusqlite::Result<Vec<_>>>() {
        Ok(items) => items,
        Err(err) => {
            tracing::warn!(%err, "Failed to decode metadata results row");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to load metadata results",
            );
        }
    };
    Json(results).into_response()
}
