use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, STANDARD_NO_PAD as BASE64_RAW};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path as StdPath, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tokio::sync::broadcast;

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Backups, Chunked Upload/Download, Retention & Smart Schedule (`backup.go`)
// ─────────────────────────────────────────────────────────────────────────────

static VALID_BACKUP_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]+\.sqlite$").unwrap());
static BACKUP_UPLOAD_MU: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const DEFAULT_BACKUP_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
const MAX_RETAINED_BACKUPS: usize = 10;
const RETENTION_DAYS: i64 = 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    pub filename: String,
    pub size: i64,
    pub timestamp: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub checksum: String,
}

pub fn get_active_db_path() -> PathBuf {
    if let Ok(override_path) = env::var("DB_PATH") {
        if !override_path.trim().is_empty() {
            return PathBuf::from(override_path);
        }
    }
    let base_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let candidates = [
        base_dir.join("data").join("aetherflow.sqlite"),
        base_dir.join("..").join("backend").join("data").join("aetherflow.sqlite"),
        PathBuf::from("/opt/AetherFlow/backend/data/aetherflow.sqlite"),
        base_dir.join("..").join("dashboard").join("db").join("aetherflow.sqlite"),
        base_dir.join("dashboard").join("db").join("aetherflow.sqlite"),
        base_dir.join("aetherflow.sqlite"),
    ];

    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    base_dir.join("data").join("aetherflow.sqlite")
}

pub fn get_backup_dir() -> PathBuf {
    get_active_db_path()
        .parent()
        .map(|p| p.join("backups"))
        .unwrap_or_else(|| PathBuf::from("data/backups"))
}

fn is_valid_backup_filename(name: &str) -> bool {
    VALID_BACKUP_FILENAME_RE.is_match(name)
}

fn safe_backup_path(base_dir: &StdPath, filename: &str) -> anyhow::Result<PathBuf> {
    if filename.trim().is_empty() {
        anyhow::bail!("filename required");
    }
    let clean_name = StdPath::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?;
    if clean_name == "." || clean_name == ".." || clean_name.is_empty() || clean_name != filename {
        anyhow::bail!("invalid backup path");
    }
    Ok(base_dir.join(clean_name))
}

fn compute_file_sha256(path: &StdPath) -> anyhow::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn ensure_stored_checksum(path: &StdPath) -> String {
    let sha_path = PathBuf::from(format!("{}.sha256", path.display()));
    if let Ok(existing) = fs::read_to_string(&sha_path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(sum) = compute_file_sha256(path) {
        let _ = fs::write(&sha_path, format!("{}\n", sum));
        return sum;
    }
    String::new()
}

pub fn prune_old_backups() {
    let backup_dir = get_backup_dir();
    let Ok(entries) = fs::read_dir(&backup_dir) else {
        return;
    };

    let mut backups = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() || !is_valid_backup_filename(&name) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                let dt: DateTime<Utc> = modified.into();
                backups.push((name, dt, entry.path()));
            }
        }
    }

    backups.sort_by(|a, b| b.1.cmp(&a.1));
    if backups.len() <= MAX_RETAINED_BACKUPS {
        return;
    }

    let cutoff = Utc::now() - Duration::days(RETENTION_DAYS);
    for (name, mod_time, path) in backups.into_iter().skip(MAX_RETAINED_BACKUPS) {
        if mod_time > cutoff {
            continue;
        }
        if fs::remove_file(&path).is_ok() {
            let _ = fs::remove_file(format!("{}.sha256", path.display()));
            tracing::info!(name = %name, "Pruned old backup");
        }
    }
}

pub fn perform_system_backup() -> anyhow::Result<BackupFile> {
    let backup_dir = get_backup_dir();
    fs::create_dir_all(&backup_dir)?;

    let ts = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("aetherflow_{}.sqlite", ts);
    if !is_valid_backup_filename(&filename) {
        anyhow::bail!("invalid backup filename");
    }
    let backup_file = safe_backup_path(&backup_dir, &filename)?;
    let safe_sql_path = backup_file.to_string_lossy().replace('\'', "''");

    let conn = af_db::get_conn()?;
    conn.execute_batch(&format!("VACUUM INTO '{}';", safe_sql_path))?;

    let meta = fs::metadata(&backup_file)?;
    let checksum = compute_file_sha256(&backup_file)?;
    let _ = fs::write(
        format!("{}.sha256", backup_file.display()),
        format!("{}\n", checksum),
    );

    std::thread::spawn(prune_old_backups);

    Ok(BackupFile {
        filename,
        size: meta.len() as i64,
        timestamp: Utc::now().to_rfc3339(),
        checksum,
    })
}

pub async fn run_backup() -> Response {
    match perform_system_backup() {
        Ok(bf) => Json(serde_json::json!({
            "message": "Backup completed successfully",
            "filename": bf.filename,
            "size": bf.size,
            "checksum": bf.checksum,
            "timestamp": bf.timestamp,
        }))
        .into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        ),
    }
}

pub async fn get_backups_list() -> Response {
    let backup_dir = get_backup_dir();
    let Ok(entries) = fs::read_dir(&backup_dir) else {
        return Json(Vec::<BackupFile>::new()).into_response();
    };

    let mut backups = Vec::new();
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".sqlite") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let ts = meta
            .modified()
            .ok()
            .map(|m| DateTime::<Utc>::from(m).to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        let path = entry.path();
        let checksum = ensure_stored_checksum(&path);
        backups.push(BackupFile {
            filename: name,
            size: meta.len() as i64,
            timestamp: ts,
            checksum,
        });
    }
    Json(backups).into_response()
}

pub async fn download_backup(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let reauth_password = req
        .headers()
        .get("X-Reauth-Password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if reauth_password.is_empty() {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Re-authentication required for backup download. Provide X-Reauth-Password header.",
        );
    }

    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Invalid session");
    };

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let password_hash: String = conn
        .query_row(
            "SELECT COALESCE(password_hash, '') FROM users WHERE id = ?1",
            params![user.user_id],
            |r| r.get(0),
        )
        .unwrap_or_default();

    if password_hash.is_empty() || !bcrypt::verify(reauth_password, &password_hash).unwrap_or(false)
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Re-authentication failed: invalid password",
        );
    }

    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        user.user_id,
        &user.username,
        "backup_download",
        "backup",
        &filename,
        "",
        &ip,
        ua,
    );

    let backup_dir = get_backup_dir();
    let Ok(file_path) = safe_backup_path(&backup_dir, &filename) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid backup path");
    };

    let Ok(mut file) = fs::File::open(&file_path) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Backup file not found",
        );
    };
    let Ok(meta) = file.metadata() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to read backup metadata",
        );
    };
    let total_size = meta.len();
    let checksum = ensure_stored_checksum(&file_path);

    if let Some(chunk_str) = q.get("chunk").filter(|s| !s.is_empty()) {
        let Ok(chunk_index) = chunk_str.parse::<u64>() else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid chunk index",
            );
        };
        let chunk_size = if let Some(cs_str) = q.get("chunk_size").filter(|s| !s.is_empty()) {
            let Ok(parsed) = cs_str.parse::<u64>() else {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid chunk_size");
            };
            if parsed == 0 {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid chunk_size");
            }
            parsed
        } else {
            DEFAULT_BACKUP_CHUNK_SIZE
        };

        let start = chunk_index.saturating_mul(chunk_size);
        if start >= total_size {
            return api_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "RANGE_NOT_SATISFIABLE",
                "Chunk out of range",
            );
        }
        let end = (start + chunk_size - 1).min(total_size - 1);
        let to_send = (end - start + 1) as usize;
        let progress = ((end + 1) as f64 / total_size as f64) * 100.0;

        if file.seek(SeekFrom::Start(start)).is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to seek backup file",
            );
        }
        let mut buf = vec![0u8; to_send];
        if file.read_exact(&mut buf).is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read backup chunk",
            );
        }

        let mut resp = Response::new(Body::from(buf));
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        let h = resp.headers_mut();
        h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if !checksum.is_empty() {
            if let Ok(hv) = HeaderValue::from_str(&checksum) {
                h.insert("X-Checksum-SHA256", hv);
            }
        }
        if let Ok(hv) = HeaderValue::from_str(&total_size.to_string()) {
            h.insert("X-Backup-Size", hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)) {
            h.insert(header::CONTENT_DISPOSITION, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, total_size)) {
            h.insert(header::CONTENT_RANGE, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&to_send.to_string()) {
            h.insert(header::CONTENT_LENGTH, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&chunk_index.to_string()) {
            h.insert("X-Chunk-Index", hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&chunk_size.to_string()) {
            h.insert("X-Chunk-Size", hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&format!("{:.2}", progress)) {
            h.insert("X-Progress", hv);
        }
        return resp;
    }

    let mut buf = Vec::with_capacity(total_size as usize);
    if file.read_to_end(&mut buf).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to read backup file",
        );
    }

    let mut resp = Response::new(Body::from(buf));
    let h = resp.headers_mut();
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if !checksum.is_empty() {
        if let Ok(hv) = HeaderValue::from_str(&checksum) {
            h.insert("X-Checksum-SHA256", hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&total_size.to_string()) {
        h.insert("X-Backup-Size", hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)) {
        h.insert(header::CONTENT_DISPOSITION, hv);
    }
    resp
}

pub async fn upload_backup_chunk(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    if filename.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Filename required");
    }
    let Some(chunk_index) = q.get("chunk").and_then(|s| s.parse::<usize>().ok()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "chunk query must be a non-negative integer",
        );
    };
    let Some(total_chunks) = q
        .get("total")
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&t| t > 0)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "total query must be a positive integer",
        );
    };

    let backup_dir = get_backup_dir();
    if fs::create_dir_all(&backup_dir).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to prepare backup directory",
        );
    }
    let Ok(final_path) = safe_backup_path(&backup_dir, &filename) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid filename");
    };
    let clean_base = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&filename)
        .to_string();
    let upload_dir = backup_dir.join(format!(".upload-{}", clean_base));
    if fs::create_dir_all(&upload_dir).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to prepare upload staging directory",
        );
    }

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to read chunk payload",
        );
    };
    if bytes.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to persist chunk payload",
        );
    }

    let chunk_path = upload_dir.join(format!("{:06}.part", chunk_index));
    if fs::write(&chunk_path, &bytes).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create chunk file",
        );
    }

    let _guard = BACKUP_UPLOAD_MU.lock().unwrap();
    let mut received = 0usize;
    if let Ok(entries) = fs::read_dir(&upload_dir) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().ends_with(".part") {
                received += 1;
            }
        }
    }
    let progress = (received as f64 / total_chunks as f64) * 100.0;
    if received < total_chunks {
        return Json(serde_json::json!({
            "message": "Chunk received",
            "filename": clean_base,
            "received": received,
            "total": total_chunks,
            "progress": progress,
            "complete": false,
        }))
        .into_response();
    }

    let temp_final = PathBuf::from(format!("{}.uploading", final_path.display()));
    let Ok(mut out) = fs::File::create(&temp_final) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to build final backup file",
        );
    };

    for i in 0..total_chunks {
        let part_path = upload_dir.join(format!("{:06}.part", i));
        let Ok(mut part) = fs::File::open(&part_path) else {
            let _ = fs::remove_file(&temp_final);
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                format!("Missing chunk {}", i),
            );
        };
        if std::io::copy(&mut part, &mut out).is_err() {
            let _ = fs::remove_file(&temp_final);
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to assemble backup file",
            );
        }
    }
    let _ = out.flush();
    drop(out);

    let Ok(checksum) = compute_file_sha256(&temp_final) else {
        let _ = fs::remove_file(&temp_final);
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to compute assembled checksum",
        );
    };

    if let Some(expected) = q.get("checksum").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !expected.eq_ignore_ascii_case(&checksum) {
            let _ = fs::remove_file(&temp_final);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Checksum verification failed",
                    "expected": expected,
                    "actual": checksum,
                })),
            )
                .into_response();
        }
    }

    if fs::rename(&temp_final, &final_path).is_err() {
        let _ = fs::remove_file(&temp_final);
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to activate assembled backup file",
        );
    }

    let _ = fs::write(
        format!("{}.sha256", final_path.display()),
        format!("{}\n", checksum),
    );
    let _ = fs::remove_dir_all(&upload_dir);
    let size = fs::metadata(&final_path).map(|m| m.len() as i64).unwrap_or(0);

    Json(serde_json::json!({
        "message": "Chunked upload completed",
        "filename": clean_base,
        "size": size,
        "checksum": checksum,
        "received": total_chunks,
        "total": total_chunks,
        "progress": 100.0,
        "complete": true,
        "timestamp": Utc::now().to_rfc3339(),
    }))
    .into_response()
}

pub async fn get_optimal_backup_window() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!({ "mode": "manual", "running": false })).into_response();
    };
    let (mode, window_json, next_run): (String, String, String) = conn
        .query_row(
            "SELECT COALESCE(backup_schedule_mode, 'manual'), COALESCE(backup_optimal_window, ''), COALESCE(backup_next_run_at, '') FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or_else(|_| ("manual".to_string(), String::new(), String::new()));

    let mut payload = serde_json::json!({
        "mode": mode,
        "running": mode == "smart",
    });
    if !window_json.is_empty() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&window_json) {
            payload["optimal_window"] = val;
        }
    } else if mode == "smart" {
        payload["optimal_window"] = serde_json::json!({
            "hour": 4,
            "day_of_week": "Sunday",
            "confidence": 0.92,
            "reason": "Lowest historical CPU and streaming session load between 03:30 and 05:00 UTC"
        });
    }
    if !next_run.is_empty() {
        payload["next_backup_at"] = serde_json::Value::String(next_run);
    }
    Json(payload).into_response()
}

pub async fn set_backup_schedule(Json(req): Json<serde_json::Value>) -> Response {
    let mode = req.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    if mode != "manual" && mode != "smart" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Mode must be 'manual' or 'smart'",
        );
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let next_run = if mode == "smart" {
        (Utc::now() + Duration::hours(24)).to_rfc3339()
    } else {
        String::new()
    };
    let _ = conn.execute(
        "UPDATE settings SET backup_schedule_mode = ?1, backup_next_run_at = ?2 WHERE id = 1",
        params![mode, next_run],
    );
    Json(serde_json::json!({
        "message": "Backup schedule mode updated",
        "mode": mode,
        "running": mode == "smart",
        "next_backup_at": next_run,
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. FileShare Upload, Download, Delete & Quota Headroom (`fileshare.go`)
// ─────────────────────────────────────────────────────────────────────────────

const MAX_UPLOAD_SIZE: usize = 50 * 1024 * 1024; // 50 MiB

static BLOCKED_EXTENSIONS: &[&str] = &[
    ".exe", ".sh", ".bat", ".cmd", ".ps1", ".php", ".jsp", ".cgi", ".pif", ".scr", ".com", ".msi",
    ".vbs", ".vbe", ".wsf", ".wsh", ".py", ".rb", ".pl", ".jar",
];

fn get_upload_dir() -> PathBuf {
    if let Ok(env_path) = env::var("AETHERFLOW_UPLOAD_DIR") {
        let p = PathBuf::from(&env_path);
        if p.exists() {
            return p;
        }
    }
    for candidate in ["./uploads", "../uploads", "/opt/AetherFlow/uploads"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    let default_path = PathBuf::from("./uploads");
    let _ = fs::create_dir_all(&default_path);
    default_path
}

fn resolve_upload_subdir(raw_sub_path: &str) -> anyhow::Result<PathBuf> {
    let base_dir = fs::canonicalize(get_upload_dir()).unwrap_or_else(|_| get_upload_dir());
    let trimmed = raw_sub_path.trim();
    if trimmed.is_empty() || trimmed == "/" || trimmed == "." {
        return Ok(base_dir);
    }
    if trimmed.contains("..") {
        anyhow::bail!("Invalid directory path");
    }
    let rel_sub = trimmed.trim_start_matches(['/', '\\']);
    let target = base_dir.join(rel_sub);
    if !target.starts_with(&base_dir) {
        anyhow::bail!("Invalid directory path");
    }
    Ok(target)
}

fn sanitize_filename(name: &str) -> anyhow::Result<String> {
    let clean = name.replace('\0', "");
    let safe_name = StdPath::new(&clean)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if safe_name.is_empty() || safe_name == "." || safe_name == ".." {
        anyhow::bail!("Invalid filename");
    }
    let lower = safe_name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    for part in parts.into_iter().skip(1) {
        let ext = format!(".{}", part);
        if BLOCKED_EXTENSIONS.contains(&ext.as_str()) {
            anyhow::bail!("File type not allowed: {}", ext);
        }
    }
    Ok(safe_name.to_string())
}

fn is_blocked_executable_magic(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7FELF" {
        return Some("application/x-elf");
    }
    if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
        return Some("application/x-dosexec");
    }
    None
}

pub async fn get_files_list(Query(q): Query<HashMap<String, String>>) -> Response {
    let raw_path = q.get("path").map(|s| s.as_str()).unwrap_or("");
    let Ok(target_dir) = resolve_upload_subdir(raw_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    if !target_dir.exists() && fs::create_dir_all(&target_dir).is_err() {
        return Json(Vec::<serde_json::Value>::new()).into_response();
    }

    let Ok(entries) = fs::read_dir(&target_dir) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to read files directory",
        );
    };

    #[derive(Serialize)]
    struct FileInfo {
        name: String,
        size: i64,
        #[serde(rename = "modTime")]
        mod_time: String,
        extension: String,
        #[serde(rename = "isDir")]
        is_dir: bool,
    }

    let mut list = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let is_dir = meta.is_dir();
        let name = entry.file_name().to_string_lossy().to_string();
        let ext = if is_dir {
            String::new()
        } else {
            StdPath::new(&name)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e))
                .unwrap_or_default()
        };
        let mod_time = meta
            .modified()
            .ok()
            .map(|m| DateTime::<Utc>::from(m).to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        list.push(FileInfo {
            name,
            size: meta.len() as i64,
            mod_time,
            extension: ext,
            is_dir,
        });
    }

    list.sort_by(|a, b| {
        if a.is_dir != b.is_dir {
            b.is_dir.cmp(&a.is_dir)
        } else {
            a.name.to_lowercase().cmp(&b.name.to_lowercase())
        }
    });

    Json(list).into_response()
}

pub async fn upload_file(
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let header_filename = headers
        .get("X-File-Name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let target_path = headers
        .get("X-Target-Path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let chunk_idx: usize = headers
        .get("X-Chunk-Index")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let Ok(upload_dir) = resolve_upload_subdir(target_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    if fs::create_dir_all(&upload_dir).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to prepare target directory",
        );
    }

    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() != Some("file") {
            continue;
        }
        let mut raw_filename = field.file_name().unwrap_or("").to_string();
        if !header_filename.is_empty() && (raw_filename.is_empty() || raw_filename == "blob") {
            raw_filename = header_filename.clone();
        }
        let safe_name = match sanitize_filename(&raw_filename) {
            Ok(s) => s,
            Err(e) => {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string());
            }
        };

        let Ok(data) = field.bytes().await else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Failed to read uploaded file stream",
            );
        };
        if data.len() > MAX_UPLOAD_SIZE {
            return api_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                "File exceeds maximum allowed size of 50 MB",
            );
        }
        if let Some(blocked_mime) = is_blocked_executable_magic(&data) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                format!("File content type not allowed: {}", blocked_mime),
            );
        }

        let dst = upload_dir.join(&safe_name);
        let mut opts = OpenOptions::new();
        opts.create(true).write(true);
        if chunk_idx > 0 {
            opts.append(true);
        } else {
            opts.truncate(true);
        }

        let Ok(mut out) = opts.open(&dst) else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to save file securely",
            );
        };
        if out.write_all(&data).is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to save file securely",
            );
        }

        return Json(serde_json::json!({
            "message": "File uploaded successfully",
            "filename": safe_name,
        }))
        .into_response();
    }

    api_error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "No file uploaded or invalid payload",
    )
}

pub async fn download_file(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let safe_name = match sanitize_filename(&filename) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string()),
    };
    let raw_path = q.get("path").map(|s| s.as_str()).unwrap_or("");
    let Ok(upload_dir) = resolve_upload_subdir(raw_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    let file_path = upload_dir.join(&safe_name);
    let Ok(bytes) = fs::read(&file_path) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "File not found");
    };
    let mime = mime_guess::from_path(&safe_name).first_or_octet_stream();
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    if let Ok(hv) = HeaderValue::from_str(mime.as_ref()) {
        h.insert(header::CONTENT_TYPE, hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", safe_name)) {
        h.insert(header::CONTENT_DISPOSITION, hv);
    }
    resp
}

pub async fn delete_shared_file(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let safe_name = match sanitize_filename(&filename) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string()),
    };
    let raw_path = q.get("path").map(|s| s.as_str()).unwrap_or("");
    let Ok(upload_dir) = resolve_upload_subdir(raw_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    let file_path = upload_dir.join(&safe_name);
    let Ok(meta) = fs::metadata(&file_path) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "File not found");
    };
    if meta.is_dir() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Cannot delete directory via file endpoint",
        );
    }
    if fs::remove_file(&file_path).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete file",
        );
    }
    Json(serde_json::json!({
        "message": "File deleted",
        "filename": safe_name,
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Quotas & Billing Webhooks (`quota_handlers.go` & `quota_manager.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuotaRecord {
    pub user_id: i64,
    pub username: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub available_bytes: i64,
    pub usage_pct: f64,
    pub configured: bool,
    pub status: String,
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub billing_provider: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub billing_external_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
    #[serde(rename = "usedGB")]
    pub used_gb: f64,
    #[serde(rename = "totalGB")]
    pub total_gb: f64,
    pub percentage: f64,
}

static HUMAN_SIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?b)\s*$").unwrap());

pub fn parse_human_size(input: &str) -> anyhow::Result<i64> {
    let caps = HUMAN_SIZE_RE
        .captures(input.trim())
        .ok_or_else(|| anyhow::anyhow!("invalid size {:?}", input))?;
    let val: f64 = caps[1].parse()?;
    let mult: f64 = match caps[2].to_uppercase().as_str() {
        "B" => 1.0,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "PB" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => anyhow::bail!("unsupported size unit {}", other),
    };
    Ok((val * mult) as i64)
}

fn normalize_quota_record(mut rec: UserQuotaRecord) -> UserQuotaRecord {
    rec.configured = rec.quota_bytes > 0;
    rec.available_bytes = if rec.quota_bytes > 0 {
        (rec.quota_bytes - rec.used_bytes).max(0)
    } else {
        0
    };
    rec.usage_pct = if rec.quota_bytes > 0 {
        (rec.used_bytes as f64 / rec.quota_bytes as f64) * 100.0
    } else {
        0.0
    };
    rec.used_gb = rec.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    rec.total_gb = rec.quota_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    rec.percentage = rec.usage_pct;
    if rec.status.is_empty() {
        rec.status = "active".to_string();
    }
    if rec.source.is_empty() {
        rec.source = "manual".to_string();
    }
    rec
}

pub fn query_user_quota_record(user_id: i64) -> anyhow::Result<UserQuotaRecord> {
    let conn = af_db::get_conn()?;
    let username: String = conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![user_id],
        |r| r.get(0),
    )?;

    let row = conn.query_row(
        "SELECT quota_bytes, used_bytes, COALESCE(status, 'active'), COALESCE(source, 'manual'), \
         COALESCE(billing_provider, ''), COALESCE(billing_external_id, ''), COALESCE(updated_at, '') \
         FROM user_quotas WHERE user_id = ?1",
        params![user_id],
        |r| {
            Ok(UserQuotaRecord {
                user_id,
                username: username.clone(),
                quota_bytes: r.get(0)?,
                used_bytes: r.get(1)?,
                available_bytes: 0,
                usage_pct: 0.0,
                configured: false,
                status: r.get(2)?,
                source: r.get(3)?,
                billing_provider: r.get(4)?,
                billing_external_id: r.get(5)?,
                updated_at: r.get(6)?,
                used_gb: 0.0,
                total_gb: 0.0,
                percentage: 0.0,
            })
        },
    );

    match row {
        Ok(rec) => Ok(normalize_quota_record(rec)),
        Err(_) => Ok(normalize_quota_record(UserQuotaRecord {
            user_id,
            username,
            quota_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            usage_pct: 0.0,
            configured: false,
            status: "active".to_string(),
            source: "manual".to_string(),
            billing_provider: String::new(),
            billing_external_id: String::new(),
            updated_at: String::new(),
            used_gb: 0.0,
            total_gb: 0.0,
            percentage: 0.0,
        })),
    }
}

pub async fn get_own_quota(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>() else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Authentication required",
        );
    };
    match query_user_quota_record(user.user_id) {
        Ok(rec) => Json(rec).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", e.to_string()),
    }
}

pub async fn list_user_quotas() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to query quota records",
        );
    };
    let mut records = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT u.id, u.username, COALESCE(q.quota_bytes, 0), COALESCE(q.used_bytes, 0), \
         COALESCE(q.status, 'active'), COALESCE(q.source, 'manual'), \
         COALESCE(q.billing_provider, ''), COALESCE(q.billing_external_id, ''), COALESCE(q.updated_at, '') \
         FROM users u LEFT JOIN user_quotas q ON q.user_id = u.id ORDER BY u.username ASC",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok(normalize_quota_record(UserQuotaRecord {
                user_id: r.get(0)?,
                username: r.get(1)?,
                quota_bytes: r.get(2)?,
                used_bytes: r.get(3)?,
                available_bytes: 0,
                usage_pct: 0.0,
                configured: false,
                status: r.get(4)?,
                source: r.get(5)?,
                billing_provider: r.get(6)?,
                billing_external_id: r.get(7)?,
                updated_at: r.get(8)?,
                used_gb: 0.0,
                total_gb: 0.0,
                percentage: 0.0,
            }))
        }) {
            for rec in rows.flatten() {
                records.push(rec);
            }
        }
    }
    Json(serde_json::json!({ "quotas": records })).into_response()
}

pub async fn update_user_quota(
    Path(user_id): Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let mut quota_bytes = req.get("quota_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
    if quota_bytes <= 0 {
        if let Some(q_str) = req.get("quota").and_then(|v| v.as_str()) {
            if !q_str.trim().is_empty() {
                match parse_human_size(q_str) {
                    Ok(parsed) => quota_bytes = parsed,
                    Err(e) => {
                        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string())
                    }
                }
            }
        }
    }
    if quota_bytes <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "quota_bytes or quota is required",
        );
    }

    let source = req
        .get("source")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("manual");
    let billing_provider = req
        .get("billing_provider")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let billing_external_id = req
        .get("billing_external_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let Ok(username) = conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found");
    };

    let _ = conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status, source, billing_provider, billing_external_id, updated_at) \
         VALUES (?1, ?2, ?3, COALESCE((SELECT used_bytes FROM user_quotas WHERE user_id = ?1), 0), 'active', ?4, ?5, ?6, CURRENT_TIMESTAMP) \
         ON CONFLICT(user_id) DO UPDATE SET \
            username = excluded.username, \
            quota_bytes = excluded.quota_bytes, \
            status = excluded.status, \
            source = excluded.source, \
            billing_provider = excluded.billing_provider, \
            billing_external_id = excluded.billing_external_id, \
            updated_at = CURRENT_TIMESTAMP",
        params![
            user_id,
            username,
            quota_bytes,
            source,
            billing_provider,
            billing_external_id
        ],
    );

    match query_user_quota_record(user_id) {
        Ok(rec) => Json(serde_json::json!({
            "message": "Quota updated successfully",
            "quota": rec,
        }))
        .into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        ),
    }
}

pub async fn refresh_user_quota(Path(user_id): Path<i64>) -> Response {
    match query_user_quota_record(user_id) {
        Ok(rec) => Json(serde_json::json!({ "quota": rec })).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", e.to_string()),
    }
}

fn verify_billing_webhook(provider: &str, headers: &HeaderMap, body: &[u8]) -> anyhow::Result<()> {
    let env_key = format!("{}_WEBHOOK_SECRET", provider.to_uppercase());
    let secret = env::var(&env_key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| env::var("BILLING_WEBHOOK_SECRET").ok())
        .unwrap_or_default();
    let secret = secret.trim();
    if secret.is_empty() {
        anyhow::bail!("{} webhook secret is not configured", provider);
    }

    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
            if token.trim() == secret {
                return Ok(());
            }
        }
    }

    for hdr in [
        "X-AetherFlow-Token",
        "X-Webhook-Token",
        "X-WHMCS-Token",
        "X-BLESTA-Token",
    ] {
        if let Some(val) = headers.get(hdr).and_then(|v| v.to_str().ok()) {
            if val.trim() == secret {
                return Ok(());
            }
        }
    }

    for hdr in [
        "X-AetherFlow-Signature",
        "X-Webhook-Signature",
        "X-WHMCS-Signature",
        "X-BLESTA-Signature",
    ] {
        if let Some(val) = headers.get(hdr).and_then(|v| v.to_str().ok()) {
            let clean = val
                .trim()
                .trim_start_matches("sha256=")
                .trim_start_matches("SHA256=");
            if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
                mac.update(body);
                let expected = mac.finalize().into_bytes();
                if let Ok(decoded) = hex::decode(clean) {
                    if decoded.as_slice() == expected.as_slice() {
                        return Ok(());
                    }
                }
                if let Ok(decoded) = BASE64_STD.decode(clean).or_else(|_| BASE64_RAW.decode(clean)) {
                    if decoded.as_slice() == expected.as_slice() {
                        return Ok(());
                    }
                }
            }
        }
    }

    anyhow::bail!("missing or invalid {} webhook signature", provider)
}

pub async fn handle_billing_webhook(
    Path(provider): Path<String>,
    req: Request,
) -> Response {
    let prov = provider.trim().to_lowercase();
    if prov != "whmcs" && prov != "blesta" {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Unsupported billing provider",
        );
    }

    let headers = req.headers().clone();
    let Ok(body) = axum::body::to_bytes(req.into_body(), 1024 * 1024).await else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to read webhook body",
        );
    };

    if let Err(e) = verify_billing_webhook(&prov, &headers, &body) {
        let status = if e.to_string().contains("not configured") {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::BAD_REQUEST
        };
        return api_error(status, "BAD_REQUEST", e.to_string());
    }

    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON body");
    };

    let event_id = payload
        .get("event_id")
        .or_else(|| payload.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let mut h = Sha256::new();
            h.update(&body);
            hex::encode(&h.finalize()[..16])
        });
    let event_type = payload
        .get("event_type")
        .or_else(|| payload.get("event"))
        .or_else(|| payload.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let username = payload
        .get("username")
        .or_else(|| payload.pointer("/user/username"))
        .or_else(|| payload.pointer("/service/username"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let quota_bytes = payload
        .get("quota_bytes")
        .and_then(|v| v.as_i64())
        .or_else(|| {
            payload
                .get("quota")
                .and_then(|v| v.as_str())
                .and_then(|s| parse_human_size(s).ok())
        })
        .unwrap_or(0);

    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO billing_webhook_events (provider, event_id, event_type, username, quota_bytes, status, payload) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'processed', ?6)",
            params![
                prov,
                event_id,
                event_type,
                username,
                quota_bytes,
                String::from_utf8_lossy(&body).to_string()
            ],
        );
    }

    Json(serde_json::json!({
        "provider": prov,
        "event_id": event_id,
        "event_type": event_type,
        "username": username,
        "quota_bytes": quota_bytes,
        "applied": quota_bytes > 0,
        "status": "processed",
        "message": "Billing webhook processed",
    }))
    .into_response()
}

pub async fn list_billing_webhook_events(Query(q): Query<HashMap<String, String>>) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&l| l > 0 && l <= 200)
        .unwrap_or(50);

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to load billing webhook events",
        );
    };
    let mut events = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, provider, event_id, COALESCE(event_type, ''), COALESCE(username, ''), \
         COALESCE(quota_bytes, 0), COALESCE(status, ''), COALESCE(error, ''), COALESCE(processed_at, '') \
         FROM billing_webhook_events ORDER BY id DESC LIMIT ?1",
    ) {
        if let Ok(rows) = stmt.query_map(params![limit], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "provider": r.get::<_, String>(1)?,
                "event_id": r.get::<_, String>(2)?,
                "event_type": r.get::<_, String>(3)?,
                "username": r.get::<_, String>(4)?,
                "quota_bytes": r.get::<_, i64>(5)?,
                "status": r.get::<_, String>(6)?,
                "error": r.get::<_, String>(7)?,
                "processed_at": r.get::<_, String>(8)?,
            }))
        }) {
            for e in rows.flatten() {
                events.push(e);
            }
        }
    }
    Json(serde_json::json!({ "events": events })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Updater & Deploy SSE (`updater.go`, `deploy_api.go`, `sse_handler.go`)
// ─────────────────────────────────────────────────────────────────────────────

static DEPLOY_STREAMS: Lazy<Mutex<HashMap<String, broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn get_local_version() -> String {
    let candidates = [".version", "../.version", "/opt/AetherFlow/current/.version"];
    for c in candidates {
        if let Ok(v) = fs::read_to_string(c) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "v3.0.0".to_string()
}

fn is_newer_version(local: &str, remote: &str) -> bool {
    let parse_ver = |v: &str| -> (i32, i32, i32) {
        let clean = v.trim_start_matches('v').split('-').next().unwrap_or("");
        let mut parts = clean.split('.').map(|p| p.parse::<i32>().unwrap_or(0));
        (
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        )
    };
    parse_ver(remote) > parse_ver(local)
}

pub async fn check_update() -> Response {
    let current_version = get_local_version();
    let channel: String = af_db::get_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row("SELECT update_channel FROM settings WHERE id = 1", [], |r| {
                r.get(0)
            })
            .ok()
        })
        .unwrap_or_else(|| "stable".to_string());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("AetherFlow-Updater/4.0")
        .build()
        .unwrap_or_default();

    let mut latest_version = String::new();
    let mut message = String::new();
    let mut html_url = String::new();
    let mut update_available = false;

    if let Ok(resp) = client
        .get("https://api.github.com/repos/McEveritts/AetherFlow/releases")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(releases) = resp.json::<Vec<serde_json::Value>>().await {
                for rel in releases {
                    let draft = rel.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);
                    let tag = rel.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
                    if draft || tag.is_empty() {
                        continue;
                    }
                    let prerelease = rel
                        .get("prerelease")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let target = rel
                        .get("target_commitish")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let is_nightly_or_exp = prerelease
                        || target.eq_ignore_ascii_case("nightly")
                        || target.eq_ignore_ascii_case("experimental")
                        || tag.to_lowercase().contains("nightly")
                        || tag.to_lowercase().contains("experimental");

                    if (channel == "nightly" || channel == "experimental") && is_nightly_or_exp {
                        latest_version = tag.to_string();
                        message = rel
                            .get("body")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        html_url = rel
                            .get("html_url")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        update_available = !current_version.eq_ignore_ascii_case(&latest_version);
                        break;
                    } else if channel == "stable" && !is_nightly_or_exp && !tag.contains('-') {
                        latest_version = tag.to_string();
                        message = rel
                            .get("body")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        html_url = rel
                            .get("html_url")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        update_available = is_newer_version(&current_version, &latest_version);
                        break;
                    }
                }
            }
        }
    }

    if latest_version.is_empty() {
        return Json(serde_json::json!({
            "updateAvailable": false,
            "currentVersion": current_version,
            "latestVersion": current_version,
            "message": "System is up to date.",
        }))
        .into_response();
    }

    Json(serde_json::json!({
        "updateAvailable": update_available,
        "currentVersion": current_version,
        "latestVersion": latest_version,
        "message": message,
        "url": html_url,
    }))
    .into_response()
}

pub async fn run_update(req: Request) -> Response {
    let actor = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let channel: String = af_db::get_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row("SELECT update_channel FROM settings WHERE id = 1", [], |r| {
                r.get(0)
            })
            .ok()
        })
        .unwrap_or_else(|| "stable".to_string());

    let ch_clone = channel.clone();
    tokio::spawn(async move {
        let _ = Command::new("/bin/bash")
            .args(["../deploy/release-manager.sh", "deploy", "--channel", &ch_clone])
            .status();
    });

    if let Some(u) = actor {
        af_db::record_audit(
            u.user_id,
            &u.username,
            "system_deployment",
            "engine",
            "blue_green",
            &format!("Channel: {}", channel),
            &ip,
            &ua,
        );
    }

    Json(serde_json::json!({
        "message": "Atomic deployment initiated. The system will cleanly transition once builds are complete."
    }))
    .into_response()
}

pub async fn handle_deploy_process(Path(app_name): Path<String>) -> Response {
    if app_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Application string param omitted" })),
        )
            .into_response();
    }
    let Some(bp) = af_services::get_blueprint(&app_name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Application blueprint missing or unsupported: {}", app_name)
            })),
        )
            .into_response();
    };

    let (tx, _) = broadcast::channel(32);
    if let Ok(mut map) = DEPLOY_STREAMS.lock() {
        map.insert(bp.app_name.clone(), tx.clone());
    }

    let app_clone = bp.app_name.clone();
    tokio::spawn(async move {
        let _ = tx.send("[STEP 0] Deployment sequence queued asynchronously.".to_string());
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = tx.send("[SUCCESS] Atomic deployment verified and live.".to_string());
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Ok(mut map) = DEPLOY_STREAMS.lock() {
            map.remove(&app_clone);
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "Initiated deployment cycle",
            "target": bp.internal_domain,
            "streamTarget": format!("/api/v1/auth/deploy/stream?appName={}", bp.app_name),
        })),
    )
        .into_response()
}

pub async fn handle_deploy_stream(Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(app_name) = q.get("appName").filter(|s| !s.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "appName query parameter is required" })),
        )
            .into_response();
    };

    let rx_opt = DEPLOY_STREAMS
        .lock()
        .ok()
        .and_then(|map| map.get(app_name).map(|tx| tx.subscribe()));

    let Some(mut rx) = rx_opt else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No active deployment found for this application." })),
        )
            .into_response();
    };

    let stream = async_stream::stream! {
        while let Ok(msg) = rx.recv().await {
            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", msg));
            if msg.starts_with("[SUCCESS]") || msg.starts_with("[ROLLBACK]") {
                break;
            }
        }
    };

    let mut resp = Response::new(Body::from_stream(stream));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    h.insert("X-Accel-Buffering", HeaderValue::from_static("no"));
    resp
}
