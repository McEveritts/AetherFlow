use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rust_embed::RustEmbed;
use std::env;
use std::fs;
use std::path::Path;

#[derive(RustEmbed)]
#[folder = "../../../backend/web/dist"]
struct EmbeddedDist;

fn read_asset(rel_path: &str) -> Option<Vec<u8>> {
    if let Ok(custom_dir) = env::var("STATIC_DIR") {
        let trimmed = custom_dir.trim();
        if !trimmed.is_empty() {
            let fs_path = Path::new(trimmed).join(rel_path);
            if fs_path.is_file() {
                if let Ok(bytes) = fs::read(&fs_path) {
                    return Some(bytes);
                }
            }
        }
    }
    EmbeddedDist::get(rel_path).map(|f| f.data.into_owned())
}

fn has_index_bundle() -> bool {
    read_asset("index.html").is_some()
}

fn normalize_clean_path(req_path: &str) -> String {
    let mut parts = Vec::new();
    for seg in req_path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        "index.html".to_string()
    } else {
        parts.join("/")
    }
}

fn build_file_response(path_key: &str, bytes: Vec<u8>, cache_control: &'static str) -> Response {
    let mime = mime_guess::from_path(path_key).first_or_octet_stream();
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    if let Ok(ct) = HeaderValue::from_str(mime.as_ref()) {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache_control));
    resp
}

/// Implements the exact 5-step Next.js 16 App Router SPA resolution order from `backend/web/embed.go`:
/// 1. Never serve HTML for `/api/*` or `/ws/*` (return JSON 404).
/// 2. Aggressive immutable caching for `/_next/static/*`.
/// 3. Next.js RSC Flight payload resolution (`RSC: 1` header or `?_rsc=` query -> `.txt` with `text/x-component`).
/// 4. Direct file match, `<route>.html` clean URL match, `<route>/index.html` directory match.
/// 5. SPA fallback to root `index.html`.
pub async fn spa_fallback_handler(req: Request) -> Response {
    let req_path = req.uri().path().to_string();

    // Step 0a: Never serve HTML for unknown API or WebSocket endpoints.
    if req_path == "/api" || req_path.starts_with("/api/") || req_path.starts_with("/ws/") {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not_found",
                "message": "The requested API endpoint does not exist."
            })),
        )
            .into_response();
    }

    if !has_index_bundle() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "frontend_not_bundled",
                "message": "Static UI is not embedded in this dev build. Run with embedded dist or set STATIC_DIR."
            })),
        )
            .into_response();
    }

    let clean_path = normalize_clean_path(&req_path);
    let is_immutable_static = clean_path.starts_with("_next/static/");
    let default_cache = if is_immutable_static {
        "public, max-age=31536000, immutable"
    } else if clean_path == "sw.js"
        || clean_path == "manifest.json"
        || clean_path.ends_with(".html")
        || clean_path.ends_with(".txt")
    {
        "no-cache, no-store, must-revalidate"
    } else {
        "public, max-age=3600"
    };

    // Step 0b: Next.js App Router RSC flight payload resolution
    let is_rsc_header = req
        .headers()
        .get("RSC")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1")
        .unwrap_or(false);
    let is_rsc_query = req
        .uri()
        .query()
        .map(|q| q.split('&').any(|kv| kv.starts_with("_rsc=")))
        .unwrap_or(false);

    if is_rsc_header || is_rsc_query {
        let rsc_candidates = if clean_path == "index.html" {
            vec!["index.txt".to_string()]
        } else {
            vec![
                format!("{}.txt", clean_path),
                format!("{}/index.txt", clean_path),
            ]
        };
        for candidate in rsc_candidates {
            if let Some(data) = read_asset(&candidate) {
                let mut resp = Response::new(Body::from(data));
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/x-component; charset=utf-8"),
                );
                resp.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                );
                return resp;
            }
        }
    }

    // Step 1: Direct file match
    if let Some(data) = read_asset(&clean_path) {
        return build_file_response(&clean_path, data, default_cache);
    }

    // Step 2: Clean route match for Next.js static export (`/login` -> `login.html`)
    let html_candidate = format!("{}.html", clean_path);
    if let Some(data) = read_asset(&html_candidate) {
        return build_file_response(
            &html_candidate,
            data,
            "no-cache, no-store, must-revalidate",
        );
    }

    // Step 3: Directory index match (`/login/` -> `login/index.html`)
    let dir_index_candidate = format!("{}/index.html", clean_path);
    if let Some(data) = read_asset(&dir_index_candidate) {
        return build_file_response(
            &dir_index_candidate,
            data,
            "no-cache, no-store, must-revalidate",
        );
    }

    // Step 4: SPA fallback to root `index.html`
    if let Some(data) = read_asset("index.html") {
        let mut resp = Response::new(Body::from(data));
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
        return resp;
    }

    StatusCode::NOT_FOUND.into_response()
}
