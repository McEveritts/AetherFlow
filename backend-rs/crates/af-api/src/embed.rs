use af_files::BrowserFs;
use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use std::cell::OnceCell;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

// An explicitly set, even empty, STATIC_DIR never falls back to the release layout.
fn static_dir_for_executable(override_dir: Option<&OsStr>, exe: &Path) -> Option<PathBuf> {
    match override_dir {
        Some(dir) if dir.is_empty() => None,
        Some(dir) => Some(PathBuf::from(dir)),
        None => Some(exe.parent()?.join("web/dist")),
    }
}

fn static_dir() -> Option<PathBuf> {
    if let Some(dir) = env::var_os("STATIC_DIR") {
        return static_dir_for_executable(Some(&dir), Path::new(""));
    }
    static_dir_for_executable(None, &env::current_exe().ok()?)
}

const MAX_STATIC_ASSET_BYTES: u64 = 32 * 1024 * 1024;

struct AssetRoot {
    fs: BrowserFs,
}

impl AssetRoot {
    fn open(path: &Path) -> Option<Self> {
        // Resolve a symlinked root once, then anchor every file open to its directory fd.
        let path = fs::canonicalize(path).ok()?;
        let fs = BrowserFs::open(&path).ok()?;
        Some(Self { fs })
    }

    fn read(&self, rel_path: &str) -> Option<Vec<u8>> {
        if !Path::new(rel_path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        {
            return None;
        }
        let file = self.fs.open_file(rel_path).ok()?;
        let size = file.metadata().ok()?.len();
        if size > MAX_STATIC_ASSET_BYTES {
            return None;
        }
        let mut bytes = Vec::with_capacity(size as usize);
        file.take(MAX_STATIC_ASSET_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() as u64 <= MAX_STATIC_ASSET_BYTES).then_some(bytes)
    }
}

#[cfg(test)]
fn read_asset(rel_path: &str) -> Option<Vec<u8>> {
    AssetRoot::open(&static_dir()?)?.read(rel_path)
}

fn normalize_clean_path(req_path: &str) -> Option<String> {
    // Uri::path is still percent encoded. Decode exactly once before checking
    // components and reserved prefixes; never turn traversal into another path.
    let input = req_path.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut position = 0;
    while position < input.len() {
        if input[position] == b'%' {
            let digits = input.get(position + 1..position + 3)?;
            let high = (digits[0] as char).to_digit(16)?;
            let low = (digits[1] as char).to_digit(16)?;
            decoded.push((high * 16 + low) as u8);
            position += 3;
        } else {
            decoded.push(input[position]);
            position += 1;
        }
    }
    let decoded = std::str::from_utf8(&decoded).ok()?;
    if decoded.chars().any(|c| c == '\\' || c.is_control()) {
        return None;
    }
    let mut parts = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        Some("index.html".to_string())
    } else {
        Some(parts.join("/"))
    }
}

fn build_file_response(path_key: &str, bytes: Vec<u8>, cache_control: &'static str) -> Response {
    let mime = mime_guess::from_path(path_key).first_or_octet_stream();
    let length = bytes.len();
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).expect("valid content length"),
    );
    let content_type = if path_key.ends_with(".wasm") {
        "application/wasm"
    } else {
        mime.as_ref()
    };
    if let Ok(ct) = HeaderValue::from_str(content_type) {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    resp
}

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const NO_CACHE: &str = "no-cache, no-store, must-revalidate";

fn cache_policy(path: &str) -> &'static str {
    // Documents and update entry points must revalidate even with hashed names.
    if path == "sw.js"
        || path == "manifest.json"
        || path.starts_with("locales/")
        || path.ends_with(".html")
    {
        return NO_CACHE;
    }
    let hashed = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .split(['-', '_', '.'])
        .any(|part| part.len() >= 8 && part.bytes().all(|c| c.is_ascii_hexdigit()));
    if hashed {
        IMMUTABLE
    } else {
        "public, max-age=3600"
    }
}

fn encoding_quality(encoding: &str, wanted: &str) -> Option<f32> {
    let mut exact: Option<f32> = None;
    let mut wildcard: Option<f32> = None;
    for entry in encoding.split(',') {
        let mut parts = entry.trim().split(';');
        let name = parts.next().unwrap_or("").trim();
        let mut quality = 1.0_f32;
        for parameter in parts {
            if let Some((key, value)) = parameter.trim().split_once('=') {
                if key.trim().eq_ignore_ascii_case("q") {
                    quality = value
                        .trim()
                        .parse::<f32>()
                        .ok()
                        .filter(|q| (0.0..=1.0).contains(q))
                        .unwrap_or(0.0);
                }
            }
        }
        let slot = if name.eq_ignore_ascii_case(wanted) {
            &mut exact
        } else if name == "*" {
            &mut wildcard
        } else {
            continue;
        };
        *slot = Some(slot.unwrap_or(0.0).max(quality));
    }
    if wanted == "identity" {
        // Identity is acceptable by default, except when explicitly excluded
        // by identity;q=0 or by *;q=0 without a more specific identity entry.
        exact.or(wildcard.filter(|q| *q == 0.0))
    } else {
        exact.or(wildcard)
    }
}

fn accepts_encoding(encoding: &str, wanted: &str) -> bool {
    encoding_quality(encoding, wanted).unwrap_or(0.0) > 0.0
}

fn accepts_identity(encoding: &str) -> bool {
    encoding_quality(encoding, "identity").unwrap_or(1.0) > 0.0
}

fn unacceptable_encoding() -> Response {
    let mut response = StatusCode::NOT_ACCEPTABLE.into_response();
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
    response
}

fn negotiated_asset(
    path: &str,
    accept_encoding: &str,
    read: impl Fn(&str) -> Option<Vec<u8>>,
) -> Option<Response> {
    let compressible = [".wasm", ".js", ".css", ".json", ".svg"]
        .iter()
        .any(|ext| path.ends_with(ext));
    if compressible {
        for (encoding, extension) in [("br", "br"), ("gzip", "gz")] {
            if accepts_encoding(accept_encoding, encoding) {
                if let Some(bytes) = read(&format!("{path}.{extension}")) {
                    let mut response = build_file_response(path, bytes, cache_policy(path));
                    response
                        .headers_mut()
                        .insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
                    response
                        .headers_mut()
                        .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                    return Some(response);
                }
            }
        }
    }
    read(path).map(|bytes| {
        if !accepts_identity(accept_encoding) {
            return unacceptable_encoding();
        }
        let mut response = build_file_response(path, bytes, cache_policy(path));
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        response
    })
}

fn document_response(index: Vec<u8>, accept_encoding: &str) -> Response {
    if !accepts_identity(accept_encoding) {
        return unacceptable_encoding();
    }
    let mut response = build_file_response("index.html", index, NO_CACHE);
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    response
}

/// Serve the Rust WASM SPA: API and WebSocket misses remain JSON errors, direct
/// assets negotiate Brotli/gzip and cache content-hashed names immutably, and client
/// navigation falls back to the root document with caching disabled.
pub async fn spa_fallback_handler(req: Request) -> Response {
    // Canonicalization and file reads can block; keep them off the async workers.
    tokio::task::spawn_blocking(move || {
        let root = OnceCell::new();
        spa_response(&req, |path| {
            root.get_or_init(|| AssetRoot::open(&static_dir()?))
                .as_ref()?
                .read(path)
        })
    })
    .await
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn spa_response(req: &Request, read: impl Fn(&str) -> Option<Vec<u8>>) -> Response {
    let mut response = spa_response_inner(req, read);
    if req.method() == Method::HEAD {
        // HEAD has the same status and representation headers as GET, without a body.
        if !response.headers().contains_key(header::CONTENT_LENGTH) {
            if let Some(length) = response.body().size_hint().exact() {
                if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
                    response.headers_mut().insert(header::CONTENT_LENGTH, value);
                }
            }
        }
        *response.body_mut() = Body::empty();
    }
    response
}

fn json_not_found(message: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "not_found", "message": message})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
    response
}

fn spa_response_inner(req: &Request, read: impl Fn(&str) -> Option<Vec<u8>>) -> Response {
    let Some(clean_path) = normalize_clean_path(req.uri().path()) else {
        return json_not_found("The requested path does not exist.");
    };

    // Never serve HTML for unknown API or WebSocket endpoints.
    if clean_path == "api"
        || clean_path.starts_with("api/")
        || clean_path == "ws"
        || clean_path.starts_with("ws/")
    {
        return json_not_found("The requested API endpoint does not exist.");
    }

    if req.method() != Method::GET && req.method() != Method::HEAD {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }

    let Some(index) = read("index.html") else {
        let mut response = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "FRONTEND_NOT_BUNDLED",
                "error": "frontend_not_bundled",
                "message": "Static UI is unavailable. Set STATIC_DIR to the frontend asset directory, or place web/dist beside the API executable."
            })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
        return response;
    };

    let accept_encoding = req
        .headers()
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");

    if clean_path == "index.html" {
        return document_response(index, &accept_encoding);
    }

    if let Some(response) = negotiated_asset(&clean_path, &accept_encoding, read) {
        return response;
    }

    // Missing files must not masquerade as successful HTML downloads. Unmatched
    // extensionless routes continue to enter the client-side SPA router.
    let asset_namespace = ["assets", "locales", "img", "images", "fonts"]
        .iter()
        .any(|prefix| clean_path == *prefix || clean_path.starts_with(&format!("{prefix}/")));
    let filename = clean_path.rsplit('/').next().unwrap_or(&clean_path);
    if asset_namespace || filename.contains('.') {
        return json_not_found("The requested static asset does not exist.");
    }

    document_response(index, &accept_encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    static STATIC_DIR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct StaticDir {
        directory: std::path::PathBuf,
        previous: Option<std::ffi::OsString>,
    }

    impl StaticDir {
        // Callers hold STATIC_DIR_LOCK until after this fixture is dropped.
        fn new() -> Self {
            let fixture = Self {
                directory: env::temp_dir().join(format!("af-embed-{}", uuid::Uuid::new_v4())),
                previous: env::var_os("STATIC_DIR"),
            };
            fs::create_dir_all(&fixture.directory).unwrap();
            env::set_var("STATIC_DIR", &fixture.directory);
            fixture
        }
    }

    impl Drop for StaticDir {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => env::set_var("STATIC_DIR", value),
                None => env::remove_var("STATIC_DIR"),
            }
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn fixture(path: &str) -> Option<Vec<u8>> {
        match path {
            "app-0123456789abcdef.wasm" | "app-0123456789abcdef.js" | "styles.css" => {
                Some(b"original".to_vec())
            }
            "app-0123456789abcdef.wasm.br" | "app-0123456789abcdef.js.br" | "styles.css.br" => {
                Some(b"brotli".to_vec())
            }
            "app-0123456789abcdef.wasm.gz" | "app-0123456789abcdef.js.gz" | "styles.css.gz" => {
                Some(b"gzip".to_vec())
            }
            _ => None,
        }
    }

    #[test]
    fn wasm_has_streaming_mime_and_immutable_cache() {
        let response = negotiated_asset("app-0123456789abcdef.wasm", "", fixture).unwrap();
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/wasm");
        assert_eq!(response.headers()[header::CACHE_CONTROL], IMMUTABLE);
        assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn brotli_sidecars_keep_original_mime_and_bytes() {
        for (path, mime) in [
            ("app-0123456789abcdef.wasm", "application/wasm"),
            ("app-0123456789abcdef.js", "text/javascript"),
            ("styles.css", "text/css"),
        ] {
            let response = negotiated_asset(path, "gzip, br;q=0.8", fixture).unwrap();
            assert_eq!(response.headers()[header::CONTENT_TYPE], mime);
            assert_eq!(response.headers()[header::CONTENT_ENCODING], "br");
            assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .as_ref(),
                b"brotli"
            );
        }
    }

    #[tokio::test]
    async fn omitted_disabled_or_missing_encodings_use_base_asset() {
        for encoding in [
            "",
            "deflate",
            "br;q=0",
            "br;q=0.0",
            "brr",
            "br;q=invalid",
            "gzip;q=0",
            "gzip;q=invalid",
            "gzip;q=2",
            "gzip;q=NaN",
            "gzip;q=0, br;q=0",
        ] {
            let response = negotiated_asset("styles.css", encoding, fixture).unwrap();
            assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .as_ref(),
                b"original"
            );
        }
        let response = negotiated_asset("styles.css", "br", |p| {
            (p == "styles.css").then(|| b"base".to_vec())
        })
        .unwrap();
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert!(negotiated_asset("missing.wasm", "br", fixture).is_none());
    }

    #[tokio::test]
    async fn gzip_sidecars_keep_wasm_mime_and_brotli_has_precedence() {
        for (encoding, expected, body) in [
            ("gzip, deflate", "gzip", b"gzip".as_slice()),
            ("gzip, br", "br", b"brotli".as_slice()),
            ("br;q=0, gzip;q=0.8", "gzip", b"gzip".as_slice()),
        ] {
            let response =
                negotiated_asset("app-0123456789abcdef.wasm", encoding, fixture).unwrap();
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/wasm");
            assert_eq!(response.headers()[header::CONTENT_ENCODING], expected);
            assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
            assert_eq!(response.headers()[header::CACHE_CONTROL], IMMUTABLE);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .as_ref(),
                body
            );
        }
        let response = negotiated_asset("styles.css", "br, gzip", |path| {
            (path == "styles.css.gz").then(|| b"gzip-only".to_vec())
        })
        .unwrap();
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
    }

    #[tokio::test]
    async fn encoding_wildcard_and_identity_exclusions_are_respected() {
        let response = negotiated_asset("styles.css", "*;q=0.5, br;q=0", fixture).unwrap();
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");

        for accept in ["*;q=0", "br;q=0, gzip;q=0, identity;q=0"] {
            let response = negotiated_asset("styles.css", accept, fixture).unwrap();
            assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
            assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
            assert_eq!(response.headers()[header::CACHE_CONTROL], NO_CACHE);
        }
        let response = negotiated_asset("styles.css", "*;q=0, identity;q=1", fixture).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));

        for uri in ["/", "/login"] {
            let request = Request::builder()
                .uri(uri)
                .header(header::ACCEPT_ENCODING, "identity;q=0, *;q=0")
                .body(Body::empty())
                .unwrap();
            let response = spa_response(&request, |path| {
                (path == "index.html").then(|| b"document".to_vec())
            });
            assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
            assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
        }

        let request = Request::builder()
            .uri("/styles.css")
            .header(header::ACCEPT_ENCODING, "br;q=0")
            .header(header::ACCEPT_ENCODING, "gzip;q=0.8")
            .body(Body::empty())
            .unwrap();
        let response = spa_response(&request, |path| {
            if path == "index.html" {
                Some(b"document".to_vec())
            } else {
                fixture(path)
            }
        });
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
    }

    #[tokio::test]
    async fn static_dir_rejects_oversized_assets() {
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        fs::File::create(fixture.directory.join("large.wasm"))
            .unwrap()
            .set_len(MAX_STATIC_ASSET_BYTES + 1)
            .unwrap();
        assert!(read_asset("large.wasm").is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn static_dir_refuses_symlinks_below_the_canonical_root() {
        use std::os::unix::fs::symlink;
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        let root = fixture.directory.join("public");
        fs::create_dir_all(&root).unwrap();
        let secret = fixture.directory.join("secret.wasm");
        fs::write(&secret, b"outside-secret").unwrap();
        fs::write(root.join("index.html"), b"<html>safe SPA</html>").unwrap();
        fs::write(root.join("app.wasm"), b"safe asset").unwrap();
        symlink(&secret, root.join("leak.wasm")).unwrap();
        symlink(&fixture.directory, root.join("outside")).unwrap();
        symlink(root.join("app.wasm"), root.join("inside.wasm")).unwrap();
        let root_alias = fixture.directory.join("public-link");
        symlink(&root, &root_alias).unwrap();
        env::set_var("STATIC_DIR", &root_alias);
        assert_eq!(read_asset("app.wasm").unwrap(), b"safe asset");
        for path in [
            "inside.wasm",
            "leak.wasm",
            "outside/secret.wasm",
            "../secret.wasm",
        ] {
            assert!(read_asset(path).is_none(), "{path}");
            let req = Request::builder()
                .uri(format!("/{path}"))
                .body(Body::empty())
                .unwrap();
            let response = spa_fallback_handler(req).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        }
        assert!(read_asset(secret.to_str().unwrap()).is_none());
    }

    #[tokio::test]
    async fn static_dir_missing_sidecars_serve_only_the_custom_uncompressed_worker() {
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        fs::write(fixture.directory.join("index.html"), b"custom SPA").unwrap();
        fs::write(fixture.directory.join("sw.js"), b"custom service worker").unwrap();
        assert!(read_asset("sw.js.br").is_none());
        assert!(read_asset("sw.js.gz").is_none());
        let request = Request::builder()
            .uri("/sw.js")
            .header(header::ACCEPT_ENCODING, "br, gzip")
            .body(Body::empty())
            .unwrap();
        let response = spa_fallback_handler(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(response.headers()[header::CACHE_CONTROL], NO_CACHE);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .as_ref(),
            b"custom service worker"
        );
    }

    #[tokio::test]
    async fn invalid_static_dir_never_uses_another_root() {
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        let missing = fixture.directory.join("missing");
        let file = fixture.directory.join("file");
        fs::write(&file, b"not a directory").unwrap();
        for root in [
            fixture.directory.as_os_str(),
            missing.as_os_str(),
            file.as_os_str(),
            OsStr::new(""),
        ] {
            env::set_var("STATIC_DIR", root);
            assert!(read_asset("index.html").is_none());
            let request = Request::builder().uri("/").body(Body::empty()).unwrap();
            let response = spa_fallback_handler(request).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(data["error"], "frontend_not_bundled");
            assert_eq!(data["code"], "FRONTEND_NOT_BUNDLED");
            assert!(data["message"].as_str().unwrap().contains("STATIC_DIR"));
            assert!(data["message"].as_str().unwrap().contains("web/dist"));
        }
    }

    #[tokio::test]
    async fn locale_json_negotiates_brotli_with_json_mime_and_no_cache() {
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        fs::write(fixture.directory.join("index.html"), b"custom SPA").unwrap();
        fs::create_dir(fixture.directory.join("locales")).unwrap();
        fs::write(fixture.directory.join("locales/fr.json"), b"{}").unwrap();
        fs::write(
            fixture.directory.join("locales/fr.json.br"),
            b"brotli catalog",
        )
        .unwrap();
        fs::write(
            fixture.directory.join("locales/fr.json.gz"),
            b"gzip catalog",
        )
        .unwrap();
        let request = Request::builder()
            .uri("/locales/fr.json")
            .header(header::ACCEPT_ENCODING, "br, gzip")
            .body(Body::empty())
            .unwrap();
        let response = spa_fallback_handler(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], NO_CACHE);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .as_ref(),
            b"brotli catalog"
        );
    }

    #[test]
    fn manifest_json_and_svg_negotiate_brotli_and_gzip() {
        for (path, mime, cache) in [
            ("manifest.json", "application/json", NO_CACHE),
            ("img/logo-01234567.svg", "image/svg+xml", IMMUTABLE),
        ] {
            for (accept, encoding, extension) in [("br, gzip", "br", "br"), ("gzip", "gzip", "gz")]
            {
                let response = negotiated_asset(path, accept, |candidate| {
                    (candidate == format!("{path}.{extension}")).then(|| b"sidecar".to_vec())
                })
                .unwrap();
                assert_eq!(response.headers()[header::CONTENT_TYPE], mime);
                assert_eq!(response.headers()[header::CONTENT_ENCODING], encoding);
                assert_eq!(response.headers()[header::VARY], "Accept-Encoding");
                assert_eq!(response.headers()[header::CACHE_CONTROL], cache);
            }
        }
    }

    #[test]
    fn cache_entrypoints_revalidate_and_trunk_assets_are_immutable() {
        for path in [
            "index.html",
            "sw.js",
            "manifest.json",
            "locales/fr.json",
            "locales/catalog-01234567.json",
            "login.html",
            "assets/index.html",
            "app-01234567.html",
        ] {
            assert_eq!(cache_policy(path), NO_CACHE, "{path}");
        }
        for path in [
            "af-web-app-a0b1c2d3e4f5_bg.wasm",
            "af-web-app-a0b1c2d3e4f5.js",
            "compiled-01234567.css",
            "assets/logo-01234567.svg",
        ] {
            assert_eq!(cache_policy(path), IMMUTABLE, "{path}");
        }
        for path in ["app.wasm", "assets/logo.svg", "sw-helper.js", "notes.txt"] {
            assert_eq!(cache_policy(path), "public, max-age=3600", "{path}");
        }
    }

    #[tokio::test]
    async fn client_routes_always_use_the_root_spa_document() {
        for uri in [
            "/",
            "/login",
            "/login/",
            "/settings/display",
            "/login?_rsc=old",
        ] {
            let request = Request::builder()
                .uri(uri)
                .header("RSC", "1")
                .body(Body::empty())
                .unwrap();
            let response = spa_response(&request, |path| match path {
                "index.html" => Some(b"<html>Rust WASM SPA</html>".to_vec()),
                "index.txt" | "login.txt" | "login.html" | "login/index.html" => {
                    Some(b"obsolete route export".to_vec())
                }
                _ => None,
            });
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
            assert_eq!(response.headers()[header::CACHE_CONTROL], NO_CACHE);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .as_ref(),
                b"<html>Rust WASM SPA</html>"
            );
        }
    }

    #[tokio::test]
    async fn api_and_websocket_misses_never_return_spa_html() {
        for uri in ["/api", "/api/missing", "/ws", "/ws/missing"] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let response = spa_response(&request, |_| Some(b"<html>SPA</html>".to_vec()));
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(data["error"], "not_found");
        }
    }

    #[tokio::test]
    async fn absent_wasm_bundle_returns_a_json_error() {
        let request = Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let response = spa_response(&request, |_| None);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["error"], "frontend_not_bundled");
    }

    #[tokio::test]
    async fn release_layout_and_explicit_overrides_select_exactly_one_root() {
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        let executable = fixture.directory.join("release/aetherflow-api");
        let sibling = fixture.directory.join("release/web/dist");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("index.html"), b"sibling UI").unwrap();
        let selected = static_dir_for_executable(None, &executable).unwrap();
        assert_eq!(selected, sibling);
        assert_eq!(
            AssetRoot::open(&selected)
                .unwrap()
                .read("index.html")
                .unwrap(),
            b"sibling UI"
        );

        let missing_override = fixture.directory.join("missing");
        let selected =
            static_dir_for_executable(Some(missing_override.as_os_str()), &executable).unwrap();
        assert_eq!(selected, missing_override);
        assert!(AssetRoot::open(&selected).is_none());
        assert!(static_dir_for_executable(Some(OsStr::new("")), &executable).is_none());

        env::remove_var("STATIC_DIR");
        assert_eq!(
            static_dir(),
            Some(
                env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("web/dist")
            )
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn root_descriptor_stays_confined_when_the_directory_is_replaced() {
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        let original = fixture.directory.join("public");
        let moved = fixture.directory.join("original");
        fs::create_dir(&original).unwrap();
        fs::write(original.join("index.html"), b"trusted").unwrap();
        let root = AssetRoot::open(&original).unwrap();
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("index.html"), b"replacement").unwrap();
        assert_eq!(root.read("index.html").unwrap(), b"trusted");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn outside_sidecars_and_hardlinks_are_not_served() {
        use std::os::unix::fs::symlink;
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        let root = fixture.directory.join("public");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("index.html"), b"SPA").unwrap();
        fs::write(root.join("app.wasm"), b"safe wasm").unwrap();
        fs::write(fixture.directory.join("secret"), b"private").unwrap();
        symlink(fixture.directory.join("secret"), root.join("app.wasm.br")).unwrap();
        fs::hard_link(fixture.directory.join("secret"), root.join("hardlink.wasm")).unwrap();
        env::set_var("STATIC_DIR", &root);
        assert!(read_asset("hardlink.wasm").is_none());
        let request = Request::builder()
            .uri("/app.wasm")
            .header(header::ACCEPT_ENCODING, "br")
            .body(Body::empty())
            .unwrap();
        let response = spa_fallback_handler(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            "safe wasm"
        );
    }

    #[tokio::test]
    async fn encoded_traversal_and_reserved_api_paths_are_rejected_before_reading() {
        for uri in [
            "/../secret",
            "/%2e%2e/secret",
            "/images/%2E%2e%2Fsecret",
            "/safe%5c..%5csecret",
            "/secret%00",
            "/%ff",
            "/bad%2",
            "/%61pi/missing",
            "/%77s%2fmissing",
            "/./api/missing",
        ] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let response = spa_response(&request, |_| panic!("must not read assets for {uri}"));
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        }
    }

    #[tokio::test]
    async fn missing_assets_are_404_but_document_routes_use_the_spa() {
        for (uri, status) in [
            ("/missing.wasm", StatusCode::NOT_FOUND),
            ("/assets/missing", StatusCode::NOT_FOUND),
            ("/locales/missing.json", StatusCode::NOT_FOUND),
            ("/img/missing.png", StatusCode::NOT_FOUND),
            ("/login", StatusCode::OK),
            ("/settings/display", StatusCode::OK),
        ] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let response = spa_response(&request, |path| {
                (path == "index.html").then(|| b"SPA".to_vec())
            });
            assert_eq!(response.status(), status, "{uri}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], NO_CACHE);
            if status == StatusCode::OK {
                assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
                assert_eq!(
                    axum::body::to_bytes(response.into_body(), 1024)
                        .await
                        .unwrap(),
                    "SPA"
                );
            } else {
                assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            }
        }
    }

    #[tokio::test]
    async fn head_matches_get_headers_and_status_without_a_body() {
        for uri in [
            "/",
            "/login",
            "/app-0123456789abcdef.wasm",
            "/missing.wasm",
            "/api/missing",
        ] {
            let request = |method| {
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::ACCEPT_ENCODING, "br, gzip")
                    .body(Body::empty())
                    .unwrap()
            };
            let read = |path: &str| {
                if path == "index.html" {
                    Some(b"document".to_vec())
                } else {
                    fixture(path)
                }
            };
            let get = spa_response(&request(Method::GET), read);
            let head = spa_response(&request(Method::HEAD), read);
            assert_eq!(head.status(), get.status(), "{uri}");
            for name in [
                header::CONTENT_TYPE,
                header::CACHE_CONTROL,
                header::CONTENT_ENCODING,
                header::VARY,
            ] {
                assert_eq!(
                    head.headers().get(&name),
                    get.headers().get(&name),
                    "{uri}: {name}"
                );
            }
            let head_length = head.headers()[header::CONTENT_LENGTH]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let get_bytes = axum::body::to_bytes(get.into_body(), 1024).await.unwrap();
            assert_eq!(head_length, get_bytes.len(), "{uri}");
            assert!(axum::body::to_bytes(head.into_body(), 1024)
                .await
                .unwrap()
                .is_empty());
        }

        let head = Request::builder()
            .method(Method::HEAD)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let response = spa_response(&head, |_| None);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert!(
            response.headers()[header::CONTENT_LENGTH]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                > 0
        );
        assert!(axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn non_get_methods_do_not_receive_the_spa() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let response = spa_response(&request, |_| panic!("must not read assets for POST"));
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
    }

    #[tokio::test]
    async fn router_fallback_keeps_security_headers() {
        use axum::{middleware, Router};
        use tower::ServiceExt;
        let _lock = STATIC_DIR_LOCK.lock().await;
        let fixture = StaticDir::new();
        fs::write(fixture.directory.join("index.html"), b"SPA").unwrap();
        let router = Router::new()
            .fallback(spa_fallback_handler)
            .layer(middleware::from_fn(
                crate::routes::security_headers_middleware,
            ));
        for uri in ["/login", "/missing.wasm", "/api/missing"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            let csp = response.headers()["content-security-policy"]
                .to_str()
                .unwrap();
            if uri.starts_with("/api/") {
                assert!(csp.contains("default-src 'none'"));
            } else {
                assert!(csp.contains("'wasm-unsafe-eval'"));
                assert!(!csp.contains("'unsafe-inline'"));
            }
        }
    }

    #[test]
    fn normalization_does_not_escape_asset_root() {
        assert_eq!(normalize_clean_path("/../../app.wasm"), None);
        assert_eq!(normalize_clean_path("/"), Some("index.html".to_string()));
    }
}
