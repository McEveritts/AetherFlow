use crate::stats::AppState;
use axum::extract::{OriginalUri, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use tokio::task;

const MAX_STATIC_ASSET_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum AssetError {
    Forbidden(&'static str),
    NotFound,
    Internal(anyhow::Error),
}

pub async fn handle_static_asset(
    State(state): State<AppState>,
    OriginalUri(orig_uri): OriginalUri,
) -> Response {
    let assets_root = state.config.assets_path.clone();
    let url_base = state.config.url_base.clone();
    let req_path = orig_uri.path().to_string();

    match load_confined_asset(&assets_root, &url_base, &req_path).await {
        Ok((bytes, mime)) => {
            let mut res = (StatusCode::OK, bytes).into_response();
            if let Ok(ct) = HeaderValue::from_str(&mime) {
                res.headers_mut().insert(CONTENT_TYPE, ct);
            }
            res.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            res
        }
        Err(AssetError::NotFound) => (StatusCode::NOT_FOUND, "Not Found").into_response(),
        Err(AssetError::Forbidden(reason)) => {
            tracing::warn!(path = %req_path, reason = reason, "Blocked unsafe static asset request");
            (StatusCode::FORBIDDEN, "Forbidden").into_response()
        }
        Err(AssetError::Internal(err)) => {
            tracing::error!(path = %req_path, error = %err, "Failed reading static asset");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}

pub async fn load_confined_asset(
    assets_root: &Path,
    url_base: &str,
    request_path: &str,
) -> Result<(Vec<u8>, String), AssetError> {
    let segments = sanitize_asset_segments(request_path, url_base)?;
    let root = assets_root.to_path_buf();

    task::spawn_blocking(move || read_confined_blocking(&root, &segments))
        .await
        .map_err(|err| AssetError::Internal(anyhow::anyhow!("asset read task failed: {err}")))?
}

pub fn sanitize_asset_segments(raw_path: &str, url_base: &str) -> Result<Vec<String>, AssetError> {
    if raw_path.contains('\0') || raw_path.contains('\\') {
        return Err(AssetError::Forbidden("null byte or backslash in raw path"));
    }

    let trimmed = raw_path.trim_start_matches('/');
    let stripped = if !url_base.is_empty() {
        if trimmed == url_base {
            ""
        } else if let Some(rest) = trimmed.strip_prefix(&format!("{url_base}/")) {
            rest
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    let mut segments = Vec::new();
    for raw_seg in stripped.split('/') {
        if raw_seg.is_empty() {
            continue;
        }
        if raw_seg == "." || raw_seg == ".." {
            return Err(AssetError::Forbidden("dot segment traversal"));
        }
        let decoded = urlencoding::decode(raw_seg)
            .map_err(|_| AssetError::Forbidden("invalid percent-encoding"))?;
        let dec = decoded.as_ref();
        if dec.is_empty() {
            continue;
        }
        if dec.contains('\0') || dec.contains('\\') || dec.contains('/') {
            return Err(AssetError::Forbidden("encoded separator or null byte"));
        }
        if dec == "." || dec == ".." {
            return Err(AssetError::Forbidden("encoded traversal segment"));
        }
        segments.push(dec.to_string());
    }

    Ok(segments)
}

fn read_confined_blocking(
    root: &Path,
    segments: &[String],
) -> Result<(Vec<u8>, String), AssetError> {
    // Verify assets_root itself is not a symlink using symlink_metadata first for clear erroring,
    // then open with O_DIRECTORY | O_NOFOLLOW to prevent TOCTOU races.
    match fs::symlink_metadata(root) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(AssetError::Forbidden("assets_path is a symlink"));
            }
            if !meta.is_dir() {
                return Err(AssetError::NotFound);
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Err(AssetError::NotFound),
        Err(err) => return Err(AssetError::Internal(err.into())),
    }

    let mut current_dir = open_dir_root_nofollow(root)?;

    if segments.is_empty() {
        return open_index_in_dir(&current_dir);
    }

    for seg in &segments[..segments.len() - 1] {
        current_dir = openat_dir_nofollow(&current_dir, seg)?;
    }

    let leaf_name = &segments[segments.len() - 1];
    let leaf_fd = openat_entry_nofollow(&current_dir, leaf_name)?;
    let leaf_file = File::from(leaf_fd);
    let meta = leaf_file
        .metadata()
        .map_err(|e| AssetError::Internal(e.into()))?;

    if meta.is_dir() {
        let dir_fd = OwnedFd::from(leaf_file);
        return open_index_in_dir(&dir_fd);
    }

    if !meta.is_file() {
        return Err(AssetError::Forbidden("non-regular file rejected"));
    }

    read_regular_file(leaf_file, meta.len(), leaf_name)
}

fn open_index_in_dir(dir_fd: &OwnedFd) -> Result<(Vec<u8>, String), AssetError> {
    for candidate in ["index.html", "index-modern.html"] {
        match openat_entry_nofollow(dir_fd, candidate) {
            Ok(fd) => {
                let file = File::from(fd);
                let meta = file
                    .metadata()
                    .map_err(|e| AssetError::Internal(e.into()))?;
                if meta.is_file() {
                    return read_regular_file(file, meta.len(), candidate);
                }
            }
            Err(AssetError::NotFound) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(AssetError::NotFound)
}

fn read_regular_file(
    mut file: File,
    size: u64,
    filename: &str,
) -> Result<(Vec<u8>, String), AssetError> {
    if size > MAX_STATIC_ASSET_BYTES as u64 {
        return Err(AssetError::Forbidden("static asset exceeds size cap"));
    }
    let mut buf = Vec::with_capacity((size as usize).min(MAX_STATIC_ASSET_BYTES));
    (&mut file)
        .take((MAX_STATIC_ASSET_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| AssetError::Internal(e.into()))?;
    if buf.len() > MAX_STATIC_ASSET_BYTES {
        return Err(AssetError::Forbidden("static asset exceeds size cap"));
    }

    let mime = guess_mime_header(filename);
    Ok((buf, mime))
}

fn guess_mime_header(filename: &str) -> String {
    let guessed = mime_guess::from_path(filename).first_or_octet_stream();
    let ess = guessed.essence_str();
    match ess {
        "text/html"
        | "application/javascript"
        | "text/javascript"
        | "text/css"
        | "application/json" => {
            if ess == "text/html" {
                "text/html; charset=utf-8".to_string()
            } else {
                format!("{ess}; charset=utf-8")
            }
        }
        _ => guessed.as_ref().to_string(),
    }
}

fn cstring_segment(seg: &str) -> Result<CString, AssetError> {
    CString::new(seg.as_bytes()).map_err(|_| AssetError::Forbidden("interior null byte"))
}

fn open_dir_root_nofollow(path: &Path) -> Result<OwnedFd, AssetError> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AssetError::Forbidden("invalid root path"))?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(map_errno(std::io::Error::last_os_error()));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    ensure_opened_fd_is_dir(owned)
}

fn openat_dir_nofollow(parent: &OwnedFd, segment: &str) -> Result<OwnedFd, AssetError> {
    let cseg = cstring_segment(segment)?;
    // Omit O_DIRECTORY here so Linux checks O_NOFOLLOW first and returns ELOOP
    // consistently even when a symlink points to a directory.
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), cseg.as_ptr(), flags) };
    if fd < 0 {
        return Err(map_errno(std::io::Error::last_os_error()));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    ensure_opened_fd_is_dir(owned)
}

fn ensure_opened_fd_is_dir(owned: OwnedFd) -> Result<OwnedFd, AssetError> {
    let file = File::from(owned);
    let meta = file
        .metadata()
        .map_err(|e| AssetError::Internal(e.into()))?;
    if !meta.is_dir() {
        return Err(AssetError::NotFound);
    }
    Ok(OwnedFd::from(file))
}

fn openat_entry_nofollow(parent: &OwnedFd, segment: &str) -> Result<OwnedFd, AssetError> {
    let cseg = cstring_segment(segment)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), cseg.as_ptr(), flags) };
    if fd < 0 {
        return Err(map_errno(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn map_errno(err: std::io::Error) -> AssetError {
    match err.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::EACCES) | Some(libc::EPERM) => {
            AssetError::Forbidden("symlink or permission denied")
        }
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => AssetError::NotFound,
        _ => AssetError::Internal(PathBuf::new().display().to_string().pipe_err(err)),
    }
}

trait PipeErr {
    fn pipe_err(self, err: std::io::Error) -> anyhow::Error;
}

impl PipeErr for String {
    fn pipe_err(self, err: std::io::Error) -> anyhow::Error {
        err.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let unique = format!(
                "af-librespeed-assets-{}-{}-{}",
                label,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            let dir = std::env::temp_dir().join(unique);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn serves_index_modern_fallback_and_blocks_traversal_and_symlinks() {
        let tmp = TempDirGuard::new("confinement");
        let assets = tmp.0.join("assets");
        let outside = tmp.0.join("secret.txt");
        let sub = assets.join("javascript");
        fs::create_dir_all(&sub).unwrap();
        fs::write(&outside, b"TOP_SECRET").unwrap();
        fs::write(assets.join("index-modern.html"), b"<h1>Obsidian</h1>").unwrap();
        fs::write(sub.join("app.js"), b"console.log(1);").unwrap();

        let (body, mime) = load_confined_asset(&assets, "speedtest", "/speedtest")
            .await
            .expect("index-modern fallback");
        assert_eq!(body, b"<h1>Obsidian</h1>");
        assert!(mime.starts_with("text/html"));

        let (js_body, js_mime) = load_confined_asset(&assets, "speedtest", "/javascript/app.js")
            .await
            .expect("js file");
        assert_eq!(js_body, b"console.log(1);");
        assert!(js_mime.contains("javascript"));

        assert!(matches!(
            load_confined_asset(&assets, "", "/../secret.txt").await,
            Err(AssetError::Forbidden(_))
        ));
        assert!(matches!(
            load_confined_asset(&assets, "", "/%2e%2e/secret.txt").await,
            Err(AssetError::Forbidden(_))
        ));
        assert!(matches!(
            load_confined_asset(&assets, "", "/foo\\bar").await,
            Err(AssetError::Forbidden(_))
        ));
        assert!(matches!(
            load_confined_asset(&assets, "", "/foo%00bar").await,
            Err(AssetError::Forbidden(_))
        ));

        symlink(&outside, assets.join("leak.txt")).unwrap();
        assert!(matches!(
            load_confined_asset(&assets, "", "/leak.txt").await,
            Err(AssetError::Forbidden(_))
        ));

        let real_outside_dir = tmp.0.join("outside_dir");
        fs::create_dir_all(&real_outside_dir).unwrap();
        fs::write(real_outside_dir.join("k.txt"), b"x").unwrap();
        symlink(&real_outside_dir, assets.join("linked_dir")).unwrap();
        assert!(matches!(
            load_confined_asset(&assets, "", "/linked_dir/k.txt").await,
            Err(AssetError::Forbidden(_))
        ));

        let sym_root = tmp.0.join("sym_assets");
        symlink(&assets, &sym_root).unwrap();
        assert!(matches!(
            load_confined_asset(&sym_root, "", "/").await,
            Err(AssetError::Forbidden(_))
        ));
    }
}
