use super::*;
use af_web_core::api::RawResponse;

pub(super) const BASE: &str = "/api/v1/auth/mcbrowser";
pub(super) const DIRECT_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(super) const CHUNK_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const FORM: &str = "glass-input w-full px-3 py-2";
pub(super) const ARCHIVES: [(&str, &str); 9] = [
    ("zip", ".zip"),
    ("tar", ".tar"),
    ("targz", ".tar.gz"),
    ("tarbz2", ".tar.bz2"),
    ("tarxz", ".tar.xz"),
    ("tarlz4", ".tar.lz4"),
    ("tarsz", ".tar.sz"),
    ("tarbr", ".tar.br"),
    ("tarzst", ".tar.zst"),
];

pub(super) fn bytes(size: u64) -> String {
    let mut value = size as f64;
    let mut unit = "B";
    for candidate in ["KiB", "MiB", "GiB", "TiB"] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = candidate;
    }
    format!("{value:.1} {unit}")
}
pub(super) fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}
pub(super) fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}
pub(super) fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
pub(super) fn name_path(parent: &str, name: &str) -> Result<String, String> {
    if name.trim().is_empty() || name.contains('/') {
        return Err("Enter a single file or folder name.".into());
    }
    relative_path(&join(parent, name), false)
}
pub(super) fn error(message: impl Into<String>) -> ApiError {
    ApiError {
        status: 0,
        message: message.into(),
        code: None,
    }
}
pub(super) fn js_error(value: JsValue) -> ApiError {
    error(
        value
            .as_string()
            .unwrap_or_else(|| "Browser operation failed".into()),
    )
}
pub(super) async fn response_value(
    context: AppContext,
    response: RawResponse,
) -> Result<(Value, Option<String>), ApiError> {
    let status = response.status();
    let ok = response.ok();
    let etag = response.headers().get("ETag").ok().flatten();
    let raw = response.text().await?;
    let value = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&raw).map_err(|_| {
            error(tt_with(
                context,
                "Invalid server response (HTTP {status})",
                &[("status", &(tt(context, &(status).to_string())).to_string())],
            ))
        })?
    };
    if !ok {
        return Err(ApiError {
            status,
            message: value["message"]
                .as_str()
                .or_else(|| value["error"].as_str())
                .unwrap_or("Request failed")
                .to_owned(),
            code: value["code"].as_str().map(str::to_owned),
        });
    }
    Ok((value, etag))
}
pub(super) async fn checked(
    context: AppContext,
    response: RawResponse,
) -> Result<RawResponse, ApiError> {
    if response.ok() {
        Ok(response)
    } else {
        Err(response_value(context, response)
            .await
            .err()
            .unwrap_or_else(|| error("Request failed")))
    }
}
pub(super) fn header_u64(
    context: AppContext,
    response: &RawResponse,
    name: &str,
) -> Result<u64, ApiError> {
    response
        .headers()
        .get(name)
        .map_err(js_error)?
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            error(tt_with(
                context,
                "Missing or invalid {name} response header",
                &[("name", (name))],
            ))
        })
}
pub(super) fn base64(data: &[u8]) -> String {
    pub(super) const TABLE: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for part in data.chunks(3) {
        let a = part[0] as usize;
        let b = part.get(1).copied().unwrap_or(0) as usize;
        let c = part.get(2).copied().unwrap_or(0) as usize;
        result.push(TABLE[a >> 2] as char);
        result.push(TABLE[((a & 3) << 4) | (b >> 4)] as char);
        result.push(if part.len() > 1 {
            TABLE[((b & 15) << 2) | (c >> 6)] as char
        } else {
            '='
        });
        result.push(if part.len() > 2 {
            TABLE[c & 63] as char
        } else {
            '='
        });
    }
    result
}
pub(super) fn metadata_value(response: &RawResponse, key: &str) -> Option<String> {
    let metadata = response.headers().get("Upload-Metadata").ok()??;
    let encoded = metadata.split(',').find_map(|entry| {
        let (name, value) = entry.trim().split_once(' ')?;
        (name == key).then_some(value)
    })?;
    let binary = web_sys::window()?.atob(encoded).ok()?;
    String::from_utf8(binary.chars().map(|c| c as u8).collect()).ok()
}
pub(super) async fn read_slice(
    file: &web_sys::File,
    from: u64,
    to: u64,
) -> Result<Vec<u8>, ApiError> {
    let blob = file
        .slice_with_f64_and_f64(from as f64, to as f64)
        .map_err(js_error)?;
    let buffer = JsFuture::from(blob.array_buffer())
        .await
        .map_err(js_error)?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}
pub(super) async fn hash(data: Vec<u8>) -> Result<String, ApiError> {
    match worker_pool()
        .execute(WorkerRequest::Sha256Chunk { bytes: data })
        .await
    {
        WorkerResponse::Hash { hex } => Ok(hex),
        WorkerResponse::Error { message } => Err(error(message)),
        _ => Err(error("The hashing worker returned an invalid response")),
    }
}
pub(super) async fn fingerprint(
    file: &web_sys::File,
    size: u64,
    conflict: &str,
) -> Result<String, ApiError> {
    let modified = file.last_modified() as u64;
    let first_end = size.min(64 * 1024);
    let last_start = first_end.max(size.saturating_sub(64 * 1024));
    // Discovery can reconcile publication before returning a session. Bind its
    // lookup identity to the requested policy so even that read cannot select
    // an older session authorized to overwrite under a different user intent.
    let mut data = format!("af-tus-fp-v2:{size}:{modified}:{conflict}:").into_bytes();
    data.extend(read_slice(file, 0, first_end).await?);
    data.push(b':');
    data.extend(read_slice(file, last_start, size).await?);
    Ok(format!(
        "v2:{size}:{modified}:{conflict}:{}",
        hash(data).await?
    ))
}
pub(super) fn upload_location(raw: &str) -> Result<String, ApiError> {
    let origin = web_sys::window()
        .ok_or_else(|| error("Browser unavailable"))?
        .location()
        .origin()
        .map_err(js_error)?;
    let url = web_sys::Url::new_with_base(raw, &origin).map_err(js_error)?;
    let prefix = format!("{BASE}/uploads/");
    let path = url.pathname();
    let id = path.strip_prefix(&prefix).unwrap_or_default();
    if url.origin() != origin
        || !url.search().is_empty()
        || !url.hash().is_empty()
        || id.len() != 32
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(error("Server returned an invalid upload session URL"));
    }
    Ok(path)
}

pub(super) fn language(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "rs" => "rust",
        "go" => "go",
        "py" => "python",
        "ts" | "tsx" => "typescript",
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "json" => "json",
        "toml" => "toml",
        "yaml" | "yml" => "yaml",
        "sh" | "bash" | "zsh" => "shell",
        "md" | "markdown" => "markdown",
        "html" | "htm" | "xml" | "svg" => "html",
        "css" | "scss" => "css",
        "sql" => "sql",
        "ini" | "conf" | "cfg" | "env" => "ini",
        _ => "text",
    }
}
pub(super) fn media_kind(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "bmp" | "ico" => "image",
        "mp4" | "webm" | "ogv" | "mov" | "mkv" | "m4v" => "video",
        "mp3" | "wav" | "ogg" | "m4a" | "aac" | "flac" | "opus" => "audio",
        "pdf" => "pdf",
        _ => "",
    }
}

pub(super) fn action_label(context: AppContext, kind: &str) -> String {
    tt(
        context,
        match kind {
            "rename" => "Rename",
            "move" => "Move",
            "copy" => "Copy",
            "delete" => "Delete",
            "archive" => "Create archive",
            "extract" => "Extract archive",
            "checksums" => "Checksums",
            "info" => "Info",
            "folder" => "New folder",
            "file" => "New file",
            _ => kind,
        },
    )
}
