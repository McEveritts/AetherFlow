use super::*;
use af_web_core::api::{api_url, api_url_for_server, RawResponse};

pub(super) const BASE: &str = "/api/v1/auth/mcbrowser";
pub(super) const DIRECT_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(super) const CHUNK_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const MAX_CSV_PREVIEW_BYTES: u64 = 5 * 1024 * 1024;
pub(super) const MAX_EPUB_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_THUMBNAIL_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const MAX_CSV_PREVIEW_ROWS: usize = 500;
pub(super) const FORM: &str = "af-input w-full px-3 py-2";
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
pub(super) fn upload_location_for_server(
    raw: &str,
    origin: &str,
    server: Option<&str>,
) -> Result<String, ApiError> {
    let base = url::Url::parse(origin).map_err(|_| error("Browser origin unavailable"))?;
    let url = base
        .join(raw.trim())
        .map_err(|_| error("Server returned an invalid upload session URL"))?;
    let expected_prefix = api_url_for_server(server, &format!("{BASE}/uploads/"));
    let path = url.path();
    let id = path.strip_prefix(&expected_prefix).unwrap_or_default();
    if url.origin() != base.origin()
        || url.query().is_some()
        || url.fragment().is_some()
        || id.len() != 32
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(error("Server returned an invalid upload session URL"));
    }
    Ok(path.to_owned())
}

pub(super) fn upload_location(raw: &str, server: Option<&str>) -> Result<String, ApiError> {
    let origin = web_sys::window()
        .ok_or_else(|| error("Browser unavailable"))?
        .location()
        .origin()
        .map_err(js_error)?;
    upload_location_for_server(raw, &origin, server)
}

pub(super) const EDITOR_THEME_OPTIONS: [&str; 8] = [
    "chrome",
    "github",
    "solarized_light",
    "monokai",
    "dracula",
    "twilight",
    "tomorrow_night",
    "solarized_dark",
];

pub(super) const CSV_ENCODING_OPTIONS: [&str; 14] = [
    "utf-8",
    "windows-1252",
    "iso-8859-1",
    "iso-8859-2",
    "iso-8859-15",
    "windows-1250",
    "windows-1251",
    "utf-16le",
    "utf-16be",
    "shift_jis",
    "euc-jp",
    "gbk",
    "big5",
    "euc-kr",
];

pub(super) fn language(path: &str) -> &'static str {
    let file_name = leaf(path).to_ascii_lowercase();
    if file_name == "dockerfile" || file_name.starts_with("dockerfile.") {
        return "dockerfile";
    }
    if matches!(
        file_name.as_str(),
        "makefile" | "gnumakefile" | "ocamlmakefile"
    ) {
        return "makefile";
    }
    if file_name == ".gitignore" {
        return "gitignore";
    }
    if matches!(
        file_name.as_str(),
        ".bashrc" | ".bash_profile" | ".profile" | ".zshrc" | ".shrc"
    ) {
        return "shell";
    }
    if file_name == ".env" || file_name.starts_with(".env.") {
        return "ini";
    }
    if matches!(
        file_name.as_str(),
        "htaccess" | "htgroups" | "htpasswd" | ".htaccess" | ".htgroups" | ".htpasswd"
    ) {
        return "apache_conf";
    }
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
        "ts" | "mts" | "cts" | "typescript" => "typescript",
        "tsx" => "tsx",
        "jsx" => "jsx",
        "js" | "jsm" | "mjs" | "cjs" => "javascript",
        "json5" => "json5",
        "json" => "json",
        "toml" => "toml",
        "yaml" | "yml" => "yaml",
        "sh" | "bash" | "zsh" => "shell",
        "bat" | "cmd" => "batchfile",
        "ps1" => "powershell",
        "md" | "markdown" => "markdown",
        "html" | "htm" | "xhtml" => "html",
        "svg" => "svg",
        "xml" | "rdf" | "rss" | "wsdl" | "xslt" | "atom" | "mathml" | "mml" | "xul" | "xbl"
        | "xaml" => "xml",
        "css" => "css",
        "scss" => "scss",
        "less" => "less",
        "sql" => "sql",
        "properties" => "properties",
        "nginx" => "nginx",
        "ini" | "conf" | "cfg" | "prefs" | "env" => "ini",
        "cpp" | "c" | "cc" | "cxx" | "h" | "hh" | "hpp" | "ino" => "c_cpp",
        "java" => "java",
        "cs" => "csharp",
        "php" => "php",
        "rb" | "ru" | "gemspec" | "rake" => "ruby",
        "diff" | "patch" => "diff",
        "lua" => "lua",
        "pl" | "pm" => "perl",
        "swift" => "swift",
        "kt" | "kts" => "kotlin",
        "scala" | "sbt" => "scala",
        "gql" | "graphql" => "graphql",
        "prisma" => "prisma",
        "tf" | "tfvars" | "terragrunt" | "hcl" => "terraform",
        "tex" | "latex" | "ltx" | "bib" => "latex",
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
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "bmp" | "ico" | "tif" | "tiff" => {
            "image"
        }
        "mp4" | "webm" | "ogv" | "mov" | "mkv" | "m4v" => "video",
        "mp3" | "wav" | "ogg" | "oga" | "m4a" | "aac" | "flac" | "opus" => "audio",
        "pdf" => "pdf",
        "csv" | "tsv" => "csv",
        "epub" => "epub",
        _ => "",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CsvPreviewData {
    pub(super) delimiter: char,
    pub(super) headers: Vec<String>,
    pub(super) rows: Vec<Vec<String>>,
    pub(super) total_rows: usize,
    pub(super) truncated: bool,
}

pub(super) fn detect_csv_delimiter(raw: &str, path: &str) -> char {
    if path
        .rsplit('.')
        .next()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("tsv"))
    {
        return '\t';
    }
    let first_line = raw
        .trim_start_matches('\u{feff}')
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    let candidates = [',', ';', '\t', '|'];
    let mut best = ',';
    let mut best_count = 0usize;
    for candidate in candidates {
        let mut count = 0usize;
        let mut in_quotes = false;
        for ch in first_line.chars() {
            if ch == '"' {
                in_quotes = !in_quotes;
            } else if !in_quotes && ch == candidate {
                count += 1;
            }
        }
        if count > best_count {
            best = candidate;
            best_count = count;
        }
    }
    best
}

pub(super) fn parse_csv_preview(raw: &str, delimiter: char, max_rows: usize) -> CsvPreviewData {
    let input = raw.trim_start_matches('\u{feff}');
    let mut headers: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut total_rows = 0usize;
    let mut truncated = false;

    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    let flush_row = |current: &mut Vec<String>,
                     headers: &mut Vec<String>,
                     rows: &mut Vec<Vec<String>>,
                     total_rows: &mut usize,
                     truncated: &mut bool| {
        if current.is_empty() || (current.len() == 1 && current[0].is_empty()) {
            current.clear();
            return;
        }
        let finished = std::mem::take(current);
        if headers.is_empty() {
            *headers = finished;
        } else {
            *total_rows += 1;
            if rows.len() < max_rows {
                rows.push(finished);
            } else {
                *truncated = true;
            }
        }
    };

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
        } else if ch == '"' && field.is_empty() {
            in_quotes = true;
        } else if ch == delimiter {
            row.push(std::mem::take(&mut field));
        } else if ch == '\r' || ch == '\n' {
            if ch == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            row.push(std::mem::take(&mut field));
            flush_row(
                &mut row,
                &mut headers,
                &mut rows,
                &mut total_rows,
                &mut truncated,
            );
        } else {
            field.push(ch);
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        flush_row(
            &mut row,
            &mut headers,
            &mut rows,
            &mut total_rows,
            &mut truncated,
        );
    }

    CsvPreviewData {
        delimiter,
        headers,
        rows,
        total_rows,
        truncated,
    }
}

pub(super) fn mcbrowser_media_url_encoded(encoded_path: &str) -> String {
    api_url(&format!("{BASE}/media?path={encoded_path}"))
}

pub(super) fn mcbrowser_preview_big_url_encoded(encoded_path: &str) -> String {
    api_url(&format!("{BASE}/preview/big?path={encoded_path}"))
}

pub(super) fn mcbrowser_preview_thumb_url_encoded(encoded_path: &str) -> String {
    api_url(&format!("{BASE}/preview/thumb?path={encoded_path}"))
}

pub(super) fn mcbrowser_download_url_encoded(encoded_path: &str) -> String {
    api_url(&format!("{BASE}/download?path={encoded_path}"))
}

pub(super) fn mcbrowser_preview_download_href(
    server: Option<&str>,
    encoded_path: &str,
) -> Option<String> {
    (!encoded_path.is_empty())
        .then(|| api_url_for_server(server, &format!("{BASE}/download?path={encoded_path}")))
}

pub(super) fn safe_subtitle_url_for_server(raw: &str, server: Option<&str>) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("/api/v1/auth/mcbrowser/subtitle?") {
        return None;
    }
    if trimmed.contains('\r') || trimmed.contains('\n') || trimmed.contains("..") {
        return None;
    }
    Some(api_url_for_server(server, trimmed))
}

#[cfg(test)]
pub(super) fn safe_subtitle_url(raw: &str) -> Option<String> {
    safe_subtitle_url_for_server(raw, af_web_core::api::active_server().as_deref())
}

fn decode_windows_1252(bytes: &[u8]) -> String {
    const CP1252_HIGH: [char; 32] = [
        '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}',
        '\u{017D}', '\u{FFFD}', '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}',
        '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}',
        '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
    ];
    bytes
        .iter()
        .map(|&b| {
            if (0x80..=0x9F).contains(&b) {
                CP1252_HIGH[(b - 0x80) as usize]
            } else {
                b as char
            }
        })
        .collect()
}

fn decode_iso_8859_15(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0xA4 => '\u{20AC}',
            0xA6 => '\u{0160}',
            0xA8 => '\u{0161}',
            0xB4 => '\u{017D}',
            0xB8 => '\u{017E}',
            0xBC => '\u{0152}',
            0xBD => '\u{0153}',
            0xBE => '\u{0178}',
            other => other as char,
        })
        .collect()
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let bom = if little_endian {
        &[0xff, 0xfe]
    } else {
        &[0xfe, 0xff]
    };
    let slice = bytes.strip_prefix(bom).unwrap_or(bytes);
    let (pairs, _) = slice.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|&pair| {
            if little_endian {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(target_arch = "wasm32")]
fn browser_text_decode(bytes: &[u8], encoding: &str) -> Option<String> {
    use wasm_bindgen::JsCast;
    let global = js_sys::global();
    let ctor = js_sys::Reflect::get(&global, &JsValue::from_str("TextDecoder"))
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    let ctor_args = js_sys::Array::of1(&JsValue::from_str(encoding));
    let decoder = js_sys::Reflect::construct(&ctor, &ctor_args).ok()?;
    let decode_fn = js_sys::Reflect::get(&decoder, &JsValue::from_str("decode"))
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    let view = js_sys::Uint8Array::from(bytes);
    let decode_args = js_sys::Array::of1(view.as_ref());
    js_sys::Reflect::apply(&decode_fn, &decoder, &decode_args)
        .ok()?
        .as_string()
}

fn decode_csv_bytes_native(bytes: &[u8], encoding: &str) -> Result<String, &'static str> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "" | "utf-8" | "utf8" => Ok(String::from_utf8_lossy(bytes).into_owned()),
        "windows-1252" | "cp1252" => Ok(decode_windows_1252(bytes)),
        "iso-8859-1" | "latin1" => Ok(bytes.iter().map(|&b| b as char).collect()),
        "iso-8859-15" | "latin9" => Ok(decode_iso_8859_15(bytes)),
        "utf-16le" => Ok(decode_utf16(bytes, true)),
        "utf-16be" => Ok(decode_utf16(bytes, false)),
        _ => Err("Unsupported CSV encoding"),
    }
}

pub(super) fn decode_csv_bytes(bytes: &[u8], encoding: &str) -> Result<String, &'static str> {
    let normalized = encoding.trim().to_ascii_lowercase();
    let target = if normalized.is_empty() {
        "utf-8"
    } else {
        normalized.as_str()
    };
    #[cfg(target_arch = "wasm32")]
    if let Some(decoded) = browser_text_decode(bytes, target) {
        return Ok(decoded);
    }
    decode_csv_bytes_native(bytes, target)
}

pub(super) fn is_valid_editor_theme(theme: &str) -> bool {
    !theme.is_empty()
        && theme.len() <= 64
        && theme.trim() == theme
        && theme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HydratedPreferences {
    pub(super) grid: bool,
    pub(super) sort: String,
    pub(super) descending: bool,
    pub(super) editor_theme: String,
}

pub(super) fn normalize_editor_theme(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix("ace/theme/")
        .or_else(|| trimmed.strip_prefix("ACE/THEME/"))
        .unwrap_or(trimmed);
    is_valid_editor_theme(stripped).then(|| stripped.to_owned())
}

pub(super) fn apply_preferences_from_server(data: &Value) -> Option<HydratedPreferences> {
    let obj = data.as_object()?;
    let view = obj.get("view").and_then(Value::as_str).unwrap_or("list");
    let grid = matches!(view, "grid" | "gallery");
    let sort = match obj.get("sort").and_then(Value::as_str) {
        Some("size") => "size",
        Some("modified") => "modified",
        _ => "name",
    }
    .to_owned();
    let descending = obj
        .get("direction")
        .and_then(Value::as_str)
        .is_some_and(|dir| dir == "desc");
    let editor_theme = obj
        .get("editor_theme")
        .or_else(|| obj.get("ace_editor_theme"))
        .or_else(|| obj.get("aceEditorTheme"))
        .and_then(Value::as_str)
        .and_then(normalize_editor_theme)
        .unwrap_or_else(|| "chrome".to_owned());
    Some(HydratedPreferences {
        grid,
        sort,
        descending,
        editor_theme,
    })
}

pub(super) fn build_preferences_payload(
    base: &Value,
    grid: bool,
    sort: &str,
    descending: bool,
    editor_theme: &str,
) -> Value {
    let view = if grid {
        if base["view"].as_str() == Some("gallery") {
            "gallery"
        } else {
            "grid"
        }
    } else {
        "list"
    };
    let backend_sort = if matches!(sort, "name" | "size" | "modified") {
        sort
    } else {
        base["sort"]
            .as_str()
            .filter(|value| matches!(*value, "name" | "size" | "modified"))
            .unwrap_or("name")
    };
    let resolved_theme = if is_valid_editor_theme(editor_theme) {
        editor_theme
    } else {
        base["editor_theme"]
            .as_str()
            .or_else(|| base["ace_editor_theme"].as_str())
            .or_else(|| base["aceEditorTheme"].as_str())
            .filter(|value| is_valid_editor_theme(value))
            .unwrap_or("chrome")
    };
    let locale = base["locale"]
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or("en");
    json!({
        "view": view,
        "sort": backend_sort,
        "direction": if descending { "desc" } else { "asc" },
        "show_hidden": base["show_hidden"].as_bool().unwrap_or(false),
        "single_click": base["single_click"].as_bool().unwrap_or(false),
        "natural_sort": base["natural_sort"].as_bool().unwrap_or(true),
        "redirect_after_copy_move": base["redirect_after_copy_move"].as_bool().unwrap_or(false),
        "date_format": base["date_format"].as_bool().unwrap_or(false),
        "editor_theme": resolved_theme,
        "locale": locale,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PreferenceDesired {
    pub(super) grid: bool,
    pub(super) sort: String,
    pub(super) descending: bool,
    pub(super) editor_theme: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct PreferenceSyncState {
    pub(super) hydrated: bool,
    pub(super) in_flight: bool,
    pub(super) server_doc: Value,
    pub(super) desired: Option<PreferenceDesired>,
    pub(super) last_error: Option<String>,
}

impl PreferenceSyncState {
    pub(super) fn reset(&mut self) {
        self.hydrated = false;
        self.in_flight = false;
        self.server_doc = Value::Null;
        self.desired = None;
        self.last_error = None;
    }

    pub(super) fn hydrate(&mut self, server: Value) -> Option<HydratedPreferences> {
        if self.hydrated || !server.is_object() {
            return None;
        }
        let parsed = apply_preferences_from_server(&server)?;
        let canonical = build_preferences_payload(
            &server,
            parsed.grid,
            &parsed.sort,
            parsed.descending,
            &parsed.editor_theme,
        );
        self.server_doc = canonical;
        self.hydrated = true;
        self.in_flight = false;
        self.desired = None;
        self.last_error = None;
        Some(parsed)
    }

    pub(super) fn queue_change(
        &mut self,
        grid: bool,
        sort: String,
        descending: bool,
        editor_theme: String,
    ) -> bool {
        if !self.hydrated {
            return false;
        }
        let next = PreferenceDesired {
            grid,
            sort,
            descending,
            editor_theme,
        };
        if self.in_flight {
            // Keep latest choice even if it reverts toward pre-flight server_doc;
            // once the active PUT finishes, take_next_payload reconciles against the new server_doc.
            self.desired = Some(next);
            self.last_error = None;
            return false;
        }
        let candidate = build_preferences_payload(
            &self.server_doc,
            next.grid,
            &next.sort,
            next.descending,
            &next.editor_theme,
        );
        if candidate == self.server_doc {
            self.desired = None;
            self.last_error = None;
            return false;
        }
        self.desired = Some(next);
        self.last_error = None;
        self.in_flight = true;
        true
    }

    pub(super) fn take_next_payload(&mut self) -> Option<Value> {
        if !self.in_flight {
            return None;
        }
        let Some(ref next) = self.desired else {
            self.in_flight = false;
            return None;
        };
        let payload = build_preferences_payload(
            &self.server_doc,
            next.grid,
            &next.sort,
            next.descending,
            &next.editor_theme,
        );
        if payload == self.server_doc {
            self.desired = None;
            self.in_flight = false;
            return None;
        }
        Some(payload)
    }

    pub(super) fn on_success(&mut self, sent_payload: Value, saved_response: Value) {
        self.server_doc = if saved_response.is_object() {
            if let Some(parsed) = apply_preferences_from_server(&saved_response) {
                build_preferences_payload(
                    &saved_response,
                    parsed.grid,
                    &parsed.sort,
                    parsed.descending,
                    &parsed.editor_theme,
                )
            } else {
                sent_payload
            }
        } else {
            sent_payload
        };
        self.last_error = None;
        if let Some(ref next) = self.desired {
            let latest = build_preferences_payload(
                &self.server_doc,
                next.grid,
                &next.sort,
                next.descending,
                &next.editor_theme,
            );
            if latest == self.server_doc {
                self.desired = None;
            }
        }
    }

    pub(super) fn on_error(&mut self, message: String) {
        self.in_flight = false;
        self.last_error = Some(message);
    }

    pub(super) fn retry(&mut self) -> bool {
        if !self.hydrated || self.in_flight || self.desired.is_none() {
            return false;
        }
        self.last_error = None;
        self.in_flight = true;
        true
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

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn csv_preview_parser_handles_quotes_delimiters_and_bounds_as_inert_text() {
        let raw = "\u{feff}name,note\r\n\"<script>alert(1)</script>\",\"hello, \"\"world\"\"\"\r\nrow2,val2\r\nrow3,val3\r\n";
        assert_eq!(detect_csv_delimiter(raw, "data.csv"), ',');
        assert_eq!(detect_csv_delimiter("a\tb\n1\t2\n", "data.tsv"), '\t');
        let parsed = parse_csv_preview(raw, ',', 2);
        assert_eq!(parsed.headers, vec!["name", "note"]);
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.total_rows, 3);
        assert!(parsed.truncated);
        assert_eq!(parsed.rows[0][0], "<script>alert(1)</script>");
        assert_eq!(parsed.rows[0][1], "hello, \"world\"");
    }

    #[test]
    fn subtitle_url_validator_blocks_external_and_traversal_targets() {
        assert_eq!(
            safe_subtitle_url("/api/v1/auth/mcbrowser/subtitle?path=movies%2Fclip.vtt").as_deref(),
            Some("/api/v1/auth/mcbrowser/subtitle?path=movies%2Fclip.vtt")
        );
        for bad in [
            "https://evil.example/sub.vtt",
            "javascript:alert(1)",
            "//evil.example/sub.vtt",
            "/api/v1/auth/mcbrowser/subtitle?path=../etc/passwd",
            "/api/v1/auth/mcbrowser/media?path=clip.vtt",
        ] {
            assert!(safe_subtitle_url(bad).is_none(), "{bad}");
        }
    }

    struct ActiveServerGuard;
    impl ActiveServerGuard {
        fn new(server: Option<&str>) -> Self {
            af_web_core::api::set_active_server(server.map(str::to_string));
            Self
        }
    }
    impl Drop for ActiveServerGuard {
        fn drop(&mut self) {
            af_web_core::api::set_active_server(None);
        }
    }

    #[test]
    fn subtitle_and_mcbrowser_direct_urls_route_active_peer_after_validation() {
        let _guard = ActiveServerGuard::new(None);
        assert_eq!(
            safe_subtitle_url("  /api/v1/auth/mcbrowser/subtitle?path=movies%2Fclip.vtt  ")
                .as_deref(),
            Some("/api/v1/auth/mcbrowser/subtitle?path=movies%2Fclip.vtt")
        );
        assert_eq!(
            mcbrowser_media_url_encoded("movies%2Fclip%201.mp4"),
            "/api/v1/auth/mcbrowser/media?path=movies%2Fclip%201.mp4"
        );
        assert_eq!(
            mcbrowser_preview_big_url_encoded("photos%2Fimg%201.png"),
            "/api/v1/auth/mcbrowser/preview/big?path=photos%2Fimg%201.png"
        );
        assert_eq!(
            mcbrowser_preview_thumb_url_encoded("photos%2Fimg%201.png"),
            "/api/v1/auth/mcbrowser/preview/thumb?path=photos%2Fimg%201.png"
        );
        assert_eq!(
            mcbrowser_download_url_encoded("docs%2Freport%201.pdf"),
            "/api/v1/auth/mcbrowser/download?path=docs%2Freport%201.pdf"
        );

        af_web_core::api::set_active_server(Some("media-2".into()));
        assert_eq!(
            safe_subtitle_url("  /api/v1/auth/mcbrowser/subtitle?path=movies%2Fclip.vtt  ")
                .as_deref(),
            Some("/api/v1/peers/media-2/auth/mcbrowser/subtitle?path=movies%2Fclip.vtt")
        );
        for bad in [
            "https://evil.example/sub.vtt",
            "javascript:alert(1)",
            "//evil.example/sub.vtt",
            "/api/v1/auth/mcbrowser/subtitle?path=../etc/passwd",
            "/api/v1/auth/mcbrowser/subtitle?path=clip.vtt\r\nX-Test: 1",
            "/api/v1/auth/mcbrowser/media?path=clip.vtt",
            "/api/v1/peers/other/auth/mcbrowser/subtitle?path=clip.vtt",
        ] {
            assert!(safe_subtitle_url(bad).is_none(), "{bad}");
        }
        assert_eq!(
            mcbrowser_media_url_encoded("movies%2Fclip%201.mp4"),
            "/api/v1/peers/media-2/auth/mcbrowser/media?path=movies%2Fclip%201.mp4"
        );
        assert_eq!(
            mcbrowser_preview_big_url_encoded("photos%2Fimg%201.png"),
            "/api/v1/peers/media-2/auth/mcbrowser/preview/big?path=photos%2Fimg%201.png"
        );
        assert_eq!(
            mcbrowser_preview_thumb_url_encoded("photos%2Fimg%201.png"),
            "/api/v1/peers/media-2/auth/mcbrowser/preview/thumb?path=photos%2Fimg%201.png"
        );
        assert_eq!(
            mcbrowser_download_url_encoded("docs%2Freport%201.pdf"),
            "/api/v1/peers/media-2/auth/mcbrowser/download?path=docs%2Freport%201.pdf"
        );
    }

    #[test]
    fn tus_upload_location_validates_exact_active_server_prefix_and_rejects_mismatches() {
        let origin = "https://panel.example.test";
        let hex = "0123456789abcdef0123456789abcdef";

        // Local server accepts local prefix only.
        assert_eq!(
            upload_location_for_server(
                &format!("/api/v1/auth/mcbrowser/uploads/{hex}"),
                origin,
                None
            )
            .unwrap(),
            format!("/api/v1/auth/mcbrowser/uploads/{hex}")
        );
        assert!(upload_location_for_server(
            &format!("/api/v1/peers/media-2/auth/mcbrowser/uploads/{hex}"),
            origin,
            None
        )
        .is_err());

        // Remote peer accepts only its exact prefixed path, never unprefixed local or another peer.
        assert_eq!(
            upload_location_for_server(
                &format!("/api/v1/peers/media-2/auth/mcbrowser/uploads/{hex}"),
                origin,
                Some("media-2")
            )
            .unwrap(),
            format!("/api/v1/peers/media-2/auth/mcbrowser/uploads/{hex}")
        );
        for bad in [
            format!("/api/v1/auth/mcbrowser/uploads/{hex}"),
            format!("/api/v1/peers/other-peer/auth/mcbrowser/uploads/{hex}"),
            format!("https://evil.example/api/v1/peers/media-2/auth/mcbrowser/uploads/{hex}"),
            format!("/api/v1/peers/media-2/auth/mcbrowser/uploads/{hex}?extra=1"),
            "/api/v1/peers/media-2/auth/mcbrowser/uploads/not-hex-32".to_string(),
        ] {
            assert!(
                upload_location_for_server(&bad, origin, Some("media-2")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn csv_encoding_and_dotfile_language_detection_match_backend_formats() {
        // Windows-1252 bytes: "café,10€" -> 0xE9 = é, 0x80 = €
        let cp1252 = b"caf\xe9,10\x80";
        assert_eq!(
            decode_csv_bytes(cp1252, "windows-1252").unwrap(),
            "café,10€"
        );
        assert_eq!(decode_csv_bytes(b"caf\xe9", "iso-8859-1").unwrap(), "café");
        assert_eq!(decode_csv_bytes(b"10\xa4", "iso-8859-15").unwrap(), "10€");
        // UTF-16LE with BOM: "a,b"
        let utf16le = [0xFF, 0xFE, b'a', 0, b',', 0, b'b', 0];
        assert_eq!(decode_csv_bytes(&utf16le, "utf-16le").unwrap(), "a,b");
        assert!(decode_csv_bytes(b"abc", "bogus-encoding").is_err());

        assert_eq!(language("deploy/Dockerfile.prod"), "dockerfile");
        assert_eq!(language("Makefile"), "makefile");
        assert_eq!(language(".gitignore"), "gitignore");
        assert_eq!(language(".htaccess"), "apache_conf");
        assert_eq!(language(".env.local"), "ini");
        assert_eq!(language("config/app.properties"), "properties");
        assert_eq!(language("sites/app.nginx"), "nginx");
        assert_eq!(language("src/main.cpp"), "c_cpp");
        assert_eq!(language("src/App.java"), "java");
        assert_eq!(language("src/Program.cs"), "csharp");
        assert_eq!(language("public/index.php"), "php");
        assert_eq!(language("Rakefile.rake"), "ruby");
        assert_eq!(language("scripts/build.bat"), "batchfile");
        assert_eq!(language("scripts/deploy.ps1"), "powershell");
        assert_eq!(language("assets/logo.svg"), "svg");
        assert_eq!(language("feed/site.xml"), "xml");
        assert_eq!(language("changes/fix.patch"), "diff");
        assert_eq!(language("scripts/init.lua"), "lua");
        assert_eq!(language("tools/parse.pl"), "perl");
        assert_eq!(language("ios/App.swift"), "swift");
        assert_eq!(language("android/Main.kt"), "kotlin");
        assert_eq!(language("build.sbt"), "scala");
        assert_eq!(language("schema.gql"), "graphql");
        assert_eq!(language("schema.prisma"), "prisma");
        assert_eq!(language("infra/main.tf"), "terraform");
        assert_eq!(language("docs/paper.tex"), "latex");
        assert_eq!(language("data/config.json5"), "json5");
        assert_eq!(language("styles/app.scss"), "scss");
        assert_eq!(language("styles/theme.less"), "less");
        assert_eq!(language("web/App.tsx"), "tsx");
        assert_eq!(language("web/Card.jsx"), "jsx");

        // Legacy ace/theme/ prefix is normalized cleanly.
        assert_eq!(
            normalize_editor_theme("ace/theme/nord_dark").as_deref(),
            Some("nord_dark")
        );
    }

    #[test]
    fn preferences_payload_preserves_server_fields_and_sanitizes_sort() {
        let server = json!({
            "view": "grid",
            "sort": "modified",
            "direction": "desc",
            "show_hidden": true,
            "single_click": true,
            "natural_sort": false,
            "redirect_after_copy_move": true,
            "date_format": true,
            "editor_theme": "solarized_dark",
            "locale": "de"
        });
        assert_eq!(
            apply_preferences_from_server(&server),
            Some(HydratedPreferences {
                grid: true,
                sort: "modified".into(),
                descending: true,
                editor_theme: "solarized_dark".into(),
            })
        );
        // "kind" is a client-only sort option; backend PreferencesDocument only accepts name|size|modified.
        let payload = build_preferences_payload(&server, false, "kind", false, "dracula");
        assert_eq!(payload["view"], "list");
        assert_eq!(payload["sort"], "modified");
        assert_eq!(payload["direction"], "asc");
        assert_eq!(payload["show_hidden"], true);
        assert_eq!(payload["editor_theme"], "dracula");
        assert_eq!(payload["locale"], "de");
        assert_eq!(payload.as_object().unwrap().len(), 10);

        // Gallery view and default editor_theme ("chrome") are preserved cleanly.
        let gallery = json!({"view": "gallery", "sort": "name", "direction": "asc"});
        let gallery_payload = build_preferences_payload(&gallery, true, "size", true, "");
        assert_eq!(gallery_payload["view"], "gallery");
        assert_eq!(gallery_payload["editor_theme"], "chrome");
    }

    #[test]
    fn preference_sync_serializes_coalesces_preserves_fields_and_retries_on_failure() {
        let mut sync = PreferenceSyncState::default();
        let initial = json!({
            "view": "list",
            "sort": "name",
            "direction": "asc",
            "show_hidden": true,
            "single_click": true,
            "natural_sort": false,
            "redirect_after_copy_move": true,
            "date_format": true,
            "editor_theme": "monokai",
            "locale": "de"
        });
        assert_eq!(
            sync.hydrate(initial),
            Some(HydratedPreferences {
                grid: false,
                sort: "name".into(),
                descending: false,
                editor_theme: "monokai".into(),
            })
        );

        // 1. First change starts single-flight loop.
        assert!(sync.queue_change(true, "name".into(), false, "monokai".into()));
        let first = sync.take_next_payload().expect("first payload");
        assert_eq!(first["view"], "grid");
        assert_eq!(first["editor_theme"], "monokai");
        assert_eq!(first["show_hidden"], true);

        // 2. Rapid intermediate changes (including editor_theme) while PUT #1 is in flight coalesce into latest choice only.
        assert!(!sync.queue_change(true, "size".into(), false, "twilight".into()));
        assert!(!sync.queue_change(true, "modified".into(), true, "dracula".into()));

        // 3. PUT #1 succeeds -> server_doc advances, next payload reflects final coalesced choice.
        sync.on_success(first.clone(), first);
        let second = sync.take_next_payload().expect("coalesced payload");
        assert_eq!(second["view"], "grid");
        assert_eq!(second["sort"], "modified");
        assert_eq!(second["direction"], "desc");
        assert_eq!(second["editor_theme"], "dracula");
        assert_eq!(second["locale"], "de");
        assert_eq!(second["single_click"], true);

        // 4. PUT #2 fails -> server_doc stays at PUT #1, error recorded, retry re-enqueues PUT #2.
        sync.on_error("Network timeout".into());
        assert!(!sync.in_flight);
        assert_eq!(sync.last_error.as_deref(), Some("Network timeout"));
        assert_eq!(sync.server_doc["sort"], "name");
        assert_eq!(sync.server_doc["editor_theme"], "monokai");
        assert!(sync.retry());
        let retried = sync.take_next_payload().expect("retried payload");
        assert_eq!(retried, second);

        // 5. Reversal while PUT #2 retry is in flight still flushes after retry succeeds.
        assert!(!sync.queue_change(false, "name".into(), false, "monokai".into()));
        sync.on_success(retried.clone(), retried);
        let reversal = sync.take_next_payload().expect("reversal payload");
        assert_eq!(reversal["view"], "list");
        assert_eq!(reversal["sort"], "name");
        assert_eq!(reversal["editor_theme"], "monokai");
        sync.on_success(reversal.clone(), reversal);
        assert_eq!(sync.take_next_payload(), None);
        assert!(!sync.in_flight);

        // 6. Account change reset wipes pending state.
        sync.reset();
        assert!(!sync.hydrated);
        assert!(!sync.queue_change(true, "size".into(), true, "dracula".into()));
    }
}
