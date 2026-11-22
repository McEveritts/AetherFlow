mod documents;
mod subtitles;
mod thumbnails;

use documents::{csv_preview, epub_preview};
#[allow(unused_imports)]
pub use documents::{
    parse_epub_bytes, sanitize_xhtml_to_chapter, validate_csv_preview_bytes, EpubBookPreview,
    EpubChapter, MAX_CSV_PREVIEW_BYTES, MAX_EPUB_BYTES,
};
#[allow(unused_imports)]
pub use subtitles::{
    discover_subtitles_for_user_with_conn, discover_subtitles_in_fs, subtitle_text,
    SubtitleTrackInfo, SubtitlesDiscoveryResponse, MAX_SUBTITLE_BYTES,
};
use subtitles::{subtitle, subtitles_discovery};
#[cfg(test)]
use thumbnails::{encode_jpeg_image, encode_png_image};
#[allow(unused_imports)]
pub use thumbnails::{
    extract_jpeg_exif_thumbnail, generate_bounded_thumbnail, inspect_image_dimensions,
    invalidate_thumbnail_cache, read_image_dimensions_from_file,
    validate_image_dimensions_for_thumbnail, ImageResolution, MediaQuery, PreviewSize,
    ThumbnailQuery, BIG_PREVIEW_DIMENSION, MAX_DECODED_IMAGE_ALLOC_BYTES, MAX_IMAGE_HEIGHT,
    MAX_IMAGE_WIDTH, MAX_THUMBNAIL_SOURCE_BYTES, THUMB_DIMENSION,
};
use thumbnails::{preview_big, preview_thumb, render_thumbnail_response, thumbnail};

use super::policy::{authorize_with_conn, Permission};
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaMetadataResponse {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub content_type: Option<String>,
    pub size: u64,
    pub modified: Option<String>,
    pub resolution: Option<ImageResolution>,
    pub subtitles: Vec<SubtitleTrackInfo>,
}

pub(super) fn router() -> Router {
    Router::new()
        .route("/mcbrowser/media", get(media))
        .route("/mcbrowser/media-info", get(media_info))
        .route("/mcbrowser/thumbnail", get(thumbnail))
        .route("/mcbrowser/preview/thumb", get(preview_thumb))
        .route("/mcbrowser/preview/big", get(preview_big))
        .route("/mcbrowser/subtitle", get(subtitle))
        .route("/mcbrowser/subtitles", get(subtitles_discovery))
        .route("/mcbrowser/csv", get(csv_preview))
        .route("/mcbrowser/epub", get(epub_preview))
}

pub fn media_type(path: &str, bytes: &[u8]) -> Option<&'static str> {
    let extension = path.rsplit('.').next()?.to_ascii_lowercase();
    let starts = |signature: &[u8]| bytes.starts_with(signature);
    let is_iso_media = bytes.len() >= 12 && &bytes[4..8] == b"ftyp";
    let is_quicktime_atom = bytes.len() >= 8
        && matches!(
            &bytes[4..8],
            b"ftyp" | b"moov" | b"mdat" | b"wide" | b"free" | b"skip" | b"pnot"
        );
    match extension.as_str() {
        "png" if starts(b"\x89PNG\r\n\x1a\n") => Some("image/png"),
        "jpg" | "jpeg" if starts(b"\xff\xd8\xff") => Some("image/jpeg"),
        "gif" if starts(b"GIF87a") || starts(b"GIF89a") => Some("image/gif"),
        "webp" if starts(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") => Some("image/webp"),
        "avif" if is_iso_media && matches!(&bytes[8..12], b"avif" | b"avis" | b"mif1") => {
            Some("image/avif")
        }
        "bmp" if starts(b"BM") && bytes.len() >= 26 => Some("image/bmp"),
        "tif" | "tiff" if starts(b"II*\x00") || starts(b"MM\x00*") => Some("image/tiff"),
        "pdf" if starts(b"%PDF-") => Some("application/pdf"),
        "epub" if starts(b"PK\x03\x04") => Some("application/epub+zip"),
        "mp4" | "m4v" if is_iso_media => Some("video/mp4"),
        "mov" if is_quicktime_atom => Some("video/quicktime"),
        "webm" if starts(b"\x1a\x45\xdf\xa3") => Some("video/webm"),
        "mkv" if starts(b"\x1a\x45\xdf\xa3") => Some("video/x-matroska"),
        "mp3"
            if starts(b"ID3")
                || (bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] & 0xe0 == 0xe0) =>
        {
            Some("audio/mpeg")
        }
        "ogg" | "oga" | "opus" if starts(b"OggS") => Some("audio/ogg"),
        "ogv" if starts(b"OggS") => Some("video/ogg"),
        "flac" if starts(b"fLaC") => Some("audio/flac"),
        "wav" if starts(b"RIFF") && bytes.get(8..12) == Some(b"WAVE") => Some("audio/wav"),
        "m4a" if is_iso_media => Some("audio/mp4"),
        "aac"
            if is_iso_media
                || (bytes.len() >= 2 && bytes[0] == 0xff && (bytes[1] & 0xf6) == 0xf0) =>
        {
            Some("audio/aac")
        }
        _ => None,
    }
}

pub fn is_image_content_type(content_type: &str) -> bool {
    content_type.starts_with("image/")
}

pub fn is_video_extension(path: &str) -> bool {
    let Some((_, ext)) = path.rsplit_once('.') else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "mp4" | "m4v" | "mov" | "webm" | "mkv" | "ogv"
    )
}

pub fn is_supported_subtitle_extension(path: &str) -> bool {
    let Some((_, ext)) = path.rsplit_once('.') else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "vtt" | "srt" | "ass" | "ssa"
    )
}

pub fn is_subtitle_directory_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "sub" | "subs" | "subtitles"
    )
}

pub(super) fn media_headers(response: &mut Response, content_type: &'static str) {
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'self'; sandbox"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
}

async fn media(
    Extension(user): Extension<AuthUser>,
    Query(query): Query<MediaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(raw_size) = query
        .size
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !raw_size.eq_ignore_ascii_case("raw")
            && !raw_size.eq_ignore_ascii_case("full")
            && !raw_size.eq_ignore_ascii_case("original")
        {
            return match PreviewSize::parse(raw_size) {
                Ok(size) => render_thumbnail_response(user, query.path, size).await,
                Err(err) => err.into_response(),
            };
        }
    }

    let path = match normalize_relative_path(&query.path, false) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let task = tokio::task::spawn_blocking(move || {
        let user_id = validate_mcbrowser_user(&user)?;
        let connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for media check".to_owned())
        })?;
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let mut file = open_authorized_file_with_conn(
            &connection,
            &user,
            &filesystem,
            &path,
            Permission::Read,
        )?;
        let mut signature = [0u8; 64];
        let signature_length = file
            .read(&mut signature)
            .map_err(|_| McBrowserError::Internal("Failed to inspect media".to_owned()))?;
        let content_type = media_type(&path, &signature[..signature_length]).ok_or_else(|| {
            McBrowserError::BadRequest(
                "Unsupported media format or mismatched file signature".to_owned(),
            )
        })?;
        let length = file
            .metadata()
            .map_err(|_| McBrowserError::Internal("Failed to inspect media metadata".to_owned()))?
            .len();
        let parsed = parse_single_byte_range(range.as_deref(), length)?;
        let start = match parsed {
            ParsedByteRange::Full => 0,
            ParsedByteRange::Partial { start, .. } => start,
        };
        file.seek(SeekFrom::Start(start))
            .map_err(|_| McBrowserError::Internal("Failed to seek media".to_owned()))?;
        Ok::<_, McBrowserError>((file, length, parsed, content_type, path))
    })
    .await;
    let (file, length, parsed, content_type, path) = match task {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return error.into_response(),
        Err(_) => return McBrowserError::Internal("Media task failed".to_owned()).into_response(),
    };
    let (status, content_length, range_header) = match parsed {
        ParsedByteRange::Full => (StatusCode::OK, length, None),
        ParsedByteRange::Partial { start, end } => (
            StatusCode::PARTIAL_CONTENT,
            end - start + 1,
            Some(format!("bytes {start}-{end}/{length}")),
        ),
    };
    let mut response = Response::new(Body::from_stream(FileRangeStream::new(
        tokio::fs::File::from_std(file),
        content_length,
    )));
    *response.status_mut() = status;
    media_headers(&mut response, content_type);
    let headers = response.headers_mut();
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(value) = HeaderValue::from_str(&content_length.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    if let Some(value) = range_header.and_then(|value| HeaderValue::from_str(&value).ok()) {
        headers.insert(header::CONTENT_RANGE, value);
    }
    let disposition = build_attachment_content_disposition(&path);
    if let Ok(value) = disposition.to_str() {
        if let Ok(value) = HeaderValue::from_str(&value.replacen("attachment;", "inline;", 1)) {
            headers.insert(header::CONTENT_DISPOSITION, value);
        }
    }
    response
}

async fn media_info(
    Extension(user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    let path = match normalize_relative_path(&query.path, false) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    let task = tokio::task::spawn_blocking(move || {
        let user_id = validate_mcbrowser_user(&user)?;
        let connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for media metadata".to_owned())
        })?;
        authorize_with_conn(&connection, &user, Permission::Read, &path)?;
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let resolved = filesystem
            .metadata_resolving_internal_links(&path)
            .map_err(|error| map_fs_io_error(error, "Failed to inspect media metadata"))?;
        for resolution_path in &resolved.resolution_paths {
            authorize_with_conn(&connection, &user, Permission::Read, resolution_path)?;
        }
        authorize_with_conn(
            &connection,
            &user,
            Permission::Read,
            &resolved.resolved_path,
        )?;
        let mut entry = resolved.entry;
        entry.name = path.rsplit('/').next().unwrap_or(&path).to_owned();
        entry.path = path.clone();

        let mut content_type = None;
        let mut resolution = None;
        let mut subtitles = Vec::new();

        if entry.kind == "file" {
            match open_authorized_file_with_conn(
                &connection,
                &user,
                &filesystem,
                &path,
                Permission::Read,
            ) {
                Ok(mut file) => {
                    if let Ok(meta) = file.metadata() {
                        entry.size = meta.len();
                        entry.modified = meta.modified().ok().map(|modified| {
                            chrono::DateTime::<chrono::Utc>::from(modified).to_rfc3339()
                        });
                    }
                    let mut sig = [0u8; 64];
                    if let Ok(n) = file.read(&mut sig) {
                        content_type = media_type(&path, &sig[..n]).map(str::to_owned);
                    }
                    if content_type.as_deref().is_some_and(is_image_content_type) {
                        resolution = read_image_dimensions_from_file(&path, &mut file).ok();
                    }
                    if is_video_extension(&path) {
                        subtitles = discover_subtitles_for_user_with_conn(
                            &connection,
                            &filesystem,
                            &user,
                            &path,
                        )
                        .unwrap_or_default();
                    }
                }
                Err(error) => return Err(error),
            }
        }

        Ok::<_, McBrowserError>(MediaMetadataResponse {
            path: entry.path,
            name: entry.name,
            kind: entry.kind,
            content_type,
            size: entry.size,
            modified: entry.modified,
            resolution,
            subtitles,
        })
    })
    .await;

    match task {
        Ok(Ok(info)) => {
            let mut resp = Json(info).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => McBrowserError::Internal("Media metadata task failed".to_owned()).into_response(),
    }
}

#[cfg(test)]
#[path = "media_tests.rs"]
mod tests;
