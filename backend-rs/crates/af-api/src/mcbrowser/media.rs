use super::policy::{authorize, authorize_with_conn, Permission};
use super::*;
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::imageops::FilterType;
use image::{
    ColorType, DynamicImage, GenericImageView, ImageEncoder, ImageFormat, ImageReader, Limits,
};
use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex as StdMutex;
use zip::ZipArchive;

pub const MAX_SUBTITLE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_CSV_PREVIEW_BYTES: u64 = 5 * 1024 * 1024;
pub const MAX_EPUB_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_THUMBNAIL_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_IMAGE_WIDTH: u32 = 10_000;
pub const MAX_IMAGE_HEIGHT: u32 = 10_000;
pub const MAX_DECODED_IMAGE_ALLOC_BYTES: u64 = 400 * 1024 * 1024; // 10000x10000x4 RGBA ceiling
pub const THUMB_DIMENSION: u32 = 256;
pub const BIG_PREVIEW_DIMENSION: u32 = 1080;

const MAX_EPUB_ARCHIVE_ENTRIES: usize = 2_048;
const MAX_EPUB_CHAPTERS: usize = 256;
const MAX_EPUB_ENTRY_UNCOMPRESSED_BYTES: usize = 2 * 1024 * 1024;
const MAX_EPUB_TOTAL_UNCOMPRESSED_BYTES: usize = 8 * 1024 * 1024;
const THUMBNAIL_CACHE_MAX_ENTRIES: usize = 256;
const THUMBNAIL_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;

static THUMBNAIL_CACHE: Lazy<StdMutex<ThumbnailCache>> =
    Lazy::new(|| StdMutex::new(ThumbnailCache::default()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageResolution {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PreviewSize {
    Thumb,
    Big,
}

impl PreviewSize {
    pub fn parse(raw: &str) -> Result<Self, McBrowserError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "thumb" | "256" | "small" => Ok(Self::Thumb),
            "big" | "1080" | "large" => Ok(Self::Big),
            _ => Err(McBrowserError::BadRequest(
                "Invalid thumbnail size: expected 'thumb' (256) or 'big' (1080)".to_owned(),
            )),
        }
    }

    pub const fn target_dimensions(self) -> (u32, u32) {
        match self {
            Self::Thumb => (THUMB_DIMENSION, THUMB_DIMENSION),
            Self::Big => (BIG_PREVIEW_DIMENSION, BIG_PREVIEW_DIMENSION),
        }
    }

    #[allow(dead_code)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Thumb => "thumb",
            Self::Big => "big",
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct MediaQuery {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub size: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ThumbnailQuery {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub size: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtitleTrackInfo {
    pub path: String,
    pub name: String,
    pub label: String,
    pub language: Option<String>,
    pub format: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtitlesDiscoveryResponse {
    pub path: String,
    pub subtitles: Vec<SubtitleTrackInfo>,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpubChapter {
    pub id: String,
    pub title: String,
    pub href: String,
    pub paragraphs: Vec<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpubBookPreview {
    pub path: String,
    pub title: String,
    pub author: Option<String>,
    pub language: Option<String>,
    pub description: Option<String>,
    pub chapters: Vec<EpubChapter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ThumbnailCacheKey {
    user_id: i64,
    path: String,
    size: PreviewSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileVersionStamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

#[derive(Debug, Clone)]
struct ThumbnailCacheEntry {
    stamp: FileVersionStamp,
    bytes: Vec<u8>,
    content_type: &'static str,
    resolution: ImageResolution,
}

#[derive(Default)]
struct ThumbnailCache {
    entries: HashMap<ThumbnailCacheKey, ThumbnailCacheEntry>,
    order: VecDeque<ThumbnailCacheKey>,
    total_bytes: usize,
}

impl ThumbnailCache {
    fn get(
        &self,
        key: &ThumbnailCacheKey,
        expected_stamp: FileVersionStamp,
    ) -> Option<ThumbnailCacheEntry> {
        let entry = self.entries.get(key)?;
        if entry.stamp == expected_stamp {
            Some(entry.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, key: ThumbnailCacheKey, entry: ThumbnailCacheEntry) {
        let entry_bytes = entry.bytes.len();
        if entry_bytes > THUMBNAIL_CACHE_MAX_BYTES / 4 {
            return;
        }
        if let Some(prev) = self.entries.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(prev.bytes.len());
            self.order.retain(|k| k != &key);
        }
        while (self.entries.len() >= THUMBNAIL_CACHE_MAX_ENTRIES
            || self.total_bytes.saturating_add(entry_bytes) > THUMBNAIL_CACHE_MAX_BYTES)
            && !self.order.is_empty()
        {
            if let Some(oldest_key) = self.order.pop_front() {
                if let Some(removed) = self.entries.remove(&oldest_key) {
                    self.total_bytes = self.total_bytes.saturating_sub(removed.bytes.len());
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_add(entry_bytes);
        self.order.push_back(key.clone());
        self.entries.insert(key, entry);
    }

    #[allow(dead_code)]
    fn invalidate_user_path(&mut self, user_id: i64, path_prefix: &str) {
        let clean = path_prefix.trim_matches('/');
        let keys_to_remove: Vec<ThumbnailCacheKey> = self
            .entries
            .keys()
            .filter(|k| {
                k.user_id == user_id
                    && (clean.is_empty()
                        || k.path == clean
                        || k.path.starts_with(&format!("{clean}/")))
            })
            .cloned()
            .collect();
        for key in keys_to_remove {
            if let Some(removed) = self.entries.remove(&key) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.bytes.len());
            }
            self.order.retain(|k| k != &key);
        }
    }
}

#[allow(dead_code)]
pub fn invalidate_thumbnail_cache(user_id: i64, path_prefix: &str) {
    if let Ok(mut guard) = THUMBNAIL_CACHE.lock() {
        guard.invalidate_user_path(user_id, path_prefix);
    }
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

fn media_headers(response: &mut Response, content_type: &'static str) {
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

fn image_format_for_content_type(content_type: &str) -> Option<ImageFormat> {
    match content_type {
        "image/png" => Some(ImageFormat::Png),
        "image/jpeg" => Some(ImageFormat::Jpeg),
        "image/gif" => Some(ImageFormat::Gif),
        "image/webp" => Some(ImageFormat::WebP),
        "image/bmp" => Some(ImageFormat::Bmp),
        "image/tiff" => Some(ImageFormat::Tiff),
        _ => None,
    }
}

fn bounded_image_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_WIDTH);
    limits.max_image_height = Some(MAX_IMAGE_HEIGHT);
    limits.max_alloc = Some(MAX_DECODED_IMAGE_ALLOC_BYTES);
    limits
}

pub fn inspect_image_dimensions(
    path: &str,
    bytes: &[u8],
) -> Result<ImageResolution, McBrowserError> {
    let content_type = media_type(path, bytes).ok_or_else(|| {
        McBrowserError::BadRequest(
            "Unsupported image format or mismatched file signature".to_owned(),
        )
    })?;
    if !is_image_content_type(content_type) {
        return Err(McBrowserError::BadRequest(
            "Path is not a supported raster image".to_owned(),
        ));
    }

    let dims = if let Some(format) = image_format_for_content_type(content_type) {
        let reader = ImageReader::with_format(Cursor::new(bytes), format);
        reader
            .into_dimensions()
            .ok()
            .map(|(width, height)| ImageResolution { width, height })
            .or_else(|| parse_header_dimensions_fallback(content_type, bytes))
    } else if content_type == "image/avif" {
        parse_avif_dimensions(bytes)
    } else {
        None
    }
    .ok_or_else(|| McBrowserError::BadRequest("Corrupt or truncated image header".to_owned()))?;

    if dims.width == 0 || dims.height == 0 {
        return Err(McBrowserError::BadRequest(
            "Image header reports zero width or height".to_owned(),
        ));
    }
    Ok(dims)
}

pub fn validate_image_dimensions_for_thumbnail(
    dims: ImageResolution,
) -> Result<ImageResolution, McBrowserError> {
    if dims.width == 0 || dims.height == 0 {
        return Err(McBrowserError::BadRequest(
            "Image dimensions must be non-zero".to_owned(),
        ));
    }
    if dims.width > MAX_IMAGE_WIDTH || dims.height > MAX_IMAGE_HEIGHT {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Image dimensions {}x{} exceed maximum {}x{}: image too large for thumbnail generation",
            dims.width, dims.height, MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT
        )));
    }
    let decoded_rgba_bytes = (dims.width as u64)
        .saturating_mul(dims.height as u64)
        .saturating_mul(4);
    if decoded_rgba_bytes > MAX_DECODED_IMAGE_ALLOC_BYTES {
        return Err(McBrowserError::PayloadTooLarge(
            "Image decoded pixel buffer exceeds allocation limit".to_owned(),
        ));
    }
    Ok(dims)
}

pub fn read_image_dimensions_from_file(
    path: &str,
    file: &mut File,
) -> Result<ImageResolution, McBrowserError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| McBrowserError::Internal("Failed to seek image file".to_owned()))?;
    let mut header_buf = vec![0u8; 65_536];
    let mut read_total = 0usize;
    while read_total < header_buf.len() {
        match file.read(&mut header_buf[read_total..]) {
            Ok(0) => break,
            Ok(n) => read_total += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(McBrowserError::Internal(
                    "Failed to read image header".to_owned(),
                ))
            }
        }
    }
    let _ = file.seek(SeekFrom::Start(0));
    inspect_image_dimensions(path, &header_buf[..read_total])
}

fn parse_header_dimensions_fallback(content_type: &str, bytes: &[u8]) -> Option<ImageResolution> {
    match content_type {
        "image/png" if bytes.len() >= 24 && &bytes[12..16] == b"IHDR" => {
            let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
            let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
            Some(ImageResolution { width, height })
        }
        "image/gif" if bytes.len() >= 10 => {
            let width = u16::from_le_bytes([bytes[6], bytes[7]]) as u32;
            let height = u16::from_le_bytes([bytes[8], bytes[9]]) as u32;
            Some(ImageResolution { width, height })
        }
        "image/bmp" if bytes.len() >= 26 => {
            let w_raw = i32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
            let h_raw = i32::from_le_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]);
            Some(ImageResolution {
                width: w_raw.unsigned_abs(),
                height: h_raw.unsigned_abs(),
            })
        }
        _ => None,
    }
}

fn parse_avif_dimensions(bytes: &[u8]) -> Option<ImageResolution> {
    if bytes.len() < 24 || &bytes[4..8] != b"ftyp" {
        return None;
    }
    for idx in 0..bytes.len().saturating_sub(16) {
        if &bytes[idx..idx + 4] == b"ispe" && idx >= 4 {
            let box_size = u32::from_be_bytes([
                bytes[idx - 4],
                bytes[idx - 3],
                bytes[idx - 2],
                bytes[idx - 1],
            ]) as usize;
            if box_size >= 20 && idx + 16 <= bytes.len() {
                let width = u32::from_be_bytes([
                    bytes[idx + 8],
                    bytes[idx + 9],
                    bytes[idx + 10],
                    bytes[idx + 11],
                ]);
                let height = u32::from_be_bytes([
                    bytes[idx + 12],
                    bytes[idx + 13],
                    bytes[idx + 14],
                    bytes[idx + 15],
                ]);
                if width > 0 && height > 0 {
                    return Some(ImageResolution { width, height });
                }
            }
        }
    }
    None
}

pub fn extract_jpeg_exif_thumbnail(bytes: &[u8]) -> Option<(Vec<u8>, ImageResolution)> {
    if bytes.len() < 12 || !bytes.starts_with(b"\xff\xd8") {
        return None;
    }
    let mut idx = 2usize;
    while idx + 4 <= bytes.len() {
        if bytes[idx] != 0xff {
            idx += 1;
            continue;
        }
        while idx < bytes.len() && bytes[idx] == 0xff {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }
        let marker = bytes[idx];
        idx += 1;
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        if marker == 0xd8 || marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if idx + 2 > bytes.len() {
            break;
        }
        let seg_len = u16::from_be_bytes([bytes[idx], bytes[idx + 1]]) as usize;
        if seg_len < 2 || idx + seg_len > bytes.len() {
            break;
        }
        if marker == 0xe1 && seg_len >= 14 {
            let payload = &bytes[idx + 2..idx + seg_len];
            if payload.starts_with(b"Exif\x00\x00") {
                let tiff = &payload[6..];
                if let Some(thumb) = parse_tiff_ifd1_jpeg_thumbnail(tiff) {
                    // Validate embedded EXIF thumbnail by decoding it with the image crate
                    let mut reader =
                        ImageReader::with_format(Cursor::new(&thumb), ImageFormat::Jpeg);
                    reader.limits(bounded_image_limits());
                    if let Ok(decoded_thumb) = reader.decode() {
                        let (w, h) = decoded_thumb.dimensions();
                        if w > 0 && h > 0 && w <= MAX_IMAGE_WIDTH && h <= MAX_IMAGE_HEIGHT {
                            return Some((
                                thumb,
                                ImageResolution {
                                    width: w,
                                    height: h,
                                },
                            ));
                        }
                    }
                }
            }
        }
        idx += seg_len;
    }
    None
}

fn parse_tiff_ifd1_jpeg_thumbnail(tiff: &[u8]) -> Option<Vec<u8>> {
    if tiff.len() < 8 {
        return None;
    }
    let le = match &tiff[0..4] {
        b"II*\x00" => true,
        b"MM\x00*" => false,
        _ => return None,
    };
    let read_u16 = |offset: usize| -> Option<u16> {
        let b = tiff.get(offset..offset + 2)?;
        Some(if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let b = tiff.get(offset..offset + 4)?;
        Some(if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };

    let ifd0_offset = read_u32(4)? as usize;
    let ifd0_count = read_u16(ifd0_offset)? as usize;
    let ifd1_ptr_offset = ifd0_offset
        .checked_add(2)?
        .checked_add(ifd0_count.checked_mul(12)?)?;
    let ifd1_offset = read_u32(ifd1_ptr_offset)? as usize;
    if ifd1_offset == 0 || ifd1_offset >= tiff.len() {
        return None;
    }

    let ifd1_count = read_u16(ifd1_offset)? as usize;
    if ifd1_count > 512 {
        return None;
    }
    let mut thumb_offset: Option<usize> = None;
    let mut thumb_len: Option<usize> = None;
    let mut entry_pos = ifd1_offset.checked_add(2)?;

    for _ in 0..ifd1_count {
        if entry_pos + 12 > tiff.len() {
            break;
        }
        let tag = read_u16(entry_pos)?;
        let val = read_u32(entry_pos + 8)? as usize;
        match tag {
            0x0201 => thumb_offset = Some(val),
            0x0202 => thumb_len = Some(val),
            _ => {}
        }
        entry_pos += 12;
    }

    let offset = thumb_offset?;
    let length = thumb_len?;
    if length < 4 || length > 4 * 1024 * 1024 {
        return None;
    }
    let slice = tiff.get(offset..offset.checked_add(length)?)?;
    if !slice.starts_with(b"\xff\xd8\xff") {
        return None;
    }
    Some(slice.to_vec())
}

fn decode_image_bounded(
    bytes: &[u8],
    format: ImageFormat,
) -> Result<(DynamicImage, ImageResolution), McBrowserError> {
    let dims_reader = ImageReader::with_format(Cursor::new(bytes), format);
    let (width, height) = dims_reader
        .into_dimensions()
        .map_err(|_| McBrowserError::BadRequest("Corrupt or unreadable image header".to_owned()))?;
    let orig_dims = validate_image_dimensions_for_thumbnail(ImageResolution { width, height })?;

    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(bounded_image_limits());
    let decoded = reader.decode().map_err(|err| {
        let msg = err.to_string();
        if msg.to_ascii_lowercase().contains("limit") {
            McBrowserError::PayloadTooLarge(
                "Image exceeds dimension or memory allocation limits".to_owned(),
            )
        } else {
            McBrowserError::BadRequest("Failed to decode image pixel data".to_owned())
        }
    })?;
    Ok((decoded, orig_dims))
}

fn encode_jpeg_image(img: &DynamicImage, quality: u8) -> Result<Vec<u8>, McBrowserError> {
    let rgb = img.to_rgb8();
    let (w, h) = rgb.dimensions();
    let mut out = Vec::with_capacity((w as usize).saturating_mul(h as usize) / 2 + 1024);
    let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
    encoder
        .encode(rgb.as_raw(), w, h, ColorType::Rgb8.into())
        .map_err(|_| McBrowserError::Internal("Failed to encode JPEG image".to_owned()))?;
    Ok(out)
}

fn encode_png_image(img: &DynamicImage) -> Result<Vec<u8>, McBrowserError> {
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let mut out = Vec::with_capacity((w as usize).saturating_mul(h as usize) + 1024);
    let encoder = PngEncoder::new(&mut out);
    encoder
        .write_image(rgba.as_raw(), w, h, ColorType::Rgba8.into())
        .map_err(|_| McBrowserError::Internal("Failed to encode PNG image".to_owned()))?;
    Ok(out)
}

pub fn generate_bounded_thumbnail(
    path: &str,
    bytes: &[u8],
    size: PreviewSize,
) -> Result<(Vec<u8>, &'static str, ImageResolution), McBrowserError> {
    let content_type = media_type(path, bytes).ok_or_else(|| {
        McBrowserError::BadRequest(
            "Unsupported image format or mismatched file signature".to_owned(),
        )
    })?;
    if !is_image_content_type(content_type) {
        return Err(McBrowserError::BadRequest(
            "Thumbnails can only be generated for allowlisted image files".to_owned(),
        ));
    }

    let orig_dims = inspect_image_dimensions(path, bytes)?;
    validate_image_dimensions_for_thumbnail(orig_dims)?;

    // Upstream parity (`http/preview.go:88-90`): GIF files pass through directly after signature + 10000x10000 check
    if content_type == "image/gif" {
        return Ok((bytes.to_vec(), "image/gif", orig_dims));
    }

    let format = image_format_for_content_type(content_type).ok_or_else(|| {
        McBrowserError::BadRequest(format!(
            "Unsupported image format '{content_type}' for server-side resize"
        ))
    })?;

    // Upstream parity (`img/service.go:167-177`): EXIF embedded thumbnail fast-path for JPEG thumb (256)
    if size == PreviewSize::Thumb && format == ImageFormat::Jpeg {
        if let Some((exif_thumb, thumb_dims)) = extract_jpeg_exif_thumbnail(bytes) {
            return Ok((exif_thumb, "image/jpeg", thumb_dims));
        }
    }

    let (decoded, _) = decode_image_bounded(bytes, format)?;
    let (target_w, target_h) = size.target_dimensions();

    let resized = match size {
        // Upstream parity (`img/service.go:184-186`): ResizeModeFill with QualityLow (Nearest) -> 256x256
        PreviewSize::Thumb => decoded.resize_to_fill(target_w, target_h, FilterType::Nearest),
        // Upstream parity (`img/service.go:187-190`): ResizeModeFit with QualityMedium (Triangle) -> <= 1080x1080 (no upscale)
        PreviewSize::Big => {
            let (cur_w, cur_h) = decoded.dimensions();
            if cur_w <= target_w && cur_h <= target_h {
                decoded
            } else {
                decoded.resize(target_w, target_h, FilterType::Triangle)
            }
        }
    };

    let (out_w, out_h) = resized.dimensions();
    let out_dims = ImageResolution {
        width: out_w,
        height: out_h,
    };

    // Upstream parity (`http/preview.go:130-137`):
    // - PreviewSize::Thumb always encodes to JPEG (quality ~75)
    // - PreviewSize::Big preserves PNG for PNG sources and uses JPEG (quality ~85) otherwise
    match (size, format) {
        (PreviewSize::Big, ImageFormat::Png) => {
            let encoded = encode_png_image(&resized)?;
            Ok((encoded, "image/png", out_dims))
        }
        (PreviewSize::Thumb, _) => {
            let encoded = encode_jpeg_image(&resized, 75)?;
            Ok((encoded, "image/jpeg", out_dims))
        }
        (PreviewSize::Big, _) => {
            let encoded = encode_jpeg_image(&resized, 85)?;
            Ok((encoded, "image/jpeg", out_dims))
        }
    }
}

async fn render_thumbnail_response(
    user: AuthUser,
    raw_path: String,
    size: PreviewSize,
) -> Response {
    let path = match normalize_relative_path(&raw_path, false) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    let Ok(permit) = Arc::clone(&PREVIEW_SEMAPHORE).acquire_owned().await else {
        return McBrowserError::Internal("Thumbnail limiter closed".to_owned()).into_response();
    };
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let user_id = validate_mcbrowser_user(&user)?;
        let connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for thumbnail check".to_owned())
        })?;
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let mut file = open_authorized_file_with_conn(
            &connection,
            &user,
            &filesystem,
            &path,
            Permission::Read,
        )?;
        let meta = file
            .metadata()
            .map_err(|_| McBrowserError::Internal("Failed to read image metadata".to_owned()))?;
        if meta.len() > MAX_THUMBNAIL_SOURCE_BYTES {
            return Err(McBrowserError::PayloadTooLarge(
                "Image file exceeds 32 MiB source limit for thumbnail generation".to_owned(),
            ));
        }

        let stamp = FileVersionStamp {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        };
        let cache_key = ThumbnailCacheKey {
            user_id,
            path: path.clone(),
            size,
        };
        if let Ok(cache) = THUMBNAIL_CACHE.lock() {
            if let Some(hit) = cache.get(&cache_key, stamp) {
                return Ok::<_, McBrowserError>((
                    hit.bytes,
                    hit.content_type,
                    hit.resolution,
                    path,
                ));
            }
        }

        // Inspect header dimensions first BEFORE reading entire file buffer to reject >10000x10000 bombs early
        let dims = read_image_dimensions_from_file(&path, &mut file)?;
        validate_image_dimensions_for_thumbnail(dims)?;

        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.take(MAX_THUMBNAIL_SOURCE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| McBrowserError::Internal("Failed to read image file".to_owned()))?;

        let (encoded, content_type, out_dims) = generate_bounded_thumbnail(&path, &bytes, size)?;
        if let Ok(mut cache) = THUMBNAIL_CACHE.lock() {
            cache.insert(
                cache_key,
                ThumbnailCacheEntry {
                    stamp,
                    bytes: encoded.clone(),
                    content_type,
                    resolution: out_dims,
                },
            );
        }
        Ok((encoded, content_type, out_dims, path))
    })
    .await;

    match task {
        Ok(Ok((bytes, content_type, dims, path))) => {
            let len = bytes.len();
            let mut response = Response::new(Body::from(bytes));
            media_headers(&mut response, content_type);
            let headers = response.headers_mut();
            if let Ok(val) = HeaderValue::from_str(&len.to_string()) {
                headers.insert(header::CONTENT_LENGTH, val);
            }
            if let Ok(val) = HeaderValue::from_str(&dims.width.to_string()) {
                headers.insert("x-image-width", val);
            }
            if let Ok(val) = HeaderValue::from_str(&dims.height.to_string()) {
                headers.insert("x-image-height", val);
            }
            let disposition = build_attachment_content_disposition(&path);
            if let Ok(value) = disposition.to_str() {
                if let Ok(value) =
                    HeaderValue::from_str(&value.replacen("attachment;", "inline;", 1))
                {
                    headers.insert(header::CONTENT_DISPOSITION, value);
                }
            }
            response
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => McBrowserError::Internal("Thumbnail task failed".to_owned()).into_response(),
    }
}

async fn thumbnail(
    Extension(user): Extension<AuthUser>,
    Query(query): Query<ThumbnailQuery>,
) -> Response {
    let size = match query.size.as_deref() {
        Some(raw) if !raw.trim().is_empty() => match PreviewSize::parse(raw) {
            Ok(s) => s,
            Err(e) => return e.into_response(),
        },
        _ => PreviewSize::Thumb,
    };
    render_thumbnail_response(user, query.path, size).await
}

async fn preview_thumb(
    Extension(user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    render_thumbnail_response(user, query.path, PreviewSize::Thumb).await
}

async fn preview_big(
    Extension(user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    render_thumbnail_response(user, query.path, PreviewSize::Big).await
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

fn convert_ass_timestamp_to_vtt(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let mut parts = trimmed.split(':');
    let hours: u32 = parts.next()?.trim().parse().ok()?;
    let minutes: u32 = parts.next()?.trim().parse().ok()?;
    let sec_part = parts.next()?;
    if parts.next().is_some() || minutes >= 60 {
        return None;
    }
    let (secs_str, frac_str) = sec_part.split_once('.').unwrap_or((sec_part, "0"));
    let seconds: u32 = secs_str.trim().parse().ok()?;
    if seconds >= 60 {
        return None;
    }
    let frac_digits: String = frac_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let millis: u32 = match frac_digits.len() {
        0 => 0,
        1 => frac_digits.parse::<u32>().ok()? * 100,
        2 => frac_digits.parse::<u32>().ok()? * 10,
        _ => frac_digits[..3].parse::<u32>().ok()?,
    };
    Some(format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}"))
}

fn strip_ass_override_tags(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len());
    let mut in_brace = false;
    for ch in raw.chars() {
        match ch {
            '{' => in_brace = true,
            '}' if in_brace => in_brace = false,
            _ if !in_brace => cleaned.push(ch),
            _ => {}
        }
    }
    cleaned
        .replace("\\N", "\n")
        .replace("\\n", "\n")
        .replace("\\h", " ")
        .trim()
        .to_owned()
}

fn convert_ass_or_ssa_to_vtt(text: &str) -> Result<String, McBrowserError> {
    let mut in_events = false;
    let mut start_idx = 1usize;
    let mut end_idx = 2usize;
    let mut text_idx = 9usize;
    let mut total_fields = 10usize;
    let mut cues: Vec<(String, String, String)> = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("!:") {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_events = line.eq_ignore_ascii_case("[events]");
            continue;
        }
        if !in_events {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("Format:")
            .or_else(|| line.strip_prefix("format:"))
        {
            let cols: Vec<String> = rest
                .split(',')
                .map(|c| c.trim().to_ascii_lowercase())
                .collect();
            if cols.len() >= 3 {
                total_fields = cols.len();
                if let Some(pos) = cols.iter().position(|c| c == "start") {
                    start_idx = pos;
                }
                if let Some(pos) = cols.iter().position(|c| c == "end") {
                    end_idx = pos;
                }
                if let Some(pos) = cols.iter().position(|c| c == "text") {
                    text_idx = pos;
                } else {
                    text_idx = cols.len() - 1;
                }
            }
            continue;
        }

        if let Some(rest) = line
            .strip_prefix("Dialogue:")
            .or_else(|| line.strip_prefix("dialogue:"))
        {
            let fields: Vec<&str> = rest.splitn(total_fields, ',').collect();
            if fields.len() <= start_idx.max(end_idx).max(text_idx) {
                continue;
            }
            let Some(start_vtt) = convert_ass_timestamp_to_vtt(fields[start_idx]) else {
                continue;
            };
            let Some(end_vtt) = convert_ass_timestamp_to_vtt(fields[end_idx]) else {
                continue;
            };
            let cue_text = strip_ass_override_tags(fields[text_idx]);
            if !cue_text.is_empty() {
                cues.push((start_vtt, end_vtt, cue_text));
            }
        }
    }

    if cues.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Invalid ASS/SSA subtitle format: no valid Dialogue events found".to_owned(),
        ));
    }

    let mut out = String::from("WEBVTT\n\n");
    for (idx, (start, end, body)) in cues.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&format!("{}\n{start} --> {end}\n{body}\n", idx + 1));
    }
    Ok(out)
}

pub fn subtitle_text(path: &str, bytes: Vec<u8>) -> Result<String, McBrowserError> {
    if bytes.len() as u64 > MAX_SUBTITLE_BYTES || bytes.contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Subtitles must be UTF-8 text under 2 MiB".to_owned(),
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| McBrowserError::BadRequest("Subtitles must be UTF-8 text".to_owned()))?;
    let text = text.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let extension = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if extension == "vtt"
        && (text.starts_with("WEBVTT\n") || text.starts_with("WEBVTT ") || text == "WEBVTT")
    {
        return Ok(text);
    }
    if extension == "ass" || extension == "ssa" {
        return convert_ass_or_ssa_to_vtt(&text);
    }
    if extension != "srt" {
        return Err(McBrowserError::BadRequest(
            "Expected WebVTT, SubRip (.srt), or SubStation Alpha (.ass/.ssa) subtitles".to_owned(),
        ));
    }
    let br_tag = regex::Regex::new(r"(?i)<br(?:\s+[^>]*)?\s*/?>")
        .map_err(|_| McBrowserError::Internal("Subtitle parser unavailable".to_owned()))?;
    let normalized_text = br_tag.replace_all(&text, "\n");
    let timestamp = regex::Regex::new(
        r"(?m)^(\d{2,}:\d{2}:\d{2}),(\d{3}) --> (\d{2,}:\d{2}:\d{2}),(\d{3})([ \t]*.*)$",
    )
    .map_err(|_| McBrowserError::Internal("Subtitle parser unavailable".to_owned()))?;
    if !timestamp.is_match(&normalized_text) {
        return Err(McBrowserError::BadRequest(
            "Invalid SubRip timestamp format".to_owned(),
        ));
    }
    Ok(format!(
        "WEBVTT\n\n{}",
        timestamp.replace_all(&normalized_text, "$1.$2 --> $3.$4$5")
    ))
}

fn split_parent_and_leaf(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((parent, leaf)) => (parent, leaf),
        None => ("", path),
    }
}

fn file_stem_and_ext(name: &str) -> (&str, &str) {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, ext),
        _ => (name, ""),
    }
}

fn build_subtitle_track_info(sub_path: &str, video_stem: &str) -> SubtitleTrackInfo {
    let (_, name) = split_parent_and_leaf(sub_path);
    let (sub_stem, ext) = file_stem_and_ext(name);
    let format = ext.to_ascii_lowercase();
    let label = sub_stem.to_owned();

    let language = if sub_stem.len() > video_stem.len()
        && sub_stem[..video_stem.len()].eq_ignore_ascii_case(video_stem)
    {
        let suffix = sub_stem[video_stem.len()..].trim_start_matches(['.', '_', '-', ' ']);
        if !suffix.is_empty() && suffix.len() <= 16 {
            Some(suffix.to_owned())
        } else {
            None
        }
    } else {
        None
    };

    let encoded = urlencoding::encode(sub_path);
    SubtitleTrackInfo {
        path: sub_path.to_owned(),
        name: name.to_owned(),
        label,
        language,
        format,
        url: format!("/api/v1/auth/mcbrowser/subtitle?path={encoded}"),
    }
}

fn starts_with_case_insensitive(haystack: &str, prefix: &str) -> bool {
    haystack
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn is_entry_authorized_file<F>(bfs: &BrowserFs, entry: &Entry, authorize_read: &mut F) -> bool
where
    F: FnMut(&str) -> bool,
{
    if (entry.kind == "file" || entry.kind == "symlink") && authorize_read(&entry.path) {
        if let Ok(resolved) = bfs.metadata_resolving_internal_links(&entry.path) {
            return resolved.entry.kind == "file"
                && resolved
                    .resolution_paths
                    .iter()
                    .all(|hop| authorize_read(hop))
                && authorize_read(&resolved.resolved_path);
        }
    }
    false
}

fn list_authorized_dir_entries<F>(
    bfs: &BrowserFs,
    entry: &Entry,
    authorize_read: &mut F,
) -> Option<Vec<Entry>>
where
    F: FnMut(&str) -> bool,
{
    if entry.kind != "directory" && entry.kind != "symlink" {
        return None;
    }
    list_authorized_alias_directory(bfs, &entry.path, authorize_read)
}

fn list_authorized_alias_directory<F>(
    bfs: &BrowserFs,
    path: &str,
    authorize_read: &mut F,
) -> Option<Vec<Entry>>
where
    F: FnMut(&str) -> bool,
{
    if !authorize_read(path) {
        return None;
    }
    let mut traced = bfs.list_with_trace_resolving_internal_links(path).ok()?;
    if !traced
        .resolution_paths
        .iter()
        .all(|hop| authorize_read(hop))
        || !authorize_read(&traced.resolved_path)
    {
        return None;
    }
    for entry in &mut traced.entries {
        entry.path = if path.is_empty() {
            entry.name.clone()
        } else {
            format!("{path}/{}", entry.name)
        };
    }
    Some(traced.entries)
}

pub fn discover_subtitles_in_fs<F>(
    bfs: &BrowserFs,
    video_path: &str,
    mut authorize_read: F,
) -> Result<Vec<SubtitleTrackInfo>, McBrowserError>
where
    F: FnMut(&str) -> bool,
{
    let normalized_video = normalize_relative_path(video_path, false)?;
    let video = bfs
        .metadata_resolving_internal_links(&normalized_video)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect video for subtitles"))?;
    if !authorize_read(&normalized_video)
        || !video.resolution_paths.iter().all(|hop| authorize_read(hop))
        || !authorize_read(&video.resolved_path)
    {
        return Err(McBrowserError::Forbidden(
            "Video is not readable".to_owned(),
        ));
    }
    if video.entry.kind != "file" {
        return Err(McBrowserError::BadRequest(
            "Expected a video file".to_owned(),
        ));
    }
    let (parent_dir, video_leaf) = split_parent_and_leaf(&normalized_video);
    let (video_stem, _) = file_stem_and_ext(video_leaf);
    if video_stem.is_empty() {
        return Ok(Vec::new());
    }

    let parent_entries =
        list_authorized_alias_directory(bfs, parent_dir, &mut authorize_read).unwrap_or_default();

    let mut same_dir_matches: Vec<String> = Vec::new();
    let mut sub_dir_stem_matches: Vec<String> = Vec::new();
    let mut sub_dir_other_matches: Vec<String> = Vec::new();

    for entry in &parent_entries {
        if is_entry_authorized_file(bfs, entry, &mut authorize_read) {
            if is_supported_subtitle_extension(&entry.name)
                && starts_with_case_insensitive(&entry.name, video_stem)
            {
                same_dir_matches.push(entry.path.clone());
            }
        } else if is_subtitle_directory_name(&entry.name) {
            if let Some(sub_entries) = list_authorized_dir_entries(bfs, entry, &mut authorize_read)
            {
                for sub_entry in sub_entries {
                    if is_entry_authorized_file(bfs, &sub_entry, &mut authorize_read) {
                        if is_supported_subtitle_extension(&sub_entry.name) {
                            if starts_with_case_insensitive(&sub_entry.name, video_stem) {
                                sub_dir_stem_matches.push(sub_entry.path);
                            } else {
                                sub_dir_other_matches.push(sub_entry.path);
                            }
                        }
                    } else if starts_with_case_insensitive(&sub_entry.name, video_stem) {
                        if let Some(nested_entries) =
                            list_authorized_dir_entries(bfs, &sub_entry, &mut authorize_read)
                        {
                            for nested in nested_entries {
                                if is_supported_subtitle_extension(&nested.name)
                                    && is_entry_authorized_file(bfs, &nested, &mut authorize_read)
                                {
                                    sub_dir_stem_matches.push(nested.path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    same_dir_matches.sort();
    sub_dir_stem_matches.sort();
    sub_dir_other_matches.sort();

    let mut seen = std::collections::HashSet::new();
    let mut tracks = Vec::new();
    for path in same_dir_matches
        .into_iter()
        .chain(sub_dir_stem_matches)
        .chain(sub_dir_other_matches)
    {
        if seen.insert(path.clone()) {
            tracks.push(build_subtitle_track_info(&path, video_stem));
        }
    }
    Ok(tracks)
}

pub fn discover_subtitles_for_user_with_conn(
    connection: &rusqlite::Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    video_path: &str,
) -> Result<Vec<SubtitleTrackInfo>, McBrowserError> {
    discover_subtitles_in_fs(bfs, video_path, |candidate| {
        authorize_with_conn(connection, user, Permission::Read, candidate).is_ok()
    })
}

#[allow(dead_code)]
pub fn discover_subtitles_for_user(
    bfs: &BrowserFs,
    user: &AuthUser,
    video_path: &str,
) -> Result<Vec<SubtitleTrackInfo>, McBrowserError> {
    if let Ok(connection) = af_db::get_conn() {
        return discover_subtitles_for_user_with_conn(&connection, bfs, user, video_path);
    }
    discover_subtitles_in_fs(bfs, video_path, |candidate| {
        authorize(user, Permission::Read, candidate).is_ok()
    })
}

async fn subtitle(
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
            McBrowserError::Internal("Database unavailable for subtitle check".to_owned())
        })?;
        authorize_with_conn(&connection, &user, Permission::Read, &path)?;
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;

        let target_path = if is_supported_subtitle_extension(&path) {
            path
        } else if is_video_extension(&path) {
            let discovered =
                discover_subtitles_for_user_with_conn(&connection, &filesystem, &user, &path)?;
            discovered
                .into_iter()
                .next()
                .map(|t| t.path)
                .ok_or_else(|| {
                    McBrowserError::NotFound(
                        "No matching subtitle sidecar found for video".to_owned(),
                    )
                })?
        } else {
            return Err(McBrowserError::BadRequest(
                "Expected WebVTT (.vtt), SubRip (.srt), or SubStation Alpha (.ass/.ssa) subtitle path".to_owned(),
            ));
        };

        let file = open_authorized_file_with_conn(
            &connection,
            &user,
            &filesystem,
            &target_path,
            Permission::Read,
        )?;
        let mut bytes = Vec::new();
        file.take(MAX_SUBTITLE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| McBrowserError::Internal("Failed to read subtitles".to_owned()))?;
        subtitle_text(&target_path, bytes)
    })
    .await;
    match task {
        Ok(Ok(text)) => {
            let mut response = Response::new(Body::from(text));
            media_headers(&mut response, "text/vtt; charset=utf-8");
            response
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => McBrowserError::Internal("Subtitle task failed".to_owned()).into_response(),
    }
}

async fn subtitles_discovery(
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
            McBrowserError::Internal("Database unavailable for subtitle discovery".to_owned())
        })?;
        authorize_with_conn(&connection, &user, Permission::Read, &path)?;
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let subtitles =
            discover_subtitles_for_user_with_conn(&connection, &filesystem, &user, &path)?;
        Ok::<_, McBrowserError>(SubtitlesDiscoveryResponse { path, subtitles })
    })
    .await;

    match task {
        Ok(Ok(payload)) => {
            let mut resp = Json(payload).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => {
            McBrowserError::Internal("Subtitle discovery task failed".to_owned()).into_response()
        }
    }
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

pub fn validate_csv_preview_bytes(path: &str, bytes: &[u8]) -> Result<(), McBrowserError> {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if ext != "csv" && ext != "tsv" {
        return Err(McBrowserError::BadRequest(
            "CSV preview requires a .csv or .tsv file".to_owned(),
        ));
    }
    if bytes.len() as u64 > MAX_CSV_PREVIEW_BYTES {
        return Err(McBrowserError::PayloadTooLarge(
            "CSV file exceeds 5 MiB preview limit".to_owned(),
        ));
    }
    // Reject obvious binary containers (ELF, PNG, ZIP, PDF, GIF, JPEG)
    if bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"%PDF-")
        || bytes.starts_with(b"\xff\xd8\xff")
    {
        return Err(McBrowserError::BadRequest(
            "CSV file contains binary signature".to_owned(),
        ));
    }
    let has_utf16_bom = bytes.starts_with(b"\xff\xfe") || bytes.starts_with(b"\xfe\xff");
    if !has_utf16_bom && bytes.contains(&0) {
        return Err(McBrowserError::BadRequest(
            "CSV file contains unexpected NUL bytes".to_owned(),
        ));
    }
    Ok(())
}

async fn csv_preview(
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
            McBrowserError::Internal("Database unavailable for CSV preview".to_owned())
        })?;
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let file = open_authorized_file_with_conn(
            &connection,
            &user,
            &filesystem,
            &path,
            Permission::Read,
        )?;
        let meta = file
            .metadata()
            .map_err(|_| McBrowserError::Internal("Failed to inspect CSV metadata".to_owned()))?;
        if meta.len() > MAX_CSV_PREVIEW_BYTES {
            return Err(McBrowserError::PayloadTooLarge(
                "CSV file exceeds 5 MiB preview limit".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.take(MAX_CSV_PREVIEW_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| McBrowserError::Internal("Failed to read CSV file".to_owned()))?;
        validate_csv_preview_bytes(&path, &bytes)?;
        Ok::<_, McBrowserError>((bytes, path))
    })
    .await;

    match task {
        Ok(Ok((bytes, path))) => {
            let mut response = Response::new(Body::from(bytes));
            media_headers(&mut response, "text/csv; charset=utf-8");
            let disposition = build_attachment_content_disposition(&path);
            if let Ok(value) = disposition.to_str() {
                if let Ok(value) =
                    HeaderValue::from_str(&value.replacen("attachment;", "inline;", 1))
                {
                    response
                        .headers_mut()
                        .insert(header::CONTENT_DISPOSITION, value);
                }
            }
            response
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => McBrowserError::Internal("CSV preview task failed".to_owned()).into_response(),
    }
}

fn read_zip_entries_bounded(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>, McBrowserError> {
    if bytes.len() < 22 || !bytes.starts_with(b"PK\x03\x04") {
        return Err(McBrowserError::BadRequest(
            "Invalid EPUB archive signature".to_owned(),
        ));
    }

    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| {
        McBrowserError::BadRequest("Corrupt or unreadable EPUB ZIP archive".to_owned())
    })?;

    if archive.len() > MAX_EPUB_ARCHIVE_ENTRIES {
        return Err(McBrowserError::BadRequest(
            "EPUB archive exceeds maximum entry count limit".to_owned(),
        ));
    }

    let mut files = HashMap::new();
    let mut total_uncompressed = 0usize;

    for i in 0..archive.len() {
        let entry = archive.by_index(i).map_err(|_| {
            McBrowserError::BadRequest("Malformed EPUB ZIP central directory entry".to_owned())
        })?;
        if entry.is_dir() {
            continue;
        }
        let raw_name = entry
            .name()
            .map_err(|_| {
                McBrowserError::BadRequest("Invalid UTF-8 in EPUB ZIP entry name".to_owned())
            })?
            .into_owned();
        if raw_name.ends_with('/') {
            continue;
        }
        let clean_name = normalize_relative_path(&raw_name, false)?;

        // Only extract XML/OPF/XHTML/HTML/NCX/mimetype entries needed for reading
        let lower_name = clean_name.to_ascii_lowercase();
        let should_extract = clean_name == "mimetype"
            || lower_name.ends_with(".xml")
            || lower_name.ends_with(".opf")
            || lower_name.ends_with(".xhtml")
            || lower_name.ends_with(".html")
            || lower_name.ends_with(".htm")
            || lower_name.ends_with(".ncx");
        if !should_extract {
            continue;
        }

        let declared_uncomp = entry.size() as usize;
        if declared_uncomp > MAX_EPUB_ENTRY_UNCOMPRESSED_BYTES {
            return Err(McBrowserError::PayloadTooLarge(
                "EPUB chapter exceeds 2 MiB uncompressed safety limit".to_owned(),
            ));
        }

        let mut decompressed = Vec::with_capacity(declared_uncomp.min(65_536));
        entry
            .take((MAX_EPUB_ENTRY_UNCOMPRESSED_BYTES + 1) as u64)
            .read_to_end(&mut decompressed)
            .map_err(|_| {
                McBrowserError::BadRequest("Failed to decompress EPUB entry".to_owned())
            })?;

        if decompressed.len() > MAX_EPUB_ENTRY_UNCOMPRESSED_BYTES {
            return Err(McBrowserError::PayloadTooLarge(
                "EPUB decompressed entry exceeds 2 MiB limit".to_owned(),
            ));
        }
        total_uncompressed = total_uncompressed.saturating_add(decompressed.len());
        if total_uncompressed > MAX_EPUB_TOTAL_UNCOMPRESSED_BYTES {
            return Err(McBrowserError::PayloadTooLarge(
                "EPUB book exceeds 8 MiB total uncompressed text limit".to_owned(),
            ));
        }

        files.insert(clean_name, decompressed);
    }

    Ok(files)
}

fn decode_xml_entities(input: &str) -> String {
    input
        .replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&#xA0;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
}

fn extract_xml_tag_text(xml: &str, tag_suffix: &str) -> Option<String> {
    let pattern = format!(
        r"(?is)<(?:[a-z0-9_]+:)?{tag_suffix}(?:\s[^>]*)?>(.*?)</(?:[a-z0-9_]+:)?{tag_suffix}>"
    );
    let re = regex::Regex::new(&pattern).ok()?;
    let caps = re.captures(xml)?;
    let raw = caps.get(1)?.as_str();
    let tag_strip = regex::Regex::new(r"<[^>]+>").ok()?;
    let clean = decode_xml_entities(&tag_strip.replace_all(raw, ""))
        .trim()
        .to_owned();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn extract_xml_attr(tag: &str, attr_name: &str) -> Option<String> {
    let pattern = format!(r#"(?i)\b{attr_name}\s*=\s*["']([^"']*)["']"#);
    let re = regex::Regex::new(&pattern).ok()?;
    let caps = re.captures(tag)?;
    Some(decode_xml_entities(caps.get(1)?.as_str().trim()))
}

pub fn sanitize_xhtml_to_chapter(
    id: &str,
    href: &str,
    raw_xhtml: &str,
    fallback_title: &str,
) -> EpubChapter {
    // Strip dangerous blocks (<script>, <style>, <svg>, <iframe>, <object>, <embed>, <applet>, <form>, <math>, <noscript>) completely
    let mut without_dangerous = raw_xhtml.to_owned();
    for tag in [
        "script", "style", "svg", "iframe", "object", "embed", "applet", "form", "math", "noscript",
    ] {
        let block_pat =
            format!(r"(?is)<(?:[a-z0-9_]+:)?{tag}\b[^>]*>.*?</(?:[a-z0-9_]+:)?{tag}\s*>");
        if let Ok(re) = regex::Regex::new(&block_pat) {
            without_dangerous = re.replace_all(&without_dangerous, " ").into_owned();
        }
        let self_closing_pat = format!(r"(?is)<(?:[a-z0-9_]+:)?{tag}\b[^>]*/\s*>");
        if let Ok(re) = regex::Regex::new(&self_closing_pat) {
            without_dangerous = re.replace_all(&without_dangerous, " ").into_owned();
        }
    }

    let heading_title = extract_xml_tag_text(&without_dangerous, "h1")
        .or_else(|| extract_xml_tag_text(&without_dangerous, "h2"))
        .or_else(|| extract_xml_tag_text(&without_dangerous, "title"))
        .unwrap_or_else(|| fallback_title.to_owned());

    let head_re = regex::Regex::new(r"(?is)<head\b[^>]*>.*?</head>").ok();
    let body_only = match &head_re {
        Some(re) => re.replace_all(&without_dangerous, " ").into_owned(),
        None => without_dangerous,
    };

    // Convert block-level closing tags and <br> into paragraph breaks
    let block_breaks = regex::Regex::new(
        r"(?i)</(p|div|h1|h2|h3|h4|h5|h6|li|blockquote|section|article|tr)>|<br\s*/?>",
    )
    .ok();
    let broken = match &block_breaks {
        Some(re) => re.replace_all(&body_only, "\n\n").into_owned(),
        None => body_only,
    };

    let all_tags = regex::Regex::new(r"<[^>]*>").ok();
    let stripped = match &all_tags {
        Some(re) => re.replace_all(&broken, "").into_owned(),
        None => broken,
    };
    let decoded = decode_xml_entities(&stripped);

    let mut paragraphs = Vec::new();
    for raw_para in decoded.split("\n\n") {
        let collapsed: String = raw_para.split_whitespace().collect::<Vec<_>>().join(" ");
        if !collapsed.is_empty() {
            paragraphs.push(collapsed);
        }
    }

    let text = paragraphs.join("\n\n");
    EpubChapter {
        id: id.to_owned(),
        title: heading_title,
        href: href.to_owned(),
        paragraphs,
        text,
    }
}

fn resolve_epub_relative_href(opf_dir: &str, href: &str) -> Option<String> {
    let without_fragment = href.split('#').next().unwrap_or(href).trim();
    if without_fragment.is_empty() {
        return None;
    }
    let combined = if opf_dir.is_empty() {
        without_fragment.to_owned()
    } else {
        format!("{opf_dir}/{without_fragment}")
    };
    normalize_relative_path(&combined, false).ok()
}

pub fn parse_epub_bytes(path: &str, bytes: &[u8]) -> Result<EpubBookPreview, McBrowserError> {
    if bytes.len() as u64 > MAX_EPUB_BYTES {
        return Err(McBrowserError::PayloadTooLarge(
            "EPUB file exceeds 64 MiB limit".to_owned(),
        ));
    }
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if ext != "epub" {
        return Err(McBrowserError::BadRequest(
            "Expected an .epub file path".to_owned(),
        ));
    }

    let entries = read_zip_entries_bounded(bytes)?;
    let container_bytes = entries.get("META-INF/container.xml").ok_or_else(|| {
        McBrowserError::BadRequest("Invalid EPUB: missing META-INF/container.xml".to_owned())
    })?;
    let container_xml = std::str::from_utf8(container_bytes).map_err(|_| {
        McBrowserError::BadRequest("Invalid EPUB container.xml encoding".to_owned())
    })?;

    let rootfile_re = regex::Regex::new(r"(?is)<rootfile\b[^>]*>")
        .map_err(|_| McBrowserError::Internal("EPUB XML parser unavailable".to_owned()))?;
    let rootfile_tag = rootfile_re
        .find(container_xml)
        .map(|m| m.as_str())
        .ok_or_else(|| {
            McBrowserError::BadRequest("Invalid EPUB: missing rootfile in container.xml".to_owned())
        })?;
    let raw_opf_path = extract_xml_attr(rootfile_tag, "full-path").ok_or_else(|| {
        McBrowserError::BadRequest("Invalid EPUB: rootfile missing full-path attribute".to_owned())
    })?;
    let opf_path = normalize_relative_path(&raw_opf_path, false)?;
    let (opf_dir, _) = split_parent_and_leaf(&opf_path);

    let opf_bytes = entries.get(&opf_path).ok_or_else(|| {
        McBrowserError::BadRequest(format!("Invalid EPUB: missing package file '{opf_path}'"))
    })?;
    let opf_xml = std::str::from_utf8(opf_bytes)
        .map_err(|_| McBrowserError::BadRequest("Invalid EPUB OPF package encoding".to_owned()))?;

    let (_, leaf_name) = split_parent_and_leaf(path);
    let (fallback_book_title, _) = file_stem_and_ext(leaf_name);
    let title =
        extract_xml_tag_text(opf_xml, "title").unwrap_or_else(|| fallback_book_title.to_owned());
    let author = extract_xml_tag_text(opf_xml, "creator");
    let language = extract_xml_tag_text(opf_xml, "language");
    let description = extract_xml_tag_text(opf_xml, "description");

    let item_re = regex::Regex::new(r"(?is)<item\b[^>]*>")
        .map_err(|_| McBrowserError::Internal("EPUB manifest parser unavailable".to_owned()))?;
    let mut manifest: HashMap<String, (String, String)> = HashMap::new();
    for m in item_re.find_iter(opf_xml) {
        let tag = m.as_str();
        if let (Some(id), Some(href)) = (extract_xml_attr(tag, "id"), extract_xml_attr(tag, "href"))
        {
            let media = extract_xml_attr(tag, "media-type").unwrap_or_default();
            manifest.insert(id, (href, media));
        }
    }

    let itemref_re = regex::Regex::new(r"(?is)<itemref\b[^>]*>")
        .map_err(|_| McBrowserError::Internal("EPUB spine parser unavailable".to_owned()))?;
    let mut spine_ids = Vec::new();
    for m in itemref_re.find_iter(opf_xml) {
        if let Some(idref) = extract_xml_attr(m.as_str(), "idref") {
            spine_ids.push(idref);
        }
    }

    let mut chapters = Vec::new();
    for (idx, item_id) in spine_ids.iter().take(MAX_EPUB_CHAPTERS).enumerate() {
        let Some((href, media_type)) = manifest.get(item_id) else {
            continue;
        };
        if !media_type.is_empty() && !media_type.contains("html") && !media_type.contains("xml") {
            continue;
        }
        let Some(resolved_path) = resolve_epub_relative_href(opf_dir, href) else {
            continue;
        };
        let Some(chapter_bytes) = entries.get(&resolved_path) else {
            continue;
        };
        let Ok(chapter_xhtml) = std::str::from_utf8(chapter_bytes) else {
            continue;
        };
        let fallback_title = format!("Chapter {}", idx + 1);
        let chapter =
            sanitize_xhtml_to_chapter(item_id, &resolved_path, chapter_xhtml, &fallback_title);
        if !chapter.text.is_empty() || !chapter.title.is_empty() {
            chapters.push(chapter);
        }
    }

    if chapters.is_empty() {
        return Err(McBrowserError::BadRequest(
            "EPUB contains no readable XHTML spine chapters".to_owned(),
        ));
    }

    Ok(EpubBookPreview {
        path: path.to_owned(),
        title,
        author,
        language,
        description,
        chapters,
    })
}

async fn epub_preview(
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
            McBrowserError::Internal("Database unavailable for EPUB preview".to_owned())
        })?;
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let file = open_authorized_file_with_conn(
            &connection,
            &user,
            &filesystem,
            &path,
            Permission::Read,
        )?;
        let meta = file
            .metadata()
            .map_err(|_| McBrowserError::Internal("Failed to inspect EPUB metadata".to_owned()))?;
        if meta.len() > MAX_EPUB_BYTES {
            return Err(McBrowserError::PayloadTooLarge(
                "EPUB file exceeds 64 MiB limit".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.take(MAX_EPUB_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| McBrowserError::Internal("Failed to read EPUB file".to_owned()))?;
        parse_epub_bytes(&path, &bytes)
    })
    .await;

    match task {
        Ok(Ok(book)) => {
            let mut resp = Json(book).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => McBrowserError::Internal("EPUB preview task failed".to_owned()).into_response(),
    }
}

#[cfg(test)]
#[path = "media_tests.rs"]
mod tests;
