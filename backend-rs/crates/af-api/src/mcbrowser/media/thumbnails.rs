use super::super::policy::Permission;
use super::super::*;
use super::{is_image_content_type, media_headers, media_type};
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

pub const MAX_THUMBNAIL_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_IMAGE_WIDTH: u32 = 10_000;
pub const MAX_IMAGE_HEIGHT: u32 = 10_000;
pub const MAX_DECODED_IMAGE_ALLOC_BYTES: u64 = 400 * 1024 * 1024; // 10000x10000x4 RGBA ceiling
pub const THUMB_DIMENSION: u32 = 256;
pub const BIG_PREVIEW_DIMENSION: u32 = 1080;

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

pub fn invalidate_thumbnail_cache(user_id: i64, path_prefix: &str) {
    if let Ok(mut guard) = THUMBNAIL_CACHE.lock() {
        guard.invalidate_user_path(user_id, path_prefix);
    }
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
    if !(4..=4 * 1024 * 1024).contains(&length) {
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

pub(super) fn encode_jpeg_image(
    img: &DynamicImage,
    quality: u8,
) -> Result<Vec<u8>, McBrowserError> {
    let rgb = img.to_rgb8();
    let (w, h) = rgb.dimensions();
    let mut out = Vec::with_capacity((w as usize).saturating_mul(h as usize) / 2 + 1024);
    let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
    encoder
        .encode(rgb.as_raw(), w, h, ColorType::Rgb8.into())
        .map_err(|_| McBrowserError::Internal("Failed to encode JPEG image".to_owned()))?;
    Ok(out)
}

pub(super) fn encode_png_image(img: &DynamicImage) -> Result<Vec<u8>, McBrowserError> {
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

pub(super) async fn render_thumbnail_response(
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

pub(super) async fn thumbnail(
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

pub(super) async fn preview_thumb(
    Extension(user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    render_thumbnail_response(user, query.path, PreviewSize::Thumb).await
}

pub(super) async fn preview_big(
    Extension(user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    render_thumbnail_response(user, query.path, PreviewSize::Big).await
}
