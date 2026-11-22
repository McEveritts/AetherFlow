use super::super::policy::Permission;
use super::super::*;
use super::media_headers;
use super::subtitles::{file_stem_and_ext, split_parent_and_leaf};
use std::collections::HashMap;
use std::io::Cursor;
use zip::ZipArchive;

pub const MAX_CSV_PREVIEW_BYTES: u64 = 5 * 1024 * 1024;
pub const MAX_EPUB_BYTES: u64 = 64 * 1024 * 1024;

const MAX_EPUB_ARCHIVE_ENTRIES: usize = 2_048;
const MAX_EPUB_CHAPTERS: usize = 256;
const MAX_EPUB_ENTRY_UNCOMPRESSED_BYTES: usize = 2 * 1024 * 1024;
const MAX_EPUB_TOTAL_UNCOMPRESSED_BYTES: usize = 8 * 1024 * 1024;

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

pub(super) async fn csv_preview(
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

pub(super) async fn epub_preview(
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
