use super::super::policy::{authorize_with_conn, Permission};
use super::super::*;
use super::{
    is_subtitle_directory_name, is_supported_subtitle_extension, is_video_extension, media_headers,
};

pub const MAX_SUBTITLE_BYTES: u64 = 2 * 1024 * 1024;

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

pub(super) fn split_parent_and_leaf(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((parent, leaf)) => (parent, leaf),
        None => ("", path),
    }
}

pub(super) fn file_stem_and_ext(name: &str) -> (&str, &str) {
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

pub(super) async fn subtitle(
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

pub(super) async fn subtitles_discovery(
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
