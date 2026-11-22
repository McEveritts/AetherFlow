use super::types::{SearchKindFilter, SearchQuery, SearchResponse};
use super::{MAX_SEARCH_ENTRIES, MAX_SEARCH_SCAN_ENTRIES};
use crate::auth::AuthUser;
use crate::mcbrowser::{
    map_fs_io_error, normalize_relative_path, open_configured_user_browser_fs_with_conn,
    validate_mcbrowser_user, McBrowserError,
};
use af_files::Entry;
use axum::extract::{Extension, Query};
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub fn parse_search_type_filter(raw: Option<&str>) -> Result<SearchKindFilter, McBrowserError> {
    let Some(val) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(SearchKindFilter::Any);
    };
    if val.eq_ignore_ascii_case("file") {
        Ok(SearchKindFilter::File)
    } else if val.eq_ignore_ascii_case("directory") {
        Ok(SearchKindFilter::Directory)
    } else {
        Err(McBrowserError::BadRequest(
            "Invalid search type filter: must be 'file' or 'directory'".to_string(),
        ))
    }
}

pub fn filter_walked_entries(
    walked: Vec<Entry>,
    query: &str,
    kind_filter: SearchKindFilter,
    max_entries: usize,
) -> SearchResponse {
    let truncated = walked.len() > max_entries;
    let parsed_query = crate::mcbrowser::search_query::SearchQuery::parse(query);

    let entries = walked
        .into_iter()
        .take(max_entries)
        .filter(|entry| {
            let kind_ok = match kind_filter {
                SearchKindFilter::Any => entry.kind == "file" || entry.kind == "directory",
                SearchKindFilter::File => entry.kind == "file",
                SearchKindFilter::Directory => entry.kind == "directory",
            };
            if !kind_ok {
                return false;
            }
            parsed_query.matches(&entry.name)
        })
        .collect();

    SearchResponse {
        entries,
        truncated,
        ai_interpretation: None,
        ai_powered: None,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowAiSearchPlan {
    #[serde(default)]
    pub phrase: String,
    #[serde(default)]
    pub required_tokens: Vec<String>,
    #[serde(default)]
    pub optional_tokens: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub min_size_bytes: Option<u64>,
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
    #[serde(default)]
    pub kind_override: Option<String>,
    #[serde(default)]
    pub interpretation: String,
    #[serde(default)]
    pub llm_used: bool,
}

pub(super) const NL_FILLER_WORDS: &[&str] = &[
    "find",
    "search",
    "for",
    "show",
    "me",
    "all",
    "files",
    "file",
    "folders",
    "folder",
    "directories",
    "directory",
    "about",
    "related",
    "to",
    "in",
    "from",
    "with",
    "named",
    "called",
    "looking",
    "where",
    "is",
    "are",
    "my",
    "our",
    "please",
    "can",
    "you",
    "locate",
    "list",
    "get",
    "matching",
    "containing",
    "that",
    "have",
    "has",
];

pub(super) const STOPWORD_ARTICLES: &[&str] =
    &["the", "a", "an", "of", "and", "or", "on", "at", "by"];

pub fn build_deterministic_nl_plan(raw_query: &str) -> FlowAiSearchPlan {
    let parsed_mods = crate::mcbrowser::search_query::SearchQuery::parse(raw_query);
    let cleaned_raw = raw_query
        .replace("case:insensitive", "")
        .replace("case:sensitive", "");
    let cleaned_raw = regex::Regex::new(r"type:[0-9A-Za-z_]+")
        .map(|re| re.replace_all(&cleaned_raw, "").into_owned())
        .unwrap_or(cleaned_raw);

    let trimmed = cleaned_raw.trim().trim_matches('"').trim();
    let lower = trimmed.to_lowercase();

    let mut extensions: Vec<String> = Vec::new();
    for cond in &parsed_mods.conditions {
        match cond {
            crate::mcbrowser::search_query::SearchCondition::Video => {
                for ext in ["mkv", "mp4", "avi", "mov", "m4v", "webm", "ts"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
            }
            crate::mcbrowser::search_query::SearchCondition::Audio => {
                for ext in ["mp3", "flac", "aac", "ogg", "opus", "wav", "m4a"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
            }
            crate::mcbrowser::search_query::SearchCondition::Image => {
                for ext in ["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
            }
            crate::mcbrowser::search_query::SearchCondition::Extension(ext) => {
                let e = ext.to_lowercase();
                if !extensions.contains(&e) {
                    extensions.push(e);
                }
            }
        }
    }

    let raw_words: Vec<String> = lower
        .split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let mut min_size_bytes: Option<u64> = None;
    let mut max_size_bytes: Option<u64> = None;
    let mut kind_override: Option<String> = None;
    let mut seasonal_tokens: Vec<String> = Vec::new();

    // Detect "season N" or "episode N" patterns
    for idx in 0..raw_words.len() {
        if (raw_words[idx] == "season" || raw_words[idx] == "s") && idx + 1 < raw_words.len() {
            if let Ok(num) = raw_words[idx + 1].parse::<u32>() {
                seasonal_tokens.push(format!("s{num:02}"));
                seasonal_tokens.push(format!("season {num}"));
            }
        }
        if (raw_words[idx] == "episode" || raw_words[idx] == "ep") && idx + 1 < raw_words.len() {
            if let Ok(num) = raw_words[idx + 1].parse::<u32>() {
                seasonal_tokens.push(format!("e{num:02}"));
            }
        }
    }

    let mut content_tokens: Vec<String> = Vec::new();
    let mut skip_next = false;

    for idx in 0..raw_words.len() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let w = raw_words[idx].as_str();

        if (w == "season" || w == "episode" || w == "ep")
            && idx + 1 < raw_words.len()
            && raw_words[idx + 1].parse::<u32>().is_ok()
        {
            skip_next = true;
            continue;
        }

        match w {
            "Folders" | "folders" | "folder" | "directories" | "directory" => {
                if kind_override.is_none() {
                    kind_override = Some("directory".to_string());
                }
                continue;
            }
            "video" | "videos" | "movie" | "movies" | "episode" | "episodes" => {
                for ext in ["mkv", "mp4", "avi", "mov", "m4v", "webm", "ts"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
                continue;
            }
            "spreadsheet" | "spreadsheets" | "excel" => {
                for ext in ["xlsx", "xls", "csv", "ods"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
                continue;
            }
            "document" | "documents" | "docs" | "pdf" | "pdfs" => {
                if w == "pdf" || w == "pdfs" {
                    if !extensions.contains(&"pdf".to_string()) {
                        extensions.push("pdf".to_string());
                    }
                } else {
                    for ext in ["pdf", "doc", "docx", "txt", "md", "rtf"] {
                        if !extensions.contains(&ext.to_string()) {
                            extensions.push(ext.to_string());
                        }
                    }
                }
                continue;
            }
            "audio" | "music" | "song" | "songs" => {
                for ext in ["mp3", "flac", "aac", "ogg", "opus", "wav", "m4a"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
                continue;
            }
            "image" | "images" | "photo" | "photos" | "picture" | "pictures" => {
                for ext in ["png", "jpg", "jpeg", "gif", "webp", "svg"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
                continue;
            }
            "archive" | "archives" => {
                for ext in ["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "zst"] {
                    if !extensions.contains(&ext.to_string()) {
                        extensions.push(ext.to_string());
                    }
                }
                continue;
            }
            "large" | "big" | "huge" => {
                min_size_bytes = Some(100 * 1024 * 1024);
                continue;
            }
            "small" | "tiny" => {
                max_size_bytes = Some(10 * 1024 * 1024);
                continue;
            }
            _ => {}
        }

        if NL_FILLER_WORDS.contains(&w) {
            continue;
        }
        content_tokens.push(w.to_string());
    }

    // Separate significant tokens from articles like "the", unless all tokens are articles
    let significant: Vec<String> = content_tokens
        .iter()
        .filter(|t| !STOPWORD_ARTICLES.contains(&t.as_str()))
        .cloned()
        .collect();

    let required_tokens = if !significant.is_empty() {
        significant
    } else if !content_tokens.is_empty() {
        content_tokens.clone()
    } else {
        Vec::new()
    };

    let phrase = if !content_tokens.is_empty() {
        content_tokens.join(" ")
    } else {
        lower.clone()
    };

    let mut summary_parts = Vec::new();
    if !phrase.is_empty() {
        summary_parts.push(format!("matching \"{}\"", phrase));
    }
    if !seasonal_tokens.is_empty() {
        summary_parts.push(format!("season/episode ({})", seasonal_tokens.join(" / ")));
    }
    if !extensions.is_empty() {
        summary_parts.push(format!("file types [{}]", extensions.join(", ")));
    }
    if min_size_bytes.is_some() {
        summary_parts.push("size > 100 MiB".to_string());
    }
    if max_size_bytes.is_some() {
        summary_parts.push("size < 10 MiB".to_string());
    }

    let interpretation = if summary_parts.is_empty() {
        format!(
            "FlowAI natural-language search for \"{}\"",
            raw_query.trim()
        )
    } else {
        format!("FlowAI smart search: {}", summary_parts.join(" · "))
    };

    FlowAiSearchPlan {
        phrase,
        required_tokens,
        optional_tokens: seasonal_tokens,
        extensions,
        min_size_bytes,
        max_size_bytes,
        kind_override,
        interpretation,
        llm_used: false,
    }
}

pub fn filter_and_rank_entries_with_flowai(
    walked: Vec<Entry>,
    plan: &FlowAiSearchPlan,
    kind_filter: SearchKindFilter,
    max_entries: usize,
) -> SearchResponse {
    let effective_kind = match kind_filter {
        SearchKindFilter::Any => match plan.kind_override.as_deref() {
            Some("file") => SearchKindFilter::File,
            Some("directory") => SearchKindFilter::Directory,
            _ => SearchKindFilter::Any,
        },
        explicit => explicit,
    };

    let phrase_lower = plan.phrase.trim().to_lowercase();
    let req_tokens: Vec<String> = plan
        .required_tokens
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let opt_tokens: Vec<String> = plan
        .optional_tokens
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut scored: Vec<(i64, Entry)> = Vec::new();

    for entry in walked {
        let kind_ok = match effective_kind {
            SearchKindFilter::Any => entry.kind == "file" || entry.kind == "directory",
            SearchKindFilter::File => entry.kind == "file",
            SearchKindFilter::Directory => entry.kind == "directory",
        };
        if !kind_ok {
            continue;
        }

        if let Some(min_sz) = plan.min_size_bytes {
            if entry.kind != "file" || entry.size < min_sz {
                continue;
            }
        }
        if let Some(max_sz) = plan.max_size_bytes {
            if entry.kind != "file" || entry.size > max_sz {
                continue;
            }
        }

        let name_lower = entry.name.to_lowercase();
        let path_lower = entry.path.to_lowercase();
        let normalized_name = name_lower.replace(['.', '_', '-'], " ");
        let normalized_path = path_lower.replace(['.', '_', '-'], " ");

        if !plan.extensions.is_empty() {
            let ext_match = entry
                .name
                .rsplit_once('.')
                .map(|(_, ext)| {
                    let ext_l = ext.to_lowercase();
                    plan.extensions.iter().any(|e| e == &ext_l)
                })
                .unwrap_or(false);
            // Allow directories if their name/path matches the phrase/tokens strongly, unless files were strictly requested
            if !ext_match && (effective_kind == SearchKindFilter::File || entry.kind == "file") {
                continue;
            }
            if !ext_match && entry.kind == "directory" && req_tokens.is_empty() {
                continue;
            }
        }

        let mut score: i64 = 0;

        if !phrase_lower.is_empty() {
            if name_lower == phrase_lower || normalized_name == phrase_lower {
                score += 200;
            } else if name_lower.contains(&phrase_lower) || normalized_name.contains(&phrase_lower)
            {
                score += 120;
            } else if path_lower.contains(&phrase_lower) || normalized_path.contains(&phrase_lower)
            {
                score += 80;
            }
        }

        if !req_tokens.is_empty() {
            let mut matched_in_name = 0usize;
            let mut matched_in_path = 0usize;
            for tok in &req_tokens {
                if name_lower.contains(tok) || normalized_name.contains(tok) {
                    matched_in_name += 1;
                    matched_in_path += 1;
                    score += 35;
                } else if path_lower.contains(tok) || normalized_path.contains(tok) {
                    matched_in_path += 1;
                    score += 20;
                }
            }

            if matched_in_path == req_tokens.len() {
                score += 60;
                if matched_in_name == req_tokens.len() {
                    score += 40;
                }
            } else if req_tokens.len() > 1 && matched_in_path == 0 {
                continue;
            } else if matched_in_path < req_tokens.len() {
                // Require all significant tokens to appear in either path or name
                continue;
            }
        }

        if !opt_tokens.is_empty() {
            let any_opt = opt_tokens.iter().any(|tok| {
                name_lower.contains(tok)
                    || normalized_name.contains(tok)
                    || path_lower.contains(tok)
                    || normalized_path.contains(tok)
            });
            if any_opt {
                score += 45;
            } else {
                // When a specific season/episode was requested, require at least one seasonal variant to match
                continue;
            }
        }

        if req_tokens.is_empty()
            && opt_tokens.is_empty()
            && (!plan.extensions.is_empty()
                || plan.min_size_bytes.is_some()
                || plan.max_size_bytes.is_some())
        {
            score += 10;
        }

        if score > 0 {
            scored.push((score, entry));
        }
    }

    scored.sort_by(|(score_a, entry_a), (score_b, entry_b)| {
        score_b
            .cmp(score_a)
            .then_with(|| match (entry_a.kind.as_str(), entry_b.kind.as_str()) {
                ("directory", "directory") => entry_a.path.cmp(&entry_b.path),
                ("directory", _) => std::cmp::Ordering::Less,
                (_, "directory") => std::cmp::Ordering::Greater,
                _ => entry_a.path.cmp(&entry_b.path),
            })
    });

    let truncated = scored.len() > max_entries;
    let entries = scored
        .into_iter()
        .take(max_entries)
        .map(|(_, entry)| entry)
        .collect();

    SearchResponse {
        entries,
        truncated,
        ai_interpretation: Some(plan.interpretation.clone()),
        ai_powered: Some(true),
    }
}

pub(super) async fn enrich_nl_plan_with_flowai_llm(
    raw_query: &str,
    base: FlowAiSearchPlan,
) -> FlowAiSearchPlan {
    // Only invoke external LLM when query looks like a multi-word natural language prompt (>= 3 words)
    let word_count = raw_query.split_whitespace().count();
    if word_count < 3 {
        return base;
    }
    let ps = crate::intelligence::resolve_provider_settings();
    let has_configured_provider = !ps.gemini_api_key.is_empty()
        || !ps.openai_api_key.is_empty()
        || !ps.anthropic_api_key.is_empty()
        || ps.default_model == "ollama"
        || ps.default_model == "lm-studio"
        || ps.default_model == "anthropic-local";
    if !has_configured_provider {
        return base;
    }

    let sys_prompt = "You are FlowAI File Search Planner for AetherFlow McBrowser. Convert a user's natural language file search query into a strict JSON object with keys: {\"phrase\": \"core title or subject phrase in lowercase\", \"required_tokens\": [\"lowercase\", \"significant\", \"keywords\"], \"optional_tokens\": [\"optional season/episode/variant tokens like s01\"], \"extensions\": [\"lowercase extensions without dot if user asked for specific file/media types, else empty\"], \"interpretation\": \"brief 1-sentence human-readable summary of how FlowAI interpreted the search\"}. Do not include filler words (find, show, files, episodes, etc.) in required_tokens. Output ONLY valid JSON.";

    let call_fut = crate::intelligence::call_configured_ai(&ps, sys_prompt, raw_query);
    let Ok(Ok(raw_resp)) = tokio::time::timeout(Duration::from_millis(3500), call_fut).await else {
        return base;
    };
    let cleaned = crate::intelligence::clean_json_fence(&raw_resp);
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cleaned) else {
        return base;
    };

    let mut plan = base;
    if let Some(p) = parsed.get("phrase").and_then(|v| v.as_str()).map(str::trim) {
        if !p.is_empty() {
            plan.phrase = p.to_lowercase();
        }
    }
    if let Some(arr) = parsed.get("required_tokens").and_then(|v| v.as_array()) {
        let toks: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty() && !NL_FILLER_WORDS.contains(&s.as_str()))
            .collect();
        if !toks.is_empty() {
            plan.required_tokens = toks;
        }
    }
    if let Some(arr) = parsed.get("extensions").and_then(|v| v.as_array()) {
        for ext in arr.iter().filter_map(|v| v.as_str()) {
            let clean_ext = ext.trim().trim_start_matches('.').to_lowercase();
            if !clean_ext.is_empty() && !plan.extensions.contains(&clean_ext) {
                plan.extensions.push(clean_ext);
            }
        }
    }
    if let Some(interp) = parsed
        .get("interpretation")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        plan.interpretation = interp.to_string();
    }
    plan.llm_used = true;
    plan
}

pub(super) async fn search_entries(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, true) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let kind_filter = match parse_search_type_filter(query.entry_type.as_deref()) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };

    let search_q = query.q.clone();
    let use_flowai = query.ai.unwrap_or(false);
    let nl_plan = if use_flowai && !search_q.trim().is_empty() {
        let base_plan = build_deterministic_nl_plan(&search_q);
        Some(enrich_nl_plan_with_flowai_llm(&search_q, base_plan).await)
    } else {
        None
    };

    let user_for_task = auth_user;
    let res = tokio::task::spawn_blocking(move || -> Result<SearchResponse, McBrowserError> {
        let conn = af_db::get_conn()
            .map_err(|_| McBrowserError::Internal("Database unavailable for search".to_string()))?;
        crate::mcbrowser::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::policy::Permission::Read,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let (walked, hit_walk_limit) = bfs
            .walk_for_search(&normalized_path, MAX_SEARCH_SCAN_ENTRIES)
            .map_err(|err| map_fs_io_error(err, "Failed to search directory"))?;

        let mut resp = if let Some(plan) = &nl_plan {
            let mut ai_resp = filter_and_rank_entries_with_flowai(
                walked.clone(),
                plan,
                kind_filter,
                MAX_SEARCH_ENTRIES,
            );
            if ai_resp.entries.is_empty() && !search_q.trim().is_empty() {
                // Fallback to literal/standard query if strict NL token filter returned 0 results
                let fallback =
                    filter_walked_entries(walked, &search_q, kind_filter, MAX_SEARCH_ENTRIES);
                if !fallback.entries.is_empty() {
                    ai_resp.entries = fallback.entries;
                    ai_resp.truncated = fallback.truncated;
                }
            }
            ai_resp
        } else {
            filter_walked_entries(walked, &search_q, kind_filter, MAX_SEARCH_ENTRIES)
        };
        if hit_walk_limit {
            resp.truncated = true;
        }
        resp.entries.retain(|entry| {
            crate::mcbrowser::policy::authorize_with_conn(
                &conn,
                &user_for_task,
                crate::mcbrowser::policy::Permission::Read,
                &entry.path,
            )
            .is_ok()
        });
        Ok(resp)
    })
    .await;

    match res {
        Ok(Ok(search_resp)) => Json(search_resp).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Search task failed".to_string()).into_response(),
    }
}
