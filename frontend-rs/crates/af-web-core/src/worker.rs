#[cfg(any(feature = "worker-engine", test))]
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_EDITOR_BYTES: usize = 256 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SearchItem {
    pub id: String,
    pub text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SearchMatch {
    pub id: String,
    pub text: String,
    pub score: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenSpan {
    pub start: usize,
    pub end: usize,
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StreamingSample {
    pub timestamp_ms: i64,
    pub values: BTreeMap<String, f64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BucketValue {
    pub count: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StreamingBucket {
    pub timestamp_ms: i64,
    pub values: BTreeMap<String, BucketValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum WorkerRequest {
    Sha256Chunk {
        bytes: Vec<u8>,
    },
    Sha256Batch {
        chunks: Vec<Vec<u8>>,
    },
    FuzzySearch {
        query: String,
        items: Vec<SearchItem>,
        limit: usize,
    },
    TokenizeCode {
        code: String,
        language: String,
    },
    RenderMarkdown {
        source: String,
    },
    FindReplace {
        code: String,
        pattern: String,
        replacement: Option<String>,
        regex: bool,
        case_sensitive: bool,
    },
    AggregateStreaming {
        samples: Vec<StreamingSample>,
        bucket_ms: i64,
    },
    BuildExportPayload {
        rows: Vec<BTreeMap<String, serde_json::Value>>,
        format: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum WorkerResponse {
    Hash {
        hex: String,
    },
    HashBatch {
        hashes: Vec<String>,
        combined: String,
    },
    SearchResults {
        items: Vec<SearchMatch>,
    },
    Tokens {
        spans: Vec<TokenSpan>,
    },
    RenderedMarkdown {
        html: String,
    },
    FindResult {
        ranges: Vec<(usize, usize)>,
        text: String,
        replacements: usize,
    },
    Aggregated {
        buckets: Vec<StreamingBucket>,
    },
    Export {
        content: String,
        mime: String,
        extension: String,
    },
    Error {
        message: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerEnvelope<T> {
    pub id: u64,
    pub message: T,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Hash a transferred JS buffer in bounded slices. The worker transport owns
/// the ArrayBuffer and never serializes the bytes as JSON Array<number>.
#[cfg(target_arch = "wasm32")]
pub fn sha256_array(bytes: &js_sys::Uint8Array) -> String {
    let mut hash = Sha256::new();
    update_sha256_array(&mut hash, bytes);
    format!("{:x}", hash.finalize())
}
#[cfg(target_arch = "wasm32")]
fn update_sha256_array(hash: &mut Sha256, bytes: &js_sys::Uint8Array) {
    let mut scratch = [0u8; 64 * 1024];
    let mut offset = 0u32;
    while offset < bytes.length() {
        let end = offset
            .saturating_add(scratch.len() as u32)
            .min(bytes.length());
        let chunk = &mut scratch[..(end - offset) as usize];
        bytes.subarray(offset, end).copy_to(chunk);
        hash.update(chunk);
        offset = end;
    }
}
#[cfg(target_arch = "wasm32")]
pub fn sha256_array_batch(chunks: &[js_sys::Uint8Array]) -> (Vec<String>, String) {
    let mut combined = Sha256::new();
    let hashes = chunks
        .iter()
        .map(|chunk| {
            update_sha256_array(&mut combined, chunk);
            sha256_array(chunk)
        })
        .collect();
    (hashes, format!("{:x}", combined.finalize()))
}
pub fn fuzzy_search(query: &str, items: &[SearchItem], limit: usize) -> Vec<SearchMatch> {
    let query = query.trim().to_lowercase();
    let mut matches: Vec<_> = items
        .iter()
        .filter_map(|item| {
            let text = item.text.to_lowercase();
            let score = if query.is_empty() {
                0
            } else if let Some(index) = text.find(&query) {
                10_000 - index as i64 * 10 - (text.len() - query.len()) as i64
            } else {
                let mut offset = 0;
                let mut score = 0;
                let mut previous = None;
                for target in query.chars() {
                    let found = text[offset..].find(target)? + offset;
                    score += 100 - (found - offset) as i64;
                    if previous.is_some_and(|p| p == found) {
                        score += 40;
                    }
                    if found == 0
                        || text[..found]
                            .chars()
                            .next_back()
                            .is_some_and(|c| !c.is_alphanumeric())
                    {
                        score += 60;
                    }
                    offset = found + target.len_utf8();
                    previous = Some(offset);
                }
                score - text.chars().count() as i64
            };
            Some(SearchMatch {
                id: item.id.clone(),
                text: item.text.clone(),
                score,
            })
        })
        .collect();
    matches.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.text.cmp(&b.text))
            .then_with(|| a.id.cmp(&b.id))
    });
    matches.truncate(limit);
    matches
}

/// Byte spans always end on UTF-8 boundaries. Literal source is escaped by the
/// renderer; worker output contains no executable markup.
pub fn tokenize_code(code: &str, language: &str) -> Vec<TokenSpan> {
    let lang = language.to_ascii_lowercase();
    let hash_comments = matches!(
        lang.as_str(),
        "python" | "py" | "toml" | "yaml" | "yml" | "shell" | "sh" | "bash" | "ini"
    );
    let slash_comments = matches!(
        lang.as_str(),
        "rust" | "rs" | "go" | "javascript" | "js" | "typescript" | "ts" | "tsx" | "jsx" | "css"
    );
    let sql = lang == "sql";
    let markup = matches!(lang.as_str(), "html" | "xml" | "markdown" | "md");
    let keywords="fn let mut pub use mod impl struct enum trait match if else for while loop return async await move const static type where self Self crate super true false null None Some Ok Err function var new class import export from default try catch throw interface extends package func defer range go select chan map nil def lambda with as in is and or not pass elif except finally yield True False None select SELECT from FROM where WHERE insert INSERT into INTO update UPDATE delete DELETE create CREATE table TABLE join JOIN order ORDER by BY group GROUP having HAVING limit LIMIT set SET values VALUES primary PRIMARY key KEY echo then fi do done esac case sudo";
    let mut spans = Vec::new();
    let mut i = 0;
    while i < code.len() {
        let rest = &code[i..];
        let c = rest.chars().next().expect("nonempty");
        let start = i;
        let (end, kind) = if (hash_comments && c == '#')
            || (slash_comments && rest.starts_with("//"))
            || (sql && rest.starts_with("--"))
            || (lang == "ini" && c == ';')
        {
            (i + rest.find('\n').unwrap_or(rest.len()), "comment")
        } else if slash_comments && rest.starts_with("/*") {
            (
                i + rest.find("*/").map(|p| p + 2).unwrap_or(rest.len()),
                "comment",
            )
        } else if markup && rest.starts_with("<!--") {
            (
                i + rest.find("-->").map(|p| p + 3).unwrap_or(rest.len()),
                "comment",
            )
        } else if matches!(c, '\'' | '"' | '`') {
            let mut end = i + c.len_utf8();
            let mut escaped = false;
            for (offset, ch) in rest[c.len_utf8()..].char_indices() {
                end = i + c.len_utf8() + offset + ch.len_utf8();
                if ch == c && !escaped {
                    break;
                }
                escaped = ch == '\\' && !escaped;
            }
            (end, "string")
        } else if c.is_ascii_digit() {
            (
                i + rest
                    .find(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '_'))
                    .unwrap_or(rest.len()),
                "number",
            )
        } else if c.is_alphabetic() || c == '_' || c == '$' {
            let end = i + rest
                .find(|ch: char| !ch.is_alphanumeric() && !matches!(ch, '_' | '$' | '-'))
                .unwrap_or(rest.len());
            let word = &code[i..end];
            (
                end,
                if keywords.split_whitespace().any(|k| k == word) {
                    "keyword"
                } else if code[end..].trim_start().starts_with('(') {
                    "function"
                } else if lang == "json"
                    || matches!(lang.as_str(), "yaml" | "yml" | "toml" | "ini")
                        && code[end..].trim_start().starts_with([':', '='])
                {
                    "property"
                } else {
                    "plain"
                },
            )
        } else if markup && c == '<' {
            (
                i + rest.find('>').map(|p| p + 1).unwrap_or(rest.len()),
                "tag",
            )
        } else if matches!(lang.as_str(), "markdown" | "md")
            && matches!(c, '#' | '*' | '_' | '[' | ']')
        {
            (i + c.len_utf8(), "keyword")
        } else {
            (i + c.len_utf8(), "plain")
        };
        i = end.max(start + c.len_utf8());
        if kind != "plain" {
            spans.push(TokenSpan {
                start,
                end: i,
                kind: kind.into(),
            });
        }
    }
    spans
}

pub fn aggregate_streaming(
    samples: &[StreamingSample],
    bucket_ms: i64,
) -> Result<Vec<StreamingBucket>, String> {
    if bucket_ms <= 0 {
        return Err("Bucket duration must be positive".into());
    }
    let mut buckets: BTreeMap<i64, BTreeMap<String, BucketValue>> = BTreeMap::new();
    for sample in samples {
        let time = sample
            .timestamp_ms
            .div_euclid(bucket_ms)
            .checked_mul(bucket_ms)
            .ok_or("Bucket timestamp overflow")?;
        let values = buckets.entry(time).or_default();
        for (key, value) in sample.values.iter().filter(|(_, v)| v.is_finite()) {
            let entry = values.entry(key.clone()).or_insert(BucketValue {
                count: 0,
                sum: 0.0,
                min: *value,
                max: *value,
                mean: 0.0,
            });
            entry.count += 1;
            entry.sum += value;
            entry.min = entry.min.min(*value);
            entry.max = entry.max.max(*value);
            entry.mean = entry.sum / entry.count as f64;
        }
    }
    Ok(buckets
        .into_iter()
        .map(|(timestamp_ms, values)| StreamingBucket {
            timestamp_ms,
            values,
        })
        .collect())
}
fn csv_cell(text: &str) -> String {
    let safe = if text
        .trim_start()
        .starts_with(['=', '+', '-', '@', '\t', '\r'])
    {
        format!("'{text}")
    } else {
        text.to_string()
    };
    format!("\"{}\"", safe.replace('"', "\"\""))
}
/// Emergency main-thread search needs no regex engine. Map folded character
/// boundaries back to the source so multibyte offsets remain safe for editors.
#[cfg(any(not(feature = "worker-engine"), test))]
fn literal_find_replace(
    code: &str,
    pattern: &str,
    replacement: Option<&str>,
    case_sensitive: bool,
) -> (Vec<(usize, usize)>, String) {
    if pattern.is_empty() {
        return (Vec::new(), code.to_string());
    }
    let ranges: Vec<_> = if case_sensitive {
        code.match_indices(pattern)
            .map(|(start, matched)| (start, start + matched.len()))
            .collect()
    } else {
        let mut folded = String::with_capacity(code.len());
        let mut boundaries = vec![(0, 0)];
        for (start, ch) in code.char_indices() {
            folded.extend(ch.to_lowercase());
            boundaries.push((folded.len(), start + ch.len_utf8()));
        }
        folded
            .match_indices(&pattern.to_lowercase())
            .filter_map(|(start, matched)| {
                let source_offset = |offset| {
                    boundaries
                        .binary_search_by_key(&offset, |&(folded, _)| folded)
                        .ok()
                        .map(|index| boundaries[index].1)
                };
                Some((source_offset(start)?, source_offset(start + matched.len())?))
            })
            .collect()
    };
    let text = if let Some(replacement) = replacement {
        let mut text = String::with_capacity(code.len());
        let mut cursor = 0;
        for &(start, end) in &ranges {
            text.push_str(&code[cursor..start]);
            text.push_str(replacement);
            cursor = end;
        }
        text.push_str(&code[cursor..]);
        text
    } else {
        code.to_string()
    };
    (ranges, text)
}

pub fn execute_worker_request(request: WorkerRequest) -> WorkerResponse {
    let error = |message: String| WorkerResponse::Error { message };
    match request {
        WorkerRequest::Sha256Chunk { bytes } => WorkerResponse::Hash {
            hex: sha256_hex(&bytes),
        },
        WorkerRequest::Sha256Batch { chunks } => {
            let mut combined = Sha256::new();
            let hashes = chunks
                .iter()
                .map(|chunk| {
                    combined.update(chunk);
                    sha256_hex(chunk)
                })
                .collect();
            WorkerResponse::HashBatch {
                hashes,
                combined: format!("{:x}", combined.finalize()),
            }
        }
        WorkerRequest::FuzzySearch {
            query,
            items,
            limit,
        } => WorkerResponse::SearchResults {
            items: fuzzy_search(&query, &items, limit),
        },
        WorkerRequest::TokenizeCode { code, language } => {
            if code.len() > MAX_EDITOR_BYTES {
                return error("Editor limit is 256 KiB".into());
            }
            WorkerResponse::Tokens {
                spans: tokenize_code(&code, &language),
            }
        }
        WorkerRequest::RenderMarkdown { source } => WorkerResponse::RenderedMarkdown {
            html: crate::markdown::render_markdown(&source),
        },
        WorkerRequest::FindReplace {
            code,
            pattern,
            replacement,
            regex,
            case_sensitive,
        } => {
            if code.len() > MAX_EDITOR_BYTES {
                return error("Editor limit is 256 KiB".into());
            }
            #[cfg(not(any(feature = "worker-engine", test)))]
            if regex {
                return error("Regex search requires an available Web Worker".into());
            }
            if pattern.is_empty() {
                return WorkerResponse::FindResult {
                    ranges: vec![],
                    text: code,
                    replacements: 0,
                };
            }
            #[cfg(any(feature = "worker-engine", test))]
            let (ranges, text) = {
                let pattern = if regex {
                    pattern
                } else {
                    regex::escape(&pattern)
                };
                let compiled: Regex = match RegexBuilder::new(&pattern)
                    .case_insensitive(!case_sensitive)
                    .size_limit(2 * 1024 * 1024)
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => return error(e.to_string()),
                };
                let ranges: Vec<_> = compiled
                    .find_iter(&code)
                    .take(MAX_EDITOR_BYTES)
                    .map(|m| (m.start(), m.end()))
                    .collect();
                let text = replacement.as_ref().map_or_else(
                    || code.clone(),
                    |replacement| {
                        if regex {
                            compiled
                                .replace_all(&code, replacement.as_str())
                                .into_owned()
                        } else {
                            compiled
                                .replace_all(&code, regex::NoExpand(replacement))
                                .into_owned()
                        }
                    },
                );
                (ranges, text)
            };
            #[cfg(not(any(feature = "worker-engine", test)))]
            let (ranges, text) =
                literal_find_replace(&code, &pattern, replacement.as_deref(), case_sensitive);
            let replacements = if replacement.is_some() {
                ranges.len()
            } else {
                0
            };
            if text.len() > MAX_EDITOR_BYTES {
                return error("Replacement exceeds 256 KiB editor limit".into());
            }
            WorkerResponse::FindResult {
                ranges,
                text,
                replacements,
            }
        }
        WorkerRequest::AggregateStreaming { samples, bucket_ms } => {
            match aggregate_streaming(&samples, bucket_ms) {
                Ok(buckets) => WorkerResponse::Aggregated { buckets },
                Err(e) => error(e),
            }
        }
        WorkerRequest::BuildExportPayload { rows, format } => {
            if format.eq_ignore_ascii_case("json") {
                return match serde_json::to_string_pretty(&rows) {
                    Ok(content) => WorkerResponse::Export {
                        content,
                        mime: "application/json".into(),
                        extension: "json".into(),
                    },
                    Err(e) => error(e.to_string()),
                };
            }
            if !format.eq_ignore_ascii_case("csv") {
                return error("Export format must be CSV or JSON".into());
            }
            let keys: std::collections::BTreeSet<_> =
                rows.iter().flat_map(|row| row.keys().cloned()).collect();
            let mut lines = vec![keys
                .iter()
                .map(|k| csv_cell(k))
                .collect::<Vec<_>>()
                .join(",")];
            for row in rows {
                lines.push(
                    keys.iter()
                        .map(|k| match row.get(k) {
                            Some(serde_json::Value::String(s)) => csv_cell(s),
                            Some(serde_json::Value::Number(n)) => n.to_string(),
                            Some(v) => csv_cell(&v.to_string()),
                            None => String::new(),
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            WorkerResponse::Export {
                content: lines.join("\r\n"),
                mime: "text/csv;charset=utf-8".into(),
                extension: "csv".into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn batch_hashes_chunks_and_combined_stream() {
        let result = execute_worker_request(WorkerRequest::Sha256Batch {
            chunks: vec![b"a".to_vec(), b"bc".to_vec()],
        });
        match result {
            WorkerResponse::HashBatch { hashes, combined } => {
                assert_eq!(hashes.len(), 2);
                assert_eq!(combined, sha256_hex(b"abc"));
            }
            _ => panic!("wrong response"),
        }
    }
    #[test]
    fn fuzzy_prefers_substrings_is_unicode_safe_and_stable() {
        let items = vec![
            SearchItem {
                id: "1".into(),
                text: "Service Monitor".into(),
            },
            SearchItem {
                id: "2".into(),
                text: "Services".into(),
            },
            SearchItem {
                id: "3".into(),
                text: "Übersicht".into(),
            },
        ];
        assert_eq!(fuzzy_search("services", &items, 5)[0].id, "2");
        assert_eq!(fuzzy_search("übt", &items, 5)[0].id, "3");
        assert!(fuzzy_search("zzzz", &items, 5).is_empty());
        assert_eq!(fuzzy_search("", &items, 1).len(), 1);
    }
    #[test]
    fn syntax_spans_are_ordered_utf8_safe_for_all_supported_languages() {
        for language in [
            "rust",
            "go",
            "python",
            "js",
            "typescript",
            "json",
            "toml",
            "yaml",
            "shell",
            "markdown",
            "html",
            "css",
            "sql",
            "ini",
        ] {
            let code = "let café = \"世界\"; # comment\nSELECT 42";
            let spans = tokenize_code(code, language);
            assert!(spans.iter().all(|s| code.get(s.start..s.end).is_some()));
            assert!(spans.windows(2).all(|s| s[0].end <= s[1].start));
            assert!(spans.iter().any(|s| s.kind == "number"));
        }
    }
    #[test]
    fn comments_and_strings_are_not_executable_html() {
        let spans = tokenize_code("// <script>\nlet x = \"hello\";", "rust");
        assert_eq!(spans[0].kind, "comment");
        assert!(spans.iter().any(|s| s.kind == "string"));
    }
    #[test]
    fn literal_replacements_do_not_expand_dollars() {
        let response = execute_worker_request(WorkerRequest::FindReplace {
            code: "Aa aa".into(),
            pattern: "aa".into(),
            replacement: Some("$1".into()),
            regex: false,
            case_sensitive: false,
        });
        match response {
            WorkerResponse::FindResult {
                text, replacements, ..
            } => {
                assert_eq!(text, "$1 $1");
                assert_eq!(replacements, 2);
            }
            _ => panic!("wrong response"),
        }
    }
    #[test]
    fn emergency_literal_search_keeps_unicode_offsets_and_literal_replacements() {
        let code = "CAFÉ café café.* İ";
        let (ranges, text) = literal_find_replace(code, "café", Some("$1"), false);
        assert_eq!(ranges, vec![(0, 5), (6, 11), (12, 17)]);
        assert_eq!(text, "$1 $1 $1.* İ");
        assert_eq!(
            literal_find_replace(code, "café.*", Some("found"), true).1,
            "CAFÉ café found İ"
        );
        assert_eq!(
            literal_find_replace(code, "i\u{307}", None, false).0,
            vec![(20, 22)]
        );
        assert!(literal_find_replace(code, "i", None, false).0.is_empty());
        assert_eq!(
            literal_find_replace(code, "", Some("unused"), false).1,
            code
        );
        assert!(literal_find_replace(code, "missing", None, false)
            .0
            .is_empty());
    }
    #[test]
    fn regex_captures_and_invalid_patterns() {
        let request = |pattern: &str| WorkerRequest::FindReplace {
            code: "item42".into(),
            pattern: pattern.into(),
            replacement: Some("$1!".into()),
            regex: true,
            case_sensitive: true,
        };
        assert!(matches!(
            execute_worker_request(request("[")),
            WorkerResponse::Error { .. }
        ));
        assert!(
            matches!(execute_worker_request(request("item([0-9]+)")),WorkerResponse::FindResult{text,..}if text=="42!")
        );
    }
    #[test]
    fn regex_find_replace_preserves_multibyte_utf8_boundaries() {
        let code = "let café = 42;";
        for (pattern, replacement, expected) in [
            (r"\w+", "name", "name name = name;"),
            (r"\d+", "num", "let café = num;"),
            ("é", "e", "let cafe = 42;"),
            ("CAFÉ", "name", "let name = 42;"),
            ("", "unused", code),
        ] {
            let response = execute_worker_request(WorkerRequest::FindReplace {
                code: code.into(),
                pattern: pattern.into(),
                replacement: Some(replacement.into()),
                regex: true,
                case_sensitive: false,
            });
            match response {
                WorkerResponse::FindResult { ranges, text, .. } => {
                    assert_eq!(text, expected);
                    assert!(ranges
                        .iter()
                        .all(|&(start, end)| code.get(start..end).is_some()));
                }
                _ => panic!("wrong response for {pattern}"),
            }
        }
        for (code, pattern, expected) in [
            ("fn café() {}", "fn .*", vec![(0, 13)]),
            ("let name = \"café\";", "\"[^\"]+\"", vec![(11, 18)]),
            ("é世", ".", vec![(0, 2), (2, 5)]),
        ] {
            let response = execute_worker_request(WorkerRequest::FindReplace {
                code: code.into(),
                pattern: pattern.into(),
                replacement: None,
                regex: true,
                case_sensitive: true,
            });
            let WorkerResponse::FindResult { ranges, text, .. } = response else {
                panic!("expected UTF-8 matches for {pattern}: {response:?}");
            };
            assert_eq!(ranges, expected);
            assert_eq!(text, code);
            assert!(ranges
                .iter()
                .all(|&(start, end)| code.get(start..end).is_some()));
        }
    }
    #[test]
    fn enforces_editor_size_limit() {
        assert!(matches!(
            execute_worker_request(WorkerRequest::TokenizeCode {
                code: "x".repeat(MAX_EDITOR_BYTES + 1),
                language: "rust".into()
            }),
            WorkerResponse::Error { .. }
        ));
    }
    #[test]
    fn aggregation_sorts_buckets_and_computes_real_rollups() {
        let samples = [(1100, 2.0), (1000, 4.0), (-1, 8.0)]
            .into_iter()
            .map(|(timestamp_ms, v)| StreamingSample {
                timestamp_ms,
                values: BTreeMap::from([("cpu".into(), v)]),
            })
            .collect::<Vec<_>>();
        let result = aggregate_streaming(&samples, 1000).unwrap();
        assert_eq!(result[0].timestamp_ms, -1000);
        assert_eq!(result[1].values["cpu"].mean, 3.0);
        assert_eq!(result[1].values["cpu"].count, 2);
        assert!(aggregate_streaming(&samples, 0).is_err());
    }
    #[test]
    fn csv_escapes_quotes_newlines_and_spreadsheet_formulas() {
        let response = execute_worker_request(WorkerRequest::BuildExportPayload {
            rows: vec![BTreeMap::from([
                ("name".into(), serde_json::json!("=cmd(\"x\")\n")),
                ("value".into(), serde_json::json!(-12)),
            ])],
            format: "csv".into(),
        });
        assert!(
            matches!(response,WorkerResponse::Export{content,..}if content.contains("'=cmd(\"\"x\"\")")&&content.contains("-12"))
        );
    }
    #[test]
    fn protocol_roundtrips_all_operation_payloads() {
        let request = WorkerEnvelope {
            id: 7,
            message: WorkerRequest::Sha256Chunk {
                bytes: vec![0, 255, 42],
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        let copy: WorkerEnvelope<WorkerRequest> = serde_json::from_str(&json).unwrap();
        assert_eq!(copy.id, 7);
        assert_eq!(copy.message, request.message);
    }
}
