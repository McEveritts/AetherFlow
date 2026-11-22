fn quote_closes_outer_span(after: Option<u8>, include_colon: bool) -> bool {
    match after {
        None => true,
        Some(n) if n.is_ascii_whitespace() => true,
        Some(b'"' | b'\'' | b',' | b'}' | b']' | b';' | b'&') => true,
        Some(b':') if include_colon => true,
        _ => false,
    }
}

/// Scan a `{...}` / `[...]` container. `Some(end)` is the index just past a
/// container that closed on this line (or ran to EOF). `None` means a newline
/// arrived before the opener closed, so the caller must leave the opener in
/// place for the multiline container redactor.
fn consume_balanced_container(bytes: &[u8], start: usize) -> Option<usize> {
    let mut stack = Vec::new();
    let open = bytes[start];
    stack.push(if open == b'{' { b'}' } else { b']' });
    let mut j = start + 1;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\r' || c == b'\n' {
            return None;
        }
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            j += 1;
            continue;
        }
        if c == b'\\' {
            j += 1;
            if j < bytes.len() && bytes[j] != b'\r' && bytes[j] != b'\n' {
                j += 1;
            }
            continue;
        }
        if c == b'"' || c == b'\'' {
            quote = Some(c);
            j += 1;
            continue;
        }
        if c == b'{' || c == b'[' {
            stack.push(if c == b'{' { b'}' } else { b']' });
            j += 1;
            continue;
        }
        if c == b'}' || c == b']' {
            if stack.last().copied() == Some(c) {
                stack.pop();
                j += 1;
                if stack.is_empty() {
                    return Some(j);
                }
                continue;
            }
            return None;
        }
        j += 1;
    }
    Some(j)
}

fn consume_plain_quoted(bytes: &[u8], quote_idx: usize) -> usize {
    let q = bytes[quote_idx];
    let mut j = quote_idx + 1;
    let mut bs = 0usize;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\\' {
            bs += 1;
            j += 1;
            continue;
        }
        if c == q && bs.is_multiple_of(2) {
            return j + 1;
        }
        bs = 0;
        j += 1;
    }
    bytes.len()
}

const REDACTED_URL_SHIELD: &str = "]AFURLKEEP";
const REDACTED_URL_SHIELD_LOWER: &str = "]afurlkeep";

fn shield_redacted_urls(input: &str) -> String {
    // `[REDACTED_URL]` is shaped like a JSON array, so the persisted container
    // redactor would collapse it to `[REDACTED]`. Rewrite it to `[REDACTED]`
    // plus a suffix that starts with `]`, which that scanner treats as a
    // terminator, and put the original marker back at the end.
    static MARKER_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| regex::Regex::new(r"\[REDACTED_(?:URL|url)\]").unwrap());
    MARKER_RE
        .replace_all(input, |captures: &regex::Captures| {
            let marker = captures.get(0).unwrap();
            let suffix = &input[marker.end()..];
            let standalone = match suffix.chars().next() {
                None => true,
                Some(quote @ ('\'' | '"')) => !suffix[quote.len_utf8()..].contains(quote),
                Some(next) => next.is_whitespace() || matches!(next, ',' | '}' | ']' | ';' | '&'),
            };
            if !standalone {
                "[REDACTED]".to_string()
            } else if marker.as_str() == "[REDACTED_URL]" {
                format!("[REDACTED]{REDACTED_URL_SHIELD}")
            } else {
                format!("[REDACTED]{REDACTED_URL_SHIELD_LOWER}")
            }
        })
        .into_owned()
}

fn unshield_redacted_urls(input: &str) -> String {
    input
        .replace(
            &format!("[REDACTED]{REDACTED_URL_SHIELD}"),
            "[REDACTED_URL]",
        )
        .replace(
            &format!("[REDACTED]{REDACTED_URL_SHIELD_LOWER}"),
            "[REDACTED_url]",
        )
}

fn starts_with_url_shield(s: &str) -> bool {
    s.starts_with(REDACTED_URL_SHIELD) || s.starts_with(REDACTED_URL_SHIELD_LOWER)
}

/// Length of a secret scalar starting at `s`.
///
/// The span is one shell/JSON token made of adjacent unquoted, backslash-escaped,
/// `$'...'` / `$"..."`, quoted, escaped-quoted, and balanced `{...}` / `[...]`
/// segments. `allow_comma_list` keeps internal commas (`password=part1,part2`)
/// while leaving a trailing separator comma in place. A finished `[REDACTED]`
/// marker stays put when the next quote closes an enclosing string, and a glued
/// suffix (`[REDACTED]SENTINEL`, `[REDACTED]"secret"`) is consumed with it.
fn consume_secret_scalar_value(s: &str, allow_comma_list: bool) -> usize {
    if s.starts_with("[REDACTED_URL]") || s.starts_with("[REDACTED_url]") {
        return "[REDACTED_URL]".len();
    }

    let bytes = s.as_bytes();
    let mut i = 0usize;
    if s.starts_with("[REDACTED]") {
        i = "[REDACTED]".len();
        if i >= bytes.len() {
            return i;
        }
        if starts_with_url_shield(&s[i..]) {
            return i;
        }
        let bs0 = bytes[i..].iter().take_while(|b| **b == b'\\').count();
        if i + bs0 < bytes.len() && matches!(bytes[i + bs0], b'"' | b'\'') {
            let after = bytes.get(i + bs0 + 1).copied();
            // `"[REDACTED]",` and `[REDACTED]\" https://...` close an enclosing
            // string. `[REDACTED]"secret"` / `[REDACTED]\"secret\"` do not.
            if quote_closes_outer_span(after, false)
                && (!after.is_some_and(|next| next.is_ascii_whitespace())
                    || !af_release::lifecycle::has_matching_secret_quote(bytes, i + bs0, bs0))
            {
                return i;
            }
        } else if bytes[i].is_ascii_whitespace()
            || matches!(bytes[i], b';' | b'}' | b']' | b'&')
            || (bytes[i] == b',' && !allow_comma_list)
        {
            return i;
        }
    }

    while i < bytes.len() {
        if bytes[i] == b'\r' || bytes[i] == b'\n' || starts_with_url_shield(&s[i..]) {
            break;
        }

        let mut as_unescaped_quote = false;
        if bytes[i] == b'$' && matches!(bytes.get(i + 1), Some(b'\'' | b'"')) {
            i += 1;
            as_unescaped_quote = true;
        } else if bytes[i] == b'\\' {
            let bs = bytes[i..].iter().take_while(|b| **b == b'\\').count();
            let nxt = bytes.get(i + bs).copied();
            if matches!(nxt, Some(b'"' | b'\'')) {
                let q = nxt.unwrap();
                let q_idx = i + bs;
                let after_q = bytes.get(q_idx + 1).copied();
                if i > 0
                    && quote_closes_outer_span(after_q, false)
                    && (!after_q.is_some_and(|next| next.is_ascii_whitespace())
                        || !af_release::lifecycle::has_matching_secret_quote(bytes, q_idx, bs))
                {
                    break;
                }
                let mut j = q_idx + 1;
                let mut inner_bs = 0usize;
                let mut stop_outer = false;
                while j < bytes.len() {
                    let c = bytes[j];
                    if c == b'\\' {
                        inner_bs += 1;
                        j += 1;
                        continue;
                    }
                    if c == q {
                        if inner_bs == 0 {
                            i = j;
                            stop_outer = true;
                            break;
                        }
                        if inner_bs == bs
                            || (inner_bs % 2 == 1 && escaped_quote_closes_payload(bytes, j))
                        {
                            i = j + 1;
                            if escaped_quote_closes_payload(bytes, j) {
                                stop_outer = true;
                            }
                            break;
                        }
                    }
                    inner_bs = 0;
                    j += 1;
                }
                if j >= bytes.len() && i < q_idx {
                    i = bytes.len();
                    break;
                }
                if stop_outer {
                    break;
                }
                continue;
            } else if matches!(nxt, Some(b'u' | b'U')) {
                i += bs + 1;
                continue;
            } else if let Some(nc) = nxt {
                if nc != b'\r' && nc != b'\n' {
                    i += bs + 1;
                    continue;
                }
                i += bs;
                break;
            } else {
                i += bs;
                break;
            }
        } else if matches!(bytes[i], b'"' | b'\'') {
            as_unescaped_quote = true;
        }

        if as_unescaped_quote {
            let q = bytes[i];
            if i > 0 {
                let after_q = bytes.get(i + 1).copied();
                if quote_closes_outer_span(after_q, true)
                    && (!after_q.is_some_and(|next| next.is_ascii_whitespace())
                        || !af_release::lifecycle::has_matching_secret_quote(bytes, i, 0))
                {
                    break;
                }
            }
            let end = consume_plain_quoted(bytes, i);
            if end <= i {
                break;
            }
            i = end;
            if i < bytes.len() && (bytes[i] == b'\r' || bytes[i] == b'\n') {
                break;
            }
            if i > 0 && bytes.get(i.saturating_sub(1)).copied() != Some(q) && i < bytes.len() {
                break;
            }
            continue;
        }

        if bytes[i] == b'{' || bytes[i] == b'[' {
            match consume_balanced_container(bytes, i) {
                Some(end) if end > i => {
                    i = end;
                    continue;
                }
                _ => break,
            }
        }

        if bytes[i].is_ascii_whitespace() || matches!(bytes[i], b';' | b'}' | b']' | b'&') {
            break;
        }
        if bytes[i] == b',' {
            if !allow_comma_list {
                break;
            }
            let next = bytes.get(i + 1).copied();
            let trailing_separator = match next {
                None => true,
                Some(n) => {
                    n.is_ascii_whitespace()
                        || matches!(n, b';' | b'"' | b'\'' | b'}' | b']' | b'&' | b',')
                }
            };
            if trailing_separator {
                break;
            }
        }
        if bytes[i] < 0x80 {
            i += 1;
        } else {
            let width = s[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
            i += width;
        }
    }
    i
}

fn escaped_quote_closes_payload(bytes: &[u8], quote_idx: usize) -> bool {
    let next = bytes.get(quote_idx + 1).copied();
    next.is_none()
        || matches!(
            next,
            Some(b'"' | b'\'' | b',' | b'}' | b']' | b'\r' | b'\n' | b' ')
        )
}

fn redact_prefixed_secrets(text: &str, prefix_re: &regex::Regex, allow_comma_list: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while cursor < text.len() {
        let slice = &text[cursor..];
        let Some(mat) = prefix_re.find(slice) else {
            out.push_str(slice);
            break;
        };
        if mat.end() == 0 {
            out.push_str(slice);
            break;
        }
        out.push_str(&slice[..mat.end()]);
        let value_off = cursor + mat.end();
        if af_release::lifecycle::is_complete_redacted_header(
            &slice[mat.start()..mat.end()],
            &text[value_off..],
        ) {
            cursor = value_off;
            continue;
        }
        let n = consume_secret_scalar_value(&text[value_off..], allow_comma_list);
        if n == 0 {
            // An unclosed `{` / `[` at the value start belongs to the multiline
            // container redactor. Advancing past the prefix leaves that text intact.
            cursor = value_off;
            continue;
        }
        let consumed = &text[value_off..value_off + n];
        if consumed == "[REDACTED]" || consumed.eq_ignore_ascii_case("[REDACTED_URL]") {
            out.push_str(consumed);
        } else {
            out.push_str("[REDACTED]");
        }
        cursor = value_off + n;
    }
    out
}

fn redact_scalar_cli_and_curl_secrets(text: &str) -> String {
    static CURL_PREFIX_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r#"(?i)(?:^|[^A-Za-z0-9])(?:--user(?:\s+|=)|-u\s*)"#).unwrap()
    });
    static CLI_FLAG_PREFIX_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(
        || {
            regex::Regex::new(
            r#"(?i)(?:^|[^A-Za-z0-9])(--(?:password|passwd|api-key|apikey|cookies|cookie|secret|token|session|webhook|pwd|pass))(?:\s+|=)"#,
        )
        .unwrap()
        },
    );
    let with_curl = redact_prefixed_secrets(text, &CURL_PREFIX_RE, true);
    let with_kv = redact_prefixed_secrets(
        &with_curl,
        &af_release::lifecycle::SENSITIVE_ASSIGNMENT_PREFIX_RE,
        true,
    );
    redact_prefixed_secrets(&with_kv, &CLI_FLAG_PREFIX_RE, true)
}

fn find_closing_header_quote(val: &str, pre: &str) -> Option<usize> {
    af_release::lifecycle::find_closing_header_quote(val, pre)
}

pub fn sanitize_lifecycle_field(raw: &str) -> String {
    let normalized = af_release::lifecycle::normalize_unicode_escaped_sensitive_keys(raw);
    let shielded = shield_redacted_urls(&normalized);
    let raw = shielded.as_str();
    static HTTP_HEADER_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?im)(?P<pre>\\*["'])?\b(?P<hdr>Set-Cookie|Cookie|Proxy-Authorization|X-Api-Key|X-Auth-Token|Authorization)\s*:\s*(?P<val>[^\r\n]+)"#
        ).unwrap()
    });
    static SENSITIVE_JSON_NESTED_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| {
            regex::Regex::new(
            r#"(?i)("[\w.-]*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|bearer|cookie|session|webhook|passphrase|rclone_pass|jwt_secret)[\w.-]*"\s*:\s*)(\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\])"#
        ).unwrap()
        });
    static SENSITIVE_RAW_NESTED_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| {
            regex::Regex::new(
            r#"(?i)(["']?[\w.-]*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|bearer|cookie|session|webhook|passphrase|rclone_pass|jwt_secret)[\w.-]*["']?\s*[:=]\s*)(\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\])"#
        ).unwrap()
        });
    static BEARER_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r#"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"#).unwrap()
    });
    static BASIC_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r#"(?i)\bBasic\s+[A-Za-z0-9+/=]+"#).unwrap()
    });

    let sanitize_http_headers = |text: &str| -> String {
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        while cursor < text.len() {
            let slice = &text[cursor..];
            let Some(caps) = HTTP_HEADER_RE.captures(slice) else {
                out.push_str(slice);
                break;
            };
            let full = caps.get(0).unwrap();
            let pre = caps.name("pre").map(|m| m.as_str()).unwrap_or("");
            let hdr = caps.name("hdr").map(|m| m.as_str()).unwrap_or("");
            let val_match = caps.name("val").unwrap();
            let val = val_match.as_str();
            out.push_str(&slice[..full.start()]);
            if !pre.is_empty() {
                if let Some(close_idx) = find_closing_header_quote(val, pre) {
                    let close_len = if val[close_idx..].starts_with(pre) {
                        pre.len()
                    } else {
                        1
                    };
                    out.push_str(&format!(
                        "{pre}{hdr}: [REDACTED]{}",
                        &val[close_idx..close_idx + close_len]
                    ));
                    cursor += val_match.start() + close_idx + close_len;
                    continue;
                }
                out.push_str(&format!("{pre}{hdr}: [REDACTED]"));
            } else {
                out.push_str(&format!("{hdr}: [REDACTED]"));
            }
            cursor += full.end();
        }
        out
    };

    let sanitize_nested = |text: &str| -> String {
        let s = SENSITIVE_JSON_NESTED_RE.replace_all(text, |caps: &regex::Captures| {
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if redacted_container_value(val) {
                format!("{prefix}{val}")
            } else {
                format!("{prefix}\"[REDACTED]\"")
            }
        });
        SENSITIVE_RAW_NESTED_RE
            .replace_all(&s, |caps: &regex::Captures| {
                let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                if redacted_container_value(val) {
                    format!("{prefix}{val}")
                } else {
                    format!("{prefix}[REDACTED]")
                }
            })
            .into_owned()
    };

    let s_headers = sanitize_http_headers(raw);
    // The local scanner runs first so a shell escape (`\ `, `\;`, `$'...'`,
    // concatenated quotes) is consumed as one token. The persisted scanner
    // stops at the first unescaped space or separator and would otherwise
    // leave the remainder of that token behind. It still runs next so nested
    // containers and URL credentials are redacted, then the local scanner
    // runs again for any leaked `[REDACTED]...` suffix.
    let s_local = redact_scalar_cli_and_curl_secrets(&s_headers);
    let s_persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(&s_local);
    let s3 = redact_scalar_cli_and_curl_secrets(&s_persisted);
    let s3_nested = sanitize_nested(&s3);
    let s4 = redact_scalar_cli_and_curl_secrets(&s3_nested);
    let s5 = BEARER_RE.replace_all(&s4, "Bearer [REDACTED]");
    let s6 = BASIC_RE.replace_all(&s5, "Basic [REDACTED]");
    unshield_redacted_urls(&sanitize_http_headers(&s6))
}

fn redacted_container_value(val: &str) -> bool {
    matches!(
        val,
        "[REDACTED]"
            | "\"[REDACTED]\""
            | "[REDACTED_URL]"
            | "[REDACTED_url]"
            | "\"[REDACTED_URL]\""
            | "\"[REDACTED_url]\""
    ) || val.eq_ignore_ascii_case("[REDACTED_URL]")
        || val.eq_ignore_ascii_case("\"[REDACTED_URL]\"")
}
