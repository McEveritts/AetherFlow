use anyhow::{Context, Result};
pub use libc;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

const SENSITIVE_DIAGNOSTIC_KEY_PATTERN: &str = r"(?:[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credentials?|bearer|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|jwt[_-]?secret)[A-Za-z0-9_.-]*|\b(?:[A-Za-z0-9]*[_.-])?pass(?:[_.-][A-Za-z0-9]*)*\b)";

pub static SENSITIVE_ASSIGNMENT_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&[
        r#"(?i)((?:\\*['"])?"#,
        SENSITIVE_DIAGNOSTIC_KEY_PATTERN,
        r#"(?:\\*['"])?\s*[:=]\s*)"#,
    ].concat()).unwrap()
});

pub fn is_sensitive_diagnostic_key(key: &str) -> bool {
    static SENSITIVE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(r"(?i)^{}$", SENSITIVE_DIAGNOSTIC_KEY_PATTERN)).unwrap()
    });
    SENSITIVE_KEY_RE.is_match(key)
}

static BEARER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+").unwrap());
static BASIC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+").unwrap());
pub static SENSITIVE_HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?im)(?P<pre>\\*["'])?\b(?P<hdr>Set-Cookie|Cookie|Proxy-Authorization|X-Api-Key|X-Auth-Token|Authorization)\s*:\s*(?P<val>[^\r\n]+)"#).unwrap()
});
static URL_CRED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+(?::[^/\s@]+)?@").unwrap());
pub static SENSITIVE_JSON_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)((?:\\?['"])?(?:[A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|passphrase|rclone[_-]?(?:rc[_-]?)?pass|jwt[_-]?secret|master[_-]?pass)[A-Za-z0-9_.-]*|\b(?:[A-Za-z0-9]*[_.\-])?pass(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?cookies?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?session(?:[_.\-]?(?:id|key|token|secret))?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?webhook(?:[_.\-]?(?:url|secret|token|key))?(?:[_.\-][A-Za-z0-9]*)*\b)(?:\\?['"])?)(\s*:\s*)(?:\\"(?:\\\\\\"|\\\\\\\\|\\\\[^"]|[^"\\])*\\"?|"(?:\\.|[^"\\])*"?|'(?:\\.|[^'\\])*'?|\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\]|[^\s,;{}\x5b\x5d]+(?:,[^\s,;\"{}\x5b\x5d]+)*)"#).unwrap()
});
static SENSITIVE_CONTAINER_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&[
        r#"(?i)(?:\\*["'])?\b"#,
        SENSITIVE_DIAGNOSTIC_KEY_PATTERN,
        r#"\b(?:\\*["'])?\s*[:=]\s*([\{\[])"#,
    ].concat()).unwrap()
});

pub fn redact_sensitive_nested_containers(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;

    while cursor < input.len() {
        let Some(caps) = SENSITIVE_CONTAINER_KEY_RE.captures(&input[cursor..]) else {
            out.push_str(&input[cursor..]);
            break;
        };
        let _m = caps.get(0).unwrap();
        let grp1 = caps.get(1).unwrap();
        let container_start = cursor + grp1.start();

        // Push everything up to container_start (including the key and delimiter)
        out.push_str(&input[cursor..container_start]);

        // Scan forward from container_start tracking depth and quotes across all chars including \r and \n
        let mut depth = 0usize;
        let mut in_quote: Option<char> = None;
        let mut escaped = false;
        let mut container_end = input.len();

        for (offset, ch) in input[container_start..].char_indices() {
            if let Some(q) = in_quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    in_quote = None;
                }
            } else {
                if ch == '"' || ch == '\'' {
                    in_quote = Some(ch);
                    escaped = false;
                } else if ch == '{' || ch == '[' {
                    depth += 1;
                } else if ch == '}' || ch == ']' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        container_end = container_start + offset + ch.len_utf8();
                        break;
                    }
                }
            }
        }

        out.push_str("[REDACTED]");
        cursor = container_end;
    }

    out
}

fn is_diagnostic_command_tail(value: &str) -> bool {
    static COMMAND_TAIL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^-{1,2}[A-Za-z][A-Za-z0-9-]*(?:\s|=|$)").unwrap()
    });
    COMMAND_TAIL_RE.is_match(value)
}

pub fn find_closing_header_quote(raw_val: &str, pre: &str) -> Option<usize> {
    let quote_ch = pre.chars().last()?;
    let escape_depth = pre.bytes().take_while(|byte| *byte == b'\\').count();
    let mut backslashes = 0usize;
    for (idx, ch) in raw_val.char_indices() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == quote_ch {
            if escape_depth > 0 {
                let following = raw_val[idx + ch.len_utf8()..].trim_start();
                if backslashes <= escape_depth
                    && (following.is_empty()
                        || is_diagnostic_command_tail(following)
                        || following.starts_with("https://")
                        || following.starts_with("http://")
                        || following.starts_with([',', '}', ']']))
                {
                    return Some(idx - backslashes);
                }
            } else if backslashes % 2 == 0 {
                return Some(idx);
            }
        }
        backslashes = 0;
    }
    None
}

pub fn redact_sensitive_headers(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;

    while cursor < input.len() {
        let Some(caps) = SENSITIVE_HEADER_RE.captures(&input[cursor..]) else {
            out.push_str(&input[cursor..]);
            break;
        };

        let mat = caps.get(0).unwrap();
        let match_start = cursor + mat.start();
        out.push_str(&input[cursor..match_start]);

        let pre = caps.name("pre").map(|m| m.as_str()).unwrap_or("");
        let hdr = caps.name("hdr").map(|m| m.as_str()).unwrap_or("");
        let raw_val = caps.name("val").map(|m| m.as_str()).unwrap_or("");
        let val_mat = caps.name("val").unwrap();
        let val_start = cursor + val_mat.start();

        if !pre.is_empty() {
            if let Some(close_idx) = find_closing_header_quote(raw_val, pre) {
                out.push_str(pre);
                out.push_str(hdr);
                out.push_str(": [REDACTED]");
                let quote_ch = pre.chars().last().unwrap();
                let close_quote_len = if raw_val[close_idx..].starts_with(pre) {
                    pre.len()
                } else {
                    quote_ch.len_utf8()
                };
                out.push_str(&raw_val[close_idx..close_idx + close_quote_len]);
                cursor = val_start + close_idx + close_quote_len;
                continue;
            }
        }

        out.push_str(pre);
        out.push_str(hdr);
        out.push_str(": [REDACTED]");
        cursor = val_start + raw_val.len();
    }

    out
}

pub fn has_matching_secret_quote(bytes: &[u8], quote_index: usize, escape_depth: usize) -> bool {
    let quote = bytes[quote_index];
    let mut backslashes = 0;
    for &next in &bytes[quote_index + 1..] {
        if next == b'\\' {
            backslashes += 1;
            continue;
        }
        if next == quote && ((escape_depth == 0 && backslashes % 2 == 0) || (escape_depth > 0 && backslashes == escape_depth)) {
            return true;
        }
        backslashes = 0;
    }
    false
}

/// Length of one secret scalar starting at `s`.
///
/// The span is a shell/JSON token made of adjacent segments: bare text, quotes,
/// ANSI-C `$''` / `$""`, and backslash escapes. Escaped spaces (``\ `` / ``\\ ``)
/// and escaped separators (`\;`, `\\;`) stay inside the token. `allow_comma_list`
/// keeps internal commas (`password=part1,part2`) and stops before a trailing
/// separator comma. `[REDACTED_URL]` is preserved. A finished `[REDACTED]` marker
/// stays intact when the next character closes it, and glued suffixes
/// (`[REDACTED]SENTINEL`, `[REDACTED]"secret"`, `[REDACTED]$'secret'`) are consumed
/// so the caller can collapse the whole span to one `[REDACTED]`.
fn consume_secret_scalar_value(s: &str, allow_comma_list: bool) -> usize {
    let bytes = s.as_bytes();
    if s.starts_with("[REDACTED_URL]") || s.starts_with("[REDACTED_url]") {
        return "[REDACTED_URL]".len();
    }

    let mut i = 0usize;
    if s.starts_with("[REDACTED]") {
        i = "[REDACTED]".len();
        if i >= bytes.len() {
            return i;
        }
        let bs0 = bytes[i..].iter().take_while(|b| **b == b'\\').count();
        if i + bs0 < bytes.len() && matches!(bytes[i + bs0], b'"' | b'\'') {
            let after = bytes.get(i + bs0 + 1).copied();
            let closes_enclosing = after.is_none()
                || after.unwrap().is_ascii_whitespace()
                || matches!(after, Some(b'"' | b'\'' | b',' | b'}' | b']' | b';' | b'&'));
            // `[REDACTED]",` / `[REDACTED]\" https://...` closes an enclosing string.
            // `[REDACTED]"secret"` / `[REDACTED]\"secret\"` is a glued quote segment.
            if closes_enclosing && (!after.is_some_and(|next| next.is_ascii_whitespace()) || !has_matching_secret_quote(bytes, i + bs0, bs0)) {
                return i;
            }
        } else if bytes[i].is_ascii_whitespace()
            || matches!(bytes[i], b';' | b'}' | b']' | b'&')
            || (bytes[i] == b',' && !allow_comma_list)
        {
            return i;
        }
    }

    'scalar: while i < bytes.len() {
        if bytes[i] == b'\r' || bytes[i] == b'\n' {
            break;
        }

        // ANSI-C / locale quotes (`$'...'`, `$"..."`) fall through to the quote handler.
        if bytes[i] == b'$' && matches!(bytes.get(i + 1), Some(b'\'' | b'"')) {
            i += 1;
        }

        if bytes[i] == b'\\' {
            let bs = bytes[i..].iter().take_while(|b| **b == b'\\').count();
            let nxt = bytes.get(i + bs).copied();
            match nxt {
                Some(q) if q == b'"' || q == b'\'' => {
                    let q_idx = i + bs;
                    let after_q = bytes.get(q_idx + 1).copied();
                    let closes_outer = i > 0
                        && match after_q {
                            None => true,
                            Some(n) => {
                                n.is_ascii_whitespace()
                                    || matches!(n, b'"' | b'\'' | b',' | b'}' | b']' | b';' | b'&')
                            }
                        };
                    // `{"stage": "token=SECRET\""}` — the backslash-quote closes the JSON string.
                    if closes_outer && (!after_q.is_some_and(|next| next.is_ascii_whitespace()) || !has_matching_secret_quote(bytes, q_idx, bs)) {
                        break;
                    }
                    let mut j = q_idx + 1;
                    let mut inner_bs = 0usize;
                    while j < bytes.len() {
                        if bytes[j] == b'\\' {
                            inner_bs += 1;
                            j += 1;
                            continue;
                        }
                        if bytes[j] == q {
                            if inner_bs == 0 {
                                // Unescaped quote belongs to the enclosing JSON string.
                                i = j;
                                break 'scalar;
                            }
                            if inner_bs == bs
                                || (inner_bs % 2 == 1 && escaped_quote_closes_payload(bytes, j))
                            {
                                let stop_outer =
                                    inner_bs != bs && escaped_quote_closes_payload(bytes, j);
                                i = j + 1;
                                if stop_outer {
                                    break 'scalar;
                                }
                                continue 'scalar;
                            }
                        }
                        inner_bs = 0;
                        j += 1;
                    }
                    i = bytes.len();
                    break 'scalar;
                }
                Some(nc) if nc != b'\r' && nc != b'\n' => {
                    // Shell-escaped space (`\ `), JSON-escaped space (`\\ `), `\;`, `\\;`, `\&`, `\,`.
                    i += bs + 1;
                    continue;
                }
                Some(_) => break,
                None => {
                    i += bs;
                    break;
                }
            }
        }

        if matches!(bytes[i], b'"' | b'\'') {
            let q = bytes[i];
            if i > 0 {
                let after_q = bytes.get(i + 1).copied();
                let closes_outer = match after_q {
                    None => true,
                    Some(n) => {
                        n.is_ascii_whitespace()
                            || matches!(n, b',' | b'}' | b']' | b';' | b'&' | b':' | b'"' | b'\'')
                    }
                };
                // `{"stage": "token=SECRET", "rc": 1}` — this quote closes the enclosing string.
                if closes_outer && (!after_q.is_some_and(|next| next.is_ascii_whitespace()) || !has_matching_secret_quote(bytes, i, 0)) {
                    break;
                }
            }
            let mut j = i + 1;
            let mut escaped = false;
            while j < bytes.len() {
                let c = bytes[j];
                if escaped {
                    escaped = false;
                    j += 1;
                    continue;
                }
                if c == b'\\' {
                    escaped = true;
                    j += 1;
                    continue;
                }
                if c == q {
                    i = j + 1;
                    continue 'scalar;
                }
                j += 1;
            }
            i = bytes.len();
            break 'scalar;
        }

        if bytes[i] == b'{' || bytes[i] == b'[' {
            let next = consume_balanced_container(s, i);
            if next <= i {
                i += 1;
            } else {
                i = next;
            }
            continue;
        }

        if bytes[i].is_ascii_whitespace() || matches!(bytes[i], b';' | b'}' | b']' | b'&') {
            break;
        }
        if bytes[i] == b',' {
            if !allow_comma_list {
                break;
            }
            let next = bytes.get(i + 1).copied();
            let trailing_separator = next.is_none()
                || next.unwrap().is_ascii_whitespace()
                || matches!(next, Some(b';' | b'"' | b'\'' | b'}' | b']' | b'&' | b','));
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

/// Consume a `{...}` or `[...]` container starting at `start`, including quotes
/// and backslash escapes inside it, so a `}` / `]` inside a string does not
/// close the container early.
fn consume_balanced_container(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = start;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' => {
                in_quote = Some(c);
                i += 1;
            }
            b'{' => {
                brace_depth += 1;
                i += 1;
            }
            b'[' => {
                bracket_depth += 1;
                i += 1;
            }
            b'}' => {
                if brace_depth == 0 {
                    break;
                }
                brace_depth -= 1;
                i += 1;
                if brace_depth == 0 && bracket_depth == 0 {
                    break;
                }
            }
            b']' => {
                if bracket_depth == 0 {
                    break;
                }
                bracket_depth -= 1;
                i += 1;
                if brace_depth == 0 && bracket_depth == 0 {
                    break;
                }
            }
            _ => {
                if c < 0x80 {
                    i += 1;
                } else {
                    let width = s[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
                    i += width;
                }
            }
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

/// Span of one secret scalar. `[REDACTED_URL]` stays intact; every other token,
/// including a `[REDACTED]` marker glued to another segment, is consumed whole.
fn secret_scalar_span(s: &str, allow_comma_list: bool) -> usize {
    if s.starts_with("[REDACTED_URL]") || s.starts_with("[REDACTED_url]") {
        return "[REDACTED_URL]".len();
    }
    consume_secret_scalar_value(s, allow_comma_list)
}

fn scalar_value_is_container(value: &str) -> bool {
    (value.starts_with('{') || value.starts_with('[')) && !value.starts_with("[REDACTED]")
}

pub fn is_complete_redacted_header(prefix: &str, value: &str) -> bool {
    if prefix.contains('=') || !prefix.contains(':') {
        return false;
    }
    let key = prefix.split(':').next().unwrap_or(prefix).trim()
        .trim_matches(|character: char| matches!(character, '"' | '\'' | '\\'));
    if !matches!(key.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" | "x-auth-token") {
        return false;
    }
    let Some(suffix) = value.strip_prefix("[REDACTED]") else { return false; };
    if suffix.trim().is_empty() {
        return true;
    }
    let quoted_prefix = prefix.trim().trim_start_matches('\\');
    let Some(opening_quote @ ('\'' | '"')) = quoted_prefix.chars().next() else { return false; };
    let suffix = suffix.trim_start_matches('\\');
    let Some(quote @ ('\'' | '"')) = suffix.chars().next() else { return false; };
    if quote != opening_quote {
        return false;
    }
    let following = suffix[quote.len_utf8()..].trim_start();
    following.is_empty() || is_diagnostic_command_tail(following) || following.starts_with("https://")
        || following.starts_with("http://") || following.starts_with([',', '}', ']'])
}

fn redact_prefixed_secrets(text: &str, prefix_re: &Regex, allow_comma_list: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while cursor < text.len() {
        let slice = &text[cursor..];
        let Some(mat) = prefix_re.find(slice) else {
            out.push_str(slice);
            break;
        };
        if mat.end() == 0 {
            let ch = slice.chars().next().unwrap();
            out.push(ch);
            cursor += ch.len_utf8();
            continue;
        }
        let value = &slice[mat.end()..];
        if is_complete_redacted_header(&slice[mat.start()..mat.end()], value) || scalar_value_is_container(value) {
            out.push_str(&slice[..mat.end()]);
            cursor += mat.end();
            continue;
        }
        let n = secret_scalar_span(value, allow_comma_list);
        if n == 0 {
            out.push_str(&slice[..mat.end()]);
            cursor += mat.end();
            continue;
        }
        let prefix = &slice[mat.start()..mat.end()];
        let consumed = &value[..n];
        out.push_str(&slice[..mat.end()]);
        out.push_str(&replacement_for_lifecycle_scalar(prefix, consumed));
        cursor += mat.end() + n;
    }
    out
}

fn redact_curl_user_secrets(text: &str) -> String {
    static CURL_USER_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)(\bcurl\b[^\r\n]*?\s+(?:--user(?:\s+|=)|-[A-Za-z]*[uU](?:\s+|=)?))|((?:^|[\s"'])(?:--user(?:\s+|=)|-u(?:\s+|=)))|((?:^|[\s"'])-u)"#,
        )
        .unwrap()
    });
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while cursor < text.len() {
        let slice = &text[cursor..];
        let Some(caps) = CURL_USER_PREFIX_RE.captures(slice) else {
            out.push_str(slice);
            break;
        };
        let mat = caps.get(0).unwrap();
        if mat.end() == 0 {
            let ch = slice.chars().next().unwrap();
            out.push(ch);
            cursor += ch.len_utf8();
            continue;
        }
        let value = &slice[mat.end()..];
        if scalar_value_is_container(value) {
            out.push_str(&slice[..mat.end()]);
            cursor += mat.end();
            continue;
        }
        let n = secret_scalar_span(value, true);
        let bare_attached = caps.get(1).is_none() && caps.get(2).is_none();
        let consumed = if n == 0 { "" } else { &value[..n] };
        let accept = if bare_attached {
            consumed.contains(':')
                || consumed.starts_with('"')
                || consumed.starts_with('\'')
                || consumed.starts_with('\\')
                || consumed.starts_with("[REDACTED]")
        } else {
            n > 0
        };
        if !accept {
            out.push_str(&slice[..mat.end()]);
            cursor += mat.end();
            continue;
        }
        out.push_str(&slice[..mat.end()]);
        if consumed == "[REDACTED]" || consumed == "[REDACTED_URL]" {
            out.push_str(consumed);
        } else {
            out.push_str("[REDACTED]");
        }
        cursor += mat.end() + n;
    }
    out
}

fn redact_sensitive_cli_flags(text: &str) -> String {
    static CLI_FLAG_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)((?:^|[\s"'])--(?:[A-Za-z0-9-]*-)?(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|credentials?)(?:\s+|=)\s*)"#,
        )
        .unwrap()
    });
    redact_prefixed_secrets(text, &CLI_FLAG_PREFIX_RE, true)
}

fn redact_sensitive_assignments(text: &str) -> String {
    redact_prefixed_secrets(text, &SENSITIVE_ASSIGNMENT_PREFIX_RE, true)
}

fn decode_u00_identifier(s: &str) -> Option<char> {
    let bytes = s.as_bytes();
    if bytes.len() < 5 || bytes[0] != b'u' || bytes[1] != b'0' || bytes[2] != b'0' {
        return None;
    }
    if !bytes[3].is_ascii_hexdigit() || !bytes[4].is_ascii_hexdigit() {
        return None;
    }
    let code = u8::from_str_radix(&s[3..5], 16).ok()?;
    match code {
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'-' | b'.' => Some(code as char),
        _ => None,
    }
}

fn decode_sensitive_key_body(body: &str) -> Option<String> {
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut i = 0usize;
    let mut decoded = false;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let mut escape_end = i + 1;
            while bytes.get(escape_end) == Some(&b'\\') {
                escape_end += 1;
            }
            if let Some(ch) = decode_u00_identifier(&body[escape_end..]) {
                out.push(ch);
                i = escape_end + 5;
                decoded = true;
                continue;
            }
        }
        let Some(ch) = body[i..].chars().next() else {
            break;
        };
        out.push(ch);
        i += ch.len_utf8();
    }
    if decoded {
        Some(out)
    } else {
        None
    }
}

/// Rewrite `\u00XX` / `\\u00XX` escapes inside quoted JSON keys when the decoded
/// key is sensitive, so later redaction sees `password` rather than `pass\u0077ord`.
/// Non-sensitive keys are left unchanged and the surrounding JSON stays intact.
pub fn normalize_unicode_escaped_sensitive_keys(input: &str) -> String {
    if !input.contains("\\u00") {
        return input.to_string();
    }
    static UNICODE_ESCAPED_JSON_KEY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?P<prefix>\\*")(?P<body>(?:\\+u00[0-9A-Fa-f]{2}|[A-Za-z0-9_.-])+)(?P<suffix>\\*"\s*:)"#)
            .unwrap()
    });
    UNICODE_ESCAPED_JSON_KEY_RE
        .replace_all(input, |caps: &regex::Captures| {
            let body = caps.name("body").map(|m| m.as_str()).unwrap_or("");
            match decode_sensitive_key_body(body) {
                Some(key) if is_sensitive_diagnostic_key(&key) => {
                    format!(
                        "{}{}{}",
                        caps.name("prefix").map(|m| m.as_str()).unwrap_or(""),
                        key,
                        caps.name("suffix").map(|m| m.as_str()).unwrap_or("")
                    )
                }
                _ => caps[0].to_string(),
            }
        })
        .into_owned()
}

fn is_bare_json_literal(consumed: &str) -> bool {
    matches!(consumed, "true" | "false" | "null")
        || (!consumed.is_empty() && consumed.bytes().all(|b| b.is_ascii_digit()))
}

fn replacement_for_lifecycle_scalar(prefix: &str, consumed: &str) -> String {
    if consumed == "[REDACTED]" || consumed == "[REDACTED_URL]" {
        return consumed.to_string();
    }
    let quoted_marker = consumed.len() >= 2
        && ((consumed.starts_with('"') && consumed.ends_with('"'))
            || (consumed.starts_with('\'') && consumed.ends_with('\'')))
        && matches!(
            &consumed[1..consumed.len() - 1],
            "[REDACTED]" | "[REDACTED_URL]"
        );
    if quoted_marker {
        return consumed.to_string();
    }
    let trimmed = prefix.trim_start();
    let json_key = (trimmed.starts_with('"') || trimmed.starts_with('\'')) && prefix.contains(':');
    if json_key && is_bare_json_literal(consumed) {
        "\"[REDACTED]\"".to_string()
    } else {
        "[REDACTED]".to_string()
    }
}

pub fn sanitize_persisted_lifecycle_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let normalized = normalize_unicode_escaped_sensitive_keys(input);
    let res = redact_sensitive_nested_containers(&normalized);
    let res = URL_CRED_RE.replace_all(&res, |caps: &regex::Captures<'_>| {
        let full = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
        let scheme_prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let userinfo = &full[scheme_prefix.len()..full.len().saturating_sub(1)];
        let is_hashed_cred = userinfo
            .strip_prefix("cred#")
            .is_some_and(|hex| hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let is_passwordless_ssh = scheme_prefix.eq_ignore_ascii_case("ssh://")
            && !userinfo.contains(':')
            && !userinfo.is_empty();
        if is_hashed_cred || is_passwordless_ssh {
            full.to_string()
        } else {
            format!("{}[REDACTED]@", scheme_prefix)
        }
    });
    let res = redact_curl_user_secrets(&res);
    let res = redact_sensitive_cli_flags(&res);
    let res = BEARER_RE.replace_all(&res, "Bearer [REDACTED]");
    let res = BASIC_RE.replace_all(&res, "Basic [REDACTED]");
    let res = redact_sensitive_headers(&res);
    redact_sensitive_assignments(&res)
}

pub struct OwnerLease {
    pub id: String,
    database: PathBuf,
    _file: File,
}

fn lease_path(database: &Path, owner: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        uuid::Uuid::parse_str(owner).is_ok(),
        "invalid lifecycle owner identity"
    );
    Ok(database.with_extension("lifecycle-owners").join(owner))
}

impl OwnerLease {
    pub fn create(database: &Path) -> Result<Self> {
        let id = uuid::Uuid::new_v4().to_string();
        let path = lease_path(database, &id)?;
        let parent = path.parent().context("missing lifecycle lease directory")?;
        crate::fs_security::create_dir_all_no_symlinks(parent, 0o755)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        anyhow::ensure!(
            lock_exclusive(&file)?,
            "new lifecycle owner lease already locked"
        );
        let lease = Self {
            id,
            database: database.to_owned(),
            _file: file,
        };
        lease._file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(lease)
    }
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        let cleanup = || -> Result<()> {
            let conn = Connection::open_with_flags(
                &self.database,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            conn.busy_timeout(std::time::Duration::ZERO)?;
            retire_owner(&conn, &self.database, &self.id, &self._file)
        };
        let _ = cleanup();
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<bool> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error.into())
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &File) -> Result<bool> {
    anyhow::bail!("lifecycle owner leases require advisory lock support")
}

fn open_owner_file(database: &Path, owner: &str) -> Result<File> {
    let path = lease_path(database, owner)?;
    crate::fs_security::ensure_no_symlink_ancestors(&path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("cannot inspect lifecycle owner lease")?;
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "invalid lifecycle owner lease file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(metadata.nlink() == 1, "linked lifecycle owner lease file");
    }
    Ok(file)
}

pub fn owner_is_alive(database: &Path, owner: &str) -> Result<bool> {
    let file = open_owner_file(database, owner)?;
    Ok(!lock_exclusive(&file)?)
}

#[cfg(unix)]
fn retire_owner(conn: &Connection, database: &Path, owner: &str, file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    anyhow::ensure!(
        conn.is_autocommit(),
        "lifecycle cleanup requires committed receipts"
    );
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE owner_id=?1 AND status NOT IN ('completed','failed','interrupted'))",
        [owner], |row| row.get(0),
    )?;
    anyhow::ensure!(!active, "lifecycle owner still has a reservation");
    let path = lease_path(database, owner)?;
    let parent = path.parent().context("missing lifecycle lease directory")?;
    crate::fs_security::ensure_no_symlink_ancestors(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    anyhow::ensure!(
        directory.metadata()?.mode() & 0o022 == 0,
        "lifecycle lease directory is writable by other users"
    );
    let expected = file.metadata()?;
    anyhow::ensure!(
        expected.is_file() && expected.nlink() == 1,
        "invalid lifecycle owner lease inode"
    );
    let name = std::ffi::CString::new(owner)?;
    let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            observed.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let observed = unsafe { observed.assume_init() };
    anyhow::ensure!(
        observed.st_mode & libc::S_IFMT == libc::S_IFREG
            && observed.st_nlink == 1
            && observed.st_dev == expected.dev()
            && observed.st_ino == expected.ino(),
        "lifecycle owner lease inode changed"
    );
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn retire_owner(_conn: &Connection, _database: &Path, _owner: &str, _file: &File) -> Result<()> {
    anyhow::bail!("lifecycle owner cleanup requires advisory lock support")
}

fn retire_finished_owners(conn: &Connection, database: &Path) -> Result<()> {
    if !conn.is_autocommit() {
        return Ok(());
    }
    let owners: Vec<String> = conn
        .prepare("SELECT DISTINCT owner_id FROM package_lifecycle_jobs WHERE status IN ('completed','failed','interrupted') AND owner_id!=''")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for owner in owners {
        if let Ok(file) = open_owner_file(database, &owner) {
            if matches!(lock_exclusive(&file), Ok(true)) {
                let _ = retire_owner(conn, database, &owner, &file);
            }
        }
    }
    Ok(())
}

pub fn initialize_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS package_lifecycle_jobs (
        package_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, action TEXT NOT NULL,
        status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '',
        owner_id TEXT NOT NULL DEFAULT '', service_units TEXT NOT NULL DEFAULT '[]',
        failure_category TEXT NOT NULL DEFAULT '', failed_stage TEXT NOT NULL DEFAULT '',
        exit_code INTEGER, sanitized_summary TEXT NOT NULL DEFAULT '',
        expected_target_version TEXT NOT NULL DEFAULT '', achieved_version TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS package_lifecycle_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id TEXT NOT NULL, job_id TEXT NOT NULL, action TEXT NOT NULL,
        status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '',
        owner_id TEXT NOT NULL DEFAULT '', service_units TEXT NOT NULL DEFAULT '[]',
        failure_category TEXT NOT NULL DEFAULT '', failed_stage TEXT NOT NULL DEFAULT '',
        exit_code INTEGER, sanitized_summary TEXT NOT NULL DEFAULT '',
        expected_target_version TEXT NOT NULL DEFAULT '', achieved_version TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_lifecycle_history_pkg ON package_lifecycle_history(package_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_lifecycle_history_job ON package_lifecycle_history(job_id);
    CREATE VIEW IF NOT EXISTS package_lifecycle_journal AS SELECT * FROM package_lifecycle_history;",
    )?;
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(package_lifecycle_jobs)")?
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, definition) in [
        ("owner_id", "TEXT NOT NULL DEFAULT ''"),
        ("service_units", "TEXT NOT NULL DEFAULT '[]'"),
        ("failure_category", "TEXT NOT NULL DEFAULT ''"),
        ("failed_stage", "TEXT NOT NULL DEFAULT ''"),
        ("exit_code", "INTEGER"),
        ("sanitized_summary", "TEXT NOT NULL DEFAULT ''"),
        ("expected_target_version", "TEXT NOT NULL DEFAULT ''"),
        ("achieved_version", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !columns.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE package_lifecycle_jobs ADD COLUMN {name} {definition}"
            ))?;
        }
    }
    let hist_columns: Vec<String> = conn
        .prepare("PRAGMA table_info(package_lifecycle_history)")?
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, definition) in [
        ("owner_id", "TEXT NOT NULL DEFAULT ''"),
        ("service_units", "TEXT NOT NULL DEFAULT '[]'"),
        ("failure_category", "TEXT NOT NULL DEFAULT ''"),
        ("failed_stage", "TEXT NOT NULL DEFAULT ''"),
        ("exit_code", "INTEGER"),
        ("sanitized_summary", "TEXT NOT NULL DEFAULT ''"),
        ("expected_target_version", "TEXT NOT NULL DEFAULT ''"),
        ("achieved_version", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !hist_columns.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE package_lifecycle_history ADD COLUMN {name} {definition}"
            ))?;
        }
    }
    Ok(())
}

pub fn reconcile_jobs(conn: &Connection, database: &Path) -> Result<()> {
    let has_owner: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='owner_id')",
        [], |row| row.get(0),
    )?;
    if !has_owner {
        return Ok(());
    }
    let jobs: Vec<(String, String, String)> = conn.prepare(
        "SELECT package_id,job_id,owner_id FROM package_lifecycle_jobs WHERE status IN ('installing','updating','uninstalling')",
    )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (package, job, owner) in jobs {
        if owner.is_empty() || !matches!(owner_is_alive(database, &owner), Ok(false)) {
            continue;
        }
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE package_lifecycle_jobs SET status='interrupted',finished_at=?1,failure_category='interrupted'
             WHERE package_id=?2 AND job_id=?3 AND owner_id=?4 AND status IN ('installing','updating','uninstalling')",
            params![now, package, job, owner],
        )?;
        let _ = conn.execute(
            "UPDATE package_lifecycle_history SET status='interrupted',finished_at=?1,failure_category='interrupted'
             WHERE package_id=?2 AND job_id=?3 AND owner_id=?4 AND status IN ('installing','updating','uninstalling')",
            params![now, package, job, owner],
        );
    }
    let _ = retire_finished_owners(conn, database);
    Ok(())
}

pub enum ReservationTarget<'a> {
    Package(&'a str),
    Service(&'a str),
    System,
}

pub fn port_resource(port: i32) -> Option<String> {
    if (1..=65535).contains(&port) {
        Some(format!("port:{port}"))
    } else {
        None
    }
}

pub fn package_resources(package: &str, units: &[String]) -> BTreeSet<String> {
    std::iter::once(package)
        .chain(units.iter().map(String::as_str))
        .map(|unit| unit.trim().to_ascii_lowercase())
        .map(|unit| unit.trim_end_matches(".service").to_owned())
        .filter(|unit| !unit.is_empty())
        .collect()
}

pub fn check_package_reservation(
    conn: &Connection,
    package: &str,
    units: &[String],
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    check_resources(
        conn,
        Some(package_resources(package, units)),
        job_id,
        action,
    )?;
    if !job_id.is_empty() {
        let exact: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2 AND status IN ('installing','updating','uninstalling'))",
            params![package,job_id], |row| row.get(0),
        )?;
        anyhow::ensure!(exact, "Lifecycle owner does not match requested package");
    }
    Ok(())
}

pub fn admit_job(
    conn: &mut Connection,
    package: &str,
    job_id: &str,
    action: &str,
    started_at: &str,
    units: &[String],
) -> Result<OwnerLease> {
    admit_job_with_target(conn, package, job_id, action, started_at, units, None)
}

pub fn admit_job_with_target(
    conn: &mut Connection,
    package: &str,
    job_id: &str,
    action: &str,
    started_at: &str,
    units: &[String],
    expected_target_version: Option<&str>,
) -> Result<OwnerLease> {
    anyhow::ensure!(
        !package.is_empty() && !job_id.is_empty(),
        "lifecycle identity is required"
    );
    let status = match action {
        "install" | "reinstall" => "installing",
        "update" => "updating",
        "remove" => "uninstalling",
        _ => anyhow::bail!("invalid lifecycle action"),
    };
    let database = PathBuf::from(conn.path().context("lifecycle database path missing")?);
    anyhow::ensure!(
        !database.as_os_str().is_empty(),
        "durable lifecycle database is required"
    );
    let _ = retire_finished_owners(conn, &database);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_package_reservation(&tx, package, units, "", Some(action))?;
    let lease = OwnerLease::create(&database)?;
    let normalized: Vec<_> = package_resources(package, units).into_iter().collect();
    let normalized_json = serde_json::to_string(&normalized)?;
    let target_ver_raw = expected_target_version.unwrap_or("");
    let target_ver = sanitize_persisted_lifecycle_text(target_ver_raw);
    tx.execute(
        "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version)
        VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'') ON CONFLICT(package_id) DO UPDATE SET
        job_id=excluded.job_id,action=excluded.action,status=excluded.status,started_at=excluded.started_at,finished_at='',owner_id=excluded.owner_id,service_units=excluded.service_units,failure_category='',failed_stage='',exit_code=NULL,sanitized_summary='',expected_target_version=excluded.expected_target_version,achieved_version=''",
        params![package, job_id, action, status, started_at, lease.id, normalized_json, target_ver],
    )?;
    tx.execute(
        "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version)
        VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'')",
        params![package, job_id, action, status, started_at, lease.id, normalized_json, target_ver],
    )?;
    tx.commit()?;
    Ok(lease)
}

pub fn finish_job(
    conn: &Connection,
    package: &str,
    job_id: &str,
    action: &str,
    success: bool,
    failure_category: &str,
) -> Result<()> {
    finish_job_with_diagnostics(
        conn,
        package,
        job_id,
        action,
        success,
        failure_category,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

pub fn finish_job_with_diagnostics(
    conn: &Connection,
    package: &str,
    job_id: &str,
    action: &str,
    success: bool,
    failure_category: &str,
    failed_stage: Option<&str>,
    exit_code: Option<i32>,
    sanitized_summary: Option<&str>,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
    finished_at: Option<&str>,
) -> Result<()> {
    let status = if success { "completed" } else { "failed" };
    let finished_at_owned = finished_at
        .map(ToString::to_string)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let finished_at = finished_at_owned.as_str();
    let cat = if success { "" } else { failure_category };
    let stage = sanitize_persisted_lifecycle_text(failed_stage.unwrap_or(""));
    let summary = sanitize_persisted_lifecycle_text(sanitized_summary.unwrap_or(""));
    let achieved = sanitize_persisted_lifecycle_text(achieved_version.unwrap_or(""));
    let expected = sanitize_persisted_lifecycle_text(expected_target_version.unwrap_or(""));

    let in_tx = !conn.is_autocommit();
    if !in_tx {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
    }
    let run = || -> Result<()> {
        let updated = conn.execute(
            "UPDATE package_lifecycle_jobs SET status=?1,finished_at=?2,failure_category=?3,failed_stage=?4,exit_code=?5,sanitized_summary=?6,expected_target_version=CASE WHEN ?7 != '' THEN ?7 ELSE expected_target_version END,achieved_version=?8
             WHERE package_id=?9 AND job_id=?10 AND action=?11 AND status IN ('installing','updating','uninstalling')",
            params![status, finished_at, cat, stage, exit_code, summary, expected, achieved, package, job_id, action],
        )?;
        anyhow::ensure!(updated == 1, "lifecycle receipt identity changed");
        let hist_updated = conn.execute(
            "UPDATE package_lifecycle_history SET status=?1,finished_at=?2,failure_category=?3,failed_stage=?4,exit_code=?5,sanitized_summary=?6,expected_target_version=CASE WHEN ?7 != '' THEN ?7 ELSE expected_target_version END,achieved_version=?8
             WHERE package_id=?9 AND job_id=?10 AND action=?11 AND status IN ('installing','updating','uninstalling')",
            params![status, finished_at, cat, stage, exit_code, summary, expected, achieved, package, job_id, action],
        )?;
        if hist_updated == 0 {
            let (started_at, owner_id, service_units): (String, String, String) = conn
                .query_row(
                    "SELECT started_at, owner_id, service_units FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
                    params![package, job_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap_or_else(|_| (finished_at.to_string(), String::new(), "[]".to_string()));
            conn.execute(
                "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![package, job_id, action, status, started_at, finished_at, owner_id, service_units, cat, stage, exit_code, summary, expected, achieved],
            )?;
        }
        Ok(())
    };
    match run() {
        Ok(()) => {
            if !in_tx {
                conn.execute_batch("COMMIT;")?;
            }
            Ok(())
        }
        Err(e) => {
            if !in_tx {
                let _ = conn.execute_batch("ROLLBACK;");
            }
            Err(e)
        }
    }
}

pub fn record_completed_lifecycle_job(
    conn: &Connection,
    package: &str,
    job_id: &str,
    action: &str,
    sanitized_summary: Option<&str>,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
) -> Result<()> {
    finish_job_with_diagnostics(
        conn,
        package,
        job_id,
        action,
        true,
        "",
        None,
        Some(0),
        sanitized_summary,
        expected_target_version,
        achieved_version,
        None,
    )
}

pub fn is_hex_commit(s: &str) -> bool {
    let len = s.len();
    (7..=40).contains(&len)
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && (len == 40 || s.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')))
}

pub fn is_hex_digits_7_to_40(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn commits_match_prefix(a: &str, b: &str, known_git_context: bool) -> bool {
    if !is_hex_digits_7_to_40(a) || !is_hex_digits_7_to_40(b) {
        return false;
    }
    if !known_git_context && !is_hex_commit(a) && !is_hex_commit(b) {
        return false;
    }
    let al = a.to_ascii_lowercase();
    let bl = b.to_ascii_lowercase();
    al.starts_with(&bl) || bl.starts_with(&al)
}

pub fn is_debian_plus_revision(suffix_after_plus: &str) -> bool {
    let lower = suffix_after_plus.to_ascii_lowercase();
    let trimmed = lower.trim_start_matches(|c: char| c == '+' || c == '~');
    if trimmed.is_empty() {
        return false;
    }

    // 1. deb\d+ (e.g. +deb11u1, +deb12u2 — "deb" followed immediately by an ASCII digit!)
    if let Some(rest) = trimmed.strip_prefix("deb") {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
    }

    // 2. dfsg(\.\d+|\d+|-|$) (e.g. +dfsg, +dfsg1, +dfsg.1, +dfsg-1)
    if let Some(rest) = trimmed.strip_prefix("dfsg") {
        if rest.is_empty()
            || rest.starts_with('-')
            || rest.starts_with(|c: char| c.is_ascii_digit())
            || (rest.starts_with('.') && rest[1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            return true;
        }
    }

    // 3. ds(\.\d+|\d+|-|$) (e.g. +ds, +ds1, +ds.1, +ds-1)
    if let Some(rest) = trimmed.strip_prefix("ds") {
        if rest.is_empty()
            || rest.starts_with('-')
            || rest.starts_with(|c: char| c.is_ascii_digit())
            || (rest.starts_with('.') && rest[1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            return true;
        }
    }

    // 4. really[0-9.] (e.g. +really1.0)
    if let Some(rest) = trimmed.strip_prefix("really") {
        if rest.starts_with(|c: char| c.is_ascii_digit() || c == '.') {
            return true;
        }
    }

    // 5. nmu\d+ (e.g. +nmu1)
    if let Some(rest) = trimmed.strip_prefix("nmu") {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
    }

    // 6. b\d+$ (e.g. +b1, +b2 — 'b' followed ONLY by ASCII digits!)
    if let Some(rest) = trimmed.strip_prefix('b') {
        if !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    // 7. u\d+$ (e.g. +u1 — 'u' followed ONLY by ASCII digits!)
    if let Some(rest) = trimmed.strip_prefix('u') {
        if !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    false
}

pub fn strip_semver_build_metadata(s: &str) -> &str {
    if let Some(idx) = s.find('+') {
        let suffix = &s[idx + 1..];
        if !is_debian_plus_revision(suffix) {
            return &s[..idx];
        }
    }
    s
}

pub fn is_debian_revision_suffix(suffix: &str) -> bool {
    let s = suffix.trim();
    if s.is_empty() || s.starts_with('-') || s.starts_with("0.") {
        return false;
    }
    let starts_valid = s.starts_with(|c: char| c.is_ascii_digit())
        || ((s.starts_with('r') || s.starts_with('R'))
            && s.len() > 1
            && s[1..].starts_with(|c: char| c.is_ascii_digit()));
    if !starts_valid {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "git",
        "svn",
        "test",
        "unstable",
        "experimental",
        "debug",
    ];
    for kw in PRERELEASE_KEYWORDS {
        if lower.contains(kw) {
            return false;
        }
    }

    let has_debian_marker = lower.contains("ubuntu")
        || lower.contains("deb")
        || lower.contains("dfsg")
        || lower.contains("build")
        || lower.contains("+b")
        || (lower.contains('b') && lower.contains('+'))
        || lower.contains(':');

    let is_numeric_dots = s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.');
    if is_numeric_dots && !has_debian_marker {
        return false;
    }

    true
}

pub fn is_valid_apt_debian_revision_suffix(suffix: &str) -> bool {
    let s = suffix.trim();
    if s.is_empty() || s.starts_with('-') {
        return false;
    }
    let starts_valid = s.starts_with(|c: char| c.is_ascii_digit())
        || ((s.starts_with('r') || s.starts_with('R'))
            && s.len() > 1
            && s[1..].starts_with(|c: char| c.is_ascii_digit()));
    if !starts_valid {
        return false;
    }
    if s.contains('~') {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "git",
        "svn",
        "test",
        "unstable",
        "experimental",
        "debug",
    ];
    for kw in PRERELEASE_KEYWORDS {
        if lower.contains(kw) {
            return false;
        }
    }
    true
}

pub fn is_prerelease_version_for_channel_with_source(
    version_or_tag: &str,
    update_source: Option<&str>,
) -> bool {
    let clean = strip_version_prefix(version_or_tag);
    let src = update_source.map(|s| s.trim().to_ascii_lowercase());
    let is_apt = matches!(src.as_deref(), Some("apt" | "deb" | "dpkg"));
    let effective_clean = if !is_apt {
        clean.split_once('+').map(|(v, _)| v).unwrap_or(clean)
    } else {
        clean
    };
    let lower = effective_clean.to_ascii_lowercase();

    if lower.contains('~') {
        return true;
    }

    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "unstable",
        "experimental",
        "debug",
        "dirty",
        "wip",
    ];
    for word in PRERELEASE_KEYWORDS {
        if lower.contains(word) {
            return true;
        }
    }

    match src.as_deref() {
        Some("apt") | Some("deb") | Some("dpkg") => {
            let without_epoch = if let Some((_, rem)) = clean.split_once(':') {
                rem
            } else {
                clean
            };
            if let Some((upstream, deb_rev)) = without_epoch.rsplit_once('-') {
                if upstream.contains('~') {
                    return true;
                }
                let segments_numeric = if upstream.contains('-') {
                    upstream
                        .split('-')
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                } else {
                    true
                };
                if segments_numeric && is_valid_apt_debian_revision_suffix(deb_rev) {
                    return false;
                }
                return true;
            }
            false
        }
        Some("github")
        | Some("github_release")
        | Some("github_releases")
        | Some("github_tags")
        | Some("git")
        | Some("git_tags")
        | Some("git_tag")
        | Some("git_commit")
        | Some("git_head")
        | Some("gitlab")
        | Some("gitea") => {
            let semver_core_and_pre = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);
            if semver_core_and_pre.contains('-') {
                return true;
            }
            if let Some(sv) = parse_semver(semver_core_and_pre) {
                if let Some(ref pre) = sv.prerelease {
                    if !pre.is_empty() {
                        return true;
                    }
                }
            }
            false
        }
        _ => {
            let semver_core_and_pre = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);
            if let Some((_upstream, rest)) =
                semver_core_and_pre.to_ascii_lowercase().split_once('-')
            {
                let is_plain_debian_rev = if rest.contains('-') {
                    let parts: Vec<&str> = rest.split('-').collect();
                    let earlier_numeric = parts[..parts.len() - 1]
                        .iter()
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
                    earlier_numeric && is_debian_revision_suffix(parts[parts.len() - 1])
                } else {
                    is_debian_revision_suffix(rest)
                };

                if is_plain_debian_rev {
                    return false;
                }
                if !rest.trim().is_empty() {
                    return true;
                }
            }

            if let Some(sv) = parse_semver(semver_core_and_pre) {
                if let Some(ref pre) = sv.prerelease {
                    if !pre.is_empty() {
                        return true;
                    }
                }
            }

            false
        }
    }
}

pub fn is_prerelease_version_for_channel(version_or_tag: &str) -> bool {
    is_prerelease_version_for_channel_with_source(version_or_tag, None)
}

fn dpkg_char_order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(b) if b.is_ascii_alphabetic() => b as i32,
        Some(b) => (b as i32) + 256,
    }
}

pub fn dpkg_verrevcmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = 0;
    let mut j = 0;

    while i < ab.len() || j < bb.len() {
        while (i < ab.len() && !ab[i].is_ascii_digit()) || (j < bb.len() && !bb[j].is_ascii_digit())
        {
            let ac = if i < ab.len() && !ab[i].is_ascii_digit() {
                Some(ab[i])
            } else {
                None
            };
            let bc = if j < bb.len() && !bb[j].is_ascii_digit() {
                Some(bb[j])
            } else {
                None
            };
            let ord = dpkg_char_order(ac).cmp(&dpkg_char_order(bc));
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
            if ac.is_some() {
                i += 1;
            }
            if bc.is_some() {
                j += 1;
            }
        }

        while i < ab.len() && ab[i] == b'0' {
            i += 1;
        }
        while j < bb.len() && bb[j] == b'0' {
            j += 1;
        }

        let i_start = i;
        while i < ab.len() && ab[i].is_ascii_digit() {
            i += 1;
        }
        let j_start = j;
        while j < bb.len() && bb[j].is_ascii_digit() {
            j += 1;
        }

        let a_len = i - i_start;
        let b_len = j - j_start;
        if a_len != b_len {
            return a_len.cmp(&b_len);
        }

        let ord = ab[i_start..i].cmp(&bb[j_start..j]);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    std::cmp::Ordering::Equal
}

fn parse_debian_version(raw: &str) -> (u64, &str, &str) {
    let mut s = raw.trim();
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        s = strip_version_prefix(s);
    }
    let (epoch, remainder) = if let Some((ep, rem)) = s.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().unwrap_or(0), rem)
        } else {
            (0, s)
        }
    } else {
        (0, s)
    };
    let (upstream, debian_revision) = if let Some((up, rev)) = remainder.rsplit_once('-') {
        (up, rev)
    } else {
        (remainder, "")
    };
    (epoch, upstream, debian_revision)
}

pub fn compare_debian_versions_str(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_epoch, a_up, a_rev) = parse_debian_version(a);
    let (b_epoch, b_up, b_rev) = parse_debian_version(b);

    if a_epoch != b_epoch {
        return a_epoch.cmp(&b_epoch);
    }

    let up_ord = dpkg_verrevcmp(a_up, b_up);
    if up_ord != std::cmp::Ordering::Equal {
        return up_ord;
    }

    dpkg_verrevcmp(a_rev, b_rev)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemverVersion {
    epoch: u64,
    segments: Vec<u64>,
    prerelease: Option<Vec<PrereleaseIdentifier>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleaseIdentifier {
    Numeric(String),
    Alpha(String),
}

fn parse_semver(raw: &str) -> Option<SemverVersion> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s_no_build = match s.split_once('+') {
        Some((v, _)) => v.trim(),
        None => s,
    };
    let norm = normalize_version(s_no_build);
    if norm.is_empty() {
        return None;
    }

    let (epoch, rest) = if let Some((ep, rem)) = norm.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().ok()?, rem)
        } else {
            (0, norm)
        }
    } else {
        (0, norm)
    };

    if rest.is_empty() || !rest.bytes().any(|b| b.is_ascii_digit()) {
        return None;
    }

    let (normal_str, prerelease_opt) = match rest.find(|c: char| c == '-' || c == '~') {
        Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
        None => (rest, None),
    };

    let mut segments = Vec::new();
    for seg in normal_str.split('.') {
        let seg_trim = seg.trim();
        if seg_trim.is_empty() || !seg_trim.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        segments.push(seg_trim.parse::<u64>().ok()?);
    }
    if segments.is_empty() {
        return None;
    }

    let prerelease = match prerelease_opt {
        Some(pre) if !pre.trim().is_empty() => {
            let mut ids = Vec::new();
            for part in pre.trim().split('.') {
                let part_trim = part.trim();
                if part_trim.is_empty() {
                    continue;
                }
                if part_trim.bytes().all(|b| b.is_ascii_digit()) {
                    let canonical = part_trim.trim_start_matches('0');
                    let digits = if canonical.is_empty() {
                        "0".to_string()
                    } else {
                        canonical.to_string()
                    };
                    ids.push(PrereleaseIdentifier::Numeric(digits));
                } else {
                    ids.push(PrereleaseIdentifier::Alpha(part_trim.to_string()));
                }
            }
            if ids.is_empty() {
                None
            } else {
                Some(ids)
            }
        }
        _ => None,
    };

    Some(SemverVersion {
        epoch,
        segments,
        prerelease,
    })
}

fn compare_semver_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (Some(sa), Some(sb)) = (parse_semver(a), parse_semver(b)) else {
        let a_norm = normalize_version(a);
        let b_norm = normalize_version(b);
        return dpkg_verrevcmp(a_norm, b_norm);
    };

    if sa.epoch != sb.epoch {
        return sa.epoch.cmp(&sb.epoch);
    }

    let max_len = sa.segments.len().max(sb.segments.len());
    for i in 0..max_len {
        let seg_a = sa.segments.get(i).copied().unwrap_or(0);
        let seg_b = sb.segments.get(i).copied().unwrap_or(0);
        let ord = seg_a.cmp(&seg_b);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    match (&sa.prerelease, &sb.prerelease) {
        (None, None) => std::cmp::Ordering::Equal,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(ids_a), Some(ids_b)) => {
            for (id_a, id_b) in ids_a.iter().zip(ids_b.iter()) {
                let ord = match (id_a, id_b) {
                    (PrereleaseIdentifier::Numeric(na), PrereleaseIdentifier::Numeric(nb)) => {
                        na.len().cmp(&nb.len()).then_with(|| na.cmp(nb))
                    }
                    (PrereleaseIdentifier::Numeric(_), PrereleaseIdentifier::Alpha(_)) => {
                        std::cmp::Ordering::Less
                    }
                    (PrereleaseIdentifier::Alpha(_), PrereleaseIdentifier::Numeric(_)) => {
                        std::cmp::Ordering::Greater
                    }
                    (PrereleaseIdentifier::Alpha(sa), PrereleaseIdentifier::Alpha(sb)) => {
                        sa.cmp(sb)
                    }
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            ids_a.len().cmp(&ids_b.len())
        }
    }
}

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let an = normalize_version(a);
    let bn = normalize_version(b);
    if an == bn || an.eq_ignore_ascii_case(bn) {
        return std::cmp::Ordering::Equal;
    }
    if commits_match_prefix(an, bn, false) {
        return std::cmp::Ordering::Equal;
    }
    if is_hex_digits_7_to_40(an) && is_hex_digits_7_to_40(bn) {
        if !(an.bytes().all(|b| b.is_ascii_digit()) && bn.bytes().all(|b| b.is_ascii_digit())) {
            return an.to_ascii_lowercase().cmp(&bn.to_ascii_lowercase());
        }
    }
    compare_semver_versions(a, b)
}

pub fn strip_version_prefix(s: &str) -> &str {
    let mut trimmed = s.trim();
    loop {
        let prev = trimmed;
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("release-")
            || lower.starts_with("release_")
            || lower.starts_with("release/")
        {
            trimmed = trimmed[8..].trim();
        } else if lower.starts_with("rel-")
            || lower.starts_with("rel_")
            || lower.starts_with("rel/")
        {
            trimmed = trimmed[4..].trim();
        } else if lower.starts_with("version-")
            || lower.starts_with("version_")
            || lower.starts_with("version/")
        {
            trimmed = trimmed[8..].trim();
        } else if lower.starts_with("ver-")
            || lower.starts_with("ver_")
            || lower.starts_with("ver/")
        {
            trimmed = trimmed[4..].trim();
        } else if let Some(idx) = trimmed.find(|c: char| c == '-' || c == '/' || c == '_') {
            let prefix = &trimmed[..idx];
            if prefix.eq_ignore_ascii_case("release")
                || prefix.eq_ignore_ascii_case("rel")
                || prefix.eq_ignore_ascii_case("version")
                || prefix.eq_ignore_ascii_case("ver")
            {
                trimmed = trimmed[idx + 1..].trim();
            }
        }
        if let Some(rest) = trimmed.strip_prefix(|c: char| c == 'v' || c == 'V') {
            if rest.starts_with(|c: char| c.is_ascii_digit()) || rest.is_empty() {
                trimmed = rest.trim();
            }
        }
        if trimmed == prev {
            break;
        }
    }
    trimmed
}

pub fn normalize_version(s: &str) -> &str {
    strip_version_prefix(s)
}

pub fn normalize_version_str(s: &str) -> &str {
    normalize_version(s)
}

pub fn single_version_matches(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    if !validate_target_version(ach) || !validate_target_version(exp) {
        return false;
    }
    let ach_lower = ach.to_ascii_lowercase();
    let exp_lower = exp.to_ascii_lowercase();
    let is_manifest = ach.contains(',')
        || exp.contains(',')
        || ach.contains('=')
        || exp.contains('=')
        || ach_lower.contains("frontend:")
        || exp_lower.contains("frontend:")
        || ach_lower.contains("backend:")
        || exp_lower.contains("backend:")
        || ach_lower.contains("proxy:")
        || exp_lower.contains("proxy:");

    if is_manifest {
        return matches_component_manifest(ach, exp);
    }
    if exp.eq_ignore_ascii_case(ach) {
        return true;
    }
    let norm_exp = normalize_version(exp);
    let norm_ach = normalize_version(ach);
    if norm_exp.eq_ignore_ascii_case(norm_ach) {
        return true;
    }
    let sem_exp = strip_semver_build_metadata(norm_exp);
    let sem_ach = strip_semver_build_metadata(norm_ach);
    if sem_exp.eq_ignore_ascii_case(sem_ach) {
        return true;
    }
    if commits_match_prefix(norm_exp, norm_ach, false) {
        return true;
    }
    false
}

pub fn single_version_matches_target(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    let norm_exp = strip_version_prefix(exp);
    let norm_ach = strip_version_prefix(ach);

    // Exact case-sensitive equality of normalized strings
    if norm_ach == norm_exp {
        return true;
    }

    // Only compare case-insensitively when BOTH normalized tokens are pure hexadecimal Git commit SHAs
    let ach_is_hex = is_hex_digits_7_to_40(norm_ach);
    let exp_is_hex = is_hex_digits_7_to_40(norm_exp);

    if ach_is_hex && exp_is_hex {
        if norm_ach.eq_ignore_ascii_case(norm_exp) {
            return true;
        }
        if commits_match_prefix(norm_exp, norm_ach, false) {
            return true;
        }
    }

    false
}

pub fn is_hex_sha_7_to_64(s: &str) -> bool {
    let len = s.len();
    (7..=64).contains(&len) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_hex_digits_7_to_64(s: &str) -> bool {
    is_hex_sha_7_to_64(s)
}

fn is_sensitive_key_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("api-key")
        || lower.contains("access_key")
        || lower.contains("access-key")
        || lower.contains("private_key")
        || lower.contains("private-key")
        || lower.contains("client_secret")
        || lower.contains("credential")
        || lower.contains("passphrase")
        || lower.contains("auth")
}

fn check_numeric_semver_debian(s: &str) -> bool {
    if s.contains(':') {
        let colon_count = s.matches(':').count();
        if colon_count != 1 {
            return false;
        }
        let (epoch, rest) = match s.split_once(':') {
            Some(pair) => pair,
            None => return false,
        };
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if !rest.starts_with(|c: char| c.is_ascii_digit()) {
            return false;
        }
        return rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'));
    }

    let rest = if (s.starts_with('v') || s.starts_with('V'))
        && s.len() > 1
        && s[1..]
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        &s[1..]
    } else {
        s
    };

    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }

    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'))
}

pub fn validate_single_version_token(ver: &str) -> bool {
    let trimmed = ver.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    if trimmed.chars().any(|c| {
        matches!(
            c,
            ';' | '&'
                | '|'
                | '`'
                | '$'
                | '('
                | ')'
                | '<'
                | '>'
                | '"'
                | '\''
                | '*'
                | '?'
                | '!'
                | '{'
                | '}'
        )
    }) {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    const FORBIDDEN_TOKENS: &[&str] = &[
        "latest",
        "unknown",
        "none",
        "null",
        "undefined",
        "error",
        "n/a",
        "na",
        "current",
        "installed",
        "pending",
        "default",
        "auto",
        "true",
        "false",
        "head",
        "main",
        "master",
        "stable",
        "beta",
        "nightly",
        "edge",
        "dev",
        "devel",
        "alpha",
        "rc",
        "release",
    ];
    if FORBIDDEN_TOKENS.contains(&lower.as_str()) {
        return false;
    }

    if is_sensitive_key_name(&lower) {
        return false;
    }

    // b) Valid Git commit SHA (7..=64 hex)
    if is_hex_sha_7_to_64(trimmed) {
        return true;
    }

    // a) Concrete numeric/SemVer/Debian version starting with ASCII digit (0-9)
    if check_numeric_semver_debian(trimmed) {
        return true;
    }

    // Standard release/version prefixes (e.g. Release-v1.0.0, ver-1.0.0)
    let stripped = strip_version_prefix(trimmed);
    if !stripped.is_empty() && stripped != trimmed {
        let stripped_lower = stripped.to_ascii_lowercase();
        if !FORBIDDEN_TOKENS.contains(&stripped_lower.as_str())
            && !is_sensitive_key_name(&stripped_lower)
        {
            if is_hex_sha_7_to_64(stripped) || check_numeric_semver_debian(stripped) {
                return true;
            }
        }
    }

    // c) Valid <prefix>-<sha> where <prefix> is [A-Za-z0-9._-]+ (not sensitive key)
    // and <sha> is 7..=64 hex characters or <prefix> starts with a digit.
    if let Some(idx) = trimmed.rfind('-') {
        let prefix = &trimmed[..idx];
        let sha = &trimmed[idx + 1..];
        if is_hex_sha_7_to_64(sha) && !prefix.is_empty() {
            let prefix_lower = prefix.to_ascii_lowercase();
            if prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                if prefix.starts_with(|c: char| c.is_ascii_digit())
                    || (!FORBIDDEN_TOKENS.contains(&prefix_lower.as_str())
                        && !is_sensitive_key_name(&prefix_lower))
                {
                    return true;
                }
            }
        }
    }

    false
}

pub fn is_valid_component_version(s: &str) -> bool {
    validate_single_version_token(s)
}

pub fn parse_piped_component_manifest(
    s: &str,
) -> Option<std::collections::HashMap<String, String>> {
    parse_component_manifest(s)
}

pub fn parse_component_manifest(s: &str) -> Option<std::collections::HashMap<String, String>> {
    if !s.contains(':') && !s.contains('=') {
        return None;
    }
    let parts: Vec<&str> = s.split(',').collect();
    let mut map = std::collections::HashMap::new();
    for raw_part in &parts {
        let item = raw_part.trim();
        if item.is_empty() {
            return None;
        }
        let (k, v) = if let Some(idx) = item.find(['=', ':']) {
            (&item[..idx], &item[idx + 1..])
        } else {
            return None;
        };
        let key = k.trim().to_lowercase();
        let val = v.trim().to_string();
        if key.is_empty() || val.is_empty() {
            return None;
        }
        if !validate_single_version_token(&val) {
            return None;
        }
        if map.insert(key, val).is_some() {
            return None;
        }
    }
    if map.len() < 2 {
        return None;
    }
    let has_frontend = map.contains_key("frontend");
    let has_backend = map.contains_key("backend");
    let has_proxy = map.contains_key("proxy");
    if has_frontend || has_backend || has_proxy {
        if !has_frontend || !has_backend || !has_proxy || map.len() != 3 || parts.len() != 3 {
            return None;
        }
        for k in ["frontend", "backend", "proxy"] {
            let val = map.get_mut(k)?;
            let norm = normalize_version(val);
            let val_clean = if is_hex_sha_7_to_64(norm) {
                norm.to_ascii_lowercase()
            } else if is_hex_sha_7_to_64(val) {
                val.to_ascii_lowercase()
            } else {
                val.trim().to_string()
            };
            *val = val_clean;
        }
    }
    Some(map)
}

pub fn matches_component_manifest(achieved: &str, expected: &str) -> bool {
    let exp_map = match parse_component_manifest(expected) {
        Some(m) => m,
        None => return false,
    };
    let ach_map = match parse_component_manifest(achieved) {
        Some(m) => m,
        None => return false,
    };
    if exp_map.len() != ach_map.len() {
        return false;
    }
    for (k, exp_val) in &exp_map {
        match ach_map.get(k) {
            Some(ach_val) => {
                let is_hex_pair = (is_hex_digits_7_to_40(exp_val)
                    || is_hex_digits_7_to_40(normalize_version(exp_val)))
                    && (is_hex_digits_7_to_40(ach_val)
                        || is_hex_digits_7_to_40(normalize_version(ach_val)));
                if is_hex_pair {
                    if !commits_match_prefix(exp_val, ach_val, true) {
                        return false;
                    }
                } else if !single_version_matches_target(ach_val, exp_val) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

pub fn validate_target_version(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    if trimmed.chars().any(|c| {
        matches!(
            c,
            ';' | '&'
                | '|'
                | '`'
                | '$'
                | '('
                | ')'
                | '<'
                | '>'
                | '"'
                | '\''
                | '*'
                | '?'
                | '!'
                | '{'
                | '}'
        )
    }) {
        return false;
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "unknown" | "none" | "null" | "latest"
    ) {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    let is_manifest_candidate = trimmed.contains(',')
        || trimmed.contains('=')
        || lower.contains("frontend:")
        || lower.contains("backend:")
        || lower.contains("proxy:")
        || lower.contains("frontend=")
        || lower.contains("backend=")
        || lower.contains("proxy=");

    if is_manifest_candidate {
        return parse_component_manifest(trimmed).is_some();
    }

    validate_single_version_token(trimmed)
}

pub fn is_valid_target_version_token(s: &str) -> bool {
    validate_target_version(s)
}

pub fn versions_match_target(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    if !validate_target_version(ach) || !validate_target_version(exp) {
        return false;
    }

    let ach_lower = ach.to_ascii_lowercase();
    let exp_lower = exp.to_ascii_lowercase();
    let is_manifest = ach.contains(',')
        || exp.contains(',')
        || ach.contains('=')
        || exp.contains('=')
        || ach_lower.contains("frontend:")
        || exp_lower.contains("frontend:")
        || ach_lower.contains("backend:")
        || exp_lower.contains("backend:")
        || ach_lower.contains("proxy:")
        || exp_lower.contains("proxy:");

    if is_manifest {
        return matches_component_manifest(ach, exp);
    }

    if ach == exp {
        return true;
    }

    single_version_matches_target(ach, exp)
}

pub fn get_lifecycle_history(
    conn: &Connection,
    package_id: &str,
    limit: usize,
) -> Result<Vec<af_models::PackageLifecycleRecord>> {
    let mut stmt = conn.prepare(
        "SELECT package_id, job_id, action, status, started_at, finished_at, owner_id, service_units,
                failure_category, failed_stage, exit_code, sanitized_summary, expected_target_version, achieved_version
         FROM package_lifecycle_history
         WHERE package_id = ?1
         ORDER BY id DESC LIMIT ?2",
    )?;
    let records = stmt
        .query_map(params![package_id, limit as i64], |row| {
            let service_units_raw: String = row.get(7)?;
            let service_units =
                serde_json::from_str::<Vec<String>>(&service_units_raw).unwrap_or_default();
            let failed_stage: String = row.get(9)?;
            let sanitized_summary: String = row.get(11)?;
            let expected_target_version: String = row.get(12)?;
            let achieved_version: String = row.get(13)?;
            Ok(af_models::PackageLifecycleRecord {
                package_id: row.get(0)?,
                job_id: row.get(1)?,
                action: row.get(2)?,
                status: row.get(3)?,
                started_at: row.get(4)?,
                finished_at: row.get(5)?,
                owner_id: row.get(6)?,
                service_units,
                failure_category: row.get(8)?,
                failed_stage: if failed_stage.is_empty() {
                    None
                } else {
                    Some(failed_stage)
                },
                exit_code: row.get(10)?,
                sanitized_summary: if sanitized_summary.is_empty() {
                    None
                } else {
                    Some(sanitized_summary)
                },
                expected_target_version: if expected_target_version.is_empty() {
                    None
                } else {
                    Some(expected_target_version)
                },
                achieved_version: if achieved_version.is_empty() {
                    None
                } else {
                    Some(achieved_version)
                },
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(records)
}

pub fn check_reservation(
    conn: &Connection,
    target: ReservationTarget<'_>,
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    let resources = match target {
        ReservationTarget::Package(package) => {
            let mut units = Vec::new();
            if !job_id.is_empty() {
                let table: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
                    [], |row| row.get(0),
                )?;
                if table {
                    let mut statement = conn.prepare("SELECT service_units FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2")?;
                    for raw in statement
                        .query_map(params![package, job_id], |row| row.get::<_, String>(0))?
                    {
                        units.extend(serde_json::from_str::<Vec<String>>(&raw?)?);
                    }
                }
            }
            return check_package_reservation(conn, package, &units, job_id, action);
        }
        ReservationTarget::Service(service) => Some(package_resources(service, &[])),
        ReservationTarget::System => None,
    };
    check_resources(conn, resources, job_id, action)
}

fn check_resources(
    conn: &Connection,
    resources: Option<BTreeSet<String>>,
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    let table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
        [], |row| row.get(0),
    )?;
    if !table {
        anyhow::ensure!(job_id.is_empty(), "lifecycle reservation not found");
        return Ok(());
    }
    let jobs: Vec<(String, String, String, String, String)> = conn
        .prepare(
            "SELECT package_id,job_id,action,service_units,status FROM package_lifecycle_jobs
         WHERE status NOT IN ('completed','failed','interrupted')",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut matched_owner = false;
    for (package, reserved_job, reserved_action, units, status) in jobs {
        anyhow::ensure!(resources.is_some(), "Application lifecycle reservation is active for {package}; core service control is unavailable");
        let reserved_resources =
            package_resources(&package, &serde_json::from_str::<Vec<String>>(&units)?);
        let matches_target = !resources.as_ref().unwrap().is_disjoint(&reserved_resources);
        if matches_target {
            let expected_status = match reserved_action.as_str() {
                "install" | "reinstall" => "installing",
                "update" => "updating",
                "remove" => "uninstalling",
                _ => anyhow::bail!("Lifecycle reservation action is unknown for {package}"),
            };
            anyhow::ensure!(
                status == expected_status,
                "Lifecycle reservation phase is unknown for {package}"
            );
            anyhow::ensure!(
                !job_id.is_empty() && reserved_job == job_id,
                "Application lifecycle reservation is active for {package}"
            );
            anyhow::ensure!(
                action.is_none_or(|value| value == reserved_action),
                "Lifecycle reservation action does not match"
            );
            matched_owner = true;
        }
    }
    anyhow::ensure!(
        job_id.is_empty() || matched_owner,
        "Lifecycle reservation is missing or no longer active"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReleaseCommand, ReleaseConfig, ReleaseLockGuard};
    use std::io::{BufRead, Read, Write};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn shared_companion_allows_only_matching_owner_not_unrelated_admin() {
        let (root, _, database, conn) = fixture();
        let owner = OwnerLease::create(&database).unwrap();
        insert(&conn, &owner.id);
        conn.execute(
            "UPDATE package_lifecycle_jobs SET service_units='[\"apache2.service\"]'",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('queued','other','update','updating','now',?1,'[\"apache2.service\"]')", [&owner.id]).unwrap();
        assert!(
            check_reservation(&conn, ReservationTarget::Service("apache2"), "job", None).is_err()
        );
        assert!(check_reservation(&conn, ReservationTarget::Service("apache2"), "", None).is_err());
        assert!(check_reservation(
            &conn,
            ReservationTarget::Service("apache2"),
            "foreign",
            None
        )
        .is_err());
        assert!(check_reservation(&conn, ReservationTarget::System, "job", None).is_err());
        conn.execute(
            "UPDATE package_lifecycle_jobs SET status='unknown' WHERE package_id='queued'",
            [],
        )
        .unwrap();
        assert!(
            check_reservation(&conn, ReservationTarget::Service("apache2"), "job", None).is_err()
        );
        drop((conn, owner));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn fixture() -> (PathBuf, ReleaseConfig, PathBuf, Connection) {
        let root = std::env::temp_dir().join(format!("af-owner-{}", uuid::Uuid::new_v4()));
        let cfg = ReleaseConfig::for_root(&root);
        let database = crate::config::try_resolve_db_path(&cfg, None).unwrap().path;
        std::fs::create_dir_all(database.parent().unwrap()).unwrap();
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        initialize_schema(&conn).unwrap();
        (root, cfg, database, conn)
    }

    fn insert(conn: &Connection, owner: &str) {
        conn.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,owner_id,service_units)
            VALUES ('fixture','job','update','updating','now',?1,'[\"fixture.service\",\"fixture.timer\"]')", [owner]).unwrap();
    }

    fn state(conn: &Connection) -> String {
        conn.query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn admission(cfg: &ReleaseConfig) -> crate::ReleaseResult<()> {
        let path = crate::ensure_interoperable_maintenance_lock_file(cfg)?;
        let _guard = ReleaseLockGuard::acquire(path, Duration::ZERO)?;
        crate::admin::ensure_no_active_package_lifecycle_jobs(cfg, ReleaseCommand::Deploy)
    }

    #[test]
    fn finished_jobs_retire_owner_files_without_changing_receipts() {
        let (root, _, database, mut conn) = fixture();
        let directory = database.with_extension("lifecycle-owners");
        for success in [true, false] {
            for index in 0..64 {
                let job = format!("finished-{success}-{index}");
                let lease = admit_job(&mut conn, "fixture", &job, "update", "now", &[]).unwrap();
                assert!(owner_is_alive(&database, &lease.id).unwrap());
                finish_job(&conn, "fixture", &job, "update", success, "configuration").unwrap();
                let receipt: (String, String, String, String, String) = conn
                    .query_row(
                        "SELECT owner_id,job_id,action,status,failure_category FROM package_lifecycle_jobs",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                    )
                    .unwrap();
                assert_eq!(receipt.0, lease.id);
                assert_eq!(receipt.1, job);
                assert_eq!(receipt.2, "update");
                assert_eq!(receipt.3, if success { "completed" } else { "failed" });
                assert_eq!(receipt.4, if success { "" } else { "configuration" });
                assert!(owner_is_alive(&database, &lease.id).unwrap());
                drop(lease);
                assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
            }
        }
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_preserves_shared_active_owner_and_direct_sql_receipts() {
        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        let owner = lease.id.clone();
        insert(&conn, &owner);
        conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id) VALUES ('other','other-job','remove','uninstalling','now',?1)", [&owner]).unwrap();
        conn.execute("UPDATE package_lifecycle_jobs SET status='failed',finished_at='finished',failure_category='configuration' WHERE package_id='fixture'", []).unwrap();
        drop(lease);
        assert!(lease_path(&database, &owner).unwrap().exists());
        assert!(!owner_is_alive(&database, &owner).unwrap());
        check_reservation(
            &conn,
            ReservationTarget::Package("other"),
            "other-job",
            Some("remove"),
        )
        .unwrap();
        assert!(check_reservation(
            &conn,
            ReservationTarget::Package("other"),
            "job",
            Some("remove")
        )
        .is_err());
        reconcile_jobs(&conn, &database).unwrap();
        assert!(!lease_path(&database, &owner).unwrap().exists());
        let receipts: Vec<(String, String, String, String, String)> = conn
            .prepare("SELECT package_id,job_id,action,status,owner_id FROM package_lifecycle_jobs ORDER BY package_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            receipts,
            vec![
                (
                    "fixture".into(),
                    "job".into(),
                    "update".into(),
                    "failed".into(),
                    owner.clone()
                ),
                (
                    "other".into(),
                    "other-job".into(),
                    "remove".into(),
                    "interrupted".into(),
                    owner
                ),
            ]
        );
        let finished: String = conn
            .query_row(
                "SELECT finished_at FROM package_lifecycle_jobs WHERE package_id='fixture'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(finished, "finished");
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_cleanup_preserves_live_and_successor_owner_identities() {
        let (root, _, database, mut conn) = fixture();
        let lease = admit_job(&mut conn, "fixture", "first", "update", "now", &[]).unwrap();
        let first_path = lease_path(&database, &lease.id).unwrap();
        finish_job(&conn, "fixture", "first", "update", true, "").unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert!(owner_is_alive(&database, &lease.id).unwrap());
        let successor = admit_job(&mut conn, "fixture", "second", "remove", "later", &[]).unwrap();
        let successor_path = lease_path(&database, &successor.id).unwrap();
        assert_ne!(lease.id, successor.id);
        drop(lease);
        assert!(!first_path.exists());
        assert!(owner_is_alive(&database, &successor.id).unwrap());
        for (package, job, action) in [
            ("fixture", "first", "update"),
            ("other", "second", "remove"),
            ("fixture", "second", "update"),
        ] {
            assert!(finish_job(&conn, package, job, action, true, "").is_err());
        }
        let identity: (String, String, String, String) = conn
            .query_row(
                "SELECT job_id,action,status,owner_id FROM package_lifecycle_jobs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            identity,
            (
                "second".into(),
                "remove".into(),
                "uninstalling".into(),
                successor.id.clone()
            )
        );
        drop(successor);
        assert!(successor_path.exists());
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!successor_path.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uncommitted_receipts_never_remove_recovery_evidence() {
        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let path = lease_path(&database, &lease.id).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
        drop(lease);
        retire_finished_owners(&conn, &database).unwrap();
        assert!(path.exists());
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(state(&conn), "updating");
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(path.exists());
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(state(&conn), "updating");
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!path.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn cleanup_failures_preserve_receipts_and_retry_without_weakening_locks() {
        use std::os::unix::fs::PermissionsExt;

        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let path = lease_path(&database, &lease.id).unwrap();
        let directory = path.parent().unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        finish_job(&conn, "fixture", "job", "update", false, "configuration").unwrap();
        drop(lease);
        assert!(path.exists());
        reconcile_jobs(&conn, &database).unwrap();
        assert!(path.exists());
        assert_eq!(state(&conn), "failed");
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert!(!path.exists());
        assert_eq!(state(&conn), "failed");
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn link_substitutions_never_unlink_executor_locks_or_owner_evidence() {
        use std::os::unix::fs::{symlink, MetadataExt};

        for hard_link in [false, true] {
            let (root, _, database, conn) = fixture();
            let lease = OwnerLease::create(&database).unwrap();
            insert(&conn, &lease.id);
            let path = lease_path(&database, &lease.id).unwrap();
            let evidence = root.join("original-owner");
            std::fs::rename(&path, &evidence).unwrap();
            let executor_path = root.join("package-executor.lock");
            let executor = ReleaseLockGuard::acquire(&executor_path, Duration::ZERO).unwrap();
            let executor_identity = executor.file_identity().unwrap();
            let executor_contents = std::fs::read(&executor_path).unwrap();
            if hard_link {
                std::fs::hard_link(&executor_path, &path).unwrap();
            } else {
                symlink(&executor_path, &path).unwrap();
            }
            assert!(owner_is_alive(&database, &lease.id).is_err());
            reconcile_jobs(&conn, &database).unwrap();
            assert_eq!(state(&conn), "updating");
            finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
            drop(lease);
            reconcile_jobs(&conn, &database).unwrap();
            assert!(std::fs::symlink_metadata(&path).is_ok());
            assert!(evidence.exists());
            assert_eq!(std::fs::read(&executor_path).unwrap(), executor_contents);
            let metadata = std::fs::metadata(&executor_path).unwrap();
            assert_eq!((metadata.dev(), metadata.ino()), executor_identity);
            assert!(ReleaseLockGuard::acquire(&executor_path, Duration::ZERO).is_err());
            assert_eq!(state(&conn), "completed");
            drop((conn, executor));
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    #[cfg(unix)]
    fn owner_directory_symlink_substitution_is_not_followed_during_cleanup() {
        use std::os::unix::fs::symlink;

        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
        let directory = database.with_extension("lifecycle-owners");
        let saved = root.join("saved-owners");
        let substituted = root.join("unrelated-owners");
        std::fs::create_dir(&substituted).unwrap();
        let sentinel = substituted.join(&lease.id);
        std::fs::write(&sentinel, b"unrelated executor evidence").unwrap();
        std::fs::rename(&directory, &saved).unwrap();
        symlink(&substituted, &directory).unwrap();
        drop(lease);
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"unrelated executor evidence"
        );
        assert_eq!(std::fs::read_dir(&saved).unwrap().count(), 1);
        std::fs::remove_file(&directory).unwrap();
        std::fs::rename(&saved, &directory).unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        assert!(sentinel.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_owner_survives_same_process_reopen_and_dead_owner_is_interrupted() {
        let (root, cfg, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        let path = lease_path(&database, &lease.id).unwrap();
        insert(&conn, &lease.id);
        let replacement_instance = OwnerLease::create(&database).unwrap();
        assert_ne!(replacement_instance.id, lease.id);
        drop(replacement_instance);
        assert!(admission(&cfg).is_err());
        assert_eq!(state(&conn), "updating");
        check_reservation(
            &conn,
            ReservationTarget::Service("fixture.timer"),
            "job",
            None,
        )
        .unwrap();
        assert!(check_reservation(
            &conn,
            ReservationTarget::Package("fixture"),
            "job",
            Some("remove")
        )
        .is_err());
        check_reservation(
            &conn,
            ReservationTarget::Package("other"),
            "",
            Some("remove"),
        )
        .unwrap();
        drop(lease);
        assert!(path.exists());
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!path.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn inherited_maintenance_survives_guard_drop_until_child_exits() {
        let (root, cfg, _database, conn) = fixture();
        let path = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let guard = ReleaseLockGuard::acquire(&path, Duration::ZERO).unwrap();
        let mut command = Command::new("/bin/cat");
        command.stdin(Stdio::piped()).stdout(Stdio::null());
        guard.preserve_in_child(&mut command).unwrap();
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(guard);
        assert!(admission(&cfg).is_err());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        admission(&cfg).unwrap();
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_lifecycle_table_preserves_explicit_rollback_admission() {
        use std::io::{Seek, SeekFrom};
        let (root, cfg, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let page: u64 = conn
            .query_row(
                "SELECT rootpage FROM sqlite_master WHERE name='package_lifecycle_jobs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let size: u64 = conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        let mut file = OpenOptions::new().write(true).open(&database).unwrap();
        file.seek(SeekFrom::Start((page - 1) * size)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let lock = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let _guard = ReleaseLockGuard::acquire(lock, Duration::ZERO).unwrap();
        assert!(crate::admin::ensure_no_active_package_lifecycle_jobs(
            &cfg,
            ReleaseCommand::Deploy
        )
        .is_err());
        crate::admin::ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Rollback)
            .unwrap();
        drop(lease);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_owners_fail_closed_and_runner_lock_prevents_premature_reconciliation() {
        let (root, cfg, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let lock = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let runner = ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
        drop(lease);
        assert!(admission(&cfg).is_err());
        assert_eq!(state(&conn), "updating");
        drop(runner);
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
        for unknown in ["", "bad-identity", "c37209aa-a27b-4812-b2ae-cbb605d04135"] {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET status='updating',owner_id=?1",
                [unknown],
            )
            .unwrap();
            assert!(admission(&cfg).is_err());
            assert_eq!(state(&conn), "updating");
        }
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn standalone_recovers_crashed_api_without_starting_api_or_erasing_release_recovery() {
        const WORKER: &str = "AF_OWNER_CRASH_FIXTURE";
        if let Some(database) = std::env::var_os(WORKER) {
            let database = PathBuf::from(database);
            let conn = Connection::open(&database).unwrap();
            let lease = OwnerLease::create(&database).unwrap();
            insert(&conn, &lease.id);
            println!("OWNER_READY");
            std::io::stdout().flush().unwrap();
            let mut release = [0u8];
            std::io::stdin().read_exact(&mut release).unwrap();
            drop(lease);
            return;
        }
        let (root, cfg, database, conn) = fixture();
        std::fs::create_dir_all(&cfg.releases_dir).unwrap();
        let recovery = cfg.releases_dir.join(".recovery_state.json");
        std::fs::write(&recovery, b"release-recovery-sentinel").unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lifecycle::tests::standalone_recovers_crashed_api_without_starting_api_or_erasing_release_recovery", "--nocapture"])
            .env(WORKER, &database).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.contains("OWNER_READY") {
                break;
            }
        }
        assert!(admission(&cfg).is_err());
        let owner: String = conn
            .query_row("SELECT owner_id FROM package_lifecycle_jobs", [], |row| {
                row.get(0)
            })
            .unwrap();
        let path = lease_path(&database, &owner).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(path.exists());
        assert!(!owner_is_alive(&database, &owner).unwrap());
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(&recovery).unwrap(),
            b"release-recovery-sentinel"
        );
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_package_lifecycle_history_and_diagnostics() {
        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "radarr",
            "job-history-1",
            "update",
            "2026-11-08T12:00:00Z",
            &[],
            Some("5.3.6"),
        )
        .unwrap();

        finish_job_with_diagnostics(
            &conn,
            "radarr",
            "job-history-1",
            "update",
            false,
            "target_verification",
            Some("target_verification"),
            Some(1),
            Some("version did not advance"),
            Some("5.3.6"),
            Some("5.3.5"),
            None,
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "radarr", 10).unwrap();
        assert_eq!(history.len(), 1);
        let item = &history[0];
        assert_eq!(item.job_id, "job-history-1");
        assert_eq!(item.status, "failed");
        assert_eq!(item.expected_target_version.as_deref(), Some("5.3.6"));
        assert_eq!(item.achieved_version.as_deref(), Some("5.3.5"));
        assert_eq!(item.failed_stage.as_deref(), Some("target_verification"));
        assert_eq!(item.exit_code, Some(1));

        // Start a second job
        let lease2 = admit_job_with_target(
            &mut conn,
            "radarr",
            "job-history-2",
            "update",
            "2026-11-08T12:05:00Z",
            &[],
            Some("5.3.6"),
        )
        .unwrap();

        finish_job_with_diagnostics(
            &conn,
            "radarr",
            "job-history-2",
            "update",
            true,
            "",
            None,
            Some(0),
            None,
            Some("5.3.6"),
            Some("5.3.6"),
            None,
        )
        .unwrap();

        let history_updated = get_lifecycle_history(&conn, "radarr", 10).unwrap();
        assert_eq!(history_updated.len(), 2);
        assert_eq!(history_updated[0].job_id, "job-history-2");
        assert_eq!(history_updated[0].status, "completed");
        assert_eq!(
            history_updated[0].achieved_version.as_deref(),
            Some("5.3.6")
        );
        assert_eq!(history_updated[1].job_id, "job-history-1");

        drop(lease);
        drop(lease2);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_strict_hex_commit_and_tokens() {
        // 8-digit decimal date must NOT be treated as hex commit
        assert!(!is_hex_commit("20261108"));
        assert!(!is_hex_commit("1234567"));
        assert!(!is_hex_commit("123456")); // too short

        // Valid short hex with letters
        assert!(is_hex_commit("202611a"));
        assert!(is_hex_commit("abcdef0"));
        assert!(is_hex_commit("0123456789abcdef"));

        // 40-char commit
        assert!(is_hex_commit("0000000000000000000000000000000000000000"));
        assert!(is_hex_commit("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));

        // is_valid_target_version_token
        assert!(!is_valid_target_version_token(""));
        assert!(!is_valid_target_version_token("   "));
        assert!(!is_valid_target_version_token("latest"));
        assert!(!is_valid_target_version_token("LATEST"));
        assert!(!is_valid_target_version_token("unknown"));
        assert!(!is_valid_target_version_token("none"));
        assert!(!is_valid_target_version_token("null"));
        assert!(!is_valid_target_version_token("v1.0 with space"));

        assert!(is_valid_target_version_token("v1.2.3"));
        assert!(is_valid_target_version_token("1.2.3"));
        assert!(is_valid_target_version_token("release-1.0.0"));
        assert!(is_valid_target_version_token("1234567")); // 7-digit short hex
        assert!(is_valid_target_version_token(
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        ));
        assert!(is_valid_target_version_token(
            "frontend:4b825dc,backend:012345a,proxy:abcdef1"
        ));
    }

    #[test]
    fn test_parse_manifest_and_version_match() {
        // Duplicate keys rejected
        assert!(parse_component_manifest("frontend:4b825dc,frontend:012345a").is_none());
        // Fewer than 2 components rejected
        assert!(parse_component_manifest("frontend:4b825dc").is_none());
        // Frontend/backend/proxy requires all 3
        assert!(parse_component_manifest("frontend:4b825dc,backend:012345a").is_none());
        assert!(parse_component_manifest("backend:012345a,proxy:abcdef1").is_none());
        // All 3 with hex commits valid (including all-digit short SHAs)
        let m = parse_component_manifest("frontend:4b825dc,backend:012345a,proxy:abcdef1");
        assert!(m.is_some());
        assert!(
            parse_component_manifest("frontend:20261108,backend:012345a,proxy:abcdef1").is_some()
        );
        // All 3 but non-hex commit rejected
        assert!(
            parse_component_manifest("frontend:nothex12,backend:012345a,proxy:abcdef1").is_none()
        );

        // versions_match_target with manifests
        let exp = "frontend:4b825dc642cb,backend:012345abcdef,proxy:abcdef123456";
        let ach = "frontend:4b825dc,backend:012345a,proxy:abcdef1";
        assert!(versions_match_target(ach, exp));

        // Different length manifest must fail
        let ach_extra = "frontend:4b825dc,backend:012345a,proxy:abcdef1,extra:v1.0";
        assert!(!versions_match_target(ach_extra, exp));
    }

    #[test]
    fn test_case_insensitive_and_all_digit_git_shas() {
        // 1. Case-insensitive SHA prefix matching
        let full_lower = "abcdef1234567890abcdef1234567890abcdef12";
        let short_upper = "ABCDEF12";
        assert!(single_version_matches(short_upper, full_lower));
        assert!(single_version_matches(full_lower, short_upper));
        assert!(versions_match_target(short_upper, full_lower));
        assert!(versions_match_target(full_lower, short_upper));

        // 2. All-digit short Git SHA matching 40-char SHA
        let all_digit_short = "1234567";
        let full_with_hex = "1234567abcdef0123456789abcdef0123456789a"; // 40 chars
        assert_eq!(full_with_hex.len(), 40);
        assert!(single_version_matches(all_digit_short, full_with_hex));
        assert!(single_version_matches(full_with_hex, all_digit_short));
        assert!(versions_match_target(all_digit_short, full_with_hex));

        // Inside frontend,backend,proxy Git manifest, even two all-digit short SHAs match
        let exp_git_manifest = "frontend:1234567890,backend:0123456789,proxy:9876543210";
        let ach_git_manifest = "frontend:1234567,backend:0123456,proxy:9876543";
        assert!(versions_match_target(ach_git_manifest, exp_git_manifest));

        // But 8/9 digit decimal release dates without 40-char context do NOT prefix-match
        assert!(!single_version_matches("20261108", "202611080"));
        assert!(!versions_match_target("20261108", "202611080"));

        // 3. Generic component manifests comp1:1.1,comp2:2.0 vs comp1:1.10,comp2:2.0 do NOT match
        let gen1 = "comp1:1.1,comp2:2.0";
        let gen2 = "comp1:1.10,comp2:2.0";
        assert!(!versions_match_target(gen1, gen2));
        assert!(!versions_match_target(gen2, gen1));

        let gen_same = "comp1:1.1,comp2:2.0";
        assert!(versions_match_target(gen1, gen_same));
    }

    #[test]
    fn test_finish_job_inserts_history_if_0_rows_updated() {
        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "prowlarr",
            "job-zero-row-1",
            "update",
            "2026-11-08T12:00:00Z",
            &[],
            Some("1.0.0"),
        )
        .unwrap();

        // Delete history row to simulate 0-row update
        conn.execute(
            "DELETE FROM package_lifecycle_history WHERE job_id='job-zero-row-1'",
            [],
        )
        .unwrap();

        // Finish should insert new history row
        finish_job_with_diagnostics(
            &conn,
            "prowlarr",
            "job-zero-row-1",
            "update",
            true,
            "",
            None,
            Some(0),
            None,
            Some("1.0.0"),
            Some("1.0.0"),
            None,
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "prowlarr", 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].job_id, "job-zero-row-1");
        assert_eq!(history[0].status, "completed");

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_normalize_version_and_semver_build_metadata() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("V1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release-1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release_1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release/1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel-1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel_1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release-v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel_v1.2.3"), "1.2.3");

        // Build metadata identity preserved across normalization (+debug, +git1, +b1, +20260101, etc.)
        assert_eq!(normalize_version("1.0.0+build.2"), "1.0.0+build.2");
        assert_eq!(normalize_version("1.0.0+debug"), "1.0.0+debug");
        assert_eq!(normalize_version("1.0.0+beta"), "1.0.0+beta");
        assert_eq!(normalize_version("1.0.0+upstream"), "1.0.0+upstream");
        assert_eq!(normalize_version("v1.0.0+20241108"), "1.0.0+20241108");
        assert_eq!(
            normalize_version("1.0.0-rc.1+build.42"),
            "1.0.0-rc.1+build.42"
        );

        // Stacked prefixes stripped
        assert_eq!(normalize_version("release-v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release_v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel-v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel_v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release/v1.2.3"), "1.2.3");

        // Debian + revisions preserved
        assert_eq!(normalize_version("1.2.3+deb11u1"), "1.2.3+deb11u1");
        assert_eq!(normalize_version("1.2.3+deb12u2"), "1.2.3+deb12u2");
        assert_eq!(normalize_version("1.0.0+dfsg"), "1.0.0+dfsg");
        assert_eq!(normalize_version("1.0.0+dfsg1"), "1.0.0+dfsg1");
        assert_eq!(normalize_version("1.0.0+dfsg.1"), "1.0.0+dfsg.1");
        assert_eq!(normalize_version("1.0.0+dfsg-1"), "1.0.0+dfsg-1");
        assert_eq!(normalize_version("1.0.0+ds1"), "1.0.0+ds1");
        assert_eq!(normalize_version("1.0.0+really2.0"), "1.0.0+really2.0");
        assert_eq!(normalize_version("1.0.0+nmu1"), "1.0.0+nmu1");
        assert_eq!(normalize_version("1.0.0+b1"), "1.0.0+b1");
        assert_eq!(normalize_version("1.0.0+b2"), "1.0.0+b2");
        assert_eq!(normalize_version("1.0.0+u2"), "1.0.0+u2");

        // normalize_version_str alias preserves build metadata
        assert_eq!(
            normalize_version_str("release_2.0.0+build.1"),
            "2.0.0+build.1"
        );

        // single_version_matches works with build metadata & release prefixes (SemVer equivalence)
        assert!(single_version_matches("1.0.0+build.2", "1.0.0"));
        assert!(single_version_matches("1.0.0", "1.0.0+build.2"));
        assert!(single_version_matches("1.0.0+debug", "1.0.0"));
        assert!(single_version_matches("release-v1.0.0", "1.0.0"));
        assert!(single_version_matches("release_1.0.0", "v1.0.0"));

        // Target certification distinguishes build metadata (+debug, +build.2, etc.)
        assert!(!versions_match_target("1.0.0", "1.0.0+debug"));
        assert!(!versions_match_target("1.0.0+debug", "1.0.0"));
        assert!(!versions_match_target("1.0.0+build.2", "1.0.0"));
        assert!(versions_match_target("1.0.0+debug", "v1.0.0+debug"));
        assert!(versions_match_target("1.0.0+debug", "release-v1.0.0+debug"));
    }

    #[test]
    fn test_piped_manifest_delimiters_and_component_versions() {
        // Both '=' and ':' delimiters are accepted for 3-component piped manifests
        assert!(matches_component_manifest(
            "frontend=1.0,backend=2.0,proxy=3.0",
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
        assert!(matches_component_manifest(
            "frontend:1.0,backend:2.0,proxy:3.0",
            "frontend=1.0,backend=2.0,proxy:3.0"
        ));
        assert!(matches_component_manifest(
            "frontend=v1.0,backend=v2.0,proxy=v3.0",
            "frontend=1.0,backend=2.0,proxy:3.0"
        ));
        assert!(versions_match_target(
            "frontend=1.0,backend=2.0,proxy=3.0",
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
        assert!(versions_match_target(
            "frontend=v1.0,backend=v2.0,proxy=v3.0",
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
    }

    #[test]
    fn test_source_aware_target_validation_debian_and_manifest() {
        assert!(validate_target_version("1.0~rc1-1"));
        assert!(validate_target_version("1:1.0-1"));
        assert!(validate_target_version("1.0.0+git1"));
        assert!(validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0"
        ));
        assert!(validate_target_version(
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));

        // Dangerous characters rejected
        assert!(!validate_target_version("../etc/passwd"));
        assert!(!validate_target_version("1.0.0; rm -rf /"));
        assert!(!validate_target_version("1.0.0 && whoami"));
        assert!(!validate_target_version("latest"));
        assert!(!validate_target_version("unknown"));
        assert!(!validate_target_version(""));
    }

    #[test]
    fn test_case_preservation_for_target_certification() {
        assert!(!versions_match_target("1.0.0+Debug", "1.0.0+debug"));
        assert!(!versions_match_target("1.0.0+debug", "1.0.0+Debug"));
        assert!(versions_match_target("1.0.0+Debug", "v1.0.0+Debug"));
        assert!(versions_match_target("Release-v1.0.0+Debug", "1.0.0+Debug"));
        assert!(versions_match_target("version-v1.0.0+Debug", "1.0.0+Debug"));
        assert!(versions_match_target("ver-1.0.0+Debug", "1.0.0+Debug"));
        assert!(versions_match_target("deadbeef1234", "DEADBEEF1234"));
        assert!(versions_match_target("DEADBEEF1234", "deadbeef1234"));
    }

    #[test]
    fn test_reject_incomplete_or_malformed_component_manifests() {
        assert!(!validate_target_version("frontend=1.0,backend=2.0"));
        assert!(!validate_target_version("frontend:1.0,backend:2.0"));
        assert!(!validate_target_version("frontend=1.0,backend=2.0,proxy="));
        assert!(!validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0,extra=4.0"
        ));

        assert!(validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0"
        ));
        assert!(validate_target_version(
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
        assert!(validate_target_version("1:1.0.0~rc1-1+b1"));
    }

    #[test]
    fn test_parse_component_manifest_rejects_empty_and_duplicate_entries() {
        // Empty segments (leading, trailing, double comma, whitespace-padded)
        assert!(parse_component_manifest("frontend=1.0,,backend=2.0,proxy=3.0").is_none());
        assert!(parse_component_manifest("frontend=1.0,backend=2.0,proxy=3.0,").is_none());
        assert!(parse_component_manifest(",frontend=1.0,backend=2.0,proxy=3.0").is_none());
        assert!(parse_component_manifest("frontend=1.0,  ,backend=2.0,proxy=3.0").is_none());
        assert!(!validate_target_version(
            "frontend=1.0,,backend=2.0,proxy=3.0"
        ));
        assert!(!validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0,"
        ));
        assert!(!validate_target_version(
            ",frontend=1.0,backend=2.0,proxy=3.0"
        ));
        assert!(!validate_target_version(
            "frontend=1.0,  ,backend=2.0,proxy=3.0"
        ));

        // Duplicate component keys
        assert!(
            parse_component_manifest("frontend=1.0,frontend=2.0,backend=2.0,proxy=3.0").is_none()
        );
        assert!(
            parse_component_manifest("frontend:1.0,backend:2.0,proxy:3.0,backend:2.0").is_none()
        );
        assert!(parse_component_manifest("frontend:1.0,backend:2.0,proxy:3.0,proxy:3.0").is_none());
        assert!(!validate_target_version(
            "frontend=1.0,frontend=2.0,backend=2.0,proxy=3.0"
        ));
        assert!(!validate_target_version(
            "frontend:1.0,backend:2.0,proxy:3.0,backend:2.0"
        ));
    }

    #[test]
    fn test_malformed_manifest_never_matches_itself() {
        assert!(!versions_match_target(
            "frontend=1.0,,backend=2.0,proxy=3.0",
            "frontend=1.0,,backend=2.0,proxy=3.0"
        ));
        assert!(!single_version_matches(
            "frontend=1.0,,backend=2.0,proxy=3.0",
            "frontend=1.0,,backend=2.0,proxy=3.0"
        ));
    }

    #[test]
    fn test_target_validator_rejects_credential_tokens_and_preserves_debian_epoch() {
        assert!(!validate_target_version("password:secret"));
        assert!(!validate_target_version("token:abc"));
        assert!(!validate_target_version("user:pass"));
        assert!(validate_target_version("1:1.0.0~rc1-1+b1"));
        assert!(validate_target_version("0:1.0.0"));
        assert!(validate_target_version("1.0.0+build-"));
        assert!(validate_target_version("1.0.0+build--"));
    }

    #[test]
    fn test_persisting_lifecycle_outcome_sanitizes_credentials_and_secrets() {
        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "testpkg",
            "job-secret-1",
            "update",
            "2026-11-08T12:00:00Z",
            &[],
            Some("password:secret"),
        )
        .unwrap();

        finish_job_with_diagnostics(
            &conn,
            "testpkg",
            "job-secret-1",
            "update",
            false,
            "configuration",
            Some("install_stage"),
            Some(1),
            Some("password='prefix\nPERSISTED_QUOTE_CANARY' curl -u operator:\" PERSISTED_QUOTE_CANARY\" --verbose; failed connecting with Bearer supersecret and curl -u admin:hunter2 https://example.com"),
            Some("password:secret"),
            Some("0.9.0"),
            None,
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "testpkg", 10).unwrap();
        assert_eq!(history.len(), 1);
        let record = &history[0];

        let summary = record.sanitized_summary.as_deref().unwrap();
        assert!(summary.contains("[REDACTED]"));
        assert!(!summary.contains("supersecret"));
        assert!(!summary.contains("hunter2"));
        assert!(!summary.contains("PERSISTED_QUOTE_CANARY"));

        let expected = record.expected_target_version.as_deref().unwrap();
        assert!(expected.contains("[REDACTED]"));
        assert!(!expected.contains("password:secret"));

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_sanitize_persisted_lifecycle_text_quoted_credentials() {
        assert_eq!(
            sanitize_persisted_lifecycle_text("password=\"first SECRET_TAIL\""),
            "password=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("secret='multi word secret'"),
            "secret=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("\"password\": \"first SECRET_TAIL\""),
            "\"password\": [REDACTED]"
        );
        let sample = "config with password=\"first SECRET_TAIL\" and secret='multi word secret' and \"password\": \"first SECRET_TAIL\" done";
        let sanitized = sanitize_persisted_lifecycle_text(sample);
        assert!(!sanitized.contains("SECRET_TAIL"));
        assert!(!sanitized.contains("multi word secret"));
        assert!(sanitized.contains("password=[REDACTED]"));
        assert!(sanitized.contains("secret=[REDACTED]"));
        assert!(sanitized.contains("\"password\": [REDACTED]"));
    }

    #[test]
    fn test_invalid_placeholder_and_channel_manifests_rejected() {
        assert!(!validate_target_version(
            "frontend:latest,backend:latest,proxy:latest"
        ));
        assert!(!validate_target_version("comp1:latest,comp2:unknown"));
        assert!(!validate_target_version(
            "frontend=unknown,backend=1.0.0,proxy=1.0.0"
        ));

        assert!(!versions_match_target(
            "frontend:latest,backend:latest,proxy:latest",
            "frontend:latest,backend:latest,proxy:latest"
        ));
        assert!(!versions_match_target(
            "comp1:latest,comp2:unknown",
            "comp1:latest,comp2:unknown"
        ));
        assert!(!versions_match_target(
            "frontend=unknown,backend=1.0.0,proxy=1.0.0",
            "frontend=unknown,backend=1.0.0,proxy=1.0.0"
        ));
        assert!(parse_component_manifest("frontend:latest,backend:latest,proxy:latest").is_none());
        assert!(
            parse_piped_component_manifest("frontend:latest,backend:latest,proxy:latest").is_none()
        );
        assert!(parse_component_manifest("comp1:latest,comp2:unknown").is_none());
    }

    #[test]
    fn test_sensitive_credentials_redaction_and_job_recording() {
        let sample1 = r#"{"db_password": "my_super_secret_db_pw"}"#;
        let sanitized1 = sanitize_persisted_lifecycle_text(sample1);
        assert!(!sanitized1.contains("my_super_secret_db_pw"));
        assert!(sanitized1.contains(r#"{"db_password": [REDACTED]}"#));

        let sample2 = "db_password=my_super_secret_db_pw";
        let sanitized2 = sanitize_persisted_lifecycle_text(sample2);
        assert!(!sanitized2.contains("my_super_secret_db_pw"));
        assert_eq!(sanitized2, "db_password=[REDACTED]");

        let sample3 = r#"admin_secret="first \"escaped_quote_secret\" tail_secret""#;
        let sanitized3 = sanitize_persisted_lifecycle_text(sample3);
        assert!(!sanitized3.contains("escaped_quote_secret"));
        assert!(!sanitized3.contains("tail_secret"));
        assert_eq!(sanitized3, "admin_secret=[REDACTED]");

        let sample4 = r#"{"secret": "first \"escaped_quote_secret\" tail_secret"}"#;
        let sanitized4 = sanitize_persisted_lifecycle_text(sample4);
        assert!(!sanitized4.contains("escaped_quote_secret"));
        assert!(!sanitized4.contains("tail_secret"));
        assert!(sanitized4.contains(r#"{"secret": [REDACTED]}"#));

        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "testpkg-creds",
            "job-cred-1",
            "update",
            "2026-11-09T08:00:00Z",
            &[],
            Some("1.0.0"),
        )
        .unwrap();

        let diagnostic_summary =
            format!("failure with {sample1} and {sample2} and {sample3} and {sample4}");
        record_completed_lifecycle_job(
            &conn,
            "testpkg-creds",
            "job-cred-1",
            "update",
            Some(&diagnostic_summary),
            Some("1.0.0"),
            Some("1.0.0"),
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "testpkg-creds", 10).unwrap();
        assert_eq!(history.len(), 1);
        let record = &history[0];
        let summary = record.sanitized_summary.as_deref().unwrap();
        assert!(!summary.contains("my_super_secret_db_pw"));
        assert!(!summary.contains("escaped_quote_secret"));
        assert!(!summary.contains("tail_secret"));
        assert!(summary.contains("[REDACTED]"));

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_sanitize_curl_credentials_with_intervening_flags_and_quotes() {
        let cmd1 = "curl -s -u admin:synthetic-secret http://127.0.0.1:5572/core/version";
        let sanitized1 = sanitize_persisted_lifecycle_text(cmd1);
        assert!(!sanitized1.contains("synthetic-secret"));
        assert_eq!(
            sanitized1,
            "curl -s -u [REDACTED] http://127.0.0.1:5572/core/version"
        );

        let cmd2 = r#"curl -fsSL --user "admin:my secret" http://localhost"#;
        let sanitized2 = sanitize_persisted_lifecycle_text(cmd2);
        assert!(!sanitized2.contains("my secret"));
        assert_eq!(sanitized2, "curl -fsSL --user [REDACTED] http://localhost");

        let cmd3 = "curl --user=admin:secret_pass http://localhost";
        let sanitized3 = sanitize_persisted_lifecycle_text(cmd3);
        assert!(!sanitized3.contains("secret_pass"));
        assert_eq!(sanitized3, "curl --user=[REDACTED] http://localhost");

        let cmd4 = "curl -u=admin:secret_pass http://localhost";
        let sanitized4 = sanitize_persisted_lifecycle_text(cmd4);
        assert!(!sanitized4.contains("secret_pass"));
        assert_eq!(sanitized4, "curl -u=[REDACTED] http://localhost");
    }

    #[test]
    fn test_prerelease_version_for_channel_debian_and_semver() {
        assert!(is_prerelease_version_for_channel("1.2.3-foo-1"));
        assert!(is_prerelease_version_for_channel("1.2.3-1.2"));
        assert!(is_prerelease_version_for_channel("1.2.3-rc1"));
        assert!(is_prerelease_version_for_channel("1.2.3~rc1"));
        assert!(is_prerelease_version_for_channel("1.2.3-beta.1"));
        assert!(is_prerelease_version_for_channel("1.0.0-0.1"));

        assert!(!is_prerelease_version_for_channel("1:1.2.3-1+b1"));
        assert!(!is_prerelease_version_for_channel("2.4.5-1ubuntu1"));
        assert!(!is_prerelease_version_for_channel("1.0.0-1deb12u1"));
        assert!(!is_prerelease_version_for_channel("1.2.3-1"));
        assert!(!is_prerelease_version_for_channel("1.2.3"));
    }

    #[test]
    fn test_sanitize_curl_attached_credentials_and_commas() {
        let cmd1 = "curl -uadmin:synthetic-secret http://localhost";
        let sanitized1 = sanitize_persisted_lifecycle_text(cmd1);
        assert!(!sanitized1.contains("synthetic-secret"));
        assert_eq!(sanitized1, "curl -u[REDACTED] http://localhost");

        let cmd2 = "curl -s -uadmin:part1,part2 http://localhost";
        let sanitized2 = sanitize_persisted_lifecycle_text(cmd2);
        assert!(!sanitized2.contains("part1"));
        assert!(!sanitized2.contains("part2"));
        assert_eq!(sanitized2, "curl -s -u[REDACTED] http://localhost");

        let cmd3 = "curl --user=admin:part1,part2 http://localhost";
        let sanitized3 = sanitize_persisted_lifecycle_text(cmd3);
        assert!(!sanitized3.contains("part1"));
        assert!(!sanitized3.contains("part2"));
        assert_eq!(sanitized3, "curl --user=[REDACTED] http://localhost");

        let cmd4 = "curl -u admin:sec1,sec2 http://localhost";
        let sanitized4 = sanitize_persisted_lifecycle_text(cmd4);
        assert!(!sanitized4.contains("sec1"));
        assert!(!sanitized4.contains("sec2"));
        assert_eq!(sanitized4, "curl -u [REDACTED] http://localhost");

        let cmd5 = "curl -fsSL -uadmin:secret http://localhost";
        let sanitized5 = sanitize_persisted_lifecycle_text(cmd5);
        assert!(!sanitized5.contains("secret"));
        assert_eq!(sanitized5, "curl -fsSL -u[REDACTED] http://localhost");
    }

    #[test]
    fn test_source_aware_prerelease_version_rules() {
        // is_valid_apt_debian_revision_suffix
        assert!(is_valid_apt_debian_revision_suffix("0.1"));
        assert!(is_valid_apt_debian_revision_suffix("1.2"));
        assert!(is_valid_apt_debian_revision_suffix("1+b1"));
        assert!(is_valid_apt_debian_revision_suffix("1deb12u1"));
        assert!(is_valid_apt_debian_revision_suffix("2ubuntu1"));
        assert!(is_valid_apt_debian_revision_suffix("1"));
        assert!(!is_valid_apt_debian_revision_suffix("rc1"));
        assert!(!is_valid_apt_debian_revision_suffix("beta.1"));
        assert!(!is_valid_apt_debian_revision_suffix("foo-1"));
        assert!(!is_valid_apt_debian_revision_suffix("0.1~rc1"));

        // APT source
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.0.0-0.1",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3-1.2",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1:1.2.3-1+b1",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3-1",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "2.4.5-1ubuntu1",
            Some("apt")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-rc1",
            Some("apt")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-foo-1",
            Some("apt")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3~rc1",
            Some("apt")
        ));

        // Git / git_tags source
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.0.0-0.1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1.2",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-foo-1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1:1.2.3-1+b1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "2.4.5-1ubuntu1",
            Some("git_tags")
        ));

        // Strict SemVer prerelease rejection for git / github sources including debug and revisions
        for src in ["github", "github_release", "git", "git_tags"] {
            assert!(is_prerelease_version_for_channel_with_source(
                "1.2.3-debug.1",
                Some(src)
            ));
            assert!(is_prerelease_version_for_channel_with_source(
                "1.2.3-1",
                Some(src)
            ));
            assert!(is_prerelease_version_for_channel_with_source(
                "1.2.3-ubuntu1",
                Some(src)
            ));
            assert!(!is_prerelease_version_for_channel_with_source(
                "1.2.3",
                Some(src)
            ));
        }

        // Default / None source
        assert!(is_prerelease_version_for_channel_with_source(
            "1.0.0-0.1",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1.2",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-foo-1",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-debug.1",
            None
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3-1", None
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1:1.2.3-1+b1",
            None
        ));
    }

    #[test]
    fn test_sanitize_curl_and_kv_edge_cases() {
        assert_eq!(
            sanitize_persisted_lifecycle_text("curl -uadmin https://example.com"),
            "curl -u[REDACTED] https://example.com"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("curl -uadmin:secret https://example.com"),
            "curl -u[REDACTED] https://example.com"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("curl -u admin:part1,part2 https://example.com"),
            "curl -u [REDACTED] https://example.com"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("password=part1,part2"),
            "password=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("password: part1,part2"),
            "password: [REDACTED]"
        );
    }

    #[test]
    fn test_wave19_audit_findings_lifecycle_sanitization_and_ordering() {
        // Finding 5: continuation tokens with '=' and ':'
        assert_eq!(
            sanitize_persisted_lifecycle_text("password: part1,part2=SECRET"),
            "password: [REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("token=part1,part2=SECRET; next=ok"),
            "token=[REDACTED]; next=ok"
        );

        // Finding 3: passwordless ssh:// and cred#... preserved, while other credentials redacted
        assert_eq!(
            sanitize_persisted_lifecycle_text(
                "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
            ),
            "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("git-repo:ssh://git@github.com/org/repo.git#main"),
            "git-repo:ssh://git@github.com/org/repo.git#main"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(
                "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main"
            ),
            "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("ssh://user:pass@host/repo.git"),
            "ssh://[REDACTED]@host/repo.git"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("https://user:pass@host/repo.git"),
            "https://[REDACTED]@host/repo.git"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("https://token@host/repo.git"),
            "https://[REDACTED]@host/repo.git"
        );

        // Finding 6: Build metadata with +dfsg-1 is not classified as prerelease on Git / GitHub
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dfsg-1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dfsg-1",
            Some("github")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+20130313144700",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+build-4",
            Some("git")
        ));
        // Build metadata (+...) does NOT affect prerelease classification on non-APT sources
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dev.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+debug",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dirty",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+wip",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1",
            Some("git")
        ));

        // Finding 7: 7+ digit numeric version tags compared numerically, not as hex commit hashes
        assert_eq!(
            compare_versions("10000000", "9000000"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("v10000000", "v9000000"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("20261109", "9999999"),
            std::cmp::Ordering::Greater
        );
        // Real hex commit hashes still compared lexically
        assert_eq!(
            compare_versions("deadbeef", "cafebabe"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("09abcdef", "10000000"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_nested_secret_redaction() {
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#"password: {"value":"CANARY_SECRET"}"#),
            "password: [REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#""password": {"value":"CANARY_SECRET"}"#),
            "\"password\": [REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#"secret=["CANARY_SECRET"]"#),
            "secret=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#"password={"nested":{"secret":"CANARY_SECRET"}}"#),
            "password=[REDACTED]"
        );
        let sample =
            r#"diagnostics: {"auth": {"token": "CANARY_SECRET"}, "password": ["NESTED_SECRET"]}"#;
        let sanitized = sanitize_persisted_lifecycle_text(sample);
        assert!(!sanitized.contains("CANARY_SECRET"));
        assert!(!sanitized.contains("NESTED_SECRET"));
    }

    #[test]
    fn test_build_metadata_stable_classification() {
        assert!(!is_prerelease_version_for_channel("v1.2.3+rc.1"));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            None
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            Some("github")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dev.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+debug",
            Some("github")
        ));

        // True prereleases must still be classified as prereleases
        assert!(is_prerelease_version_for_channel("1.2.3-rc.1"));
        assert!(is_prerelease_version_for_channel("1.2.3~rc.1"));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-rc.1",
            Some("git")
        ));
    }

    #[test]
    fn test_wave21_nested_containers_and_multiline_redaction() {
        // 3-level nested object
        let sample_3level = r#"{"secret": {"level1": {"level2": {"level3": "CANARY_LEVEL3"}}}}"#;
        let sanitized_3level = sanitize_persisted_lifecycle_text(sample_3level);
        assert!(!sanitized_3level.contains("CANARY_LEVEL3"));
        assert_eq!(sanitized_3level, r#"{"secret": [REDACTED]}"#);

        // 4-level nested object
        let sample_4level =
            r#"{"password": {"level1": {"level2": {"level3": {"level4": "CANARY_LEVEL4"}}}}}"#;
        let sanitized_4level = sanitize_persisted_lifecycle_text(sample_4level);
        assert!(!sanitized_4level.contains("CANARY_LEVEL4"));
        assert_eq!(sanitized_4level, r#"{"password": [REDACTED]}"#);

        // Multiline pretty-printed JSON object
        let sample_multiline = "{\n  \"api_key\": {\n    \"level1\": {\n      \"level2\": {\n        \"key\": \"CANARY_MULTILINE\"\n      }\n    }\n  }\n}";
        let sanitized_multiline = sanitize_persisted_lifecycle_text(sample_multiline);
        assert!(!sanitized_multiline.contains("CANARY_MULTILINE"));
        assert!(sanitized_multiline.contains("\"api_key\": [REDACTED]"));

        // Multiline scalar value after sensitive key
        let sample_scalar_multiline = "{\n  \"api_key\":\n    \"CANARY_SCALAR\"\n}";
        let sanitized_scalar_multiline = sanitize_persisted_lifecycle_text(sample_scalar_multiline);
        assert!(!sanitized_scalar_multiline.contains("CANARY_SCALAR"));
        assert!(sanitized_scalar_multiline.contains("[REDACTED]"));

        // Truncated / unclosed container
        let sample_truncated =
            "diagnostics: password: {\"level1\": {\"level2\": \"CANARY_TRUNCATED\"";
        let sanitized_truncated = sanitize_persisted_lifecycle_text(sample_truncated);
        assert!(!sanitized_truncated.contains("CANARY_TRUNCATED"));
        assert!(sanitized_truncated.contains("password: [REDACTED]"));

        // redact_sensitive_nested_containers direct invocation
        let direct_redacted = redact_sensitive_nested_containers(sample_3level);
        assert!(!direct_redacted.contains("CANARY_LEVEL3"));
        assert_eq!(direct_redacted, r#"{"secret": [REDACTED]}"#);
    }

    #[test]
    fn test_wave22_scalar_redaction() {
        let cases = [
            "Cookie: session=CANARY_COOKIE",
            "Set-Cookie: sid=CANARY_COOKIE; HttpOnly",
            "session=CANARY_SESSION",
            "session_id=CANARY_SESSION",
            "cookie=CANARY_COOKIE",
            r#"{"webhook_url":"https://example.test/CANARY_HOOK"}"#,
            r#"{"webhook":"CANARY_WEBHOOK"}"#,
            "webhook_secret=CANARY_HOOK",
            "pass=CANARY_PASSWORD",
            r#"{"pass":"CANARY_PASSWORD"}"#,
            "db_pass=CANARY_PASSWORD",
            "Proxy-Authorization: Basic CANARY_PROXY",
            "X-Api-Key: CANARY_API_KEY",
            "X-Auth-Token: CANARY_AUTH_TOKEN",
            "Authorization: Bearer CANARY_AUTH",
            "\"Cookie: session=CANARY_COOKIE\"",
        ];

        for c in cases {
            let redacted = sanitize_persisted_lifecycle_text(c);
            assert!(
                !redacted.contains("CANARY_"),
                "Redacted output for '{c}' still contains CANARY_: '{redacted}'"
            );
            assert!(
                redacted.contains("[REDACTED]"),
                "Redacted output for '{c}' must contain [REDACTED]: '{redacted}'"
            );
        }

        // Verify preservation of non-secret prose/keys
        let preserved = r#"{"bypass": true, "status": "passed"}"#;
        assert_eq!(sanitize_persisted_lifecycle_text(preserved), preserved);

        let prose = "compass heading is north and bypass compression";
        assert_eq!(sanitize_persisted_lifecycle_text(prose), prose);
    }

    #[test]
    fn test_w22_s01_escaped_quote_and_multi_header_sanitization() {
        // 1. Escaped double-quotes inside header value
        let cmd1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
        let out1 = sanitize_persisted_lifecycle_text(cmd1);
        assert!(!out1.contains("COOKIE_CANARY"));
        assert!(out1.contains("https://example.invalid"));
        assert_eq!(
            out1,
            r#"curl -H "Cookie: [REDACTED]" https://example.invalid"#
        );

        // 2. Set-Cookie with attributes and inner escaped quote
        let cmd2 = r#"curl -H "Set-Cookie: sid=\"COOKIE_CANARY\"; Secure" https://example.invalid"#;
        let out2 = sanitize_persisted_lifecycle_text(cmd2);
        assert!(!out2.contains("COOKIE_CANARY"));
        assert!(out2.contains("https://example.invalid"));
        assert_eq!(
            out2,
            r#"curl -H "Set-Cookie: [REDACTED]" https://example.invalid"#
        );

        // 3. Single-quoted header value with double quotes and escaped single quotes
        let cmd3a = "curl -H 'Cookie: sid=\"COOKIE_CANARY\"' https://example.invalid";
        let out3a = sanitize_persisted_lifecycle_text(cmd3a);
        assert!(!out3a.contains("COOKIE_CANARY"));
        assert!(out3a.contains("https://example.invalid"));
        assert_eq!(
            out3a,
            "curl -H 'Cookie: [REDACTED]' https://example.invalid"
        );

        let cmd3b = r"curl -H 'Cookie: sid=\'COOKIE_CANARY\'' https://example.invalid";
        let out3b = sanitize_persisted_lifecycle_text(cmd3b);
        assert!(!out3b.contains("COOKIE_CANARY"));
        assert!(out3b.contains("https://example.invalid"));
        assert_eq!(
            out3b,
            "curl -H 'Cookie: [REDACTED]' https://example.invalid"
        );

        // 4. JSON-serialized string with escaped inner quotes
        let cmd4 =
            r#"{"cmd":"curl -H \"Cookie: sid=\\\"COOKIE_CANARY\\\"\" https://example.invalid"}"#;
        let out4 = sanitize_persisted_lifecycle_text(cmd4);
        assert!(!out4.contains("COOKIE_CANARY"));
        assert!(out4.contains("https://example.invalid"), "{out4}");
        assert_eq!(
            out4,
            r#"{"cmd":"curl -H \"Cookie: [REDACTED]\" https://example.invalid"}"#
        );

        // 5. Multiple headers on the same line
        let cmd5 = r#"curl -H "Cookie: sid=\"CANARY_1\"" -H "X-Api-Key: \"CANARY_2\"" https://example.invalid"#;
        let out5 = sanitize_persisted_lifecycle_text(cmd5);
        assert!(!out5.contains("CANARY_1"));
        assert!(!out5.contains("CANARY_2"));
        assert!(out5.contains("https://example.invalid"));
        assert_eq!(
            out5,
            r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
        );

        // Multiple headers without inner escaped quotes on same line
        let cmd5b =
            r#"curl -H "Cookie: sid=CANARY_1" -H "X-Api-Key: CANARY_2" https://example.invalid"#;
        let out5b = sanitize_persisted_lifecycle_text(cmd5b);
        assert!(!out5b.contains("CANARY_1"));
        assert!(!out5b.contains("CANARY_2"));
        assert!(out5b.contains("https://example.invalid"));
        assert_eq!(
            out5b,
            r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
        );
    }

    #[test]
    fn test_w24_structured_masking_grammar() {
        let scalars = [
            r#"password=\"SECRET words\""#,
            r#"api_key=\"SECRET words\""#,
            r#"client_secret=\"SECRET words\""#,
            r#"session=\"SECRET words\""#,
            r#"webhook=\"SECRET words\""#,
            r#"rclone_rc_pass=\"SECRET words\""#,
        ];
        for sample in scalars {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert!(!out.contains("SECRET"), "scalar leaked: {sample} -> {out}");
            assert!(
                out.contains("[REDACTED]"),
                "scalar missing mask: {sample} -> {out}"
            );
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
        }

        let flags = [
            "--password SECRET word",
            "--token SECRET word",
            "--api-key SECRET word",
            "--cookie SECRET word",
            "--session SECRET word",
            "--webhook SECRET word",
            r#"--password=\"SECRET words\""#,
            "--password=SECRET",
            "--token=SECRET",
        ];
        for sample in flags {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert!(!out.contains("SECRET"), "flag leaked: {sample} -> {out}");
            assert!(
                out.contains("[REDACTED]"),
                "flag missing mask: {sample} -> {out}"
            );
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
        }

        let raw_user = r#"curl --user=\"admin:SECRET words\" https://example.invalid"#;
        let raw_out = sanitize_persisted_lifecycle_text(raw_user);
        assert!(!raw_out.contains("SECRET"), "curl user leaked: {raw_out}");
        assert!(raw_out.contains("https://example.invalid"), "{raw_out}");
        assert_eq!(raw_out, "curl --user=[REDACTED] https://example.invalid");

        let mut encoded = r#"curl --user="admin:SECRET words" https://example.invalid"#.to_string();
        for depth in 1..=4 {
            encoded = serde_json::to_string(&encoded).unwrap();
            let wrapped = format!(r#"{{"command":{encoded}}}"#);
            let out = sanitize_persisted_lifecycle_text(&wrapped);
            assert!(
                !out.contains("SECRET"),
                "depth {depth} leaked: {wrapped} -> {out}"
            );
            assert!(
                out.contains("https://example.invalid"),
                "depth {depth}: {out}"
            );
            let parsed: serde_json::Value = serde_json::from_str(&out)
                .unwrap_or_else(|err| panic!("depth {depth} json: {err}: {out}"));
            assert!(parsed.get("command").is_some(), "{out}");
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
        }

        let diag = r#"AF_DIAG_FAILURE={"stage": "password=[REDACTED]\"SECRET words\\\"", "exit_code": 17, "category": "installer", "summary": "--user [REDACTED]\"user:SECRET words\\\""}"#;
        let diag_out = sanitize_persisted_lifecycle_text(diag);
        assert!(!diag_out.contains("SECRET"), "diag leaked: {diag_out}");
        let json = diag_out
            .split_once("AF_DIAG_FAILURE=")
            .map(|(_, rest)| rest)
            .unwrap_or("");
        let parsed: serde_json::Value =
            serde_json::from_str(json).unwrap_or_else(|err| panic!("diag json: {err}: {json}"));
        assert_eq!(parsed["exit_code"], 17);
        assert_eq!(parsed["category"], "installer");
        assert!(!parsed.to_string().contains("SECRET"));
        assert_eq!(sanitize_persisted_lifecycle_text(&diag_out), diag_out);

        let preserved = "bypass=visible passed=true monkey=1";
        assert_eq!(sanitize_persisted_lifecycle_text(preserved), preserved);
    }

    #[test]
    fn test_w25_escape_aware_scalar_and_unicode_keys() {
        let exact = [
            ("password=SENTINEL", "password=[REDACTED]"),
            ("password=[REDACTED]SENTINEL", "password=[REDACTED]"),
            (
                "curl --password [REDACTED]SENTINEL --verbose",
                "curl --password [REDACTED] --verbose",
            ),
            (
                "curl -uoperator:SENTINEL https://example.invalid",
                "curl -u[REDACTED] https://example.invalid",
            ),
            (r#"{"password":123456789}"#, r#"{"password":"[REDACTED]"}"#),
            ("password:'SENTINEL'", "password:[REDACTED]"),
            (
                r"curl --password prefix\ SENTINEL --verbose",
                "curl --password [REDACTED] --verbose",
            ),
            ("password=already,SENTINEL", "password=[REDACTED]"),
            (
                r"curl --password $'SENTINEL' https://example.invalid",
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r#"curl --password $"SENTINEL" https://example.invalid"#,
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r#"curl --password prefix"SENTINEL" https://example.invalid"#,
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r"curl --password prefix'SENTINEL' https://example.invalid",
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r"curl --user operator:prefix\ SENTINEL https://example.invalid",
                "curl --user [REDACTED] https://example.invalid",
            ),
            (r"password=prefix\;SENTINEL", "password=[REDACTED]"),
            (r"password=prefix\\;SENTINEL", "password=[REDACTED]"),
            (
                r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#,
                r#"{"command":"curl --password [REDACTED] --verbose"}"#,
            ),
            (
                r#"{"command":"curl --password prefix\ SENTINEL --verbose"}"#,
                r#"{"command":"curl --password [REDACTED] --verbose"}"#,
            ),
            (
                r#"{"pass\u0077ord":"SENTINEL"}"#,
                r#"{"password":[REDACTED]}"#,
            ),
            (
                r#"{"pass\\u0077ord":"SENTINEL"}"#,
                r#"{"password":[REDACTED]}"#,
            ),
        ];
        for (sample, expected) in exact {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert_eq!(out, expected, "sample={sample}");
            assert!(!out.contains("SENTINEL"), "{out}");
            assert!(!out.contains("123456789"), "{out}");
            assert_eq!(
                sanitize_persisted_lifecycle_text(&out),
                out,
                "idempotent: {sample}"
            );
            if sample.contains("--verbose") {
                assert!(out.contains("--verbose"), "{out}");
            }
            if sample.contains("https://example.invalid") {
                assert!(out.contains("https://example.invalid"), "{out}");
            }
            if expected.starts_with(r#"{"command""#) || expected.starts_with(r#"{"password":""#) {
                serde_json::from_str::<serde_json::Value>(&out)
                    .unwrap_or_else(|err| panic!("json {err}: {out}"));
            }
        }

        let containers = [
            r#"{"Credentials":{"plain":"SENTINEL"}}"#,
            r#"{"credentials":{"a":{"b":{"c":{"plain":"SENTINEL"}}}}}"#,
            r#"{"credentials":[{"a":[{"plain":"SENTINEL"}]}]}"#,
        ];
        for sample in containers {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert!(!out.contains("SENTINEL"), "{sample} -> {out}");
            assert!(!out.contains("plain"), "{sample} -> {out}");
            assert!(out.contains("[REDACTED]"), "{out}");
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out, "{out}");
        }

        let header = r#"curl -H \"Cookie: sid=\"SENTINEL\"\" https://example.invalid"#;
        let header_out = sanitize_persisted_lifecycle_text(header);
        assert!(!header_out.contains("SENTINEL"), "{header_out}");
        assert!(
            header_out.contains("https://example.invalid"),
            "{header_out}"
        );
        assert!(header_out.contains("[REDACTED]"), "{header_out}");
        assert_eq!(sanitize_persisted_lifecycle_text(&header_out), header_out);

        let kept = r#"{"na\u006de":"visible"}"#;
        assert_eq!(sanitize_persisted_lifecycle_text(kept), kept);
    }
}
