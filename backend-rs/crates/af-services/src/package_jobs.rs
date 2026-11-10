//! Durable API lifecycle receipts. Only identity and outcome are persisted;
//! installer output can contain credentials and must never enter this journal.
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{collections::HashMap, sync::Mutex, time::Duration};

pub use af_models::{PackageJobOutcomeRecord, PackageLifecycleRecord};

pub type PackageJobOutcome = af_models::PackageJobOutcomeRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageJobInfo {
    pub job_id: String,
    pub package_id: String,
    pub action: String,
    pub status: String,
    pub progress: i32,
    pub last_line: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageJobFailure {
    Preparation,
    Installer,
    Configuration,
    ServiceRestore,
    Retention,
    ConfigurationAndServiceRestore,
    TargetVerification,
}

impl PackageJobFailure {
    pub fn category(self) -> &'static str {
        match self {
            Self::Preparation => "preparation",
            Self::Installer => "installer",
            Self::Configuration => "configuration",
            Self::ServiceRestore => "service_restore",
            Self::Retention => "retention",
            Self::ConfigurationAndServiceRestore => "configuration_and_service_restore",
            Self::TargetVerification => "target_verification",
        }
    }

    pub fn from_category(category: &str) -> Option<Self> {
        match category {
            "preparation" => Some(Self::Preparation),
            "installer" => Some(Self::Installer),
            "configuration" => Some(Self::Configuration),
            "service_restore" => Some(Self::ServiceRestore),
            "retention" => Some(Self::Retention),
            "configuration_and_service_restore" => Some(Self::ConfigurationAndServiceRestore),
            "target_verification" => Some(Self::TargetVerification),
            _ => None,
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::Preparation => "Application preparation failed before installer execution. Check application state before retrying.",
            Self::Installer => "The package installer failed. Rollback and data recovery are not confirmed; check application state before retrying.",
            Self::Configuration => "The installer finished, but required application configuration could not be synchronized.",
            Self::ServiceRestore => "The installer finished, but a stopped application service could not be restored. Check service state before retrying.",
            Self::Retention => "Package removal finished, but reinstall settings could not be retained. Data recovery is not confirmed.",
            Self::ConfigurationAndServiceRestore => "The installer finished, but required application configuration and service restoration failed. Check service state before retrying.",
            Self::TargetVerification => "The installed version could not be confirmed or did not advance to the expected target version. Check application state before retrying.",
        }
    }
}

pub fn package_job_progress_summary(status: &str) -> &'static str {
    match status {
        "installing" => "Installing application.",
        "updating" => "Updating application.",
        "uninstalling" => "Removing application.",
        "completed" => "Operation completed.",
        "failed" => "Operation failed. Contact an administrator for details.",
        "interrupted" => "Operation interrupted. Contact an administrator before retrying.",
        _ => "Operation completion is not yet confirmed.",
    }
}

pub fn is_sensitive_secret_key(k: &str) -> bool {
    if af_release::lifecycle::is_sensitive_diagnostic_key(k) {
        return true;
    }
    let lower = k.to_ascii_lowercase();
    if lower == "pass"
        || lower.starts_with("pass_")
        || lower.starts_with("pass-")
        || lower.ends_with("_pass")
        || lower.ends_with("-pass")
        || lower.contains("_pass_")
        || lower.contains("-pass-")
    {
        return true;
    }
    if lower == "cookie"
        || lower == "cookies"
        || lower.starts_with("cookie_")
        || lower.starts_with("cookie-")
        || lower.ends_with("_cookie")
        || lower.ends_with("-cookie")
        || lower.ends_with("_cookies")
        || lower.ends_with("-cookies")
    {
        return true;
    }
    if lower == "session"
        || lower.starts_with("session_")
        || lower.starts_with("session-")
        || lower.ends_with("_session")
        || lower.ends_with("-session")
    {
        return true;
    }
    if lower == "webhook"
        || lower.starts_with("webhook_")
        || lower.starts_with("webhook-")
        || lower.ends_with("_webhook")
        || lower.ends_with("-webhook")
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "password"
            | "passwd"
            | "secret"
            | "token"
            | "api_key"
            | "apikey"
            | "client_secret"
            | "master_pass"
            | "rclone_pass"
            | "rclone_rc_pass"
            | "authorization"
            | "bearer"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "private_key"
            | "auth_token"
            | "session_token"
            | "credential"
    ) || lower.ends_with("_password")
        || lower.ends_with("_passwd")
        || lower.ends_with("_secret")
        || lower.ends_with("_token")
        || lower.ends_with("_key")
        || lower.ends_with("_pass")
        || lower.ends_with("-password")
        || lower.ends_with("-passwd")
        || lower.ends_with("-secret")
        || lower.ends_with("-token")
        || lower.ends_with("-key")
        || lower.ends_with("-pass")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("api-key")
        || lower.contains("client_secret")
        || lower.contains("client-secret")
        || lower.contains("master_pass")
        || lower.contains("master-pass")
        || lower.contains("rclone_pass")
        || lower.contains("rclone-pass")
        || lower.contains("rclone_rc_pass")
        || lower.contains("rclone-rc-pass")
        || lower.contains("authorization")
        || lower.contains("bearer")
        || lower.contains("credential")
        || lower.contains("private_key")
        || lower.contains("private-key")
}

pub fn redact_json_value(val: &mut serde_json::Value) -> bool {
    let mut modified = false;
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_sensitive_secret_key(k) {
                    let redacted = serde_json::Value::String("[REDACTED]".to_string());
                    if *v != redacted {
                        *v = redacted;
                    }
                    modified = true;
                } else if redact_json_value(v) {
                    modified = true;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                if redact_json_value(item) {
                    modified = true;
                }
            }
        }
        serde_json::Value::String(s) => {
            let redacted = redact_secrets(s);
            if redacted != *s {
                *s = redacted;
                modified = true;
            }
        }
        _ => {}
    }
    modified
}

pub fn redact_embedded_json_fragments(input: &str) -> String {
    redact_secrets(input)
}

pub fn redact_embedded_json_spans(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0;
    let bytes = input.as_bytes();

    while cursor < bytes.len() {
        if bytes[cursor] == b'{' || bytes[cursor] == b'[' {
            let sub = &input[cursor..];
            let mut stream =
                serde_json::Deserializer::from_str(sub).into_iter::<serde_json::Value>();
            if let Some(Ok(mut val)) = stream.next() {
                let consumed = stream.byte_offset();
                if consumed > 0 {
                    let end = cursor + consumed;
                    let next_is_delimiter = end >= bytes.len()
                        || matches!(
                            bytes[end],
                            b' ' | b'\t'
                                | b'\n'
                                | b'\r'
                                | b','
                                | b';'
                                | b'}'
                                | b']'
                                | b')'
                                | b'"'
                                | b'\''
                        );

                    let modified = redact_json_value(&mut val);

                    if modified {
                        if let Ok(serialized) = serde_json::to_string(&val) {
                            result.push_str(&serialized);
                            cursor += consumed;
                            continue;
                        }
                    } else if next_is_delimiter {
                        result.push_str(&input[cursor..cursor + consumed]);
                        cursor += consumed;
                        continue;
                    }
                }
            }
        }
        let ch = input[cursor..].chars().next().unwrap();
        result.push(ch);
        cursor += ch.len_utf8();
    }

    result
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
            if closes_enclosing && (!after.is_some_and(|next| next.is_ascii_whitespace()) || !af_release::lifecycle::has_matching_secret_quote(bytes, i + bs0, bs0)) {
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
                    if closes_outer && (!after_q.is_some_and(|next| next.is_ascii_whitespace()) || !af_release::lifecycle::has_matching_secret_quote(bytes, q_idx, bs)) {
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
                if closes_outer && (!after_q.is_some_and(|next| next.is_ascii_whitespace()) || !af_release::lifecycle::has_matching_secret_quote(bytes, i, 0)) {
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

fn replacement_for_consumed(prefix: &str, consumed: &str) -> String {
    if consumed == "[REDACTED]" || consumed == "[REDACTED_URL]" || is_already_redacted(consumed) {
        return consumed.to_string();
    }
    let trimmed = prefix.trim_start();
    let json_key = (trimmed.starts_with('"') || trimmed.starts_with('\'')) && prefix.contains(':');
    if json_key {
        "\"[REDACTED]\"".to_string()
    } else {
        "[REDACTED]".to_string()
    }
}

fn prefix_is_http_header(prefix: &str) -> bool {
    if prefix.contains('=') || !prefix.contains(':') {
        return false;
    }
    let key = prefix
        .split(':')
        .next()
        .unwrap_or(prefix)
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '\\');
    matches!(
        key.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
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
            let ch = slice.chars().next().unwrap();
            out.push(ch);
            cursor += ch.len_utf8();
            continue;
        }
        let value = &slice[mat.end()..];
        if prefix_is_http_header(&slice[mat.start()..mat.end()]) || scalar_value_is_container(value)
        {
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
        out.push_str(&replacement_for_consumed(prefix, consumed));
        cursor += mat.end() + n;
    }
    out
}

fn redact_curl_user_secrets(text: &str) -> String {
    static CURL_USER_PREFIX_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
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
        let prefix = &slice[mat.start()..mat.end()];
        out.push_str(&slice[..mat.end()]);
        out.push_str(&replacement_for_consumed(prefix, consumed));
        cursor += mat.end() + n;
    }
    out
}

fn redact_sensitive_cli_flags(text: &str) -> String {
    static CLI_FLAG_PREFIX_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)((?:^|[\s"'])--(?:[A-Za-z0-9-]*-)?(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|credentials?)(?:\s+|=)\s*)"#,
        )
        .unwrap()
    });
    redact_prefixed_secrets(text, &CLI_FLAG_PREFIX_RE, true)
}

fn redact_sensitive_assignments(text: &str) -> String {
    redact_prefixed_secrets(text, &af_release::lifecycle::SENSITIVE_ASSIGNMENT_PREFIX_RE, true)
}

fn scrub_scalar_secret_grammar(text: &str) -> String {
    let text = redact_curl_user_secrets(text);
    let text = redact_sensitive_cli_flags(&text);
    redact_sensitive_assignments(&text)
}

static BALANCED_SECRET_PREFIX_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"(?is)(?:(?P<auth>(?:^|[\s"':;,])(?:Basic|Bearer|Token|Digest)\s+)|(?P<curl>(?:^|[\s"'])(?:\bcurl\b[^\n]*?\s+(?:--user(?:\s+|=)|-[A-Za-z]*[uU](?:\s+|=)?)|--user(?:\s+|=)|-u(?:\s+|=)))|(?P<flag>--(?:[A-Za-z0-9-]*-)?(?:pass|password|passwd|secret|token|api[_-]?key|apikey|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?)(?:\s+|=)\s*)|(?P<json>"(?:[A-Za-z0-9_.-]*?(?:password|passwd|secret|token|api[_-]?key|apikey|client[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|authorization|private[_-]?key|credential|bearer|jwt[_-]?secret)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9]*[_.\-])?pass(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?cookies?(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?session(?:[_.\-]?(?:id|key|token|secret))?(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?webhook(?:[_.\-]?(?:url|secret|token|key))?(?:[_.\-][A-Za-z0-9]*)*)"\s*:\s*(?:(?:Basic|Bearer|Token|Digest)\s+)?)|(?P<kv>["']?(?:\b[A-Za-z0-9_.-]*?(?:password|passwd|secret|token|api[_-]?key|apikey|client[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|authorization|private[_-]?key|credential|bearer|jwt[_-]?secret)[A-Za-z0-9_.-]*\b|\b(?:[A-Za-z0-9]*[_.\-])?pass(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?cookies?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?session(?:[_.\-]?(?:id|key|token|secret))?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?webhook(?:[_.\-]?(?:url|secret|token|key))?(?:[_.\-][A-Za-z0-9]*)*\b)["']?\s*[:=]\s*(?:(?:Basic|Bearer|Token|Digest)\s+)?)|(?P<env>\b(?:[A-Z0-9]*_)?(?:PASS|PASSWORD|PASSWD|SECRET|KEY|TOKEN|AUTH|COOKIE|COOKIES|SESSION|WEBHOOK)(?:_[A-Z0-9]*)*\s*=\s*))"#,
    )
    .unwrap()
});

pub fn redact_balanced_structured_secrets(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0;

    for caps in BALANCED_SECRET_PREFIX_RE.captures_iter(input) {
        let mat = caps.get(0).unwrap();
        if mat.start() < cursor {
            continue;
        }

        result.push_str(&input[cursor..mat.start()]);
        let prefix = mat.as_str();
        let value_start = mat.end();
        let is_json = caps.name("json").is_some();
        let rest = &input[value_start..];

        if caps.name("auth").is_none() && prefix_is_http_header(prefix) {
            result.push_str(prefix);
            cursor = value_start;
            continue;
        }

        if !scalar_value_is_container(rest) {
            let allow_comma = caps.name("auth").is_none();
            let n = secret_scalar_span(rest, allow_comma);
            if n == 0 {
                result.push_str(prefix);
                cursor = value_start;
                continue;
            }
            let val = &rest[..n];
            result.push_str(prefix);
            if is_already_redacted(val) {
                if is_json && !val.starts_with('"') && !val.starts_with('\'') {
                    result.push_str(r#""[REDACTED]""#);
                } else {
                    result.push_str(val);
                }
            } else if is_json {
                result.push_str(r#""[REDACTED]""#);
            } else {
                result.push_str("[REDACTED]");
            }
            cursor = value_start + n;
            continue;
        }

        let mut brace_depth: usize = 0;
        let mut bracket_depth: usize = 0;
        let mut in_double_quote = false;
        let mut in_single_quote = false;
        let mut escaped = false;
        let mut value_end = value_start;

        for (offset, ch) in input[value_start..].char_indices() {
            let at_depth_0 = brace_depth == 0 && bracket_depth == 0;
            let continue_scan = in_double_quote
                || in_single_quote
                || !at_depth_0
                || ch == '{'
                || ch == '['
                || (!ch.is_whitespace() && !matches!(ch, ',' | ';' | '}' | ']' | ')'));

            if !continue_scan {
                break;
            }

            if in_double_quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_double_quote = false;
                }
            } else if in_single_quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '\'' {
                    in_single_quote = false;
                }
            } else {
                match ch {
                    '"' => in_double_quote = true,
                    '\'' => in_single_quote = true,
                    '{' => brace_depth += 1,
                    '}' => brace_depth = brace_depth.saturating_sub(1),
                    '[' => bracket_depth += 1,
                    ']' => bracket_depth = bracket_depth.saturating_sub(1),
                    _ => {}
                }
            }
            value_end = value_start + offset + ch.len_utf8();
        }

        if value_end > value_start {
            let val = &input[value_start..value_end];
            result.push_str(prefix);
            if is_already_redacted(val) {
                if is_json && !val.starts_with('"') && !val.starts_with('\'') {
                    result.push_str(r#""[REDACTED]""#);
                } else {
                    result.push_str(val);
                }
            } else if is_json {
                result.push_str(r#""[REDACTED]""#);
            } else {
                result.push_str("[REDACTED]");
            }
            cursor = value_end;
        } else {
            result.push_str(prefix);
            cursor = value_start;
        }
    }

    result.push_str(&input[cursor..]);
    result
}

fn auth_scheme_prefix(val: &str) -> Option<&'static str> {
    let lower = val.to_ascii_lowercase();
    if lower.starts_with("bearer ") {
        Some("Bearer ")
    } else if lower.starts_with("basic ") {
        Some("Basic ")
    } else if lower.starts_with("token ") {
        Some("Token ")
    } else if lower.starts_with("digest ") {
        Some("Digest ")
    } else {
        None
    }
}

pub fn redact_sensitive_http_headers(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    static SECRET_HTTP_HEADER_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?im)(?P<pre>\\*["'])?\b(?P<hdr>Set-Cookie|Cookie|Proxy-Authorization|X-Api-Key|X-Auth-Token|Authorization)\s*:\s*(?P<val>[^\r\n]+)"#,
        )
        .unwrap()
    });

    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;

    while cursor < input.len() {
        let Some(caps) = SECRET_HTTP_HEADER_RE.captures(&input[cursor..]) else {
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
            if let Some(close_idx) = af_release::lifecycle::find_closing_header_quote(raw_val, pre)
            {
                let val = &raw_val[..close_idx];
                let quote_ch = pre.chars().last().unwrap();
                let close_quote_len = if raw_val[close_idx..].starts_with(pre) {
                    pre.len()
                } else {
                    quote_ch.len_utf8()
                };
                let closing_quote = &raw_val[close_idx..close_idx + close_quote_len];
                if is_already_redacted(val) {
                    out.push_str(pre);
                    out.push_str(hdr);
                    out.push_str(": ");
                    out.push_str(val);
                    out.push_str(closing_quote);
                } else {
                    out.push_str(pre);
                    out.push_str(hdr);
                    out.push_str(": ");
                    if let Some(scheme) = auth_scheme_prefix(val) {
                        out.push_str(scheme);
                    }
                    out.push_str("[REDACTED]");
                    out.push_str(closing_quote);
                }
                cursor = val_start + close_idx + close_quote_len;
                continue;
            }
        }

        if af_release::lifecycle::is_complete_redacted_header(&format!("{hdr}:"), raw_val) {
            out.push_str(pre);
            out.push_str(hdr);
            out.push_str(": ");
            out.push_str(raw_val);
            cursor = val_start + raw_val.len();
            continue;
        }

        if is_already_redacted(raw_val) {
            out.push_str(pre);
            out.push_str(hdr);
            out.push_str(": ");
            out.push_str(raw_val);
        } else {
            out.push_str(pre);
            out.push_str(hdr);
            out.push_str(": ");
            if let Some(scheme) = auth_scheme_prefix(raw_val) {
                out.push_str(scheme);
            }
            out.push_str("[REDACTED]");
        }
        cursor = val_start + raw_val.len();
    }

    out
}

pub fn redact_secrets(input: &str) -> String {
    // Decode escaped sensitive keys, then parse JSON spans before scalar scrubbing.
    // Scrubbing first turns `prefix\\ SENTINEL` into `prefix [REDACTED]` and leaves
    // the decoded tail with no `--password` prefix for the JSON pass to see.
    let normalized = af_release::lifecycle::normalize_unicode_escaped_sensitive_keys(input);
    let json = redact_embedded_json_spans(&normalized);
    let headers = redact_sensitive_http_headers(&json);
    let scrubbed = scrub_scalar_secret_grammar(&headers);
    let containers = af_release::lifecycle::redact_sensitive_nested_containers(&scrubbed);
    let balanced = redact_balanced_structured_secrets(&containers);
    let regexed = redact_secrets_regex(&balanced);
    scrub_scalar_secret_grammar(&regexed)
}

fn is_already_redacted(val: &str) -> bool {
    let mut trimmed = val.trim();
    if trimmed.is_empty() {
        return false;
    }
    while (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
        || (trimmed.starts_with(r#"\""#) && trimmed.ends_with(r#"\""#) && trimmed.len() >= 4)
        || (trimmed.starts_with(r#"\'"#) && trimmed.ends_with(r#"\'"#) && trimmed.len() >= 4)
    {
        if (trimmed.starts_with(r#"\""#) && trimmed.ends_with(r#"\""#) && trimmed.len() >= 4)
            || (trimmed.starts_with(r#"\'"#) && trimmed.ends_with(r#"\'"#) && trimmed.len() >= 4)
        {
            trimmed = trimmed[2..trimmed.len() - 2].trim();
        } else {
            trimmed = trimmed[1..trimmed.len() - 1].trim();
        }
    }
    if trimmed == "[REDACTED]" || trimmed == "[REDACTED_URL]" {
        return true;
    }
    if let Some((scheme, rest)) = trimmed.split_once(char::is_whitespace) {
        let scheme = scheme.trim();
        let mut rest = rest.trim();
        while (rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2)
            || (rest.starts_with('\'') && rest.ends_with('\'') && rest.len() >= 2)
            || (rest.starts_with(r#"\""#) && rest.ends_with(r#"\""#) && rest.len() >= 4)
            || (rest.starts_with(r#"\'"#) && rest.ends_with(r#"\'"#) && rest.len() >= 4)
        {
            if (rest.starts_with(r#"\""#) && rest.ends_with(r#"\""#) && rest.len() >= 4)
                || (rest.starts_with(r#"\'"#) && rest.ends_with(r#"\'"#) && rest.len() >= 4)
            {
                rest = rest[2..rest.len() - 2].trim();
            } else {
                rest = rest[1..rest.len() - 1].trim();
            }
        }
        if (scheme.eq_ignore_ascii_case("basic")
            || scheme.eq_ignore_ascii_case("bearer")
            || scheme.eq_ignore_ascii_case("token")
            || scheme.eq_ignore_ascii_case("digest"))
            && (rest == "[REDACTED]" || rest == "[REDACTED_URL]")
        {
            return true;
        }
    }
    false
}

fn redact_secrets_regex(input: &str) -> String {
    static SECRET_AUTH_HEADER_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)(^[\s"':;,])(Basic|Bearer|Token|Digest)\s+((?:\[[^\]]*\]|\{[^}]*\}|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"':;,]+)+)"#,
        )
        .unwrap()
    });
    static SECRET_URL_CRED_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"([a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/\s:@]+:)?)([^@\s/]+)@").unwrap()
    });
    static SECRET_USER_PASS_PAIR_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)(["']?\buser\b["']?\s*[:=]\s*)("[^":\s]+:(?:\\.|[^"\\])*"|'[^':\s]+:(?:\\.|[^'\\])*'|[^\s:'",;}]+:(?:\[[^\]]*\]|\{[^}]*\}|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)+)"#,
        )
        .unwrap()
    });
    static SECRET_JSON_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?is)("(?i:[A-Za-z0-9_.-]*?(?:password|passwd|secret|token|api[_-]?key|apikey|client[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|authorization|private[_-]?key|credential|bearer|jwt[_-]?secret)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9]*[_.\-])?pass(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?cookies?(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?session(?:[_.\-]?(?:id|key|token|secret))?(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?webhook(?:[_.\-]?(?:url|secret|token|key))?(?:[_.\-][A-Za-z0-9]*)*)"\s*:\s*)((?:\[[^\]]*\]|\{[^}]*\}|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)+)"#,
        )
        .unwrap()
    });
    static SECRET_JSON_TRUNCATED_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?is)("(?i:[A-Za-z0-9_.-]*?(?:password|passwd|secret|token|api[_-]?key|apikey|client[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|authorization|private[_-]?key|credential|bearer|jwt[_-]?secret)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9]*[_.\-])?pass(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?cookies?(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?session(?:[_.\-]?(?:id|key|token|secret))?(?:[_.\-][A-Za-z0-9]*)*|(?:[A-Za-z0-9]*[_.\-])?webhook(?:[_.\-]?(?:url|secret|token|key))?(?:[_.\-][A-Za-z0-9]*)*)"\s*:\s*)("(?:\\.|[^"\\])*$)"#,
        )
        .unwrap()
    });
    static SECRET_KV_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?is)(["']?(?:\b[A-Za-z0-9_.-]*?(?:password|passwd|secret|token|api[_-]?key|apikey|client[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|authorization|private[_-]?key|credential|bearer|jwt[_-]?secret)[A-Za-z0-9_.-]*\b|\b(?:[A-Za-z0-9]*[_.\-])?pass(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?cookies?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?session(?:[_.\-]?(?:id|key|token|secret))?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?webhook(?:[_.\-]?(?:url|secret|token|key))?(?:[_.\-][A-Za-z0-9]*)*\b)["']?\s*[:=]\s*)((?:(?i:Basic|Bearer|Token|Digest)\s+)?(?:\[[^\]]*\]|\{[^}]*\}|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)+)"#,
        )
        .unwrap()
    });
    static SECRET_KV_TRUNCATED_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?is)(["']?(?:\b[A-Za-z0-9_.-]*?(?:password|passwd|secret|token|api[_-]?key|apikey|client[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|authorization|private[_-]?key|credential|bearer|jwt[_-]?secret)[A-Za-z0-9_.-]*\b|\b(?:[A-Za-z0-9]*[_.\-])?pass(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?cookies?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?session(?:[_.\-]?(?:id|key|token|secret))?(?:[_.\-][A-Za-z0-9]*)*\b|\b(?:[A-Za-z0-9]*[_.\-])?webhook(?:[_.\-]?(?:url|secret|token|key))?(?:[_.\-][A-Za-z0-9]*)*\b)["']?\s*[:=]\s*)((?:(?i:Basic|Bearer|Token|Digest)\s+)?(?:"(?:\\.|[^"\\])*$|'(?:\\.|[^'\\])*$))"#,
        )
        .unwrap()
    });
    static SECRET_ENV_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)\b((?:[A-Z0-9]*_)?(?:PASS|PASSWORD|PASSWD|SECRET|KEY|TOKEN|AUTH|COOKIE|COOKIES|SESSION|WEBHOOK)(?:_[A-Z0-9]*)*\s*=\s*["']?)((?:\[[^\]]*\]|\{[^}]*\}|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"',;]+)+)"#,
        )
        .unwrap()
    });

    let s0 = redact_sensitive_http_headers(input);
    let s1 = SECRET_AUTH_HEADER_RE.replace_all(&s0, |caps: &regex::Captures| {
        let val = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        if is_already_redacted(val) {
            caps[0].to_string()
        } else {
            format!("{}{}[REDACTED]", &caps[1], &caps[2])
        }
    });
    let s2 = SECRET_URL_CRED_RE.replace_all(&s1, |caps: &regex::Captures| {
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if is_already_redacted(val) {
            caps[0].to_string()
        } else {
            format!("{}[REDACTED]@", &caps[1])
        }
    });
    let s6 = redact_sensitive_cli_flags(&redact_curl_user_secrets(&s2));
    let s7 = SECRET_USER_PASS_PAIR_RE.replace_all(&s6, |caps: &regex::Captures| {
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if is_already_redacted(val) {
            caps[0].to_string()
        } else {
            format!("{}[REDACTED]", &caps[1])
        }
    });
    let s8 = SECRET_JSON_RE.replace_all(&s7, |caps: &regex::Captures| {
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let val_trim = val.trim();
        if val_trim == r#""[REDACTED]""# || val_trim == "'[REDACTED]'" {
            caps[0].to_string()
        } else {
            format!(r#"{}"[REDACTED]""#, &caps[1])
        }
    });
    let s9 = SECRET_JSON_TRUNCATED_RE.replace_all(&s8, |caps: &regex::Captures| {
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let val_trim = val.trim();
        if val_trim == r#""[REDACTED]""# || val_trim == "'[REDACTED]'" {
            caps[0].to_string()
        } else {
            format!(r#"{}"[REDACTED]""#, &caps[1])
        }
    });
    let s10 = SECRET_KV_RE.replace_all(&s9, |caps: &regex::Captures| {
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let p1 = &caps[1];

        // Check if caps[1] opened a quote wrapping the entire KV pair without closing the key
        let quote_info = if p1.starts_with(r#"\""#) {
            Some(('"', 2))
        } else if p1.starts_with(r#"\'"#) {
            Some(('\'', 2))
        } else if p1.starts_with('"') {
            Some(('"', 1))
        } else if p1.starts_with('\'') {
            Some(('\'', 1))
        } else {
            None
        };

        if let Some((quote_ch, prefix_len)) = quote_info {
            let pre = &p1[..prefix_len];
            let key_closed = p1[prefix_len..].contains(quote_ch);
            if !key_closed {
                if let Some(close_idx) = af_release::lifecycle::find_closing_header_quote(val, pre)
                {
                    let actual_val = &val[..close_idx];
                    let close_quote_len = if val[close_idx..].starts_with(pre) {
                        pre.len()
                    } else {
                        quote_ch.len_utf8()
                    };
                    let closing_quote = &val[close_idx..close_idx + close_quote_len];
                    let extra = &val[close_idx + close_quote_len..];
                    if is_already_redacted(actual_val) {
                        return format!("{}{}{}{}", p1, actual_val, closing_quote, extra);
                    } else {
                        return format!("{}[REDACTED]{}{}", p1, closing_quote, extra);
                    }
                }
            }
        }

        let mut inner = val;
        while let Some(stripped) = inner.strip_suffix('"').or_else(|| inner.strip_suffix('\'')) {
            inner = stripped;
            while let Some(s) = inner.strip_suffix('\\') {
                inner = s;
            }
        }
        if is_already_redacted(val)
            || (is_already_redacted(inner)
                && (caps[0].starts_with('"')
                    || caps[0].starts_with('\'')
                    || caps[1].contains('"')
                    || caps[1].contains('\'')))
        {
            caps[0].to_string()
        } else {
            format!("{}[REDACTED]", &caps[1])
        }
    });
    let s11 = SECRET_KV_TRUNCATED_RE.replace_all(&s10, |caps: &regex::Captures| {
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if is_already_redacted(val) {
            caps[0].to_string()
        } else {
            format!("{}[REDACTED]", &caps[1])
        }
    });
    SECRET_ENV_RE
        .replace_all(&s11, |caps: &regex::Captures| {
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let full = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let value_off = if full.starts_with(prefix) {
                prefix.len()
            } else {
                full.rfind(prefix)
                    .map(|idx| idx + prefix.len())
                    .unwrap_or(prefix.len())
            };
            let n = secret_scalar_span(&full[value_off..], false);
            if n == 0 {
                return full.to_string();
            }
            let consumed = &full[value_off..value_off + n];
            let tail = &full[value_off + n..];
            if is_already_redacted(consumed) {
                format!("{prefix}{consumed}{tail}")
            } else {
                format!("{prefix}[REDACTED]{tail}")
            }
        })
        .into_owned()
}

pub fn sanitize_diagnostic_summary(input: &str, max_len: usize) -> String {
    let redacted = redact_secrets(input);
    let trimmed = redacted.trim();
    if trimmed.chars().count() <= max_len {
        trimmed.to_string()
    } else {
        let mut truncated: String = trimmed.chars().take(max_len).collect();
        truncated.push_str("...");
        truncated
    }
}

pub fn parse_diagnostic_markers(text: &str) -> (Option<String>, Option<i32>, Option<String>) {
    static STAGE_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?i)(?:\[STAGE:|stage[:=]\s*|stage\s+['`]?)([a-zA-Z0-9_.-]+)").unwrap()
    });
    static EXIT_CODE_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"(?i)(?:exit status|exit code|exited with code|failed with code)[:=]?\s*(-?\d+)",
        )
        .unwrap()
    });

    let failed_stage = STAGE_RE
        .captures(text)
        .and_then(|c| c.get(1))
        .map(|m| redact_secrets(m.as_str()));
    let exit_code = EXIT_CODE_RE
        .captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i32>().ok());
    let summary = if !text.trim().is_empty() {
        Some(sanitize_diagnostic_summary(text, 280))
    } else {
        None
    };

    (failed_stage, exit_code, summary)
}

#[derive(Default)]
struct JobRegistry {
    active: HashMap<String, PackageJobInfo>,
    outcomes: HashMap<String, PackageJobOutcome>,
    db: Option<Connection>,
    leases: HashMap<String, af_release::lifecycle::OwnerLease>,
}

impl JobRegistry {
    fn open(conn: Connection, reconcile: bool) -> anyhow::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        af_release::lifecycle::initialize_schema(&conn)?;
        let has_category: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='failure_category')",
            [], |row| row.get(0),
        )?;
        if !has_category {
            conn.execute_batch("ALTER TABLE package_lifecycle_jobs ADD COLUMN failure_category TEXT NOT NULL DEFAULT ''")?;
        }
        if reconcile {
            af_release::lifecycle::reconcile_jobs(&conn, Path::new(conn.path().unwrap_or("")))?;
        }
        let mut registry = Self {
            db: Some(conn),
            outcomes: HashMap::new(),
            active: HashMap::new(),
            leases: HashMap::new(),
        };
        registry.refresh()?;
        Ok(registry)
    }

    fn refresh(&mut self) -> anyhow::Result<()> {
        let Some(conn) = &self.db else { return Ok(()) };
        let rows: Vec<PackageJobOutcome> = conn.prepare(
            "SELECT package_id,job_id,action,status,started_at,finished_at,failure_category,
                    failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version
             FROM package_lifecycle_jobs",
        )?.query_map([], |row| {
            let status: String = row.get(3)?;
            let failed_stage: String = row.get::<_, Option<String>>(7)?.unwrap_or_default();
            let exit_code: Option<i32> = row.get(8)?;
            let sanitized_summary: String = row.get::<_, Option<String>>(9)?.unwrap_or_default();
            let expected_target_version: String = row.get::<_, Option<String>>(10)?.unwrap_or_default();
            let achieved_version: String = row.get::<_, Option<String>>(11)?.unwrap_or_default();
            Ok(PackageJobOutcome {
                package_id: row.get(0)?, job_id: row.get(1)?, action: row.get(2)?,
                message: outcome_summary(&status, &row.get::<_, String>(6)?).into(), status,
                started_at: row.get(4)?, finished_at: row.get(5)?,
                failed_stage: if failed_stage.is_empty() { None } else { Some(failed_stage) },
                exit_code,
                sanitized_summary: if sanitized_summary.is_empty() { None } else { Some(sanitized_summary) },
                expected_target_version: if expected_target_version.is_empty() { None } else { Some(expected_target_version) },
                achieved_version: if achieved_version.is_empty() { None } else { Some(achieved_version) },
            })
        })?.collect::<rusqlite::Result<_>>()?;
        for row in rows {
            if !matches!(row.status.as_str(), "completed" | "failed" | "interrupted") {
                if self
                    .active
                    .get(&row.package_id)
                    .is_none_or(|active| active.job_id != row.job_id || active.status != row.status)
                {
                    self.active.insert(
                        row.package_id.clone(),
                        PackageJobInfo {
                            job_id: row.job_id,
                            package_id: row.package_id.clone(),
                            action: row.action,
                            status: row.status,
                            started_at: row.started_at,
                            progress: 5,
                            last_line: "Operation completion is not yet confirmed.".into(),
                            expected_target_version: row.expected_target_version,
                        },
                    );
                }
                self.outcomes.remove(&row.package_id);
            } else {
                self.active.remove(&row.package_id);
                self.leases.remove(&row.package_id);
                if self
                    .outcomes
                    .get(&row.package_id)
                    .is_none_or(|old| old.job_id != row.job_id || old.status != row.status)
                {
                    self.outcomes.insert(row.package_id.clone(), row);
                }
            }
        }
        Ok(())
    }

    fn start(&mut self, mut info: PackageJobInfo) -> anyhow::Result<bool> {
        if let Some(conn) = &self.db {
            af_release::lifecycle::reconcile_jobs(conn, Path::new(conn.path().unwrap_or("")))?;
        }
        self.refresh()?;
        if self.active.contains_key(&info.package_id) {
            return Ok(false);
        }
        if info.job_id.is_empty() {
            info.job_id = uuid::Uuid::new_v4().to_string();
        }
        let catalog = crate::get_package_catalog()?;
        anyhow::ensure!(
            catalog
                .iter()
                .any(|package| package.name == info.package_id),
            "Package catalog entry is unavailable"
        );
        let units = crate::resolve_service_units_with_catalog(&info.package_id, &catalog);
        if let Some(conn) = &mut self.db {
            let lease = af_release::lifecycle::admit_job_with_target(
                conn,
                &info.package_id,
                &info.job_id,
                &info.action,
                &info.started_at,
                &units,
                info.expected_target_version.as_deref(),
            )?;
            self.leases.insert(info.package_id.clone(), lease);
        }
        self.outcomes.remove(&info.package_id);
        self.active.insert(info.package_id.clone(), info);
        Ok(true)
    }

    fn finish(
        &mut self,
        pkg: &str,
        action: &str,
        success: bool,
        _message: &str,
        job_id: &str,
    ) -> anyhow::Result<Option<PackageJobOutcome>> {
        self.finish_with_failure(pkg, action, success, None, job_id)
    }

    fn finish_with_failure(
        &mut self,
        pkg: &str,
        action: &str,
        success: bool,
        failure: Option<PackageJobFailure>,
        job_id: &str,
    ) -> anyhow::Result<Option<PackageJobOutcome>> {
        self.finish_with_diagnostics(
            pkg, action, success, failure, job_id, None, None, None, None, None,
        )
    }

    fn finish_with_diagnostics(
        &mut self,
        pkg: &str,
        action: &str,
        success: bool,
        failure: Option<PackageJobFailure>,
        job_id: &str,
        failed_stage: Option<String>,
        exit_code: Option<i32>,
        sanitized_summary: Option<String>,
        expected_target_version: Option<String>,
        achieved_version: Option<String>,
    ) -> anyhow::Result<Option<PackageJobOutcome>> {
        let Some(job) = self
            .active
            .get(pkg)
            .filter(|j| j.job_id == job_id && j.action == action)
        else {
            return Ok(None);
        };
        let status = if success { "completed" } else { "failed" };
        let category = if success {
            ""
        } else {
            failure.map_or("", PackageJobFailure::category)
        };
        let sanitized_summary = sanitized_summary.map(|s| redact_secrets(&s));
        let failed_stage = failed_stage.map(|s| redact_secrets(&s));
        let expected_target =
            expected_target_version.or_else(|| job.expected_target_version.clone());
        let outcome = PackageJobOutcome {
            job_id: job.job_id.clone(),
            package_id: pkg.to_string(),
            action: action.to_string(),
            status: status.to_string(),
            message: outcome_summary(status, category).to_string(),
            started_at: job.started_at.clone(),
            finished_at: Utc::now().to_rfc3339(),
            failed_stage: failed_stage.clone(),
            exit_code,
            sanitized_summary: sanitized_summary.clone(),
            expected_target_version: expected_target,
            achieved_version,
        };
        if let Some(conn) = &self.db {
            af_release::lifecycle::finish_job_with_diagnostics(
                conn,
                pkg,
                &outcome.job_id,
                action,
                success,
                af_release::lifecycle::LifecycleJobDiagnostics {
                    failure_category: category,
                    failed_stage: failed_stage.as_deref(),
                    exit_code,
                    sanitized_summary: sanitized_summary.as_deref(),
                    expected_target_version: outcome.expected_target_version.as_deref(),
                    achieved_version: outcome.achieved_version.as_deref(),
                    finished_at: Some(outcome.finished_at.as_str()),
                },
            )?;
        }
        self.outcomes.insert(pkg.to_string(), outcome.clone());
        self.active.remove(pkg);
        self.leases.remove(pkg);
        Ok(Some(outcome))
    }
}

fn outcome_summary(status: &str, category: &str) -> &'static str {
    match status {
        "completed" => "Operation completed.",
        "interrupted" => "The API restarted before completion was confirmed. Check application state and logs before retrying; rollback and data recovery are not confirmed.",
        _ => PackageJobFailure::from_category(category).map_or(
            "Operation failed. Check authenticated service logs for details; rollback and data recovery are not confirmed.",
            PackageJobFailure::summary,
        ),
    }
}

static JOBS: Lazy<Mutex<JobRegistry>> = Lazy::new(|| Mutex::new(JobRegistry::default()));

/// Called after database initialization, before routes or background workers start.
pub fn initialize_package_jobs(conn: Connection) -> anyhow::Result<()> {
    let admission = af_runner::acquire_lifecycle_admission_lock(None).ok();
    *JOBS
        .lock()
        .map_err(|_| anyhow::anyhow!("lifecycle registry unavailable"))? =
        JobRegistry::open(conn, admission.is_some())?;
    Ok(())
}

#[derive(Clone, Default)]
pub struct PackageJobSnapshot {
    pub active: HashMap<String, PackageJobInfo>,
    pub outcomes: HashMap<String, PackageJobOutcome>,
}

pub fn package_job_snapshot() -> anyhow::Result<PackageJobSnapshot> {
    let (mut snapshot, path) = {
        let jobs = JOBS
            .lock()
            .map_err(|_| anyhow::anyhow!("lifecycle registry unavailable"))?;
        (
            PackageJobSnapshot {
                active: jobs.active.clone(),
                outcomes: jobs.outcomes.clone(),
            },
            jobs.db
                .as_ref()
                .and_then(|conn| conn.path())
                .map(str::to_owned),
        )
    };
    let Some(path) = path else {
        return Ok(snapshot);
    };
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_millis(150))?;
    let mut refreshed = JobRegistry {
        db: Some(conn),
        ..Default::default()
    };
    refreshed.refresh()?;
    for (package, current) in &mut refreshed.active {
        if let Some(local) = snapshot
            .active
            .get(package)
            .filter(|local| local.job_id == current.job_id && local.status == current.status)
        {
            *current = local.clone();
        }
    }
    snapshot.active = refreshed.active;
    snapshot.outcomes = refreshed.outcomes;
    Ok(snapshot)
}

pub fn take_package_job_lease(
    pkg: &str,
    job_id: &str,
) -> Option<af_release::lifecycle::OwnerLease> {
    let mut jobs = JOBS.lock().ok()?;
    if jobs.active.get(pkg)?.job_id != job_id {
        return None;
    }
    jobs.leases.remove(pkg)
}

pub fn has_active_package_jobs() -> bool {
    let Ok(_admission) = af_runner::acquire_lifecycle_admission_lock(None) else {
        return true;
    };
    let Ok(mut jobs) = JOBS.lock() else {
        return true;
    };
    if let Some(conn) = &jobs.db {
        if af_release::lifecycle::reconcile_jobs(conn, Path::new(conn.path().unwrap_or("")))
            .is_err()
        {
            return true;
        }
    }
    jobs.refresh().is_err() || !jobs.active.is_empty()
}

pub fn reconcile_package_jobs_under_admission() -> anyhow::Result<()> {
    let mut jobs = JOBS
        .lock()
        .map_err(|_| anyhow::anyhow!("lifecycle registry unavailable"))?;
    let Some(conn) = &jobs.db else {
        return Ok(());
    };
    af_release::lifecycle::reconcile_jobs(conn, Path::new(conn.path().unwrap_or("")))?;
    jobs.refresh()?;
    Ok(())
}

pub fn reconcile_package_jobs() -> anyhow::Result<()> {
    let Ok(_admission) = af_runner::acquire_lifecycle_admission_lock(None) else {
        return Ok(());
    };
    reconcile_package_jobs_under_admission()
}

pub fn get_package_job_info(pkg: &str) -> Option<PackageJobInfo> {
    match package_job_snapshot() {
        Ok(jobs) => jobs.active.get(pkg).cloned(),
        Err(_) => JOBS.lock().ok()?.active.get(pkg).cloned(),
    }
}
pub fn get_package_job_outcome(pkg: &str) -> Option<PackageJobOutcome> {
    package_job_snapshot().ok()?.outcomes.get(pkg).cloned()
}
pub fn set_package_job_info(mut info: PackageJobInfo) -> Option<PackageJobInfo> {
    info.last_line = redact_secrets(&info.last_line);
    let mut jobs = JOBS.lock().ok()?;
    let current = jobs
        .active
        .get(&info.package_id)
        .filter(|j| j.job_id == info.job_id)?;
    info.progress = info
        .progress
        .clamp(0, 95)
        .max(current.progress.clamp(0, 95));
    jobs.active.insert(info.package_id.clone(), info.clone());
    Some(info)
}

pub fn try_start_package_job(mut info: PackageJobInfo) -> bool {
    info.last_line = redact_secrets(&info.last_line);
    match JOBS.lock().map(|mut j| j.start(info)) {
        Ok(Ok(started)) => started,
        error => {
            tracing::error!(?error, "Failed to persist lifecycle admission");
            false
        }
    }
}
pub fn clear_package_job_info(pkg: &str) {
    if let Ok(mut j) = JOBS.lock() {
        j.active.remove(pkg);
    }
}
pub fn finish_package_job(
    pkg: &str,
    action: &str,
    success: bool,
    message: &str,
    job_id: &str,
) -> Option<PackageJobOutcome> {
    match JOBS
        .lock()
        .map(|mut j| j.finish(pkg, action, success, message, job_id))
    {
        Ok(Ok(outcome)) => outcome,
        error => {
            tracing::error!(
                ?error,
                "Failed to persist lifecycle outcome; leaving operation unresolved"
            );
            None
        }
    }
}

pub fn fail_package_job(
    pkg: &str,
    action: &str,
    failure: PackageJobFailure,
    job_id: &str,
) -> Option<PackageJobOutcome> {
    match JOBS
        .lock()
        .map(|mut jobs| jobs.finish_with_failure(pkg, action, false, Some(failure), job_id))
    {
        Ok(Ok(outcome)) => outcome,
        error => {
            tracing::error!(
                ?error,
                "Failed to persist lifecycle failure; leaving operation unresolved"
            );
            None
        }
    }
}

pub fn finish_package_job_with_diagnostics(
    pkg: &str,
    action: &str,
    success: bool,
    failure: Option<PackageJobFailure>,
    job_id: &str,
    failed_stage: Option<String>,
    exit_code: Option<i32>,
    sanitized_summary: Option<String>,
    expected_target_version: Option<String>,
    achieved_version: Option<String>,
) -> Option<PackageJobOutcome> {
    match JOBS.lock().map(|mut jobs| {
        jobs.finish_with_diagnostics(
            pkg,
            action,
            success,
            failure,
            job_id,
            failed_stage,
            exit_code,
            sanitized_summary,
            expected_target_version,
            achieved_version,
        )
    }) {
        Ok(Ok(outcome)) => outcome,
        error => {
            tracing::error!(
                ?error,
                "Failed to persist lifecycle outcome; leaving operation unresolved"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_http_registry_and_direct_runner_reject_shared_companion_owners() {
        let name = "package_jobs::tests::real_http_registry_and_direct_runner_reject_shared_companion_owners";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        let mut http = job("http-nextcloud");
        http.package_id = "nextcloud".into();
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(http));
        let mut http_remove = job("http-rutorrent");
        http_remove.package_id = "rutorrent".into();
        assert!(!try_start_package_job(http_remove.clone()));
        drop(admission);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            use futures::StreamExt;
            let request = af_models::PackageRunnerRequest {
                action: "update".into(),
                package_id: "organizr".into(),
                script_name: "updatepackage-organizr".into(),
                ..Default::default()
            };
            let stream = af_runner::package_lifecycle::execute_coordinated_package_stream(request);
            tokio::pin!(stream);
            let mut rejected = false;
            while let Some(line) = stream.next().await {
                rejected |= line.unwrap().starts_with("__RUNNER_EXIT_ERROR__:");
            }
            assert!(rejected);
        });
        let mut conn = Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM package_lifecycle_jobs", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(af_release::lifecycle::check_package_reservation(
            &conn,
            "rutorrent",
            &af_runner::package_lifecycle::package_service_units("rutorrent").unwrap(),
            "http-nextcloud",
            Some("update")
        )
        .is_err());
        assert!(
            finish_package_job("nextcloud", "update", true, "done", "http-nextcloud").is_some()
        );
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        let direct = af_release::lifecycle::admit_job(
            &mut conn,
            "organizr",
            "direct-organizr",
            "remove",
            "now",
            &af_runner::package_lifecycle::package_service_units("organizr").unwrap(),
        )
        .unwrap();
        assert!(!try_start_package_job(http_remove.clone()));
        drop(admission);
        assert_eq!(
            package_job_snapshot().unwrap().active["organizr"].job_id,
            "direct-organizr"
        );
        drop(direct);
        reconcile_package_jobs().unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().outcomes["organizr"].status,
            "interrupted"
        );
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(http_remove));
        drop(admission);
        finish_package_job("rutorrent", "update", true, "done", "http-rutorrent").unwrap();
        std::fs::write(root.join("packages.json"), b"not-json").unwrap();
        assert!(!try_start_package_job(job("catalog-unavailable")));
        assert!(af_runner::package_lifecycle::package_service_units("nextcloud").is_err());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn isolated_recovery_test(name: &str) -> bool {
        if std::env::var("AF_RECOVERY_TEST_CHILD").as_deref() == Ok(name) {
            return false;
        }
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_RECOVERY_TEST_CHILD", name)
            .status()
            .unwrap()
            .success());
        true
    }

    fn recovery_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("af-recovery-{}", uuid::Uuid::new_v4()));
        std::env::set_var("AETHERFLOW_FS_ROOT", &root);
        std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        let cfg = af_release::ReleaseConfig::for_root(&root);
        let path = af_release::config::try_resolve_db_path(&cfg, None)
            .unwrap()
            .path;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut packages: Vec<af_models::Package> =
            serde_json::from_str(include_str!("../../../../config/packages.json")).unwrap();
        packages.push(af_models::Package {
            name: "fixture".into(),
            service_name: "fixture".into(),
            ..Default::default()
        });
        let catalog = root.join("packages.json");
        std::fs::write(&catalog, serde_json::to_vec(&packages).unwrap()).unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
        (root, path)
    }

    fn lock_holder(path: &Path) -> std::process::Child {
        use std::io::BufRead;
        let mut child = std::process::Command::new("python3")
            .args(["-c", "import fcntl,sys; lock=open(sys.argv[1], 'r'); fcntl.flock(lock, fcntl.LOCK_EX); print('locked', flush=True); sys.stdin.readline()"])
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "locked");
        child
    }

    #[test]
    fn recovery_tick_waits_for_owner_and_maintenance_child_then_allows_retry() {
        use std::io::Write;
        let name = "package_jobs::tests::recovery_tick_waits_for_owner_and_maintenance_child_then_allows_retry";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        let mut original = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert!(original.start(job("dead-owner-job")).unwrap());
        let lease = original.leases.remove("fixture").unwrap();
        let owner_path = path.with_extension("lifecycle-owners").join(&lease.id);
        drop((lease, original));
        let mut owner = lock_holder(&owner_path);
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        reconcile_package_jobs().unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].job_id,
            "dead-owner-job"
        );
        assert!(!try_start_package_job(job("must-not-steal-owner")));
        let cfg = af_release::ReleaseConfig::for_root(&root);
        let maintenance_path =
            af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let mut child = lock_holder(&maintenance_path);
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        owner.kill().unwrap();
        owner.wait().unwrap();
        reconcile_package_jobs().unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].status,
            "updating"
        );
        assert!(af_runner::acquire_lifecycle_admission_lock(Some(&root)).is_err());
        child.stdin.take().unwrap().write_all(b"release\n").unwrap();
        assert!(child.wait().unwrap().success());
        let changes = Connection::open(&path).unwrap();
        changes.pragma_update(None, "query_only", true).unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].status,
            "updating"
        );
        reconcile_package_jobs().unwrap();
        let snapshot = package_job_snapshot().unwrap();
        assert!(snapshot.active.is_empty());
        assert_eq!(snapshot.outcomes["fixture"].status, "interrupted");
        assert_eq!(snapshot.outcomes["fixture"].job_id, "dead-owner-job");
        assert!(finish_package_job("fixture", "update", true, "late", "dead-owner-job").is_none());
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(job("retry-after-recovery")));
        drop(admission);
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].job_id,
            "retry-after-recovery"
        );
        assert!(finish_package_job(
            "fixture",
            "remove",
            true,
            "wrong-action",
            "retry-after-recovery"
        )
        .is_none());
        finish_package_job("fixture", "update", true, "done", "retry-after-recovery").unwrap();
        drop(changes);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn safe_failure_categories_survive_readonly_snapshots_and_restart() {
        let name =
            "package_jobs::tests::safe_failure_categories_survive_readonly_snapshots_and_restart";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        for failure in [
            PackageJobFailure::Preparation,
            PackageJobFailure::Installer,
            PackageJobFailure::Configuration,
            PackageJobFailure::ServiceRestore,
            PackageJobFailure::Retention,
            PackageJobFailure::ConfigurationAndServiceRestore,
        ] {
            let identity = failure.category();
            let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
            assert!(try_start_package_job(job(identity)));
            drop(admission);
            let failed = fail_package_job("fixture", "update", failure, identity).unwrap();
            assert_eq!(failed.message, failure.summary());
            assert!(failed.message.len() < 256);
            assert_eq!(package_job_snapshot().unwrap().outcomes["fixture"], failed);
            initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
            assert_eq!(package_job_snapshot().unwrap().outcomes["fixture"], failed);
            assert!(fail_package_job("fixture", "remove", failure, identity).is_none());
        }
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE package_lifecycle_jobs SET failure_category=?1",
            ["password=must-never-be-output"],
        )
        .unwrap();
        assert!(!package_job_snapshot().unwrap().outcomes["fixture"]
            .message
            .contains("password"));
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(job("fresh-identity")));
        drop(admission);
        let category: String = conn
            .query_row(
                "SELECT failure_category FROM package_lifecycle_jobs",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(category, "");
        let outcome = finish_package_job(
            "fixture",
            "update",
            false,
            "credential-do-not-persist",
            "fresh-identity",
        )
        .unwrap();
        assert!(!outcome.message.contains("credential"));
        assert_eq!(package_job_snapshot().unwrap().outcomes["fixture"], outcome);
        assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap())
            .contains("credential-do-not-persist"));
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn polling_does_not_own_maintenance_or_block_admission_registry() {
        let name =
            "package_jobs::tests::polling_does_not_own_maintenance_or_block_admission_registry";
        if std::env::var("AF_POLLING_TEST_CHILD").as_deref() != Ok(name) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("AF_POLLING_TEST_CHILD", name)
                .status()
                .unwrap()
                .success());
            return;
        }
        let (root, path) = recovery_fixture();
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        let blocker = Connection::open(&path).unwrap();
        blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = get_package_job_info("fixture");
            sender.send(()).unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root));
        let registry_available = JOBS.try_lock().is_ok();
        blocker.execute_batch("ROLLBACK").unwrap();
        receiver.recv_timeout(Duration::from_secs(6)).unwrap();
        reader.join().unwrap();
        assert!(
            admission.is_ok(),
            "status polling must never acquire the maintenance flock"
        );
        assert!(
            registry_available,
            "slow status reads must not hold the mutation registry mutex"
        );
        drop(admission);
        blocker.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let scripts = root.join("packages/package/install");
        std::fs::create_dir_all(&scripts).unwrap();
        let script = format!("installpackage-polling-{}", uuid::Uuid::new_v4());
        std::fs::write(
            scripts.join(&script),
            "#!/bin/sh\nprintf 'isolated installer completed\\n'\n",
        )
        .unwrap();
        let controls = root.join("fake-bin");
        std::fs::create_dir_all(&controls).unwrap();
        for program in ["systemctl", "sudo"] {
            let command = controls.join(program);
            std::fs::write(&command, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var(
            "PATH",
            format!("{}:{}", controls.display(), std::env::var("PATH").unwrap()),
        );
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", root.join("absent-runner.sock"));
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reading = stop.clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let started = barrier.clone();
        let poller = std::thread::spawn(move || {
            started.wait();
            let mut snapshots = 0;
            while !reading.load(std::sync::atomic::Ordering::Acquire) {
                package_job_snapshot().unwrap();
                snapshots += 1;
            }
            snapshots
        });
        barrier.wait();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for iteration in 0..8 {
                let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
                let identity = format!("parallel-{iteration}");
                assert!(try_start_package_job(job(&identity)));
                drop(admission);
                af_runner::PACKAGE_JOB_ID
                    .scope(identity.clone(), async {
                        af_runner::execute_package_local("update", "fixture", &script, 0, |_| {})
                            .await
                            .unwrap();
                        crate::control_service_with_manager(
                            "fixture.service",
                            "start",
                            "systemd-unit",
                        )
                        .await
                        .unwrap();
                    })
                    .await;
                assert!(finish_package_job("fixture", "update", true, "done", &identity).is_some());
            }
        });
        stop.store(true, std::sync::atomic::Ordering::Release);
        let snapshots = poller.join().unwrap();
        assert!(snapshots > 0);
        println!("{snapshots} real read-only snapshots overlapped 8 admissions, legacy executions and owned service controls");
        assert!(try_start_package_job(job("abandoned")));
        drop(take_package_job_lease("fixture", "abandoned").unwrap());
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].status,
            "updating"
        );
        assert!(!has_active_package_jobs());
        assert_eq!(
            get_package_job_outcome("fixture").unwrap().status,
            "interrupted"
        );
        std::env::set_current_dir(previous).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    fn job(id: &str) -> PackageJobInfo {
        PackageJobInfo {
            job_id: id.into(),
            package_id: "fixture".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 5,
            last_line: "credential-do-not-persist".into(),
            started_at: id.into(),
            expected_target_version: None,
        }
    }
    #[test]
    fn restart_retains_failure_and_interrupts_unconfirmed_work_without_persisting_output() {
        let name = "package_jobs::tests::restart_retains_failure_and_interrupts_unconfirmed_work_without_persisting_output";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        {
            let mut store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
            assert!(store.start(job("first")).unwrap());
            assert!(!store.start(job("duplicate")).unwrap());
            store
                .finish("fixture", "update", false, "secret-output", "first")
                .unwrap();
        }
        {
            let mut store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
            assert_eq!(store.outcomes["fixture"].status, "failed");
            assert!(!store.outcomes["fixture"].message.contains("secret-output"));
            assert!(store.start(job("second")).unwrap());
            assert!(store
                .finish("fixture", "update", true, "late", "first")
                .unwrap()
                .is_none());
        }
        {
            let mut store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
            assert_eq!(store.outcomes["fixture"].status, "interrupted");
            assert_eq!(store.outcomes["fixture"].job_id, "second");
            assert!(store
                .finish("fixture", "update", true, "late", "second")
                .unwrap()
                .is_none());
            assert!(store.start(job("third")).unwrap());
            store
                .finish("fixture", "update", true, "done", "third")
                .unwrap();
            assert!(store
                .finish("fixture", "update", false, "stale", "first")
                .unwrap()
                .is_none());
        }
        let store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert_eq!(store.outcomes["fixture"].status, "completed");
        assert_eq!(store.outcomes["fixture"].job_id, "third");
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("credential-do-not-persist"));
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn another_api_cannot_claim_live_work_and_dropped_task_is_not_completed() {
        let name = "package_jobs::tests::another_api_cannot_claim_live_work_and_dropped_task_is_not_completed";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        let _admission =
            af_release::ReleaseLockGuard::acquire(root.join("maintenance.lock"), Duration::ZERO)
                .unwrap();
        let mut first = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert!(first.start(job("original")).unwrap());
        let task_lease = first.leases.remove("fixture").unwrap();
        let mut restarted = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert_eq!(restarted.active["fixture"].job_id, "original");
        assert!(!restarted.start(job("replacement")).unwrap());
        drop(task_lease);
        af_release::lifecycle::reconcile_jobs(first.db.as_ref().unwrap(), &path).unwrap();
        first.refresh().unwrap();
        assert_eq!(first.outcomes["fixture"].status, "interrupted");
        assert!(first
            .finish("fixture", "update", true, "late", "original")
            .unwrap()
            .is_none());
        assert!(restarted.start(job("replacement")).unwrap());
        drop((first, restarted));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_durable_state_cannot_be_replaced_by_new_admission() {
        let name = "package_jobs::tests::unknown_durable_state_cannot_be_replaced_by_new_admission";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        let mut registry = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert!(registry.start(job("original")).unwrap());
        registry.db.as_ref().unwrap().execute(
            "UPDATE package_lifecycle_jobs SET status='unknown-worker-phase' WHERE package_id='fixture'", [],
        ).unwrap();
        registry.leases.clear();
        assert!(!registry.start(job("replacement")).unwrap());
        assert_eq!(registry.active["fixture"].job_id, "original");
        assert_eq!(registry.active["fixture"].status, "unknown-worker-phase");
        assert!(registry
            .finish("fixture", "update", true, "late", "original")
            .is_err());
        let status: String = registry
            .db
            .as_ref()
            .unwrap()
            .query_row(
                "SELECT status FROM package_lifecycle_jobs WHERE package_id='fixture'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "unknown-worker-phase");
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_secret_redaction_comprehensive() {
        let input = r#"{"access_token": "secret_tok_123", "refresh_token": "ref_456", "private_key": "priv_key_789"}"#;
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("secret_tok_123"));
        assert!(!redacted.contains("ref_456"));
        assert!(!redacted.contains("priv_key_789"));
        assert!(redacted.contains("[REDACTED]"));

        let kv_input = "access_token: tok_abc; refresh-token = ref_xyz; 'private_key': 'key_123'; auth_token=auth999; session_token: sess111";
        let kv_redacted = redact_secrets(kv_input);
        assert!(!kv_redacted.contains("tok_abc"));
        assert!(!kv_redacted.contains("ref_xyz"));
        assert!(!kv_redacted.contains("key_123"));
        assert!(!kv_redacted.contains("auth999"));
        assert!(!kv_redacted.contains("sess111"));
        assert!(kv_redacted.contains("[REDACTED]"));

        // Escaped quotes and backslashes inside JSON
        let escaped_input = r#"{"password": "my\"super\\secret"}"#;
        let escaped_redacted = redact_secrets(escaped_input);
        assert!(!escaped_redacted.contains("super"));
        assert!(!escaped_redacted.contains("secret"));
        assert!(escaped_redacted.contains("[REDACTED]"));

        // Nested JSON objects and multiline JSON secrets
        let nested_multiline = "{\n  \"service\": \"auth\",\n  \"config\": {\n    \"api_key\": \"nested_key_xyz\",\n    \"user_password\": \"multi\\nline\\\"secret\"\n  }\n}";
        let nested_redacted = redact_secrets(nested_multiline);
        assert!(!nested_redacted.contains("nested_key_xyz"));
        assert!(!nested_redacted.contains("multi\\nline"));
        assert!(nested_redacted.contains("[REDACTED]"));

        // Truncated JSON string at end of line
        let truncated_json = r#"error payload: {"password": "partial_secret_without_end"#;
        let trunc_redacted = redact_secrets(truncated_json);
        assert!(!trunc_redacted.contains("partial_secret"));
        assert!(trunc_redacted.contains("[REDACTED]"));

        // Key-value pairs with escaped quotes
        let kv_escaped = r#"password="my\"escaped\\pass" token='another\'tok'"#;
        let kv_esc_redacted = redact_secrets(kv_escaped);
        assert!(!kv_esc_redacted.contains("escaped"));
        assert!(!kv_esc_redacted.contains("another"));
        assert!(kv_esc_redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_multi_span_embedded_json_and_compound_keys_redaction() {
        // Multi-span embedded JSON on a single line
        let multi_json = r#"req={"user_password":"secret1"} resp={"api_token":"secret2"}"#;
        let multi_redacted = redact_secrets(multi_json);
        assert!(!multi_redacted.contains("secret1"));
        assert!(!multi_redacted.contains("secret2"));
        assert!(multi_redacted.contains(r#"{"user_password":"[REDACTED]"}"#));
        assert!(multi_redacted.contains(r#"{"api_token":"[REDACTED]"}"#));

        // Fallback non-JSON or malformed JSON with compound keys and escaped quotes
        let malformed = r#"user_password="pw\"1" and db_secret=sec2 github_token="tok3""#;
        let malformed_redacted = redact_secrets(malformed);
        assert!(!malformed_redacted.contains(r#"pw\"1"#));
        assert!(!malformed_redacted.contains("sec2"));
        assert!(!malformed_redacted.contains("tok3"));
        assert!(malformed_redacted.contains("[REDACTED]"));

        // Compound keys in KV and colon formats
        let compound = "admin_passwd: pass1; x_api_key=key2; rclone_rc_pass: rc3; master_pass=mp4; private_key_pem=pem5";
        let compound_redacted = redact_secrets(compound);
        assert!(!compound_redacted.contains("pass1"));
        assert!(!compound_redacted.contains("key2"));
        assert!(!compound_redacted.contains("rc3"));
        assert!(!compound_redacted.contains("mp4"));
        assert!(!compound_redacted.contains("pem5"));
        assert!(compound_redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_secret_key_context_across_json_boundaries_and_auth_credentials() {
        // 1. Secret key preceding JSON object or array across boundary
        let prefix_obj = r#"password={"raw":"my_secret_123"}"#;
        let red_prefix_obj = redact_secrets(prefix_obj);
        assert!(!red_prefix_obj.contains("my_secret_123"));
        assert!(red_prefix_obj.contains("[REDACTED]"));

        let prefix_arr = r#"secret: ["tok1", "tok2"]"#;
        let red_prefix_arr = redact_secrets(prefix_arr);
        assert!(!red_prefix_arr.contains("tok1"));
        assert!(!red_prefix_arr.contains("tok2"));
        assert!(red_prefix_arr.contains("[REDACTED]"));

        let prefix_quoted = r#""api_token": {"nested": "secret_abc"}"#;
        let red_prefix_quoted = redact_secrets(prefix_quoted);
        assert!(!red_prefix_quoted.contains("secret_abc"));
        assert!(red_prefix_quoted.contains("[REDACTED]"));

        // 2. HTTP Basic Auth / Bearer / Token / Digest
        let basic_auth = "Authorization: Basic dXNlcjpwYXNz";
        let red_basic = redact_secrets(basic_auth);
        assert!(!red_basic.contains("dXNlcjpwYXNz"));
        assert!(red_basic.contains("Basic [REDACTED]"));

        let raw_basic = "header: Basic dXNlcjpwYXNz";
        let red_raw_basic = redact_secrets(raw_basic);
        assert!(!red_raw_basic.contains("dXNlcjpwYXNz"));
        assert!(red_raw_basic.contains("Basic [REDACTED]"));

        // 3. curl -u / --user / CLI flags
        let curl_u = "curl -u admin:mysecret123 http://example.com/api";
        let red_curl_u = redact_secrets(curl_u);
        assert!(!red_curl_u.contains("mysecret123"));
        assert!(red_curl_u.contains("curl -u [REDACTED]"));

        let curl_user_quoted = "curl --user \"admin:mysecret123\" http://example.com";
        let red_curl_user = redact_secrets(curl_user_quoted);
        assert!(!red_curl_user.contains("mysecret123"));
        assert!(red_curl_user.contains("curl --user [REDACTED]"));

        let cli_pass = "program --pass mysecret123 --other flag";
        let red_cli_pass = redact_secrets(cli_pass);
        assert!(!red_cli_pass.contains("mysecret123"));
        assert!(red_cli_pass.contains("--pass [REDACTED]"));

        let cli_rc_pass = "rclone --rc-pass secret_rc_pass --rc-user user";
        let red_cli_rc = redact_secrets(cli_rc_pass);
        assert!(!red_cli_rc.contains("secret_rc_pass"));
        assert!(red_cli_rc.contains("--rc-pass [REDACTED]"));

        // 4. Embedded in non-sensitive JSON string values
        let json_with_embedded =
            r#"{"status":"executing","log":"running curl -u admin:mysecret123 http://test"}"#;
        let red_json_embedded = redact_secrets(json_with_embedded);
        assert!(!red_json_embedded.contains("mysecret123"));
        assert!(red_json_embedded.contains("curl -u [REDACTED]"));
    }

    #[test]
    fn test_redact_secrets_idempotent() {
        let inputs = [
            "Authorization: Basic dXNlcjpwYXNz",
            "curl -u admin:mysecret123 http://example.com/api",
            "program --pass mysecret123 --other flag",
            r#"{"password": "secret", "token": "tok123"}"#,
            "password=mysecret and db_secret=dbsec",
            "PASS=mysecret",
        ];
        for input in inputs {
            let once = redact_secrets(input);
            let twice = redact_secrets(&once);
            assert_eq!(
                once, twice,
                "redact_secrets must be idempotent for input: {input}"
            );
        }
    }

    #[test]
    fn test_strict_redaction_without_embedded_marker_bypass() {
        // Direct is_already_redacted unit tests
        assert!(!is_already_redacted("admin:prefix[REDACTED]suffix"));
        assert!(!is_already_redacted("Bearer prefix[REDACTED]suffix"));
        assert!(!is_already_redacted(
            "\"password\": \"prefix[REDACTED]suffix\""
        ));
        assert!(!is_already_redacted("prefix[REDACTED]suffix"));
        assert!(!is_already_redacted(
            "https://admin:prefix[REDACTED]suffix@example.com/api"
        ));
        assert!(!is_already_redacted("[REDACTED]something"));
        assert!(!is_already_redacted("something[REDACTED]"));

        assert!(is_already_redacted("[REDACTED]"));
        assert!(is_already_redacted("\"[REDACTED]\""));
        assert!(is_already_redacted("'[REDACTED]'"));
        assert!(is_already_redacted("\"\"[REDACTED]\"\""));
        assert!(is_already_redacted("[REDACTED_URL]"));
        assert!(is_already_redacted("Basic [REDACTED]"));
        assert!(is_already_redacted("Bearer [REDACTED]"));
        assert!(is_already_redacted("Token [REDACTED]"));
        assert!(is_already_redacted("Digest [REDACTED]"));
        assert!(is_already_redacted("Bearer \"[REDACTED]\""));

        // 1. admin:prefix[REDACTED]suffix in curl credentials
        let curl_in = "curl -u admin:prefix[REDACTED]suffix https://example.com/api";
        let curl_red = redact_secrets(curl_in);
        assert!(!curl_red.contains("prefix"));
        assert!(!curl_red.contains("suffix"));
        assert!(!curl_red.contains("admin:prefix"));
        assert_eq!(curl_red, "curl -u [REDACTED] https://example.com/api");
        assert_eq!(
            redact_secrets(&curl_red),
            curl_red,
            "curl redaction must be idempotent"
        );

        // 2. Bearer prefix[REDACTED]suffix in auth header
        let bearer_in = "Authorization: Bearer prefix[REDACTED]suffix";
        let bearer_red = redact_secrets(bearer_in);
        assert!(!bearer_red.contains("prefix"));
        assert!(!bearer_red.contains("suffix"));
        assert_eq!(bearer_red, "Authorization: Bearer [REDACTED]");
        assert_eq!(
            redact_secrets(&bearer_red),
            bearer_red,
            "Bearer redaction must be idempotent"
        );

        let standalone_bearer = "Bearer prefix[REDACTED]suffix";
        let sb_red = redact_secrets(standalone_bearer);
        assert!(!sb_red.contains("prefix"));
        assert!(!sb_red.contains("suffix"));
        assert_eq!(sb_red, "Bearer [REDACTED]");
        assert_eq!(
            redact_secrets(&sb_red),
            sb_red,
            "Standalone Bearer redaction must be idempotent"
        );

        // 3. "password": "prefix[REDACTED]suffix" in JSON and KV
        let json_in = r#"{"password": "prefix[REDACTED]suffix"}"#;
        let json_red = redact_secrets(json_in);
        assert!(!json_red.contains("prefix"));
        assert!(!json_red.contains("suffix"));
        assert_eq!(json_red, r#"{"password":"[REDACTED]"}"#);
        assert_eq!(
            redact_secrets(&json_red),
            json_red,
            "JSON password redaction must be idempotent"
        );

        let raw_kv_in = r#""password": "prefix[REDACTED]suffix""#;
        let raw_kv_red = redact_secrets(raw_kv_in);
        assert!(!raw_kv_red.contains("prefix"));
        assert!(!raw_kv_red.contains("suffix"));
        assert_eq!(raw_kv_red, r#""password": "[REDACTED]""#);
        assert_eq!(
            redact_secrets(&raw_kv_red),
            raw_kv_red,
            "Raw KV password redaction must be idempotent"
        );

        // 4. https://admin:prefix[REDACTED]suffix@example.com/api in URL credentials
        let url_in = "https://admin:prefix[REDACTED]suffix@example.com/api";
        let url_red = redact_secrets(url_in);
        assert!(!url_red.contains("prefix"));
        assert!(!url_red.contains("suffix"));
        assert_eq!(url_red, "https://admin:[REDACTED]@example.com/api");
        assert_eq!(
            redact_secrets(&url_red),
            url_red,
            "URL credential redaction must be idempotent"
        );
    }

    #[test]
    fn test_marker_prefixed_secrets_do_not_leak_suffix_and_are_idempotent() {
        let cases = [
            "password: [REDACTED]suffix",
            "\"password\": \"[REDACTED]suffix\"",
            "password=[REDACTED]suffix",
            "Authorization: Bearer [REDACTED]suffix",
            "Authorization: Basic [REDACTED]suffix",
            "curl -u [REDACTED]suffix",
            "curl -u admin:[REDACTED]suffix",
            "--password [REDACTED]suffix",
            "--token=[REDACTED]suffix",
            "SECRET_KEY=[REDACTED]suffix",
            "API_KEY=[REDACTED]suffix",
            "https://user:[REDACTED]suffix@example.com/path",
            "https://admin:[REDACTED]suffix@example.com/api",
        ];

        for case in cases {
            let redacted = redact_secrets(case);
            assert!(
                !redacted.contains("suffix"),
                "Redacted output for '{case}' must not contain 'suffix', got: '{redacted}'"
            );
            let second_pass = redact_secrets(&redacted);
            assert_eq!(
                second_pass, redacted,
                "Redaction must be idempotent for case '{case}' (got '{redacted}' vs '{second_pass}')"
            );
        }

        let genuine_redacted_cases = [
            "password: [REDACTED]",
            "\"password\": \"[REDACTED]\"",
            "Authorization: Bearer [REDACTED]",
            "Authorization: Basic [REDACTED]",
            "curl -u [REDACTED]",
            "API_KEY=[REDACTED]",
            "https://[REDACTED]@example.com/api",
        ];

        for case in genuine_redacted_cases {
            let redacted = redact_secrets(case);
            assert_eq!(
                redacted, case,
                "Genuine already-redacted input '{case}' must remain unchanged, got: '{redacted}'"
            );
            assert_eq!(
                redact_secrets(&redacted),
                case,
                "Subsequent redactions must remain idempotent for '{case}'"
            );
        }
    }

    #[test]
    fn test_json_prefixed_secrets_do_not_leak_suffix_and_are_idempotent() {
        let exact_cases = [
            ("password: [true]suffix", "password: [REDACTED]"),
            ("password: [1, 2, 3]suffix", "password: [REDACTED]"),
            ("password: {\"a\": 1}suffix", "password: [REDACTED]"),
            (
                "password: {\"token\": \"abc\"}suffix",
                "password: [REDACTED]",
            ),
            ("secret=[true]suffix", "secret=[REDACTED]"),
            ("--password=[true]suffix", "--password=[REDACTED]"),
            (
                "Authorization: Bearer [true]suffix",
                "Authorization: Bearer [REDACTED]",
            ),
        ];

        for (input, expected) in exact_cases {
            let redacted = redact_secrets(input);
            assert_eq!(
                redacted, expected,
                "Input '{input}' must redact to '{expected}', got '{redacted}'"
            );
            assert!(
                !redacted.contains("suffix"),
                "Redacted output for '{input}' must not contain 'suffix', got '{redacted}'"
            );
            let second_pass = redact_secrets(&redacted);
            assert_eq!(
                second_pass, redacted,
                "Redaction must be idempotent for '{input}' (got '{redacted}' vs '{second_pass}')"
            );
        }

        // Standalone JSON: {"user": "admin", "password": "[true]suffix"}
        let standalone_json = r#"{"user": "admin", "password": "[true]suffix"}"#;
        let standalone_redacted = redact_secrets(standalone_json);
        assert!(
            !standalone_redacted.contains("suffix"),
            "Standalone JSON output must not contain 'suffix', got '{standalone_redacted}'"
        );
        assert!(
            standalone_redacted.contains(r#""password":"[REDACTED]""#)
                || standalone_redacted.contains(r#""password": "[REDACTED]""#),
            "Standalone JSON password must be redacted, got '{standalone_redacted}'"
        );
        let standalone_second = redact_secrets(&standalone_redacted);
        assert_eq!(
            standalone_second, standalone_redacted,
            "Standalone JSON redaction must be idempotent"
        );

        // Additional compound and valid JSON prefix cases
        let extra_cases = [
            (
                "Authorization: Basic [true]suffix",
                "Authorization: Basic [REDACTED]",
            ),
            ("curl -u [true]suffix", "curl -u [REDACTED]"),
            ("curl -u admin:[true]suffix", "curl -u [REDACTED]"),
            ("SECRET_KEY=[true]suffix", "SECRET_KEY=[REDACTED]"),
            ("API_KEY=[true]suffix", "API_KEY=[REDACTED]"),
            ("\"password\": [true]suffix", "\"password\": \"[REDACTED]\""),
            ("secret: [1, 2]suffix", "secret: [REDACTED]"),
            ("secret=[1,2]suffix", "secret=[REDACTED]"),
            ("--password [true]suffix", "--password [REDACTED]"),
            (
                "Authorization: Bearer [1, 2, 3]suffix",
                "Authorization: Bearer [REDACTED]",
            ),
            (
                "Authorization: Bearer {\"a\": 1}suffix",
                "Authorization: Bearer [REDACTED]",
            ),
        ];

        for (input, expected) in extra_cases {
            let redacted = redact_secrets(input);
            assert_eq!(
                redacted, expected,
                "Extra input '{input}' must redact to '{expected}', got '{redacted}'"
            );
            assert!(
                !redacted.contains("suffix"),
                "Redacted output for '{input}' must not contain 'suffix', got '{redacted}'"
            );
            let second = redact_secrets(&redacted);
            assert_eq!(
                second, redacted,
                "Extra input '{input}' redaction must be idempotent"
            );
        }
    }

    #[test]
    fn test_nested_balanced_structured_secrets_do_not_leak_suffix_and_are_idempotent() {
        let cases = [
            ("password: {\"a\":{\"x\":1}}suffix", "password: [REDACTED]"),
            (
                "password: {\"a\":{\"b\":{\"c\":[1,{\"d\":2}]}}}suffix",
                "password: [REDACTED]",
            ),
            ("password: [[true, [false]]]suffix", "password: [REDACTED]"),
            ("secret={\"a\":{\"x\":1}}suffix", "secret=[REDACTED]"),
            (
                "--password={\"a\":{\"x\":1}}suffix",
                "--password=[REDACTED]",
            ),
            (
                "Authorization: Bearer {\"a\":{\"x\":1}}suffix",
                "Authorization: Bearer [REDACTED]",
            ),
        ];

        for (input, expected) in cases {
            let redacted = redact_secrets(input);
            assert_eq!(
                redacted, expected,
                "Input '{input}' must redact to '{expected}', got '{redacted}'"
            );
            assert!(
                !redacted.contains("suffix"),
                "Redacted output for '{input}' must not contain 'suffix', got '{redacted}'"
            );
            assert!(
                !redacted.contains("}suffix"),
                "Redacted output for '{input}' must not contain '}}suffix', got '{redacted}'"
            );
            let second_pass = redact_secrets(&redacted);
            assert_eq!(
                second_pass, redacted,
                "Redaction must be idempotent for '{input}'"
            );
        }

        // Test valid JSON preservation
        let json_input = r#"{"user": "admin", "password": {"a":{"x":1}}}"#;
        let json_redacted = redact_secrets(json_input);
        assert!(
            !json_redacted.contains("\"x\":1"),
            "Secret object must be redacted from JSON, got '{json_redacted}'"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&json_redacted).expect("Redacted JSON must remain valid JSON");
        assert_eq!(parsed["user"], "admin");
        assert_eq!(parsed["password"], "[REDACTED]");

        let second_json = redact_secrets(&json_redacted);
        assert_eq!(
            second_json, json_redacted,
            "JSON redaction must be idempotent"
        );
    }

    #[test]
    fn test_wave22_scalar_redaction_package_jobs() {
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
            "--session=CANARY_SESSION",
            "--webhook-url=https://example.test/CANARY_HOOK",
            "--cookie=CANARY_COOKIE",
            "SESSION=CANARY_SESSION",
            "COOKIE=CANARY_COOKIE",
            "WEBHOOK=CANARY_WEBHOOK",
        ];

        for c in cases {
            let redacted = redact_secrets(c);
            assert!(
                !redacted.contains("CANARY_"),
                "Redacted output for '{c}' still contains CANARY_: '{redacted}'"
            );
            assert!(
                redacted.contains("[REDACTED]"),
                "Redacted output for '{c}' must contain [REDACTED]: '{redacted}'"
            );
            assert_eq!(
                redact_secrets(&redacted),
                redacted,
                "Redaction must be idempotent for '{c}'"
            );
        }

        // Verify preservation of non-secret prose/keys
        let preserved = r#"{"bypass": true, "status": "passed"}"#;
        assert_eq!(redact_secrets(preserved), preserved);

        let prose = "compass heading is north and bypass compression";
        assert_eq!(redact_secrets(prose), prose);
    }

    #[test]
    fn test_w22_s01_escaped_quote_and_multi_header_sanitization_services() {
        // 1. Escaped double-quotes inside header value
        let cmd1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
        let out1 = redact_secrets(cmd1);
        assert!(!out1.contains("COOKIE_CANARY"));
        assert!(out1.contains("https://example.invalid"));
        assert_eq!(
            out1,
            r#"curl -H "Cookie: [REDACTED]" https://example.invalid"#
        );
        assert_eq!(redact_secrets(&out1), out1);

        // 2. Set-Cookie with attributes and inner escaped quote
        let cmd2 = r#"curl -H "Set-Cookie: sid=\"COOKIE_CANARY\"; Secure" https://example.invalid"#;
        let out2 = redact_secrets(cmd2);
        assert!(!out2.contains("COOKIE_CANARY"));
        assert!(out2.contains("https://example.invalid"));
        assert_eq!(
            out2,
            r#"curl -H "Set-Cookie: [REDACTED]" https://example.invalid"#
        );
        assert_eq!(redact_secrets(&out2), out2);

        // 3. Single-quoted header value with double quotes and escaped single quotes
        let cmd3a = "curl -H 'Cookie: sid=\"COOKIE_CANARY\"' https://example.invalid";
        let out3a = redact_secrets(cmd3a);
        assert!(!out3a.contains("COOKIE_CANARY"));
        assert!(out3a.contains("https://example.invalid"));
        assert_eq!(
            out3a,
            "curl -H 'Cookie: [REDACTED]' https://example.invalid"
        );
        assert_eq!(redact_secrets(&out3a), out3a);

        let cmd3b = r"curl -H 'Cookie: sid=\'COOKIE_CANARY\'' https://example.invalid";
        let out3b = redact_secrets(cmd3b);
        assert!(!out3b.contains("COOKIE_CANARY"));
        assert!(out3b.contains("https://example.invalid"));
        assert_eq!(
            out3b,
            "curl -H 'Cookie: [REDACTED]' https://example.invalid"
        );
        assert_eq!(redact_secrets(&out3b), out3b);

        // 4. JSON-serialized string with escaped inner quotes
        let cmd4 =
            r#"{"cmd":"curl -H \"Cookie: sid=\\\"COOKIE_CANARY\\\"\" https://example.invalid"}"#;
        let out4 = redact_secrets(cmd4);
        assert!(!out4.contains("COOKIE_CANARY"));
        assert!(out4.contains("https://example.invalid"));
        assert_eq!(
            out4,
            r#"{"cmd":"curl -H \"Cookie: [REDACTED]\" https://example.invalid"}"#
        );
        assert_eq!(redact_secrets(&out4), out4);

        // 5. Multiple headers on the same line
        let cmd5 = r#"curl -H "Cookie: sid=\"CANARY_1\"" -H "X-Api-Key: \"CANARY_2\"" https://example.invalid"#;
        let out5 = redact_secrets(cmd5);
        assert!(!out5.contains("CANARY_1"));
        assert!(!out5.contains("CANARY_2"));
        assert!(out5.contains("https://example.invalid"));
        assert_eq!(
            out5,
            r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
        );
        assert_eq!(redact_secrets(&out5), out5);

        // Multiple headers without inner escaped quotes on same line
        let cmd5b =
            r#"curl -H "Cookie: sid=CANARY_1" -H "X-Api-Key: CANARY_2" https://example.invalid"#;
        let out5b = redact_secrets(cmd5b);
        assert!(!out5b.contains("CANARY_1"));
        assert!(!out5b.contains("CANARY_2"));
        assert!(out5b.contains("https://example.invalid"));
        assert_eq!(
            out5b,
            r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
        );
        assert_eq!(redact_secrets(&out5b), out5b);
    }

    #[test]
    fn test_w24_structured_masking_grammar_package_jobs() {
        let scalars = [
            r#"password=\"SECRET words\""#,
            r#"api_key=\"SECRET words\""#,
            r#"client_secret=\"SECRET words\""#,
            r#"session=\"SECRET words\""#,
            r#"webhook=\"SECRET words\""#,
            r#"rclone_rc_pass=\"SECRET words\""#,
        ];
        for sample in scalars {
            let out = redact_secrets(sample);
            assert!(!out.contains("SECRET"), "scalar leaked: {sample} -> {out}");
            assert!(
                out.contains("[REDACTED]"),
                "scalar missing mask: {sample} -> {out}"
            );
            assert_eq!(
                redact_secrets(&out),
                out,
                "scalar not idempotent: {sample} -> {out}"
            );
        }

        let flags = [
            "--password SECRET word",
            "--token SECRET word",
            "--api-key SECRET word",
            "--cookie SECRET word",
            "--session SECRET word",
            "--webhook SECRET word",
            r#"--password=\"SECRET words\""#,
            "--user=\"user:SECRET words\"",
            "curl --user=\"admin:SECRET words\" https://example.invalid",
            "curl --user=admin:SECRET https://example.invalid",
            "curl -u=admin:SECRET https://example.invalid",
        ];
        for sample in flags {
            let out = redact_secrets(sample);
            assert!(!out.contains("SECRET"), "flag leaked: {sample} -> {out}");
            assert!(
                out.contains("[REDACTED]"),
                "flag missing mask: {sample} -> {out}"
            );
            assert!(
                !sample.contains("https://example.invalid")
                    || out.contains("https://example.invalid"),
                "url dropped: {sample} -> {out}"
            );
            assert_eq!(
                redact_secrets(&out),
                out,
                "flag not idempotent: {sample} -> {out}"
            );
        }

        let mut encoded = r#"curl --user="admin:SECRET words" https://example.invalid"#.to_string();
        for depth in 1..=4 {
            encoded = serde_json::to_string(&encoded).unwrap();
            let wrapped = format!(r#"{{"command":{encoded}}}"#);
            let out = redact_secrets(&wrapped);
            assert!(
                !out.contains("SECRET"),
                "depth {depth} leaked: {wrapped} -> {out}"
            );
            assert!(
                out.contains("https://example.invalid"),
                "depth {depth}: {out}"
            );
            serde_json::from_str::<serde_json::Value>(&out)
                .unwrap_or_else(|err| panic!("depth {depth} json: {err}: {out}"));
            assert_eq!(
                redact_secrets(&out),
                out,
                "depth {depth} not idempotent: {out}"
            );
        }

        let diag = r#"AF_DIAG_FAILURE={"stage": "password=[REDACTED]\"SECRET words\\\"", "exit_code": 17, "category": "installer", "summary": "--user [REDACTED]\"user:SECRET words\\\""}"#;
        let diag_out = redact_secrets(diag);
        assert!(!diag_out.contains("SECRET"), "diag leaked: {diag_out}");
        let json = diag_out
            .split_once("AF_DIAG_FAILURE=")
            .map(|(_, rest)| rest)
            .unwrap_or("");
        let parsed: serde_json::Value =
            serde_json::from_str(json).unwrap_or_else(|err| panic!("diag json: {err}: {json}"));
        assert_eq!(parsed["exit_code"], 17, "diag_out={diag_out}");
        assert_eq!(parsed["category"], "installer");
        assert!(!parsed.to_string().contains("SECRET"));
        assert_eq!(redact_secrets(&diag_out), diag_out);

        let preserved = "bypass=visible passed=true monkey=1";
        assert_eq!(redact_secrets(preserved), preserved);
    }

    #[test]
    fn test_quote_boundaries_are_masked_through_runner_persistence_and_projection() {
        let cases = [
            "password=\" QUOTED_CANARY\"",
            "password=prefix\" QUOTED_CANARY\"",
            "curl -u operator:\" QUOTED_CANARY\" --verbose",
            "password='prefix\nQUOTED_CANARY'\nX-Api-Key: ordinary",
            "password=[REDACTED]\" QUOTED_CANARY\"",
            "password=[REDACTED_URL]QUOTED_CANARY",
            "password=[REDACTED_url]\" QUOTED_CANARY\"",
        ];
        for sample in cases {
            let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(sample);
            let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(sample);
            let projected = redact_secrets(sample);
            let chained = redact_secrets(&af_release::lifecycle::sanitize_persisted_lifecycle_text(&runner));
            for result in [&runner, &persisted, &projected, &chained] {
                assert!(!result.contains("QUOTED_CANARY"), "{sample:?} -> {result:?}");
                assert!(!redact_secrets(result).contains("QUOTED_CANARY"));
                assert!(!af_runner::package_lifecycle::sanitize_lifecycle_field(result).contains("QUOTED_CANARY"));
            }
        }
    }

    #[test]
    fn test_release_gate_sensitive_key_grammar_across_boundaries() {
        for prefix in ["database", &"x".repeat(125), &"x".repeat(512)] {
            for key in ["Password", "Cookie", "Session", "Webhook", "Authorization"] {
                for escape_depth in [0, 1, 2, 4, 8] {
                    let encoded_key = if escape_depth == 0 {
                        key.to_string()
                    } else {
                        format!("{}u00{:02x}{}", "\\".repeat(escape_depth), key.as_bytes()[0], &key[1..])
                    };
                    for value in [r#""GRAMMAR_CANARY""#, r#"{"value":"GRAMMAR_CANARY"}"#, r#"["GRAMMAR_CANARY"]"#] {
                        let mut input = format!(r#""{prefix}{encoded_key}Encoded":{value}"#);
                        for _ in 0..3 {
                            for (boundary, result) in [
                                ("runner", af_runner::package_lifecycle::sanitize_lifecycle_field(&input)),
                                ("persistence", af_release::lifecycle::sanitize_persisted_lifecycle_text(&input)),
                                ("projection", redact_secrets(&input)),
                            ] {
                                assert!(!result.contains("GRAMMAR_CANARY"), "{boundary}: {input:?} -> {result:?}");
                                assert!(!redact_secrets(&result).contains("GRAMMAR_CANARY"));
                            }
                            input = format!("AF_DIAG_FAILURE={}", serde_json::json!({"summary": input}));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_release_gate_receipt_preserves_closed_header_commands() {
        for tail in ["--verbose", "--retry 2", "-X GET", "-H \"Accept: application/json\""] {
            let command = format!("curl -H \"Authorization: [REDACTED]\" {tail} https://example.invalid");
            let mut input = command.clone();
            for _ in 0..3 {
                let sanitized = redact_secrets(&input);
                assert!(sanitized.contains("https://example.invalid"), "{input:?} -> {sanitized:?}");
                assert!(sanitized.contains(tail.split_whitespace().next().unwrap()), "{sanitized:?}");
                assert_eq!(redact_secrets(&sanitized), sanitized);
                input = format!("AF_DIAG_FAILURE={}", serde_json::json!({"summary": input}));
            }
        }
    }

    #[test]
    fn test_final_gate_escaped_fragments_and_marked_headers() {
        let long_key = format!(r#""{}Pass\u0077ordEncoded":"FRAGMENT_CANARY""#, "x".repeat(125));
        let samples = [
            long_key.as_str(),
            r#""databaseCookieEncoded":"FRAGMENT_CANARY""#,
            r#""databaseSessionEncoded":"FRAGMENT_CANARY""#,
            r#""incomingWebhookEncoded":"FRAGMENT_CANARY""#,
            r#""databasePasswordEncoded":"FRAGMENT_CANARY""#,
            r#""databasePass\u0077ordEncoded":"FRAGMENT_CANARY""#,
            r#""databasePass\\u0077ordEncoded":"FRAGMENT_CANARY""#,
            r#"{"databasePass\u0077ordEncoded":"FRAGMENT_CANARY"}"#,
            r#""databasePass\u0077ordEncoded":{"value":"FRAGMENT_CANARY"}"#,
            r#""databasePass\u0077ordEncoded":["FRAGMENT_CANARY""#,
            "Cookie: [REDACTED] sid=FRAGMENT_CANARY",
            "Authorization: [REDACTED] FRAGMENT_CANARY",
            "X-Api-Key: [REDACTED] FRAGMENT_CANARY",
            "Cookie: [REDACTED_URL] sid=FRAGMENT_CANARY",
            r#"Cookie: [REDACTED]" --verbose FRAGMENT_CANARY"#,
            r#"Authorization: [REDACTED]\" --retry FRAGMENT_CANARY"#,
            "Cookie: [REDACTED]' https://example.invalid/FRAGMENT_CANARY",
        ];
        for sample in samples {
            let receipt = format!("AF_DIAG_FAILURE={}", serde_json::json!({
                "stage": "installer", "exit_code": 1, "summary": sample,
            }));
            for input in [sample, receipt.as_str()] {
                let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
                let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
                let projected = redact_secrets(input);
                let chained = redact_secrets(&af_release::lifecycle::sanitize_persisted_lifecycle_text(&runner));
                for (boundary, result) in [("runner", &runner), ("persistence", &persisted), ("projection", &projected), ("chain", &chained)] {
                    assert!(!result.contains("FRAGMENT_CANARY"), "{boundary}: {input:?} -> {result:?}");
                    assert!(!redact_secrets(result).contains("FRAGMENT_CANARY"));
                }
                let connection = Connection::open_in_memory().unwrap();
                af_release::lifecycle::initialize_schema(&connection).unwrap();
                connection.execute_batch(
                    "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','fixture','update','updating','fixture');
                     INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at) VALUES ('sonarr','fixture','update','updating','fixture');"
                ).unwrap();
                af_release::lifecycle::finish_job_with_diagnostics(
                    &connection,
                    "sonarr",
                    "fixture",
                    "update",
                    false,
                    af_release::lifecycle::LifecycleJobDiagnostics {
                        failure_category: "installer",
                        failed_stage: Some("fixture"),
                        exit_code: Some(1),
                        sanitized_summary: Some(input),
                        finished_at: Some("fixture"),
                        ..Default::default()
                    },
                ).unwrap();
                for query in [
                    "SELECT sanitized_summary FROM package_lifecycle_jobs WHERE job_id='fixture'",
                    "SELECT sanitized_summary FROM package_lifecycle_history WHERE job_id='fixture'",
                ] {
                    let summary: String = connection.query_row(
                        query,
                        [], |row| row.get(0),
                    ).unwrap();
                    assert!(!summary.contains("FRAGMENT_CANARY"), "{input:?} -> {summary:?}");
                }
            }
        }
        let benign = r#""displayN\u0061me":"visible" bypass=visible passed=true monkey=1"#;
        assert_eq!(redact_secrets(benign), benign);
        let command = r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: FRAGMENT_CANARY" https://example.invalid"#;
        let sanitized = redact_secrets(command);
        assert!(!sanitized.contains("FRAGMENT_CANARY"));
        assert!(sanitized.contains("https://example.invalid"));
        assert_eq!(redact_secrets(&sanitized), sanitized);
    }

    #[test]
    fn test_w25_escape_aware_scalar_and_unicode_keys_package_jobs() {
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
                r#"{"password":"[REDACTED]"}"#,
            ),
            (
                r#"{"pass\\u0077ord":"SENTINEL"}"#,
                r#"{"password":"[REDACTED]"}"#,
            ),
        ];
        for (sample, expected) in exact {
            let out = redact_secrets(sample);
            assert_eq!(out, expected, "sample={sample}");
            assert!(!out.contains("SENTINEL"), "{out}");
            assert!(!out.contains("123456789"), "{out}");
            assert_eq!(redact_secrets(&out), out, "idempotent: {sample}");
            if sample.contains("--verbose") {
                assert!(out.contains("--verbose"), "{out}");
            }
            if sample.contains("https://example.invalid") {
                assert!(out.contains("https://example.invalid"), "{out}");
            }
            if expected.starts_with('{') {
                serde_json::from_str::<serde_json::Value>(&out)
                    .unwrap_or_else(|err| panic!("json {err}: {out}"));
            }

            let sanitized = af_release::lifecycle::sanitize_persisted_lifecycle_text(sample);
            assert!(
                !sanitized.contains("SENTINEL"),
                "sanitize leaked: {sample} -> {sanitized}"
            );
            assert!(
                !sanitized.contains("123456789"),
                "sanitize leaked number: {sample} -> {sanitized}"
            );
            let chained = redact_secrets(&sanitized);
            assert!(
                !chained.contains("SENTINEL"),
                "chain leaked: {sample} -> {sanitized} -> {chained}"
            );
            assert!(
                !chained.contains("123456789"),
                "chain leaked number: {chained}"
            );
            assert_eq!(
                redact_secrets(&chained),
                chained,
                "chain idempotent: {chained}"
            );
            if sample.contains("--verbose") {
                assert!(chained.contains("--verbose"), "{chained}");
            }
            if sample.contains("https://example.invalid") {
                assert!(chained.contains("https://example.invalid"), "{chained}");
            }
        }

        let containers = [
            (r#"{"Credentials":{"plain":"SENTINEL"}}"#, "Credentials"),
            (
                r#"{"credentials":{"a":{"b":{"c":{"plain":"SENTINEL"}}}}}"#,
                "credentials",
            ),
            (
                r#"{"credentials":[{"a":[{"plain":"SENTINEL"}]}]}"#,
                "credentials",
            ),
        ];
        for (sample, key) in containers {
            let out = redact_secrets(sample);
            assert!(!out.contains("SENTINEL"), "{sample} -> {out}");
            assert!(!out.contains("plain"), "{sample} -> {out}");
            let parsed: serde_json::Value =
                serde_json::from_str(&out).unwrap_or_else(|err| panic!("json {err}: {out}"));
            assert_eq!(parsed[key], "[REDACTED]", "{out}");
            assert_eq!(redact_secrets(&out), out, "{out}");

            let sanitized = af_release::lifecycle::sanitize_persisted_lifecycle_text(sample);
            assert!(
                !sanitized.contains("SENTINEL"),
                "sanitize leaked: {sanitized}"
            );
            let chained = redact_secrets(&sanitized);
            assert!(
                !chained.contains("SENTINEL"),
                "chain leaked: {sanitized} -> {chained}"
            );
            assert_eq!(redact_secrets(&chained), chained, "{chained}");
        }

        let header = r#"curl -H \"Cookie: sid=\"SENTINEL\"\" https://example.invalid"#;
        let header_out = redact_secrets(header);
        assert!(!header_out.contains("SENTINEL"), "{header_out}");
        assert!(
            header_out.contains("https://example.invalid"),
            "{header_out}"
        );
        assert!(header_out.contains("[REDACTED]"), "{header_out}");
        assert_eq!(redact_secrets(&header_out), header_out);
        let header_chain = redact_secrets(
            &af_release::lifecycle::sanitize_persisted_lifecycle_text(header),
        );
        assert!(!header_chain.contains("SENTINEL"), "{header_chain}");
        assert!(
            header_chain.contains("https://example.invalid"),
            "{header_chain}"
        );

        let kept = r#"{"na\u006de":"visible"}"#;
        assert_eq!(redact_secrets(kept), kept);
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(kept),
            kept
        );
    }
}
