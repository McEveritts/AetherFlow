//! Redaction for diagnostic messages that may be persisted or returned to clients.

use std::borrow::Cow;

const SECRET_LABELS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api-key",
    "apikey",
    "private-key",
    "client-secret",
];

/// Removes entire credential-bearing lines so quoted and structured values cannot be
/// partially exposed in an error receipt. Ordinary diagnostic lines are preserved.
pub fn redact_diagnostic(message: &str) -> Cow<'_, str> {
    let sensitive = |line: &str| {
        let lower = line.to_ascii_lowercase().replace('_', "-");
        let credentials_url = lower.match_indices("://").any(|(start, _)| {
            let authority = lower[start + 3..]
                .split(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#'))
                .next()
                .unwrap_or_default();
            authority.contains('@')
        });
        credentials_url
            || SECRET_LABELS.iter().any(|label| {
                lower.match_indices(label).any(|(offset, _)| {
                    let after = lower[offset + label.len()..]
                        .trim_start_matches(['"', '\''])
                        .trim_start();
                    let assignment = after.starts_with(['=', ':']) && !after[1..].trim().is_empty();
                    let flag = lower[..offset].ends_with("--") && !after.is_empty();
                    assignment || flag
                })
            })
    };
    if !message.lines().any(sensitive) {
        return Cow::Borrowed(message);
    }
    Cow::Owned(
        message
            .split_inclusive('\n')
            .map(|line| {
                if sensitive(line.trim_end()) {
                    if line.ends_with('\n') {
                        "[REDACTED]\n"
                    } else {
                        "[REDACTED]"
                    }
                } else {
                    line
                }
            })
            .collect(),
    )
}

// Keep the regex-based diagnostic grammar here while allowing af-models to remain
// dependency-light for WASM consumers. af-release instantiates it once for native callers.
#[doc(hidden)]
#[macro_export]
macro_rules! define_package_diagnostic_redaction {
    () => {
        const SENSITIVE_DIAGNOSTIC_KEY_PATTERN: &str = r"(?:[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credentials?|bearer|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|jwt[_-]?secret)[A-Za-z0-9_.-]*|\b(?:[A-Za-z0-9]*[_.-])?pass(?:[_.-][A-Za-z0-9]*)*\b)";

        pub static SENSITIVE_ASSIGNMENT_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(
                &[
                    r#"(?i)((?:\\*['"])?"#,
                    SENSITIVE_DIAGNOSTIC_KEY_PATTERN,
                    r#"(?:\\*['"])?\s*[:=]\s*)"#,
                ]
                .concat(),
            )
            .unwrap()
        });

        pub fn is_sensitive_diagnostic_key(key: &str) -> bool {
            static SENSITIVE_KEY_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(&format!(r"(?i)^{}$", SENSITIVE_DIAGNOSTIC_KEY_PATTERN)).unwrap());
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
        static SENSITIVE_CONTAINER_KEY_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(
                &[
                    r#"(?i)(?:\\*["'])?\b"#,
                    SENSITIVE_DIAGNOSTIC_KEY_PATTERN,
                    r#"\b(?:\\*["'])?\s*[:=]\s*([\{\[])"#,
                ]
                .concat(),
            )
            .unwrap()
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
            static COMMAND_TAIL_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"^-{1,2}[A-Za-z][A-Za-z0-9-]*(?:\s|=|$)").unwrap());
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
                    } else if backslashes.is_multiple_of(2) {
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
                if next == quote
                    && ((escape_depth == 0 && backslashes % 2 == 0)
                        || (escape_depth > 0 && backslashes == escape_depth))
                {
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
                    if closes_enclosing
                        && (!after.is_some_and(|next| next.is_ascii_whitespace())
                            || !has_matching_secret_quote(bytes, i + bs0, bs0))
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
                            if closes_outer
                                && (!after_q.is_some_and(|next| next.is_ascii_whitespace())
                                    || !has_matching_secret_quote(bytes, q_idx, bs))
                            {
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
                        if closes_outer
                            && (!after_q.is_some_and(|next| next.is_ascii_whitespace())
                                || !has_matching_secret_quote(bytes, i, 0))
                        {
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
            let key = prefix
                .split(':')
                .next()
                .unwrap_or(prefix)
                .trim()
                .trim_matches(|character: char| matches!(character, '"' | '\'' | '\\'));
            if !matches!(
                key.to_ascii_lowercase().as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "set-cookie"
                    | "x-api-key"
                    | "x-auth-token"
            ) {
                return false;
            }
            let Some(suffix) = value.strip_prefix("[REDACTED]") else {
                return false;
            };
            if suffix.trim().is_empty() {
                return true;
            }
            let quoted_prefix = prefix.trim().trim_start_matches('\\');
            let Some(opening_quote @ ('\'' | '"')) = quoted_prefix.chars().next() else {
                return false;
            };
            let suffix = suffix.trim_start_matches('\\');
            let Some(quote @ ('\'' | '"')) = suffix.chars().next() else {
                return false;
            };
            if quote != opening_quote {
                return false;
            }
            let following = suffix[quote.len_utf8()..].trim_start();
            following.is_empty()
                || is_diagnostic_command_tail(following)
                || following.starts_with("https://")
                || following.starts_with("http://")
                || following.starts_with([',', '}', ']'])
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
                if is_complete_redacted_header(&slice[mat.start()..mat.end()], value)
                    || scalar_value_is_container(value)
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

        pub mod diagnostic_projection {
            use super::{Lazy, consume_secret_scalar_value, consume_balanced_container, escaped_quote_closes_payload, secret_scalar_span, scalar_value_is_container};

            pub fn is_sensitive_secret_key(k: &str) -> bool {
                if super::is_sensitive_diagnostic_key(k) {
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
                redact_prefixed_secrets(
                    text,
                    &super::SENSITIVE_ASSIGNMENT_PREFIX_RE,
                    true,
                )
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
                        if let Some(close_idx) = super::find_closing_header_quote(raw_val, pre)
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

                    if super::is_complete_redacted_header(&format!("{hdr}:"), raw_val) {
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
                let normalized = super::normalize_unicode_escaped_sensitive_keys(input);
                let json = redact_embedded_json_spans(&normalized);
                let headers = redact_sensitive_http_headers(&json);
                let scrubbed = scrub_scalar_secret_grammar(&headers);
                let containers = super::redact_sensitive_nested_containers(&scrubbed);
                let balanced = redact_balanced_structured_secrets(&containers);
                let regexed = redact_secrets_regex(&balanced);
                scrub_scalar_secret_grammar(&regexed)
            }

            pub fn is_already_redacted(val: &str) -> bool {
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
                            if let Some(close_idx) = super::find_closing_header_quote(val, pre)
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
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_redacts_url_headers_and_quoted_assignments() {
        let raw = "updater failed\nAuthorization: Bearer ABC\nhttps://user:pass@example.com\n{\"GH_TOKEN\":\"XYZ\"}";
        assert_eq!(
            redact_diagnostic(raw),
            "updater failed\n[REDACTED]\n[REDACTED]\n[REDACTED]"
        );
    }
}
