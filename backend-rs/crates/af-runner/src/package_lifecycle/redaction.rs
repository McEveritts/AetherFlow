const MAX_ESCAPED_QUOTE_DEPTH: usize = 15;

#[inline]
fn utf8_char_width_at(s: &str, idx: usize) -> usize {
    let bytes = s.as_bytes();
    if idx >= bytes.len() {
        return 0;
    }
    if bytes[idx] < 0x80 {
        1
    } else {
        s[idx..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1)
    }
}

#[inline]
fn starts_with_unicode_ws(after: &[u8]) -> bool {
    af_models::secret_redaction::bytes_start_with_unicode_ws(after)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ContainerQuote {
    Literal(u8, usize),
    Unicode(u8, usize, usize, usize),
}

/// Scan a `{...}` / `[...]` container. `Ok(end)` is the index just past a
/// container that closed on this line (or stopped before an enclosing quote / EOF).
/// `Err(eol)` means a newline arrived at `eol` before the opener closed, so the
/// caller leaves the opener in place for the multiline container redactor and
/// advances to `eol` without rescanning the same line.
fn consume_balanced_container(
    s: &str,
    start: usize,
    enclosing_quotes: &af_release::lifecycle::QuoteStack,
    stop_on_newline: bool,
) -> Result<usize, usize> {
    let bytes = s.as_bytes();
    let mut j = start;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut quote: Option<ContainerQuote> = None;
    let mut inner_bs = 0usize;
    let mut u_sep_run = 0usize;
    while j < bytes.len() {
        let c = bytes[j];
        if stop_on_newline && (c == b'\r' || c == b'\n') {
            return Err(j);
        }
        if let Some(cq) = quote {
            match cq {
                ContainerQuote::Literal(q, q_depth) => {
                    if c == b'\\' {
                        inner_bs += 1;
                        j += 1;
                        continue;
                    }
                    if c == q {
                        if af_release::lifecycle::QuoteStack::matches_open_depth(q_depth, inner_bs)
                        {
                            quote = None;
                            inner_bs = 0;
                            j += 1;
                            continue;
                        }
                        if q_depth > 0
                            && enclosing_quotes.contains_strict_lower(q, inner_bs, q_depth)
                            && af_release::lifecycle::quote_closes_enclosing(bytes, j)
                        {
                            return Ok(j - inner_bs);
                        }
                    } else if matches!(c, b'"' | b'\'')
                        && af_release::lifecycle::enclosing_cross_quote_closes_outer(
                            bytes,
                            j,
                            q,
                            c,
                            inner_bs,
                            enclosing_quotes,
                        )
                    {
                        return Ok(j - inner_bs);
                    }
                    inner_bs = 0;
                    j += utf8_char_width_at(s, j);
                    continue;
                }
                ContainerQuote::Unicode(q_kind, obs, od, osep) => {
                    if c == b'\\' {
                        if inner_bs == 0 {
                            if let Some((cbs, cd, kind, cend)) =
                                af_models::secret_redaction::diag_parse_u_quote_or_apos_token_at(
                                    bytes, j,
                                )
                            {
                                if kind == b'\\' {
                                    if cbs == obs && cd == od {
                                        u_sep_run += 1;
                                    } else {
                                        u_sep_run = 0;
                                    }
                                    j = cend;
                                    continue;
                                }
                                if kind == q_kind
                                    && cbs == obs
                                    && cd == od
                                    && af_release::lifecycle::QuoteStack::matches_open_depth(
                                        osep, u_sep_run,
                                    )
                                {
                                    quote = None;
                                    u_sep_run = 0;
                                    j = cend;
                                    continue;
                                }
                                u_sep_run = 0;
                                j = cend;
                                continue;
                            }
                        }
                        u_sep_run = 0;
                        inner_bs += 1;
                        j += 1;
                        continue;
                    }
                    u_sep_run = 0;
                    if c == b'"'
                        && inner_bs.is_multiple_of(2)
                        && enclosing_quotes.contains(b'"', 0)
                        && af_release::lifecycle::quote_closes_enclosing(bytes, j)
                    {
                        return Ok(j);
                    }
                    inner_bs = 0;
                    j += utf8_char_width_at(s, j);
                    continue;
                }
            }
        }
        if c == b'\\' {
            if let Some((q_kind, obs, od, osep_raw, u_end)) =
                af_models::secret_redaction::diag_parse_u_composite_any_quote_at(bytes, j)
            {
                let osep = if osep_raw.is_multiple_of(2) {
                    0
                } else {
                    osep_raw
                };
                if osep <= MAX_ESCAPED_QUOTE_DEPTH {
                    quote = Some(ContainerQuote::Unicode(q_kind, obs, od, osep));
                    inner_bs = 0;
                    u_sep_run = 0;
                    j = u_end;
                    continue;
                }
            }
            let bs = bytes[j..].iter().take_while(|&&b| b == b'\\').count();
            match bytes.get(j + bs).copied() {
                Some(q @ (b'"' | b'\'')) => {
                    let q_idx = j + bs;
                    let next_after = bytes.get(q_idx + 1).copied();
                    let effective_depth = if bs.is_multiple_of(2) { 0 } else { bs };
                    if next_after != Some(q)
                        && enclosing_quotes.contains(q, effective_depth)
                        && af_release::lifecycle::quote_closes_enclosing_in_context(
                            bytes,
                            q_idx,
                            q,
                            effective_depth,
                            None,
                            enclosing_quotes,
                            true,
                        )
                    {
                        if bs.is_multiple_of(2) {
                            return Ok(q_idx);
                        }
                        return Ok(j);
                    }
                    quote = Some(ContainerQuote::Literal(q, effective_depth));
                    inner_bs = 0;
                    j = q_idx + 1;
                    continue;
                }
                Some(b'\r' | b'\n') if stop_on_newline => return Err(j + bs),
                Some(_) => {
                    j += bs + utf8_char_width_at(s, j + bs);
                    continue;
                }
                None => {
                    j += bs;
                    break;
                }
            }
        }
        if c == b'"' || c == b'\'' {
            let next_after = bytes.get(j + 1).copied();
            if next_after != Some(c)
                && enclosing_quotes.contains(c, 0)
                && af_release::lifecycle::quote_closes_enclosing_in_context(
                    bytes,
                    j,
                    c,
                    0,
                    None,
                    enclosing_quotes,
                    true,
                )
            {
                return Ok(j);
            }
            quote = Some(ContainerQuote::Literal(c, 0));
            inner_bs = 0;
            j += 1;
            continue;
        }
        if c == b'{' {
            brace_depth += 1;
            j += 1;
            continue;
        }
        if c == b'[' {
            bracket_depth += 1;
            j += 1;
            continue;
        }
        if c == b'}' {
            if brace_depth == 0 {
                if bracket_depth == 0 {
                    return Ok(j);
                }
                j += 1;
                continue;
            }
            brace_depth -= 1;
            j += 1;
            if brace_depth == 0 && bracket_depth == 0 {
                return Ok(j);
            }
            continue;
        }
        if c == b']' {
            if bracket_depth == 0 {
                if brace_depth == 0 {
                    return Ok(j);
                }
                j += 1;
                continue;
            }
            bracket_depth -= 1;
            j += 1;
            if brace_depth == 0 && bracket_depth == 0 {
                return Ok(j);
            }
            continue;
        }
        j += utf8_char_width_at(s, j);
    }
    Ok(j)
}

fn consume_plain_quoted(
    s: &str,
    quote_idx: usize,
    enclosing_quotes: &af_release::lifecycle::QuoteStack,
) -> usize {
    let bytes = s.as_bytes();
    let q = bytes[quote_idx];
    let mut j = quote_idx + 1;
    let mut bs = 0usize;
    let mut crossed_newline = false;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\r' || c == b'\n' {
            crossed_newline = true;
            bs = 0;
            j += 1;
            continue;
        }
        if c == b'\\' {
            bs += 1;
            j += 1;
            continue;
        }
        if c == q && bs.is_multiple_of(2) {
            return j + 1;
        }
        if !crossed_newline
            && matches!(c, b'"' | b'\'')
            && c != q
            && af_release::lifecycle::enclosing_cross_quote_closes_outer(
                bytes,
                j,
                q,
                c,
                bs,
                enclosing_quotes,
            )
        {
            return j - bs;
        }
        bs = 0;
        j += utf8_char_width_at(s, j);
    }
    bytes.len()
}

/// Scans a `\u0022...\u0022` or `\u0027...\u0027` (or `\u005c\u0022...` / `\u005c\u0027...` /
/// `\u005cu0022...` / `\\u0027...`) quoted scalar segment starting at `bytes[start..]`, returning
/// the byte offset immediately after the matching closing quote token (or before an enclosing
/// JSON `"` / EOL if `!allow_multiline` / EOF).
fn scan_u_quoted_span(
    bytes: &[u8],
    start: usize,
    enclosing_quotes: &af_release::lifecycle::QuoteStack,
    allow_multiline: bool,
) -> Option<usize> {
    let (q_kind, open_bs, open_depth, open_sep_bs_raw, inner_start) =
        af_models::secret_redaction::diag_parse_u_composite_any_quote_at(bytes, start)?;
    let open_sep_bs = if open_sep_bs_raw.is_multiple_of(2) {
        0
    } else {
        open_sep_bs_raw
    };
    let mut j = inner_start;
    let mut sep_bs_run = 0usize;
    let mut sep_bs_run_start = 0usize;
    let mut crossed_newline = false;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\r' || c == b'\n' {
            if !allow_multiline {
                return Some(j);
            }
            crossed_newline = true;
            sep_bs_run = 0;
            j += 1;
            continue;
        }
        if !crossed_newline
            && c == b'"'
            && enclosing_quotes.contains(b'"', 0)
            && af_release::lifecycle::quote_closes_enclosing(bytes, j)
        {
            return Some(j);
        }
        if c == b'\\' {
            if let Some((cbs, cd, kind, cend)) =
                af_models::secret_redaction::diag_parse_u_quote_or_apos_token_at(bytes, j)
            {
                if kind == b'\\' {
                    if cbs == open_bs && cd == open_depth {
                        if sep_bs_run == 0 {
                            sep_bs_run_start = j;
                        }
                        sep_bs_run += 1;
                    } else {
                        sep_bs_run = 0;
                    }
                    j = cend;
                    continue;
                }
                if kind == q_kind && cbs == open_bs && cd == open_depth {
                    if af_release::lifecycle::QuoteStack::matches_open_depth(
                        open_sep_bs,
                        sep_bs_run,
                    ) {
                        return Some(cend);
                    }
                    if open_sep_bs > 0 && sep_bs_run < open_sep_bs {
                        let stop = if sep_bs_run == 0 { j } else { sep_bs_run_start };
                        return Some(stop);
                    }
                }
                sep_bs_run = 0;
                j = cend;
                continue;
            }
            sep_bs_run = 0;
            let bs_s = j;
            while j < bytes.len() && bytes[j] == b'\\' {
                j += 1;
            }
            if (j - bs_s) % 2 == 1 && bytes.get(j) == Some(&b'"') {
                j += 1;
            }
            continue;
        }
        sep_bs_run = 0;
        j += 1;
    }
    Some(bytes.len())
}

/// Length of a secret scalar starting at `s`.
/// Returns `Ok(len)` for normal scalars or `Err(eol)` if an unclosed container hit
/// a newline at `eol` (deferring to the multiline container redactor without rescanning).
fn consume_secret_scalar_value(
    s: &str,
    allow_comma_list: bool,
    enclosing_quotes: &af_release::lifecycle::QuoteStack,
) -> Result<usize, usize> {
    consume_secret_scalar_value_ext(s, allow_comma_list, enclosing_quotes, true)
}

fn consume_secret_scalar_value_ext(
    s: &str,
    allow_comma_list: bool,
    enclosing_quotes: &af_release::lifecycle::QuoteStack,
    allow_containers: bool,
) -> Result<usize, usize> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let marker_len = if s
        .get(.."[REDACTED_URL]".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("[REDACTED_URL]"))
    {
        Some("[REDACTED_URL]".len())
    } else if s.starts_with("[REDACTED]") {
        Some("[REDACTED]".len())
    } else {
        None
    };
    if let Some(mlen) = marker_len {
        i = mlen;
        if i >= bytes.len() {
            return Ok(i);
        }
        let bs0 = bytes[i..].iter().take_while(|b| **b == b'\\').count();
        if i + bs0 < bytes.len() && matches!(bytes[i + bs0], b'"' | b'\'') {
            let q = bytes[i + bs0];
            let after = bytes.get(i + bs0 + 1).copied();
            let closes_outer_escaped_url = bs0 > 0
                && enclosing_quotes.contains(q, 0)
                && after.is_some_and(|next| next.is_ascii_whitespace())
                && {
                    let rest_after = s[i + bs0 + 1..].trim_start();
                    rest_after.starts_with("https://") || rest_after.starts_with("http://")
                }
                && (bs0 > MAX_ESCAPED_QUOTE_DEPTH
                    || !af_release::lifecycle::has_matching_secret_quote(bytes, i + bs0, bs0));
            // `"[REDACTED]",` and `[REDACTED]\" https://...` close an enclosing
            // string, and a lone trailing quote at EOF — or at EOL with NO matching closing quote
            // on a later line — carries no secret tail. A glued multiline quote like
            // `password=[REDACTED]"\nSUPER_SECRET"` still consumes the full quoted secret.
            let lone_eol_quote = match after {
                None => true,
                Some(b'\r' | b'\n') => {
                    !enclosing_quotes.has_matching_multiline_quote_after(bytes, i + bs0, bs0)
                }
                Some(_) => false,
            };
            if (enclosing_quotes.contains(q, bs0)
                && af_release::lifecycle::quote_closes_enclosing_in_context(
                    bytes,
                    i + bs0,
                    q,
                    bs0,
                    None,
                    enclosing_quotes,
                    false,
                ))
                || closes_outer_escaped_url
                || lone_eol_quote
                || (bs0 == 0
                    && af_release::lifecycle::is_standalone_marker_before_sensitive_json_key(
                        &s[i..],
                    ))
            {
                return Ok(i);
            }
        } else if (bytes[i] == b'\\'
            && af_models::secret_redaction::diag_parse_u_composite_any_quote_at(bytes, i)
                .is_some_and(|(_, _, _, _, u_end)| {
                    let after_u = &bytes[u_end..];
                    after_u.is_empty()
                        || starts_with_unicode_ws(after_u)
                        || matches!(
                            after_u[0],
                            b',' | b']' | b'}' | b')' | b';' | b'"' | b'\'' | b'\\'
                        )
                        || af_models::secret_redaction::url_quote_closes_json_or_container(
                            bytes,
                            u_end - 1,
                        )
                }))
            || af_release::lifecycle::is_standalone_marker_tail_byte(&bytes[i..], allow_comma_list)
        {
            return Ok(i);
        }
    }

    let mut value_started = marker_len.is_some();
    while i < bytes.len() {
        if bytes[i] == b'\r' || bytes[i] == b'\n' {
            break;
        }

        let mut as_unescaped_quote = false;
        let mut ansi_c_quote = false;
        if bytes[i] == b'$' {
            if let Some((_q_idx, bs)) =
                af_release::lifecycle::is_ansi_c_quote_opener_in_context(bytes, i, enclosing_quotes)
            {
                i += 1;
                ansi_c_quote = true;
                value_started = true;
                if bs == 0 {
                    as_unescaped_quote = true;
                }
            }
        }
        if !as_unescaped_quote && bytes[i] == b'\\' {
            if value_started
                && af_models::secret_redaction::diag_parse_u_composite_any_quote_at(bytes, i)
                    .is_some_and(|(_, _, _, _, u_end)| {
                        let after_u = &bytes[u_end..];
                        after_u.is_empty()
                            || starts_with_unicode_ws(after_u)
                            || matches!(
                                after_u[0],
                                b',' | b']' | b'}' | b')' | b';' | b'"' | b'\'' | b'\\'
                            )
                            || af_models::secret_redaction::url_quote_closes_json_or_container(
                                bytes,
                                u_end - 1,
                            )
                    })
            {
                break;
            }
            if let Some(u_end) = scan_u_quoted_span(bytes, i, enclosing_quotes, true) {
                value_started = true;
                i = u_end;
                continue;
            }
            let bs = bytes[i..].iter().take_while(|b| **b == b'\\').count();
            let nxt = bytes.get(i + bs).copied();
            if matches!(nxt, Some(b'"' | b'\'')) {
                let q = nxt.unwrap();
                let q_idx = i + bs;
                if !ansi_c_quote
                    && af_release::lifecycle::quote_closes_enclosing_in_context(
                        bytes,
                        q_idx,
                        q,
                        bs,
                        None,
                        enclosing_quotes,
                        !value_started,
                    )
                {
                    if bs > 0 && bs.is_multiple_of(2) && enclosing_quotes.contains(q, 0) {
                        i += bs;
                    }
                    break;
                }
                value_started = true;
                if bs.is_multiple_of(2) {
                    i += bs;
                    as_unescaped_quote = true;
                } else {
                    let mut j = q_idx + 1;
                    let mut inner_bs = 0usize;
                    let mut stop_outer = false;
                    let mut crossed_newline = false;
                    let mut has_later_match: Option<bool> = None;
                    while j < bytes.len() {
                        let c = bytes[j];
                        if c == b'\r' || c == b'\n' {
                            crossed_newline = true;
                            inner_bs = 0;
                            j += 1;
                            continue;
                        }
                        if c == b'\\' {
                            inner_bs += 1;
                            j += 1;
                            continue;
                        }
                        if c == q {
                            if af_release::lifecycle::QuoteStack::matches_open_depth(bs, inner_bs) {
                                i = j + 1;
                                break;
                            }
                            if !crossed_newline
                                && inner_bs == 0
                                && enclosing_quotes.contains(q, 0)
                                && af_release::lifecycle::quote_closes_enclosing(bytes, j)
                            {
                                i = j;
                                stop_outer = true;
                                break;
                            }
                            if !crossed_newline
                                && enclosing_quotes.contains_strict_lower(q, inner_bs, bs)
                                && af_release::lifecycle::quote_closes_enclosing(bytes, j)
                            {
                                i = j - inner_bs;
                                stop_outer = true;
                                break;
                            }
                            if inner_bs < bs
                                && inner_bs % 2 == 1
                                && escaped_quote_closes_payload(bytes, j)
                            {
                                let matched = *has_later_match.get_or_insert_with(|| {
                                    bs <= MAX_ESCAPED_QUOTE_DEPTH
                                        && af_release::lifecycle::has_matching_secret_quote_multiline(
                                            bytes, j, bs,
                                        )
                                });
                                if !matched {
                                    i = j + 1;
                                    stop_outer = true;
                                    break;
                                }
                            }
                        } else if !crossed_newline
                            && matches!(c, b'"' | b'\'')
                            && af_release::lifecycle::enclosing_cross_quote_closes_outer(
                                bytes,
                                j,
                                q,
                                c,
                                inner_bs,
                                enclosing_quotes,
                            )
                        {
                            i = j - inner_bs;
                            stop_outer = true;
                            break;
                        }
                        inner_bs = 0;
                        j += utf8_char_width_at(s, j);
                    }
                    if j >= bytes.len() && i < q_idx {
                        i = bytes.len();
                        break;
                    }
                    if stop_outer {
                        break;
                    }
                    continue;
                }
            } else if matches!(nxt, Some(b'u' | b'U')) {
                value_started = true;
                i += bs + 1;
                continue;
            } else if let Some(nc) = nxt {
                if !value_started
                    && bs % 2 == 1
                    && matches!(nc, b'n' | b'r' | b't' | b'f' | b'b')
                    && enclosing_quotes.contains(b'"', 0)
                {
                    let mut next_i = i + bs + 1;
                    while next_i < bytes.len() {
                        if matches!(bytes[next_i], b' ' | b'\t') {
                            next_i += 1;
                        } else if bytes[next_i] == b'\\'
                            && matches!(
                                bytes.get(next_i + 1),
                                Some(b'n' | b'r' | b't' | b'f' | b'b')
                            )
                        {
                            next_i += 2;
                        } else {
                            break;
                        }
                    }
                    if next_i < bytes.len()
                        && !matches!(bytes[next_i], b'\r' | b'\n')
                        && !(bytes[next_i] == b'"'
                            && af_release::lifecycle::quote_closes_enclosing(bytes, next_i))
                    {
                        i = next_i;
                        continue;
                    }
                    break;
                }
                if value_started
                    && bs % 2 == 1
                    && matches!(nc, b'n' | b'r' | b't' | b'f' | b'b')
                    && enclosing_quotes.contains(b'"', 0)
                {
                    // JSON-escaped newline/tab terminates an unquoted scalar inside a
                    // JSON string so subsequent lines/fields are preserved, EXCEPT for
                    // JSON-escaped POSIX line continuations (`\\\n` / `\\\r\n`, where
                    // `bs >= 3 && (bs - 1) % 4 == 2`, representing `\\` + `\n`).
                    if matches!(nc, b'n' | b'r') && bs >= 3 && (bs - 1) % 4 == 2 {
                        let mut next_i = i + bs + 1;
                        if nc == b'r'
                            && bytes.get(next_i) == Some(&b'\\')
                            && bytes.get(next_i + 1) == Some(&b'n')
                        {
                            next_i += 2;
                        }
                        if next_i < bytes.len()
                            && !matches!(bytes[next_i], b'\r' | b'\n')
                            && !(bytes[next_i] == b'"'
                                && af_release::lifecycle::quote_closes_enclosing(bytes, next_i))
                        {
                            i = next_i;
                            continue;
                        }
                    }
                    i += bs - 1;
                    break;
                }
                if nc != b'\r' && nc != b'\n' {
                    value_started = true;
                    i += bs + utf8_char_width_at(s, i + bs);
                    continue;
                }
                if bs % 2 == 1 {
                    let nl_len = if nc == b'\r' && bytes.get(i + bs + 1) == Some(&b'\n') {
                        2
                    } else {
                        1
                    };
                    let mut next_i = i + bs + nl_len;
                    if !value_started {
                        while next_i < bytes.len() && matches!(bytes[next_i], b' ' | b'\t') {
                            next_i += 1;
                        }
                    }
                    if next_i < bytes.len() && !matches!(bytes[next_i], b'\r' | b'\n') {
                        i = next_i;
                        continue;
                    }
                }
                i += bs;
                break;
            } else {
                i += bs;
                break;
            }
        } else if !as_unescaped_quote && matches!(bytes[i], b'"' | b'\'') {
            as_unescaped_quote = true;
        }

        if as_unescaped_quote {
            let q = bytes[i];
            if !ansi_c_quote
                && af_release::lifecycle::quote_closes_enclosing_in_context(
                    bytes,
                    i,
                    q,
                    0,
                    None,
                    enclosing_quotes,
                    !value_started,
                )
            {
                break;
            }
            value_started = true;
            let seg_start = i;
            let end = consume_plain_quoted(s, i, enclosing_quotes);
            if end <= i {
                break;
            }
            i = end;
            if seg_start == 0 && i >= 2 && bytes.get(i - 1) == Some(&q) {
                let inner = &s[1..i - 1];
                if inner == "[REDACTED]" || inner.eq_ignore_ascii_case("[REDACTED_URL]") {
                    let tail = &s[i..];
                    let tb = tail.as_bytes();
                    let tbs = tb.iter().take_while(|&&b| b == b'\\').count();
                    let lone_eol_q = tb.get(tbs).is_some_and(|&b| matches!(b, b'"' | b'\''))
                        && match tb.get(tbs + 1) {
                            None => true,
                            Some(b'\r' | b'\n') => !enclosing_quotes
                                .has_matching_multiline_quote_after(bytes, i + tbs, tbs),
                            Some(_) => false,
                        };
                    if lone_eol_q
                        || af_release::lifecycle::is_standalone_marker_before_sensitive_json_key(
                            tail,
                        )
                    {
                        break;
                    }
                }
            }
            if i < bytes.len() && (bytes[i] == b'\r' || bytes[i] == b'\n') {
                break;
            }
            if i > 0 && bytes.get(i.saturating_sub(1)).copied() != Some(q) && i < bytes.len() {
                break;
            }
            continue;
        }

        if allow_containers && (bytes[i] == b'{' || bytes[i] == b'[') {
            // Standalone multiline containers (`!value_started`) defer to the multiline container
            // redactor; glued containers (`password=a{\n "v": "SECRET"\n}`) scan across newlines so
            // the opening `{` is never stripped while leaving inner lines in plaintext.
            let standalone = !value_started;
            value_started = true;
            match consume_balanced_container(s, i, enclosing_quotes, standalone) {
                Ok(end) if end > i => {
                    i = end;
                    continue;
                }
                Ok(_) => break,
                Err(eol) => return Err(eol),
            }
        }

        if bytes[i].is_ascii_whitespace()
            || matches!(bytes[i], b';' | b'&')
            || starts_with_unicode_ws(&bytes[i..])
        {
            break;
        }
        if matches!(bytes[i], b'}' | b']')
            && (bytes.get(i + 1).is_none_or(|b| {
                b.is_ascii_whitespace()
                    || matches!(
                        b,
                        b',' | b';' | b'}' | b']' | b')' | b'&' | b'"' | b'\'' | b'\\'
                    )
            }) || starts_with_unicode_ws(&bytes[i + 1..]))
        {
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
                        || starts_with_unicode_ws(&bytes[i + 1..])
                        || af_release::lifecycle::comma_starts_adjacent_field(&s[i + 1..])
                }
            };
            if trailing_separator {
                break;
            }
        }
        value_started = true;
        i += utf8_char_width_at(s, i);
    }
    Ok(i)
}

fn escaped_quote_closes_payload(bytes: &[u8], quote_idx: usize) -> bool {
    let next = quote_idx
        .checked_add(1)
        .and_then(|idx| bytes.get(idx))
        .copied();
    next.is_none()
        || matches!(
            next,
            Some(b'"' | b'\'' | b',' | b'}' | b']' | b'\r' | b'\n' | b' ')
        )
}

fn prefix_matches_inner_colon_of_quoted_key(prefix: &str, value: &str) -> bool {
    let trimmed = prefix.trim();
    if !trimmed.ends_with(':') || trimmed.contains('=') {
        return false;
    }
    let open_bs = trimmed.bytes().take_while(|&b| b == b'\\').count();
    if open_bs > MAX_ESCAPED_QUOTE_DEPTH {
        return false;
    }
    let Some(&q @ (b'"' | b'\'')) = trimmed.as_bytes().get(open_bs) else {
        return false;
    };
    if trimmed.as_bytes()[open_bs + 1..].contains(&q) {
        return false;
    }
    let vb = value.as_bytes();
    let close_bs = vb.iter().take_while(|&&b| b == b'\\').count();
    if vb.get(close_bs) != Some(&q) {
        return false;
    }
    let open_depth = if open_bs.is_multiple_of(2) {
        0
    } else {
        open_bs
    };
    if !af_release::lifecycle::QuoteStack::matches_open_depth(open_depth, close_bs) {
        return false;
    }
    value[close_bs + 1..]
        .trim_start_matches([' ', '\t'])
        .starts_with(':')
}

fn prefix_is_http_header(prefix: &str) -> bool {
    if prefix.contains('=') || !prefix.contains(':') {
        return false;
    }
    let before_colon = prefix
        .rsplit_once(':')
        .map(|(before, _)| before)
        .unwrap_or(prefix)
        .trim();
    if before_colon.ends_with('"') || before_colon.ends_with('\'') {
        return false;
    }
    let key = before_colon.trim_start_matches(['"', '\'', '\\']);
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

#[inline]
fn header_multiline_next_line_allowed(sep: &str, raw_val: &str) -> bool {
    let after_colon = sep.split_once(':').map_or(sep, |(_, after)| after);
    if !after_colon.contains(['\r', '\n']) {
        return true;
    }
    let trimmed = raw_val.trim();
    if trimmed.is_empty() {
        return false;
    }
    if after_colon
        .chars()
        .next_back()
        .is_some_and(|c| c.is_whitespace() && c != '\r' && c != '\n')
    {
        !af_models::secret_redaction::diag_obs_fold_line_stops(trimmed)
    } else {
        af_models::secret_redaction::is_unindented_empty_header_secret_line(trimmed)
    }
}

fn redact_prefixed_secrets<'a>(
    text: &'a str,
    prefix_re: &regex::Regex,
    allow_comma_list: bool,
) -> std::borrow::Cow<'a, str> {
    let Some(first_mat) = prefix_re.find_at(text, 0) else {
        return std::borrow::Cow::Borrowed(text);
    };
    let mut out: Option<String> = None;
    let mut emit_cursor = 0usize;
    let mut cursor = 0usize;
    let mut quote_stack = af_release::lifecycle::QuoteStack::default();
    let mut next_mat = Some(first_mat);
    while cursor < text.len() {
        let mat = if let Some(m) = next_mat.take() {
            m
        } else {
            let Some(m) = prefix_re.find_at(text, cursor) else {
                break;
            };
            m
        };
        if mat.end() <= cursor {
            let ch = text[cursor..].chars().next().unwrap();
            cursor += ch.len_utf8();
            continue;
        }
        let raw_mat = mat.as_str();
        let mut lead_esc_skip = 0usize;
        if (raw_mat.starts_with("\\t")
            || raw_mat.starts_with("\\n")
            || raw_mat.starts_with("\\r")
            || raw_mat.starts_with("\\b")
            || raw_mat.starts_with("\\f"))
            && raw_mat
                .as_bytes()
                .get(2)
                .is_some_and(|&c| c == b'-' || c.is_ascii_alphanumeric() || c == b'_')
        {
            let bs_before = text[..mat.start() + 1]
                .bytes()
                .rev()
                .take_while(|&b| b == b'\\')
                .count();
            quote_stack.advance_to(text, mat.start());
            if bs_before.is_multiple_of(2) || !quote_stack.contains(b'"', 0) {
                cursor = mat.start() + 2;
                continue;
            }
            if !raw_mat[2..].starts_with("--") {
                lead_esc_skip = 2;
            }
        }
        let guard_off = if lead_esc_skip > 0 {
            lead_esc_skip
        } else {
            af_release::lifecycle::strip_esc_prefix_guard(raw_mat)
        };
        let prefix_start = mat.start() + guard_off;
        let value_off = mat.end();
        let prefix = &text[prefix_start..value_off];
        let balanced_json_key = af_release::lifecycle::is_balanced_json_key_prefix(prefix);
        let scrubbed_prefix = if balanced_json_key {
            af_release::lifecycle::scrub_matched_json_key_prefix(prefix)
        } else {
            std::borrow::Cow::Borrowed(prefix)
        };
        let prefix_changed = scrubbed_prefix.as_ref() != prefix;
        if prefix_changed {
            let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
            buf.push_str(&text[emit_cursor..prefix_start]);
            buf.push_str(&scrubbed_prefix);
            emit_cursor = value_off;
        }
        quote_stack.advance_to(text, value_off);
        if prefix
            .trim_end_matches(|c: char| c.is_whitespace())
            .ends_with("\\f")
            && !quote_stack.contains(b'"', 0)
        {
            cursor = value_off;
            continue;
        }
        let rest_after_prefix = &text[value_off..];
        let skip_empty_multiline_header = prefix_is_http_header(prefix)
            && prefix.rsplit_once(':').is_some_and(|(_, sep)| {
                sep.contains(['\r', '\n'])
                    && !header_multiline_next_line_allowed(
                        sep,
                        rest_after_prefix.split(['\r', '\n']).next().unwrap_or(""),
                    )
            });
        if af_release::lifecycle::is_complete_redacted_header_ctx(
            prefix,
            rest_after_prefix,
            quote_stack.contains(b'"', 0),
        ) || (!balanced_json_key
            && !af_release::lifecycle::is_balanced_quoted_key_prefix(prefix)
            && af_release::lifecycle::prefix_is_redacted_non_header_key(prefix))
            || prefix_matches_inner_colon_of_quoted_key(prefix, rest_after_prefix)
            || skip_empty_multiline_header
        {
            cursor = value_off;
            continue;
        }
        if af_release::lifecycle::parse_leading_auth_scheme(rest_after_prefix).is_some() {
            // Defer unquoted `Bearer ...` / `Basic ...` / `Token ...` / `Digest ...` values to
            // `sanitize_persisted_lifecycle_text_cow` / `redact_auth_scheme_credentials_cow` so the
            // scheme keyword is not consumed prematurely.
            cursor = value_off;
            continue;
        }
        let base_n =
            match consume_secret_scalar_value(rest_after_prefix, allow_comma_list, &quote_stack) {
                Ok(n) => n,
                Err(eol) => {
                    // An unclosed `{` / `[` reached newline: leave the entire line intact for
                    // the multiline container redactor and advance directly to `eol` (O(N)).
                    cursor = value_off + eol;
                    continue;
                }
            };
        let n = af_release::lifecycle::unclosed_prefix_quote_span(
            prefix,
            rest_after_prefix,
            base_n,
            &quote_stack,
        );
        if n == 0 {
            cursor = value_off;
            continue;
        }
        let consumed = &text[value_off..value_off + n];
        let replacement = if balanced_json_key
            && (consumed.starts_with('{') || consumed.starts_with('['))
            && !redacted_container_value(consumed)
        {
            "\"[REDACTED]\"".to_string()
        } else {
            af_release::lifecycle::replacement_for_lifecycle_scalar(&scrubbed_prefix, consumed)
        };
        if replacement != consumed {
            let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
            buf.push_str(&text[emit_cursor..value_off]);
            buf.push_str(&replacement);
            emit_cursor = value_off + n;
        }
        cursor = value_off + n;
    }
    match out {
        Some(mut buf) => {
            buf.push_str(&text[emit_cursor..]);
            std::borrow::Cow::Owned(buf)
        }
        None => std::borrow::Cow::Borrowed(text),
    }
}

#[derive(Default)]
struct CurlCmdTracker {
    curl_on_line: bool,
    last_eq: bool,
    in_quote: Option<u8>,
    curl_in_quote: Option<u8>,
    curl_crossed_newline: bool,
    in_esc_dq: bool,
    curl_in_esc_dq: bool,
    esc_bracket_depth: usize,
    pending_bs: usize,
    bracket_depth: usize,
    curl_in_bracket_depth: Option<usize>,
    pos: usize,
}

impl CurlCmdTracker {
    fn mark_curl(&mut self) {
        self.curl_on_line = true;
        self.curl_in_bracket_depth = (self.bracket_depth > 0).then_some(self.bracket_depth);
        self.curl_in_quote = self.in_quote;
        self.curl_in_esc_dq = self.in_esc_dq;
        self.curl_crossed_newline = false;
    }

    fn advance_to(&mut self, input: &str, target: usize) {
        let end = target.min(input.len());
        if end <= self.pos {
            return;
        }
        let bytes = input.as_bytes();
        let mut i = self.pos;
        while i < end {
            let b = bytes[i];
            if b == b'\r' || b == b'\n' {
                let cont = self.pending_bs % 2 == 1 || self.last_eq;
                self.pending_bs = 0;
                self.last_eq = false;
                if self.curl_on_line && self.in_quote.is_some() {
                    self.curl_crossed_newline = true;
                } else if !cont && self.curl_in_bracket_depth.is_none() {
                    self.curl_on_line = false;
                    self.in_quote = None;
                    self.curl_in_quote = None;
                    self.curl_in_esc_dq = false;
                    self.curl_crossed_newline = false;
                    self.in_esc_dq = false;
                    if self.esc_bracket_depth > 0 {
                        self.bracket_depth =
                            self.bracket_depth.saturating_sub(self.esc_bracket_depth);
                        self.esc_bracket_depth = 0;
                    }
                }
                if b == b'\r' && i + 1 < end && bytes[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if b == b'\\' {
                self.pending_bs += 1;
                i += 1;
                continue;
            }
            let trail_bs = self.pending_bs;
            let even_bs = trail_bs.is_multiple_of(2);
            let odd_bs = !even_bs;
            self.pending_bs = 0;
            if odd_bs
                && matches!(b, b'n' | b'r')
                && self.in_quote == Some(b'"')
                && !self.in_esc_dq
                && self.curl_in_bracket_depth.is_none()
            {
                let json_cont = (trail_bs >= 3 && (trail_bs - 1) % 4 == 2) || self.last_eq;
                self.last_eq = false;
                if !json_cont {
                    self.curl_on_line = false;
                    self.curl_in_quote = None;
                    self.curl_in_esc_dq = false;
                    self.curl_crossed_newline = false;
                }
                i += 1;
                continue;
            }
            if b == b'='
                && (self.in_quote.is_none() || (self.in_quote == Some(b'"') && !self.in_esc_dq))
            {
                self.last_eq = true;
            } else if !matches!(b, b' ' | b'\t') {
                self.last_eq = false;
            }
            if matches!(b, b'"' | b'\'') && even_bs {
                match self.in_quote {
                    Some(q) if q == b => {
                        self.in_quote = None;
                        self.in_esc_dq = false;
                        if self.esc_bracket_depth > 0 {
                            self.bracket_depth =
                                self.bracket_depth.saturating_sub(self.esc_bracket_depth);
                            self.esc_bracket_depth = 0;
                            if self
                                .curl_in_bracket_depth
                                .is_some_and(|d| self.bracket_depth < d)
                            {
                                self.curl_on_line = false;
                                self.curl_in_bracket_depth = None;
                                self.curl_in_quote = None;
                                self.curl_in_esc_dq = false;
                                self.curl_crossed_newline = false;
                            }
                        }
                        if self.curl_on_line && self.curl_in_bracket_depth.is_none() {
                            let after_q = &input[i + 1..];
                            let ws = af_models::secret_redaction::leading_unicode_hws_len(after_q);
                            let next_non_ws = after_q.as_bytes().get(ws).copied();
                            if self.curl_in_quote == Some(q)
                                && (self.curl_crossed_newline
                                    || next_non_ws.is_none_or(|n| {
                                        matches!(n, b',' | b'}' | b']' | b';' | b'|' | b'&' | b')')
                                    }))
                            {
                                self.curl_on_line = false;
                                self.curl_in_quote = None;
                                self.curl_in_esc_dq = false;
                                self.curl_crossed_newline = false;
                            }
                        }
                    }
                    None if !(b == b'\''
                        && af_models::secret_redaction::is_english_apostrophe_at(input, i)) =>
                    {
                        if self.curl_in_bracket_depth.is_some() {
                            let tail = &bytes[i + 1..];
                            let sep_end = if tail.starts_with(&[b'&', b'&', b])
                                || tail.starts_with(&[b'|', b'|', b])
                            {
                                Some(i + 4)
                            } else if tail.starts_with(&[b';', b]) || tail.starts_with(&[b'|', b]) {
                                Some(i + 3)
                            } else {
                                None
                            };
                            if let Some(se) = sep_end {
                                let ws = af_models::secret_redaction::leading_unicode_hws_len(
                                    &input[se..],
                                );
                                if bytes.get(se + ws) != Some(&b':') {
                                    self.curl_on_line = false;
                                    self.curl_in_bracket_depth = None;
                                    self.curl_in_quote = None;
                                    self.curl_in_esc_dq = false;
                                    self.curl_crossed_newline = false;
                                }
                            }
                        }
                        self.in_quote = Some(b);
                        self.in_esc_dq = false;
                    }
                    _ => {}
                }
                i += 1;
                continue;
            }
            if b == b'"' && trail_bs == 1 && self.in_quote == Some(b'"') {
                if !self.in_esc_dq && self.curl_in_bracket_depth.is_some() {
                    let tail = &bytes[i + 1..];
                    if tail.starts_with(b"&&\\\"")
                        || tail.starts_with(b"||\\\"")
                        || tail.starts_with(b";\\\"")
                        || tail.starts_with(b"|\\\"")
                    {
                        self.curl_on_line = false;
                        self.curl_in_bracket_depth = None;
                        self.curl_in_quote = None;
                        self.curl_in_esc_dq = false;
                        self.curl_crossed_newline = false;
                    }
                }
                if self.in_esc_dq
                    && self.curl_in_esc_dq
                    && self.curl_on_line
                    && self.curl_in_bracket_depth.is_none()
                {
                    let after_q = &input[i + 1..];
                    let ws = af_models::secret_redaction::leading_unicode_hws_len(after_q);
                    let next_non_ws = after_q.as_bytes().get(ws).copied();
                    if next_non_ws.is_some_and(|n| matches!(n, b',' | b'}' | b']')) {
                        self.curl_on_line = false;
                        self.curl_in_quote = None;
                        self.curl_in_esc_dq = false;
                        self.curl_crossed_newline = false;
                    }
                }
                self.in_esc_dq = !self.in_esc_dq;
                i += 1;
                continue;
            }
            if self.in_quote.is_none() || (self.in_quote == Some(b'"') && !self.in_esc_dq) {
                if b == b'[' {
                    self.bracket_depth += 1;
                    if self.in_quote == Some(b'"') {
                        self.esc_bracket_depth += 1;
                    }
                } else if b == b']' {
                    self.bracket_depth = self.bracket_depth.saturating_sub(1);
                    if self.in_quote == Some(b'"') {
                        self.esc_bracket_depth = self.esc_bracket_depth.saturating_sub(1);
                    }
                    if self
                        .curl_in_bracket_depth
                        .is_some_and(|d| self.bracket_depth < d)
                    {
                        self.curl_on_line = false;
                        self.curl_in_bracket_depth = None;
                        self.curl_in_quote = None;
                        self.curl_in_esc_dq = false;
                        self.curl_crossed_newline = false;
                    }
                } else if self.in_quote.is_none()
                    && (matches!(b, b';' | b'|')
                        || (b == b'}' && self.curl_in_bracket_depth.is_none())
                        || (b == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'&'))
                {
                    self.curl_on_line = false;
                    self.curl_in_bracket_depth = None;
                    self.curl_in_quote = None;
                    self.curl_in_esc_dq = false;
                    self.curl_crossed_newline = false;
                }
            }
            i += 1;
        }
        self.pos = end;
    }
}

fn decode_u_code_unit_len_local(s: &str) -> Option<(u16, usize)> {
    const MAX_U005C_CHAIN: usize = 8;
    let bytes = s.as_bytes();
    if bytes.is_empty() || !matches!(bytes[0], b'u' | b'U') {
        return None;
    }
    let mut p = 1usize;
    let mut u005c_hops = 0usize;
    loop {
        if p + 5 <= bytes.len()
            && bytes[p..p + 4].eq_ignore_ascii_case(b"005c")
            && matches!(bytes[p + 4], b'u' | b'U')
        {
            p += 5;
            continue;
        }
        if u005c_hops < MAX_U005C_CHAIN
            && p + 4 <= bytes.len()
            && bytes[p..p + 4].eq_ignore_ascii_case(b"005c")
        {
            let mut q = p + 4;
            let mut advanced = false;
            let mut inner_hops = 0usize;
            while inner_hops < MAX_U005C_CHAIN {
                let bs_start = q;
                let bs_limit = bytes.len().min(q + 32);
                while q < bs_limit && bytes[q] == b'\\' {
                    q += 1;
                }
                if q == bs_start || q + 5 > bytes.len() || !matches!(bytes[q], b'u' | b'U') {
                    break;
                }
                if bytes[q + 1..q + 5].eq_ignore_ascii_case(b"005c") {
                    q += 5;
                    inner_hops += 1;
                    continue;
                }
                if bytes[q + 1..q + 5].eq_ignore_ascii_case(b"0075")
                    || bytes[q + 1..q + 5].eq_ignore_ascii_case(b"0055")
                {
                    p = q + 5;
                    u005c_hops += 1;
                    advanced = true;
                }
                break;
            }
            if advanced {
                continue;
            }
        }
        break;
    }
    if p + 4 > bytes.len()
        || !bytes[p].is_ascii_hexdigit()
        || !bytes[p + 1].is_ascii_hexdigit()
        || !bytes[p + 2].is_ascii_hexdigit()
        || !bytes[p + 3].is_ascii_hexdigit()
    {
        return None;
    }
    let cp = u16::from_str_radix(&s[p..p + 4], 16).ok()?;
    Some((cp, p + 4))
}

#[inline]
fn is_exempt_cert_prefix(user: &str) -> bool {
    let trimmed = user.trim_matches(|c| c == '"' || c == '\'');
    let cleaned: std::borrow::Cow<'_, str> = if trimmed.contains(['"', '\'']) {
        std::borrow::Cow::Owned(trimmed.replace(['"', '\''], ""))
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    };
    matches!(
        cleaned.to_ascii_lowercase().as_str(),
        "system" | "urn" | "arn" | "http" | "https" | "ssh" | "ftp" | "file"
    )
}

#[inline]
fn bytes_after_colon_starts_url_slashes(rest: &[u8]) -> bool {
    let stripped = rest
        .iter()
        .position(|&b| !matches!(b, b'"' | b'\''))
        .map_or(&[][..], |pos| &rest[pos..]);
    stripped.starts_with(b"//")
}

#[inline]
fn is_redacted_marker_prefix(s: &str) -> bool {
    s.starts_with("[REDACTED]")
        || s.get(.."[REDACTED_URL]".len())
            .is_some_and(|p| p.eq_ignore_ascii_case("[REDACTED_URL]"))
}

/// Strictly bounded cert-passphrase precheck mirroring `secret_redaction.rs`'s
/// `bare_attached_curl_has_cred_shape_ext(..., is_cert = true)`. Rejects `{`/`[`,
/// exempt URL prefixes (`http://...`), and Windows drive letters (`C:\...`) in O(token)
/// without ever entering `consume_balanced_container` or setting a fail-open watermark.
fn bare_cert_arg_has_passphrase_shape(
    value: &str,
    quote_stack: &af_release::lifecycle::QuoteStack,
    allow_multiline_quote: bool,
) -> Result<(), usize> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(0);
    }
    let mut start_off = 0usize;
    loop {
        if start_off >= bytes.len() {
            return Err(start_off);
        }
        if bytes[start_off] != b'\\' {
            break;
        }
        let bs = bytes[start_off..]
            .iter()
            .take_while(|&&b| b == b'\\')
            .count();
        if bs % 2 == 1 {
            if let Some(&nc @ (b'\r' | b'\n')) = bytes.get(start_off + bs) {
                let nl_len = if nc == b'\r' && bytes.get(start_off + bs + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                let mut next_i = start_off + bs + nl_len;
                while next_i < bytes.len() && matches!(bytes[next_i], b' ' | b'\t') {
                    next_i += 1;
                }
                if next_i >= bytes.len() || matches!(bytes[next_i], b'\r' | b'\n') {
                    return Err(next_i);
                }
                start_off = next_i;
                continue;
            }
            if quote_stack.contains(b'"', 0)
                && matches!(bytes.get(start_off + bs), Some(b'n' | b'r' | b't' | b'f'))
            {
                let mut next_i = start_off + bs + 1;
                while next_i < bytes.len() {
                    if matches!(bytes[next_i], b' ' | b'\t') {
                        next_i += 1;
                    } else if bytes[next_i] == b'\\'
                        && matches!(bytes.get(next_i + 1), Some(b'n' | b'r' | b't' | b'f'))
                    {
                        next_i += 2;
                    } else {
                        break;
                    }
                }
                if next_i >= bytes.len() || matches!(bytes[next_i], b'\r' | b'\n') {
                    return Err(next_i);
                }
                start_off = next_i;
                continue;
            }
        }
        break;
    }
    if is_redacted_marker_prefix(&value[start_off..]) {
        return Err(start_off
            + if value[start_off..].starts_with("[REDACTED]") {
                "[REDACTED]".len()
            } else {
                "[REDACTED_URL]".len()
            });
    }
    if matches!(bytes[start_off], b'{' | b'[') {
        return Err(start_off + 1);
    }
    let mut cert_buf = [0u8; 16];
    let mut cert_clean_len = 0usize;
    let mut cert_len = 0usize;
    let mut skipped_win_drive = false;
    let check_cert_colon = |colon_after: usize,
                            cert_buf: &[u8; 16],
                            cert_clean_len: usize,
                            cert_len: usize,
                            skipped_win_drive: &mut bool,
                            in_q: Option<u8>|
     -> Option<Result<(), usize>> {
        if !*skipped_win_drive
            && cert_clean_len == 1
            && cert_buf[0].is_ascii_alphabetic()
            && matches!(bytes.get(colon_after), Some(b'\\' | b'/'))
        {
            *skipped_win_drive = true;
            return None;
        }
        let cert_ok = cert_len > 0
            && !(cert_clean_len <= cert_buf.len()
                && std::str::from_utf8(&cert_buf[..cert_clean_len])
                    .ok()
                    .is_some_and(is_exempt_cert_prefix));
        let after_c = &bytes[colon_after..];
        let pass_ok = !bytes_after_colon_starts_url_slashes(after_c)
            && match after_c.first().copied() {
                None => false,
                Some(n) if Some(n) == in_q => false,
                Some(n)
                    if in_q.is_none()
                        && (n == b'\r'
                            || n == b'\n'
                            || n.is_ascii_whitespace()
                            || matches!(n, b';' | b',' | b'}' | b']' | b')' | b'&')) =>
                {
                    false
                }
                Some(n @ (b'"' | b'\'')) => {
                    !af_release::lifecycle::quote_closes_enclosing_in_context(
                        bytes,
                        colon_after,
                        n,
                        0,
                        None,
                        quote_stack,
                        false,
                    )
                }
                Some(_) => true,
            };
        if cert_ok && pass_ok {
            Some(Ok(()))
        } else {
            Some(Err(colon_after))
        }
    };
    let mut i = start_off;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b':' {
            if let Some(res) = check_cert_colon(
                i + 1,
                &cert_buf,
                cert_clean_len,
                cert_len,
                &mut skipped_win_drive,
                None,
            ) {
                return res;
            }
            if cert_clean_len < cert_buf.len() {
                cert_buf[cert_clean_len] = b':';
            }
            cert_clean_len += 1;
            cert_len += 1;
            i += 1;
            continue;
        }
        if c == b'\r'
            || c == b'\n'
            || c.is_ascii_whitespace()
            || starts_with_unicode_ws(&bytes[i..])
            || matches!(c, b'{' | b'[' | b';' | b',' | b'}' | b']' | b')' | b'&')
        {
            return Err(i);
        }
        let mut ansi_c = false;
        if c == b'$' {
            if let Some((q_idx, q_bs)) =
                af_release::lifecycle::is_ansi_c_quote_opener_in_context(bytes, i, quote_stack)
            {
                if q_bs == 0 {
                    ansi_c = true;
                    i = q_idx;
                } else {
                    i += 1;
                    continue;
                }
            }
        }
        let c = bytes[i];
        if matches!(c, b'"' | b'\'') {
            if !ansi_c
                && af_release::lifecycle::quote_closes_enclosing_in_context(
                    bytes,
                    i,
                    c,
                    0,
                    None,
                    quote_stack,
                    i == start_off,
                )
            {
                return Err(i);
            }
            let q = c;
            i += 1;
            let mut inner_bs = 0usize;
            let mut closed = false;
            let mut crossed_newline = false;
            while i < bytes.len() {
                let ch = bytes[i];
                if ch == b'\r' || ch == b'\n' {
                    if !allow_multiline_quote {
                        return Err(i);
                    }
                    crossed_newline = true;
                    inner_bs = 0;
                    cert_clean_len += 1;
                    cert_len += 1;
                    i += 1;
                    continue;
                }
                if ch == b'\\' {
                    if inner_bs == 0 {
                        let mut be = i + 1;
                        while be < bytes.len() && bytes[be] == b'\\' {
                            be += 1;
                        }
                        if let Some((0x003A, tok_len)) = decode_u_code_unit_len_local(&value[be..])
                        {
                            if let Some(res) = check_cert_colon(
                                be + tok_len,
                                &cert_buf,
                                cert_clean_len,
                                cert_len,
                                &mut skipped_win_drive,
                                Some(q),
                            ) {
                                return res;
                            }
                            cert_clean_len += 1;
                            cert_len += 1;
                            i = be + tok_len;
                            continue;
                        }
                    }
                    inner_bs += 1;
                    i += 1;
                    continue;
                }
                if ch == q && inner_bs.is_multiple_of(2) {
                    i += 1;
                    closed = true;
                    break;
                }
                if !crossed_newline
                    && matches!(ch, b'"' | b'\'')
                    && ch != q
                    && af_release::lifecycle::enclosing_cross_quote_closes_outer(
                        bytes,
                        i,
                        q,
                        ch,
                        inner_bs,
                        quote_stack,
                    )
                {
                    return Err(i);
                }
                if ch == b':' {
                    if let Some(res) = check_cert_colon(
                        i + 1,
                        &cert_buf,
                        cert_clean_len,
                        cert_len,
                        &mut skipped_win_drive,
                        Some(q),
                    ) {
                        return res;
                    }
                }
                let w = utf8_char_width_at(value, i);
                if w == 1 && !matches!(ch, b'"' | b'\'') {
                    if cert_clean_len < cert_buf.len() {
                        cert_buf[cert_clean_len] = ch;
                    }
                    cert_clean_len += 1;
                } else if w > 1 {
                    cert_clean_len += w;
                }
                cert_len += w;
                inner_bs = 0;
                i += w;
            }
            if !closed {
                return Err(i);
            }
            continue;
        }
        if c == b'\\' {
            let bs = bytes[i..].iter().take_while(|&&b| b == b'\\').count();
            if let Some((0x003A, tok_len)) = decode_u_code_unit_len_local(&value[i + bs..]) {
                let after_u = i + bs + tok_len;
                if let Some(res) = check_cert_colon(
                    after_u,
                    &cert_buf,
                    cert_clean_len,
                    cert_len,
                    &mut skipped_win_drive,
                    None,
                ) {
                    return res;
                }
                cert_clean_len += 1;
                cert_len += 1;
                i = after_u;
                continue;
            }
            if let Some((q_kind, obs, od, osep_raw, u_end)) =
                af_models::secret_redaction::diag_parse_u_composite_any_quote_at(bytes, i)
            {
                let osep = if osep_raw.is_multiple_of(2) {
                    0
                } else {
                    osep_raw
                };
                let u_pass_closes_immediately = |colon_after: usize| -> bool {
                    let after = &bytes[colon_after..];
                    let ws = after
                        .iter()
                        .take_while(|&&n| matches!(n, b' ' | b'\t' | b'\r' | b'\n'))
                        .count();
                    let tail = &after[ws..];
                    tail.is_empty()
                        || af_models::secret_redaction::diag_parse_u_composite_any_quote_at(tail, 0)
                            .is_some_and(|(ck, cbs, cd, csep_raw, _)| {
                                let csep = if csep_raw.is_multiple_of(2) {
                                    0
                                } else {
                                    csep_raw
                                };
                                ck == q_kind && cbs == obs && cd == od && csep == osep
                            })
                };
                let mut k = u_end;
                let mut sep_run = 0usize;
                let mut crossed_newline = false;
                while k < bytes.len() {
                    let cb = bytes[k];
                    if cb == b'\r' || cb == b'\n' {
                        if !allow_multiline_quote {
                            return Err(k);
                        }
                        crossed_newline = true;
                        sep_run = 0;
                        cert_clean_len += 1;
                        cert_len += 1;
                        k += 1;
                        continue;
                    }
                    if !crossed_newline
                        && cb == b'"'
                        && quote_stack.contains(b'"', 0)
                        && af_release::lifecycle::quote_closes_enclosing(bytes, k)
                    {
                        return Err(k);
                    }
                    if cb == b':' {
                        if !u_pass_closes_immediately(k + 1) {
                            if let Some(res) = check_cert_colon(
                                k + 1,
                                &cert_buf,
                                cert_clean_len,
                                cert_len,
                                &mut skipped_win_drive,
                                Some(q_kind),
                            ) {
                                return res;
                            }
                        } else if !(!skipped_win_drive
                            && cert_clean_len == 1
                            && cert_buf[0].is_ascii_alphabetic()
                            && matches!(bytes.get(k + 1), Some(b'\\' | b'/')))
                        {
                            return Err(k + 1);
                        } else {
                            skipped_win_drive = true;
                        }
                        cert_clean_len += 1;
                        cert_len += 1;
                        sep_run = 0;
                        k += 1;
                        continue;
                    }
                    if cb == b'\\' {
                        if let Some((cbs, cd, kind, cend)) =
                            af_models::secret_redaction::diag_parse_u_quote_or_apos_token_at(
                                bytes, k,
                            )
                        {
                            if kind == b'\\' {
                                if cbs == obs && cd == od {
                                    sep_run += 1;
                                } else {
                                    sep_run = 0;
                                }
                                k = cend;
                                continue;
                            }
                            if kind == q_kind
                                && cbs == obs
                                && cd == od
                                && af_release::lifecycle::QuoteStack::matches_open_depth(
                                    osep, sep_run,
                                )
                            {
                                k = cend;
                                break;
                            }
                            sep_run = 0;
                            k = cend;
                            continue;
                        }
                        let mut be = k + 1;
                        while be < bytes.len() && bytes[be] == b'\\' {
                            be += 1;
                        }
                        if let Some((0x003A, tok_len)) = decode_u_code_unit_len_local(&value[be..])
                        {
                            if !u_pass_closes_immediately(be + tok_len) {
                                if let Some(res) = check_cert_colon(
                                    be + tok_len,
                                    &cert_buf,
                                    cert_clean_len,
                                    cert_len,
                                    &mut skipped_win_drive,
                                    Some(q_kind),
                                ) {
                                    return res;
                                }
                            } else {
                                return Err(be + tok_len);
                            }
                            cert_clean_len += 1;
                            cert_len += 1;
                            sep_run = 0;
                            k = be + tok_len;
                            continue;
                        }
                        sep_run = 0;
                        k = be;
                        continue;
                    }
                    sep_run = 0;
                    let w = utf8_char_width_at(value, k);
                    if w == 1 && !matches!(cb, b'"' | b'\'') {
                        if cert_clean_len < cert_buf.len() {
                            cert_buf[cert_clean_len] = cb;
                        }
                        cert_clean_len += 1;
                    } else if w > 1 {
                        cert_clean_len += w;
                    }
                    cert_len += w;
                    k += w;
                }
                i = k;
                continue;
            }
            if let Some(&q @ (b'"' | b'\'')) = bytes.get(i + bs) {
                let q_pos = i + bs;
                let open_depth = if bs.is_multiple_of(2) { 0 } else { bs };
                if af_release::lifecycle::quote_closes_enclosing_in_context(
                    bytes,
                    q_pos,
                    q,
                    open_depth,
                    None,
                    quote_stack,
                    i == start_off,
                ) {
                    return Err(q_pos);
                }
                let mut k = q_pos + 1;
                let mut ibs = 0usize;
                let mut closed = false;
                let mut crossed_newline = false;
                while k < bytes.len() {
                    let cb = bytes[k];
                    if cb == b'\r' || cb == b'\n' {
                        if !allow_multiline_quote {
                            return Err(k);
                        }
                        crossed_newline = true;
                        ibs = 0;
                        cert_clean_len += 1;
                        cert_len += 1;
                        k += 1;
                        continue;
                    }
                    if cb == b'\\' {
                        if ibs == 0 {
                            let mut be = k + 1;
                            while be < bytes.len() && bytes[be] == b'\\' {
                                be += 1;
                            }
                            if let Some((0x003A, tok_len)) =
                                decode_u_code_unit_len_local(&value[be..])
                            {
                                if let Some(res) = check_cert_colon(
                                    be + tok_len,
                                    &cert_buf,
                                    cert_clean_len,
                                    cert_len,
                                    &mut skipped_win_drive,
                                    Some(q),
                                ) {
                                    return res;
                                }
                                cert_clean_len += 1;
                                cert_len += 1;
                                k = be + tok_len;
                                continue;
                            }
                        }
                        ibs += 1;
                        k += 1;
                        continue;
                    }
                    if cb == q
                        && af_release::lifecycle::QuoteStack::matches_open_depth(open_depth, ibs)
                    {
                        k += 1;
                        closed = true;
                        break;
                    }
                    if !crossed_newline
                        && open_depth > 0
                        && cb == b'"'
                        && ibs.is_multiple_of(2)
                        && quote_stack.contains(b'"', 0)
                        && af_release::lifecycle::quote_closes_enclosing(bytes, k)
                    {
                        return Err(k);
                    }
                    if cb == b':' {
                        if let Some(res) = check_cert_colon(
                            k + 1,
                            &cert_buf,
                            cert_clean_len,
                            cert_len,
                            &mut skipped_win_drive,
                            Some(q),
                        ) {
                            return res;
                        }
                    }
                    let w = utf8_char_width_at(value, k);
                    if w == 1 && !matches!(cb, b'"' | b'\'') {
                        if cert_clean_len < cert_buf.len() {
                            cert_buf[cert_clean_len] = cb;
                        }
                        cert_clean_len += 1;
                    } else if w > 1 {
                        cert_clean_len += w;
                    }
                    cert_len += w;
                    ibs = 0;
                    k += w;
                }
                if !closed {
                    return Err(k);
                }
                i = k;
                continue;
            }
            if bs % 2 == 1 {
                if let Some(&nc @ (b'\r' | b'\n')) = bytes.get(i + bs) {
                    let nl_len = if nc == b'\r' && bytes.get(i + bs + 1) == Some(&b'\n') {
                        2
                    } else {
                        1
                    };
                    let next_i = i + bs + nl_len;
                    if next_i < bytes.len() && !matches!(bytes[next_i], b'\r' | b'\n') {
                        i = next_i;
                        continue;
                    }
                    return Err(next_i);
                }
                if quote_stack.contains(b'"', 0)
                    && matches!(bytes.get(i + bs), Some(b'n' | b'r' | b't' | b'f' | b'b'))
                {
                    if matches!(bytes.get(i + bs), Some(b'n' | b'r'))
                        && bs >= 3
                        && (bs - 1) % 4 == 2
                    {
                        let mut next_i = i + bs + 1;
                        if bytes.get(i + bs) == Some(&b'r')
                            && bytes.get(next_i) == Some(&b'\\')
                            && bytes.get(next_i + 1) == Some(&b'n')
                        {
                            next_i += 2;
                        }
                        if next_i < bytes.len() && !matches!(bytes[next_i], b'\r' | b'\n') {
                            i = next_i;
                            continue;
                        }
                    }
                    return Err(i + bs + 1);
                }
            }
            i += bs;
            if i < bytes.len()
                && bytes[i] != b'\r'
                && bytes[i] != b'\n'
                && !(bs.is_multiple_of(2) && bytes[i] == b':')
            {
                let w = utf8_char_width_at(value, i);
                if w == 1 {
                    if cert_clean_len < cert_buf.len() {
                        cert_buf[cert_clean_len] = bytes[i];
                    }
                    cert_clean_len += 1;
                } else {
                    cert_clean_len += w;
                }
                cert_len += w;
                i += w;
            }
            continue;
        }
        let w = utf8_char_width_at(value, i);
        if w == 1 {
            if cert_clean_len < cert_buf.len() {
                cert_buf[cert_clean_len] = c;
            }
            cert_clean_len += 1;
        } else {
            cert_clean_len += w;
        }
        cert_len += w;
        i += w;
    }
    Err(bytes.len())
}

fn split_curl_flag_and_sep(flag_part: &str) -> (&str, bool, Option<usize>) {
    let mut end = flag_part.len();
    let mut first_json_esc: Option<usize> = None;
    loop {
        let cur = &flag_part[..end];
        let trimmed = cur.trim_end_matches(|c: char| c.is_whitespace() || c == '=');
        end = trimmed.len();
        if let Some(stripped) = trimmed.strip_suffix("\\t") {
            end = stripped.len();
        } else if let Some(stripped) = trimmed
            .strip_suffix("\\f")
            .or_else(|| trimmed.strip_suffix("\\n"))
            .or_else(|| trimmed.strip_suffix("\\r"))
        {
            first_json_esc = Some(stripped.len());
            end = stripped.len();
        } else {
            break;
        }
    }
    (&flag_part[..end], end < flag_part.len(), first_json_esc)
}

fn redact_curl_prefix_secrets<'a>(text: &'a str) -> std::borrow::Cow<'a, str> {
    if !text.as_bytes().contains(&b'-') {
        return std::borrow::Cow::Borrowed(text);
    }
    static CURL_PREFIX_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)(?:(?:\\[bfnrt]|\\+[uU](?:005[cC](?:(?:\\+[uU]005[cC])*\\+[uU]00(?:75|55)|[uU]))*00(?:22|2[fF]|5[cC])|\b)curl\b|(?:^|[\s\x08"';&|(:=]|[^\x00-\x7F\p{Alphabetic}\p{N}]|\\[bfnrt])(?:(?:--user|--proxy-user)(?:(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])+|=(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*(?:\r?\n[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]*)?)|(?:--cert|--proxy-cert)(?:(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])+(?:(?:\r\n?|\n|(?:\\r)?\\n|\\r)(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*)?|(?:(?:\r\n?|\n|(?:\\r)?\\n|\\r)(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*)|=(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*(?:(?:\r\n?|\n|(?:\\r)?\\n|\\r)(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*)?)|-u(?:(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])+|=(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*(?:\r?\n[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]*)?)|(?-i:-[sSfLkivV460123gGNnqOjJlBpRaZI#]*?[uUb])(?:(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])+|=(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*(?:\r?\n[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]*)?)?|(?-i:-[sSfLkivV460123gGNnqOjJlBpRaZI#]*?E)(?:(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])+(?:(?:\r\n?|\n|(?:\\r)?\\n|\\r)(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*)?|(?:(?:\r\n?|\n|(?:\\r)?\\n|\\r)(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*)|=(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*(?:(?:\r\n?|\n|(?:\\r)?\\n|\\r)(?:[ \t\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]|\\[tf])*)?)?))"#,
        )
        .unwrap()
    });
    let Some(first_mat) = CURL_PREFIX_RE.find_at(text, 0) else {
        return std::borrow::Cow::Borrowed(text);
    };
    let mut out: Option<String> = None;
    let mut emit_cursor = 0usize;
    let mut cursor = 0usize;
    let mut curl_tracker = CurlCmdTracker::default();
    let mut no_colon_until = 0usize;
    let mut reject_scan_bytes = 0usize;
    let reject_scan_budget = text.len().saturating_mul(4).max(4096);
    let mut has_cert_colon: Option<bool> = None;
    let mut quote_stack = af_release::lifecycle::QuoteStack::default();
    let mut next_mat = Some(first_mat);
    while cursor < text.len() {
        let mat = if let Some(m) = next_mat.take() {
            m
        } else {
            let Some(m) = CURL_PREFIX_RE.find_at(text, cursor) else {
                break;
            };
            m
        };
        if mat.end() <= cursor {
            let ch = text[cursor..].chars().next().unwrap();
            cursor += ch.len_utf8();
            continue;
        }
        let mut raw_mat = mat.as_str();
        if raw_mat.starts_with('\\')
            && matches!(
                raw_mat.as_bytes().get(1),
                Some(b't' | b'n' | b'r' | b'f' | b'b')
            )
        {
            let bs_before = text[..mat.start() + 1]
                .bytes()
                .rev()
                .take_while(|&b| b == b'\\')
                .count();
            quote_stack.advance_to(text, mat.start());
            if bs_before.is_multiple_of(2) || !quote_stack.contains(b'"', 0) {
                cursor = mat.start() + 2;
                continue;
            }
        }
        if raw_mat.len() >= 4
            && raw_mat.as_bytes()[raw_mat.len() - 4..].eq_ignore_ascii_case(b"curl")
        {
            curl_tracker.advance_to(text, mat.end());
            curl_tracker.mark_curl();
            cursor = mat.end();
            continue;
        }
        let dash = raw_mat
            .as_bytes()
            .iter()
            .position(|&b| b == b'-')
            .unwrap_or(0);
        curl_tracker.advance_to(text, mat.start() + dash);
        let flag_part = &raw_mat[dash..];
        let (flag_word, mut has_sep, first_json_esc) = split_curl_flag_and_sep(flag_part);
        let mut value_off = mat.end();
        quote_stack.advance_to(text, mat.start() + dash);
        if let Some(esc_rel) = first_json_esc {
            if !quote_stack.contains(b'"', 0) {
                if esc_rel > flag_word.len() {
                    value_off = mat.start() + dash + esc_rel;
                    raw_mat = &text[mat.start()..value_off];
                } else if flag_word.starts_with("--") {
                    cursor = value_off;
                    continue;
                } else {
                    value_off = mat.start() + dash + esc_rel;
                    raw_mat = &text[mat.start()..value_off];
                    has_sep = false;
                }
            }
        }
        let is_user = has_sep
            && (flag_word.eq_ignore_ascii_case("--user")
                || flag_word.eq_ignore_ascii_case("--proxy-user")
                || flag_word.eq_ignore_ascii_case("-u"));
        let is_cert_long = has_sep
            && (flag_word.eq_ignore_ascii_case("--cert")
                || flag_word.eq_ignore_ascii_case("--proxy-cert"));
        let is_curl_short_secret = curl_tracker.curl_on_line
            && flag_word.starts_with('-')
            && !flag_word.starts_with("--")
            && af_models::secret_redaction::is_curl_short_secret_flag_body(&flag_word[1..]);
        let is_curl_short_cert = curl_tracker.curl_on_line
            && flag_word.starts_with('-')
            && !flag_word.starts_with("--")
            && af_models::secret_redaction::is_curl_short_cert_flag_body(&flag_word[1..]);
        let is_cert = is_cert_long || is_curl_short_cert;
        if !is_user && !is_curl_short_secret && !is_cert {
            let trimmed_len = dash + flag_word.len();
            cursor = (mat.start() + trimmed_len).max(mat.start() + 1);
            continue;
        }
        let unclosed_prefix = if raw_mat.starts_with(['"', '\'']) {
            let lead_bs = text[..mat.start()]
                .bytes()
                .rev()
                .take_while(|&b| b == b'\\')
                .count();
            &text[mat.start() - lead_bs..value_off]
        } else {
            raw_mat
        };
        quote_stack.advance_to(text, value_off);
        let rest_after_prefix = &text[value_off..];
        if !has_sep {
            let raw_bs = unclosed_prefix.bytes().take_while(|&b| b == b'\\').count();
            if let Some(q @ (b'"' | b'\'')) = unclosed_prefix.as_bytes().get(raw_bs).copied() {
                let open_bs = if raw_bs.is_multiple_of(2) { 0 } else { raw_bs };
                let vbytes = rest_after_prefix.as_bytes();
                let close_bs = vbytes.iter().take_while(|&&b| b == b'\\').count();
                if vbytes.get(close_bs) == Some(&q)
                    && af_release::lifecycle::QuoteStack::matches_open_depth(open_bs, close_bs)
                {
                    cursor = value_off;
                    continue;
                }
            }
        }
        if is_cert {
            let has_colon = *has_cert_colon.get_or_insert_with(|| {
                text.as_bytes().contains(&b':') || text.contains("\\u") || text.contains("\\U")
            });
            if !has_colon {
                cursor = value_off;
                continue;
            }
            let starts_bare = match rest_after_prefix.as_bytes().first().copied() {
                Some(b) if !matches!(b, b'"' | b'\'' | b'\\' | b'$') => {
                    !is_redacted_marker_prefix(rest_after_prefix)
                }
                Some(b'\\') => {
                    let bs = rest_after_prefix
                        .bytes()
                        .take_while(|&b| b == b'\\')
                        .count();
                    !matches!(
                        rest_after_prefix.as_bytes().get(bs),
                        None | Some(
                            b'"' | b'\''
                                | b'u'
                                | b'U'
                                | b'\r'
                                | b'\n'
                                | b'n'
                                | b'r'
                                | b't'
                                | b'f'
                                | b'b'
                        )
                    )
                }
                _ => false,
            };
            if (starts_bare || no_colon_until >= text.len()) && value_off < no_colon_until {
                cursor = value_off;
                continue;
            }
            if let Err(stop_off) = bare_cert_arg_has_passphrase_shape(
                rest_after_prefix,
                &quote_stack,
                reject_scan_bytes < reject_scan_budget,
            ) {
                reject_scan_bytes = reject_scan_bytes.saturating_add(stop_off.max(1));
                let scanned = &rest_after_prefix[..stop_off];
                let safe_scan = scanned.strip_suffix(':').unwrap_or(scanned);
                if !safe_scan.contains(':')
                    && !safe_scan.contains("003a")
                    && !safe_scan.contains("003A")
                {
                    no_colon_until = no_colon_until.max(value_off + safe_scan.len());
                }
                cursor = value_off;
                continue;
            }
        }
        if has_sep
            && !is_cert
            && af_release::lifecycle::parse_leading_auth_scheme(rest_after_prefix).is_some()
        {
            cursor = value_off;
            continue;
        }
        let base_n = match consume_secret_scalar_value_ext(
            rest_after_prefix,
            true,
            &quote_stack,
            !is_cert,
        ) {
            Ok(n) => n,
            Err(eol) => {
                cursor = value_off + eol;
                continue;
            }
        };
        let n = af_release::lifecycle::unclosed_prefix_quote_span(
            unclosed_prefix,
            rest_after_prefix,
            base_n,
            &quote_stack,
        );
        if n == 0 {
            cursor = value_off;
            continue;
        }
        let consumed = &text[value_off..value_off + n];
        if is_cert && !af_models::secret_redaction::curl_cert_arg_has_passphrase(consumed) {
            reject_scan_bytes = reject_scan_bytes.saturating_add(base_n.max(1));
            if !consumed.contains(':') && !consumed.contains("003a") && !consumed.contains("003A") {
                no_colon_until = no_colon_until.max(value_off + base_n);
            }
            cursor = value_off;
            continue;
        }
        let replacement =
            af_release::lifecycle::replacement_for_lifecycle_scalar(raw_mat, consumed);
        if replacement != consumed {
            let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
            buf.push_str(&text[emit_cursor..value_off]);
            buf.push_str(&replacement);
            emit_cursor = value_off + n;
        }
        cursor = value_off + n;
    }
    match out {
        Some(mut buf) => {
            buf.push_str(&text[emit_cursor..]);
            std::borrow::Cow::Owned(buf)
        }
        None => std::borrow::Cow::Borrowed(text),
    }
}

fn redact_scalar_cli_and_curl_secrets<'a>(text: &'a str) -> std::borrow::Cow<'a, str> {
    let mut cur = redact_curl_prefix_secrets(text);
    if let std::borrow::Cow::Owned(next) = redact_prefixed_secrets(
        &cur,
        &af_release::lifecycle::SENSITIVE_ASSIGNMENT_PREFIX_RE,
        true,
    ) {
        cur = std::borrow::Cow::Owned(next);
    }
    if cur.contains("--") {
        if let std::borrow::Cow::Owned(next) = redact_prefixed_secrets(
            &cur,
            &af_release::lifecycle::SENSITIVE_CLI_FLAG_PREFIX_RE,
            true,
        ) {
            cur = std::borrow::Cow::Owned(next);
        }
    }
    cur
}

/// Locate the byte offset of the opening `{` or `[` of a balanced container at the end of `raw`
/// matched by `SENSITIVE_JSON_NESTED_RE` or `SENSITIVE_RAW_NESTED_RE`. Strictly O(val.len()).
fn find_trailing_balanced_container_start(raw: &str) -> usize {
    let bytes = raw.as_bytes();
    let Some(&close) = bytes.last() else {
        return raw.len();
    };
    let open = match close {
        b'}' => b'{',
        b']' => b'[',
        _ => return raw.len(),
    };
    let mut depth = 0usize;
    let mut idx = bytes.len();
    while idx > 0 {
        idx -= 1;
        let b = bytes[idx];
        if b == close {
            depth += 1;
        } else if b == open {
            depth -= 1;
            if depth == 0 {
                return idx;
            }
        }
    }
    raw.len()
}

/// Strip the `(?:^|[^\\])(?:\\\\)*` opening-quote guard from a `SENSITIVE_JSON_NESTED_RE` prefix
/// (`raw_prefix` ends with `"\s*:\s*`). Strictly O(1).
fn strip_nested_json_guard(raw_prefix: &str) -> usize {
    let bytes = raw_prefix.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    if bytes[0] == b'\\' {
        let lead_bs = bytes.iter().take_while(|&&b| b == b'\\').count();
        if lead_bs.is_multiple_of(2) && bytes.get(lead_bs) == Some(&b'"') {
            return lead_bs;
        }
        return 0;
    }
    if bytes[0] == b'"' {
        let after = &bytes[1..];
        let bs = after.iter().take_while(|&&b| b == b'\\').count();
        if bs.is_multiple_of(2) && after.get(bs) == Some(&b'"') {
            return 1 + bs;
        }
        return 0;
    }
    let ch_len = utf8_char_width_at(raw_prefix, 0);
    let after = &bytes[ch_len..];
    let bs = after.iter().take_while(|&&b| b == b'\\').count();
    if bs.is_multiple_of(2) && after.get(bs) == Some(&b'"') {
        return ch_len + bs;
    }
    0
}

fn sanitize_nested(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.as_bytes().iter().any(|&b| b == b'{' || b == b'[') {
        return std::borrow::Cow::Borrowed(text);
    }
    const QUOTED_SENSITIVE_OR_CAPS_KEY_CORE: &str = r"(?:[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|client[_-]?secret|authorization|auth[_-]?(?:token|key|secret)|credentials?|bearer|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|jwt[_-]?secret)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9]*[_.-])*(?:pass|auth)(?:[_.-][A-Za-z0-9]*)*|(?-i:(?:[A-Za-z0-9_.-]*[.-])?(?:[A-Z0-9]*_)*KEY(?:_[A-Z0-9]*)*(?:[.-][A-Za-z0-9_.-]*)?))";
    static SENSITIVE_JSON_NESTED_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| {
            regex::Regex::new(
                &[
                    r#"(?i)(?:^|[^\\])(?:\\\\)*"(?:(?:[^"\\\r\n]|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*(?:[^A-Za-z0-9"\\\r\n]|\\(?:["\\/bfnrt]|u(?:00(?:[012][0-9A-Fa-f]|3[a-fA-F]|40|5[b-fB-F]|60|7[b-fB-F]|85|[aA]0)|1680|20(?:0[0-9A-Fa-f]|2[89fF]|5[fF])|3000|[dD][89a-fA-F][0-9A-Fa-f]{2}))))?"#,
                    QUOTED_SENSITIVE_OR_CAPS_KEY_CORE,
                    r#"(?:(?:[^A-Za-z0-9"\\\r\n]|\\(?:["\\/bfnrt]|u(?:00(?:[012][0-9A-Fa-f]|3[a-fA-F]|40|5[b-fB-F]|60|7[b-fB-F]|85|[aA]0)|1680|20(?:0[0-9A-Fa-f]|2[89fF]|5[fF])|3000|[dD][89a-fA-F][0-9A-Fa-f]{2})))(?:[^"\\\r\n]|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*)?"\s*:\s*(?:\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\])"#,
                ]
                .concat(),
            )
            .unwrap()
        });
    static SENSITIVE_RAW_NESTED_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| {
            regex::Regex::new(
                &[
                    r#"(?i)(?:""#,
                    af_release::lifecycle::SENSITIVE_DIAGNOSTIC_OR_CAPS_KEY_PATTERN,
                    r#""\s*[:=]\s*|'"#,
                    af_release::lifecycle::SENSITIVE_DIAGNOSTIC_OR_CAPS_KEY_PATTERN,
                    r#"'\s*[:=]\s*|"#,
                    af_release::lifecycle::SENSITIVE_DIAGNOSTIC_OR_CAPS_KEY_PATTERN,
                    r#"\s*[:=]\s*)(?:\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\])"#,
                ]
                .concat(),
            )
            .unwrap()
        });

    let mut cur = if let Some(first_mat) = SENSITIVE_JSON_NESTED_RE.find_at(text, 0) {
        let mut out: Option<String> = None;
        let mut emit_cursor = 0usize;
        let mut cursor = 0usize;
        let mut next_mat = Some(first_mat);
        while cursor < text.len() {
            let mat = if let Some(m) = next_mat.take() {
                m
            } else {
                let search_from =
                    if cursor >= 2 && matches!(text.as_bytes()[cursor - 1], b'}' | b']') {
                        cursor - 1
                    } else {
                        cursor
                    };
                let Some(m) = SENSITIVE_JSON_NESTED_RE.find_at(text, search_from) else {
                    break;
                };
                m
            };
            let raw_m = mat.as_str();
            let val_rel = find_trailing_balanced_container_start(raw_m);
            let guard_off = strip_nested_json_guard(&raw_m[..val_rel]);
            let prefix_start = mat.start() + guard_off;
            let val_start = mat.start() + val_rel;
            let prefix = &text[prefix_start..val_start];
            let val = &text[val_start..mat.end()];
            let balanced_json_key = af_release::lifecycle::is_balanced_json_key_prefix(prefix);
            let scrubbed_prefix = if balanced_json_key {
                af_release::lifecycle::scrub_matched_json_key_prefix(prefix)
            } else {
                std::borrow::Cow::Borrowed(prefix)
            };
            let replacement_val = if redacted_container_value(val) {
                val
            } else if balanced_json_key {
                "\"[REDACTED]\""
            } else {
                "[REDACTED]"
            };
            if scrubbed_prefix.as_ref() != prefix || replacement_val != val {
                let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
                buf.push_str(&text[emit_cursor..prefix_start]);
                buf.push_str(&scrubbed_prefix);
                buf.push_str(replacement_val);
                emit_cursor = mat.end();
            }
            cursor = mat.end();
        }
        match out {
            Some(mut buf) => {
                buf.push_str(&text[emit_cursor..]);
                std::borrow::Cow::Owned(buf)
            }
            None => std::borrow::Cow::Borrowed(text),
        }
    } else {
        std::borrow::Cow::Borrowed(text)
    };

    if let Some(first_mat) = SENSITIVE_RAW_NESTED_RE.find_at(&cur, 0) {
        let mut out: Option<String> = None;
        let mut emit_cursor = 0usize;
        let mut cursor = 0usize;
        let mut next_mat = Some(first_mat);
        while cursor < cur.len() {
            let mat = if let Some(m) = next_mat.take() {
                m
            } else {
                let Some(m) = SENSITIVE_RAW_NESTED_RE.find_at(&cur, cursor) else {
                    break;
                };
                m
            };
            let raw_m = mat.as_str();
            let val_rel = find_trailing_balanced_container_start(raw_m);
            let val_start = mat.start() + val_rel;
            let val = &cur[val_start..mat.end()];
            if !redacted_container_value(val) {
                let buf = out.get_or_insert_with(|| String::with_capacity(cur.len()));
                buf.push_str(&cur[emit_cursor..val_start]);
                buf.push_str("[REDACTED]");
                emit_cursor = mat.end();
            }
            cursor = mat.end();
        }
        if let Some(mut buf) = out {
            buf.push_str(&cur[emit_cursor..]);
            cur = std::borrow::Cow::Owned(buf);
        }
    }
    cur
}

pub fn sanitize_lifecycle_field(raw: &str) -> String {
    let normalized = af_release::lifecycle::normalize_unicode_escaped_sensitive_keys_cow(raw);
    let with_urls = af_release::lifecycle::redact_url_credentials_cow(&normalized);
    let s_headers = af_release::lifecycle::redact_sensitive_headers_cow(&with_urls);
    let s_local = redact_scalar_cli_and_curl_secrets(&s_headers);
    let s_containers =
        af_release::lifecycle::redact_sensitive_nested_containers_quoted_cow(&s_local);
    let s_persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text_cow(&s_containers);
    let s3 = redact_scalar_cli_and_curl_secrets(&s_persisted);
    let s3_nested = sanitize_nested(&s3);
    let s4 = if matches!(s3, std::borrow::Cow::Borrowed(_))
        && matches!(s3_nested, std::borrow::Cow::Borrowed(_))
    {
        std::borrow::Cow::Borrowed(s3_nested.as_ref())
    } else {
        redact_scalar_cli_and_curl_secrets(&s3_nested)
    };
    let s5 = af_release::lifecycle::redact_auth_scheme_credentials_cow(&s4);
    let s6 = af_release::lifecycle::redact_sensitive_headers_cow(&s5);
    let s7 = af_release::lifecycle::redact_unicode_quoted_sensitive_values_cow(&s6);
    af_release::lifecycle::redact_url_credentials_cow(&s7).into_owned()
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
