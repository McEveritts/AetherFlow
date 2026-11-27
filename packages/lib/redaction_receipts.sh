# AetherFlow shared helpers: secret redaction, failure receipts, job scratch, progress, GitHub tags, and Node setup.
# Sourced by packages/common.sh; do not execute directly.

AF_CURRENT_STAGE="${AF_CURRENT_STAGE:-init}"

af_set_stage() {
    AF_CURRENT_STAGE="$1"
    report_progress "${2:-0}" "Stage: $1"
}

_af_redact_awk() {
    awk -f /dev/fd/3 3<<'AWK'
 function is_space(c) { return c == " " || c == "\t" || c == "\r" || c == "\n" }
 function is_vert(c) { return c == "\r" || c == "\n" }
 function is_ws(c) { return is_space(c) || is_vert(c) }
 function is_keychar(c) { return c ~ /[A-Za-z0-9_.-]/ }
 function is_word(c) { return c ~ /[A-Za-z0-9_]/ }
 function is_alpha(c) { return c ~ /[A-Za-z]/ }
 function lowchar(c) { return tolower(c) }

 function is_sensitive(k,    l, re) {
     l = tolower(k)
     re = "^([a-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(orization|[_-]?token|[_-]?key|[_-]?secret)?|passphrase|credentials?|bearer|cookies?|session([_-]?(id|key|token|secret))?|webhook([_-]?(url|secret|token|key))?|jwt[_-]?secret|master[_-]?pass|rclone[_-]?(rc[_-]?)?pass)[a-z0-9_.-]*|([a-z0-9]+[_.-])*(pass[0-9]*|key)([_.-][a-z0-9]+)*)$"
     return l ~ re
 }

 function is_header_name(k,    l) {
     l = tolower(k)
     return l == "authorization" || l == "proxy-authorization" || l == "cookie" || l == "set-cookie" || l == "x-api-key" || l == "x-auth-token"
 }

 function eq_ci_at(s, i, lit,    n, k) {
     n = length(lit)
     if (i < 1 || i + n - 1 > length(s)) return 0
     for (k = 1; k <= n; k++) if (lowchar(substr(s, i + k - 1, 1)) != lowchar(substr(lit, k, 1))) return 0
     return 1
 }

 function hexval(h,    i, c, v, d) {
     v = 0
     for (i = 1; i <= length(h); i++) {
         c = lowchar(substr(h, i, 1))
         if (c >= "0" && c <= "9") d = index("0123456789", c) - 1
         else if (c >= "a" && c <= "f") d = index("abcdef", c) + 9
         else return -1
         v = v * 16 + d
     }
     return v
 }

 function u00_char(h) {
     return sprintf("%c", hexval(h))
 }

 function decode_u00(raw,    i, n, out, end_escape) {
     out = ""
     i = 1
     n = length(raw)
     while (i <= n) {
         if (substr(raw, i, 1) == "\\") {
             end_escape = i
             while (end_escape <= n && substr(raw, end_escape, 1) == "\\") end_escape++
             if (substr(raw, end_escape, 3) == "u00" && substr(raw, end_escape + 3, 2) ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {
                 out = out u00_char(substr(raw, end_escape + 3, 2))
                 i = end_escape + 5
                 continue
             }
         }
         out = out substr(raw, i, 1)
         i++
     }
     return out
 }

 function scheme_before(s, colon_pos,    names, k, name, start, prev) {
     names[1] = "postgresql"
     names[2] = "mongodb"
     names[3] = "postgres"
     names[4] = "https"
     names[5] = "mysql"
     names[6] = "redis"
     names[7] = "amqp"
     names[8] = "http"
     names[9] = "ftp"
     for (k = 1; k <= 9; k++) {
         name = names[k]
         start = colon_pos - length(name)
         if (start < 1) continue
         if (!eq_ci_at(s, start, name)) continue
         if (start == 1) return 1
         prev = substr(s, start - 1, 1)
         if (!is_word(prev)) return 1
     }
     return 0
 }

 function redact_urls(s,    i, n, out, j, c, colon, at, ok, scheme_ok) {
     n = length(s)
     out = ""
     i = 1
     while (i <= n) {
         if (substr(s, i, 3) == "://") {
             j = i + 3
             colon = 0
             at = 0
             ok = 1
             while (j <= n) {
                 c = substr(s, j, 1)
                 if (c == "/" || c == "@" || is_ws(c)) {
                     if (c == "@" && colon > 0 && ok) at = j
                     break
                 }
                 if (c == ":") {
                     if (colon == 0) colon = j
                     else ok = 0
                 }
                 j++
             }
             if (at > 0 && colon > i + 3) {
                 out = out "://[REDACTED]@"
                 i = at + 1
                 continue
             }
             if (scheme_before(s, i)) {
                 j = i + 3
                 while (j <= n) {
                     c = substr(s, j, 1)
                     if (c == "/" || c == "@" || is_ws(c)) break
                     j++
                 }
                 if (j <= n && substr(s, j, 1) == "@" && j > i + 3) {
                     out = out "://[REDACTED]@"
                     i = j + 1
                     continue
                 }
             }
         }
         out = out substr(s, i, 1)
         i++
     }
     return out
 }

 function read_dquoted(s, i,    n, j, bs, ch) {
     n = length(s)
     if (substr(s, i, 1) != "\"") return 0
     j = i + 1
     bs = 0
     while (j <= n) {
         ch = substr(s, j, 1)
         if (ch == "\\") { bs++; j++; continue }
         if (ch == "\"" && bs % 2 == 0) return j + 1
         if (is_vert(ch)) return 0
         bs = 0
         j++
     }
     return 0
 }

 function read_identifier_key(s, p,    n, j, end_escape, c) {
     n = length(s)
     if (substr(s, p, 1) != "\"") return 0
     j = p + 1
     while (j <= n) {
         c = substr(s, j, 1)
         if (is_keychar(c)) { j++; continue }
         if (c == "\\") {
             end_escape = j
             while (end_escape <= n && substr(s, end_escape, 1) == "\\") end_escape++
             if (substr(s, end_escape, 3) == "u00" && substr(s, end_escape + 3, 2) ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {
                 j = end_escape + 5
                 continue
             }
         } else end_escape = j
         if (j > p + 1 && substr(s, end_escape, 1) == "\"") {
             parsed_key_body_end = j
             parsed_key = decode_u00(substr(s, p + 1, j - p - 1))
             return end_escape + 1
         }
         return 0
     }
     return 0
 }

 function normalize_sensitive_json_keys(s,    i, n, out, endq, j) {
     n = length(s)
     out = ""
     i = 1
     while (i <= n) {
         if (substr(s, i, 1) == "\"") {
             endq = read_identifier_key(s, i)
             if (endq > 0) {
                 j = endq
                 while (j <= n && is_space(substr(s, j, 1))) j++
                 if (j <= n && substr(s, j, 1) == ":" && is_sensitive(parsed_key)) {
                     out = out "\"" parsed_key substr(s, parsed_key_body_end, j - parsed_key_body_end + 1)
                     i = j + 1
                     continue
                 }
                 out = out substr(s, i, endq - i)
                 i = endq
                 continue
             }
         }
         out = out substr(s, i, 1)
         i++
     }
     return out
 }

 function header_name_len(s, p,    names, k, name) {
     names[1] = "Proxy-Authorization"
     names[2] = "Set-Cookie"
     names[3] = "X-Auth-Token"
     names[4] = "X-Api-Key"
     names[5] = "Authorization"
     names[6] = "Cookie"
     for (k = 1; k <= 6; k++) {
         name = names[k]
         if (eq_ci_at(s, p, name)) return length(name)
     }
     return 0
 }

 function boundary_before_name(s, name_at) {
     if (name_at <= 1) return 1
     return ! (substr(s, name_at - 1, 1) ~ /[A-Za-z0-9_-]/)
 }

 function header_match_at(s, p,    n, pre_len, name_at, hlen, j, c, bs) {
     n = length(s)
     pre_len = 0
     name_at = p
     if (substr(s, p, 1) == "\\") {
         bs = 0
         j = p
         while (j <= n && substr(s, j, 1) == "\\") { bs++; j++ }
         c = substr(s, j, 1)
         if ((c == "\"" || c == "'") && bs >= 1) {
             pre_len = bs + 1
             name_at = j + 1
         }
     } else if (substr(s, p, 1) == "\"" || substr(s, p, 1) == "'") {
         pre_len = 1
         name_at = p + 1
     }
     if (!boundary_before_name(s, name_at)) return 0
     hlen = header_name_len(s, name_at)
     if (hlen == 0) return 0
     j = name_at + hlen
     while (j <= n && is_space(substr(s, j, 1))) j++
     if (j > n || substr(s, j, 1) != ":") return 0
     j++
     while (j <= n && is_space(substr(s, j, 1))) j++
     return j
 }

 function find_header(s, from,    n, p, endat) {
     n = length(s)
     p = from
     while (p <= n) {
         endat = header_match_at(s, p)
         if (endat > 0) {
             HDR_START = p
             HDR_END = endat
             return 1
         }
         p++
     }
     return 0
 }

 function header_pre_len(s, start,    n, j, bs, c) {
     n = length(s)
     if (substr(s, start, 1) == "\\") {
         j = start
         bs = 0
         while (j <= n && substr(s, j, 1) == "\\") { bs++; j++ }
         c = substr(s, j, 1)
         if ((c == "\"" || c == "'") && bs >= 1) return bs + 1
     } else if (substr(s, start, 1) == "\"" || substr(s, start, 1) == "'") {
         return 1
     }
     return 0
 }

 function find_unescaped_quote_end(value, quote,    i, n, bs, ch) {
     n = length(value)
     i = 1
     bs = 0
     while (i <= n) {
         ch = substr(value, i, 1)
         if (ch == "\\") { bs++; i++; continue }
         if (ch == quote && bs % 2 == 0) return i - 1
         if (is_vert(ch)) return -1
         bs = 0
         i++
     }
     return -1
 }

 function find_escaped_header_close(value, n_bs, quote,    i, n, j, bs, ch, after) {
     n = length(value)
     i = 1
     while (i <= n) {
         if (substr(value, i, 1) != "\\") { i++; continue }
         j = i
         bs = 0
         while (j <= n && substr(value, j, 1) == "\\") { bs++; j++ }
         if (j <= n && substr(value, j, 1) == quote && bs == n_bs) {
             after = j + 1
             if (after > n || is_ws(substr(value, after, 1)) || substr(value, after, 1) == "|") return i - 1
             i = j + 1
             continue
         }
         i = (j <= n ? j + 1 : j)
     }
     return -1
 }

 function looks_like_next_h(s, p,    n, i, hlen, c) {
     n = length(s)
     i = p
     while (i <= n && is_space(substr(s, i, 1))) i++
     if (!eq_ci_at(s, i, "-H")) return 0
     i += 2
     if (i > n || !is_space(substr(s, i, 1))) return 0
     while (i <= n && is_space(substr(s, i, 1))) i++
     while (i <= n && substr(s, i, 1) == "\\") i++
     c = substr(s, i, 1)
     if (c == "\"" || c == "'") i++
     hlen = header_name_len(s, i)
     if (hlen == 0) return 0
     i += hlen
     while (i <= n && is_space(substr(s, i, 1))) i++
     return i <= n && substr(s, i, 1) == ":"
 }

 function scan_unquoted_header_value(value,    i, n, ch) {
     n = length(value)
     i = 1
     while (i <= n) {
         ch = substr(value, i, 1)
         if (ch == "\r" || ch == "\n" || ch == "|") return i - 1
         if (looks_like_next_h(value, i)) return i - 1
         i++
     }
     return n
 }

 function redact_headers(s,    out, cursor, n, pre, prelen, hdr_at, hlen, hdr, value, rel, n_bs, close_len, closing, consumed) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         if (!find_header(s, cursor)) {
             out = out substr(s, cursor)
             break
         }
         out = out substr(s, cursor, HDR_START - cursor)
         prelen = header_pre_len(s, HDR_START)
         pre = substr(s, HDR_START, prelen)
         hdr_at = HDR_START + prelen
         hlen = header_name_len(s, hdr_at)
         hdr = substr(s, hdr_at, hlen)
         value = substr(s, HDR_END)
         if (prelen > 0 && substr(pre, 1, 1) != "\\") {
             rel = find_unescaped_quote_end(value, substr(pre, prelen, 1))
             if (rel >= 0) {
                 out = out pre hdr ": [REDACTED]" pre
                 cursor = HDR_END + rel + 1
                 continue
             }
         } else if (prelen > 0 && substr(pre, 1, 1) == "\\") {
             n_bs = prelen - 1
             rel = find_escaped_header_close(value, n_bs, substr(pre, prelen, 1))
             if (rel >= 0) {
                 close_len = n_bs + 1
                 closing = substr(value, rel + 1, close_len)
                 out = out pre hdr ": [REDACTED]" closing
                 cursor = HDR_END + rel + close_len
                 continue
             }
         }
         consumed = scan_unquoted_header_value(value)
         out = out pre hdr ": [REDACTED]"
         cursor = HDR_END + consumed
         if (cursor < HDR_END) cursor = HDR_END
     }
     return out
 }

 function consume_quoted_token(s, p,    n, q, j, bs, ch) {
     n = length(s)
     q = substr(s, p, 1)
     j = p + 1
     bs = 0
     while (j <= n) {
         ch = substr(s, j, 1)
         if (ch == "\\") { bs++; j++; continue }
         if (ch == q && bs % 2 == 0) return j + 1
         bs = 0
         j++
     }
     return n + 1
 }

 function consume_scalar(s, allow_comma,    n, p, c, j, bs, nxt, after, q, k, t, bs2, marker) {
     n = length(s)
     marker = "[REDACTED]"
     if (substr(s, 1, length(marker)) == marker && substr(s, 1, 13) != "[REDACTED_URL]" && substr(s, 1, 13) != "[REDACTED_url]") p = length(marker) + 1
     else p = 1
     while (p <= n) {
         c = substr(s, p, 1)
         if (c == "$" && p < n && (substr(s, p + 1, 1) == "'" || substr(s, p + 1, 1) == "\"")) {
             q = substr(s, p + 1, 1)
             j = p + 2
             while (j <= n) {
                 if (substr(s, j, 1) == "\\" && j < n && !is_vert(substr(s, j + 1, 1))) { j += 2; continue }
                 if (substr(s, j, 1) == q) { j++; break }
                 j++
             }
             p = j
             continue
         }
         if (c == "\\") {
             j = p
             bs = 0
             while (j <= n && substr(s, j, 1) == "\\") { bs++; j++ }
             if (j > n) return n
             nxt = substr(s, j, 1)
             if (is_vert(nxt)) return p - 1
             if ((nxt == "'" || nxt == "\"") && bs % 2 == 1) {
                 after = j + 1
                 if (p > 1 && index(substr(s, after), nxt) == 0 && (after > n || is_ws(substr(s, after, 1)) || substr(s, after, 1) == "," || substr(s, after, 1) == "}" || substr(s, after, 1) == "]")) return p - 1
                 q = nxt
                 k = j + 1
                 while (k <= n) {
                     t = k
                     bs2 = 0
                     while (t <= n && substr(s, t, 1) == "\\") { bs2++; t++ }
                     if (t <= n && substr(s, t, 1) == q && bs2 % 2 == 1) { p = t + 1; break }
                     if (t > n) { p = n + 1; break }
                     k = t + 1
                 }
                 if (k > n && p <= n) p = n + 1
                 continue
             }
             if ((nxt == "'" || nxt == "\"") && bs % 2 == 0) { p = j; continue }
             p = j + 1
             continue
         }
         if (c == "'" || c == "\"") {
             nxt = (p < n) ? substr(s, p + 1, 1) : ""
             if (p > 1 && index(substr(s, p + 1), c) == 0 && (nxt == "" || is_ws(nxt) || nxt == "," || nxt == "}" || nxt == "]")) return p - 1
             j = consume_quoted_token(s, p)
             if (j < 0) return -j - 1
             p = j
             continue
         }
         if (is_ws(c) || c == ";" || c == "&" || c == "}" || c == "]") return p - 1
         if (c == ",") {
             if (!allow_comma) return p - 1
             nxt = (p < n) ? substr(s, p + 1, 1) : ""
             if (nxt == "" || is_ws(nxt) || nxt == "," || nxt == ";" || nxt == "&" || nxt == "}" || nxt == "]" || nxt == "\"" || nxt == "'") return p - 1
             p++
             continue
         }
         p++
     }
     return n
 }

 function starts_container(value) {
     if (value == "") return 0
     if (substr(value, 1, 10) == "[REDACTED]") return 0
     return substr(value, 1, 1) == "{" || substr(value, 1, 1) == "["
 }

 function append_redacted(prefix,    last) {
     last = substr(prefix, length(prefix), 1)
     if (last == " " || last == "\t" || last == "=") return prefix "[REDACTED]"
     return prefix " [REDACTED]"
 }

 function scan_container(text, start,    opener, nstack, i, quote, limit, ch, stack) {
     delete stack
     opener = substr(text, start, 1)
     if (opener != "{" && opener != "[") return 0
     nstack = 0
     i = start
     quote = ""
     limit = length(text)
     while (i <= limit) {
         ch = substr(text, i, 1)
         if (quote != "") {
             if (ch == "\\") { i += 2; continue }
             if (ch == quote) quote = ""
             i++
             continue
         }
         if (ch == "\"" || ch == "'") { quote = ch; i++; continue }
         if (ch == "{" || ch == "[") {
             nstack++
             stack[nstack] = (ch == "{") ? "}" : "]"
         } else if (ch == "}" || ch == "]") {
             if (nstack < 1 || stack[nstack] != ch) return limit + 1
             delete stack[nstack]
             nstack--
             if (nstack == 0) return i + 1
         }
         i++
     }
     return limit + 1
 }

 function key_at(s, p,    n, j) {
     n = length(s)
     j = p
     if (j > n || !is_keychar(substr(s, j, 1))) return 0
     while (j <= n && is_keychar(substr(s, j, 1))) j++
     return j
 }

 function redact_containers(s,    n, out, pos, p, kend, key, j, c, sep_ok, endc, opener) {
     n = length(s)
     out = ""
     pos = 1
     while (pos <= n) {
         p = pos
         found = 0
         while (p <= n) {
             if (substr(s, p, 1) == "\"") {
                 kend = read_identifier_key(s, p)
                 if (kend > 0) {
                     key = parsed_key
                     if (is_sensitive(key)) {
                         j = kend
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         if (j <= n && substr(s, j, 1) == ":") {
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             c = substr(s, j, 1)
                             if ((c == "{" || c == "[") && substr(s, j, 10) != "[REDACTED]") {
                                 endc = scan_container(s, j)
                                 if (endc > 0) {
                                     out = out substr(s, pos, j - pos) "\"[REDACTED]\""
                                     pos = endc
                                     found = 1
                                     break
                                 }
                             }
                         }
                     }
                 }
             }
             if (substr(s, p, 1) == "\\" || (p == 1 || !is_word(substr(s, p - 1, 1)))) {
                 j = p
                 if (substr(s, j, 1) == "\\") {
                     while (j <= n && substr(s, j, 1) == "\\") j++
                     if (substr(s, j, 1) == "\"") {
                         kend = read_dquoted(s, j)
                         if (kend > 0) {
                             key = substr(s, j + 1, kend - j - 2)
                             t = kend
                             bs = 0
                             while (t <= n && substr(s, t, 1) == "\\") { bs++; t++ }
                             if (bs > 0 && substr(s, t, 1) == "\"" && is_sensitive(key)) {
                                 t++
                                 while (t <= n && is_space(substr(s, t, 1))) t++
                                 c = substr(s, t, 1)
                                 if (c == ":" || c == "=") {
                                     t++
                                     while (t <= n && is_space(substr(s, t, 1))) t++
                                     c = substr(s, t, 1)
                                     if ((c == "{" || c == "[") && substr(s, t, 10) != "[REDACTED]") {
                                         endc = scan_container(s, t)
                                         if (endc > 0) {
                                             out = out substr(s, pos, t - pos) "\"[REDACTED]\""
                                             pos = endc
                                             found = 1
                                             break
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
                 kend = key_at(s, p)
                 if (kend > p) {
                     key = substr(s, p, kend - p)
                     if (is_sensitive(key) && (p == 1 || !is_word(substr(s, p - 1, 1)))) {
                         j = kend
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         c = substr(s, j, 1)
                         if (c == ":" || c == "=") {
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             c = substr(s, j, 1)
                             if ((c == "{" || c == "[") && substr(s, j, 10) != "[REDACTED]") {
                                 endc = scan_container(s, j)
                                 if (endc > 0) {
                                     out = out substr(s, pos, j - pos) "\"[REDACTED]\""
                                     pos = endc
                                     found = 1
                                     break
                                 }
                             }
                         }
                     }
                 }
             }
             p++
         }
         if (!found) {
             out = out substr(s, pos)
             break
         }
     }
     return out
 }

 function redact_bearer_from(s,    n, out, i, which, j, c, start) {
     n = length(s)
     out = ""
     i = 1
     while (i <= n) {
         which = ""
         if (eq_ci_at(s, i, "Bearer") && (i == 1 || !is_word(substr(s, i - 1, 1))) && (i + 6 > n || !is_word(substr(s, i + 6, 1)))) which = substr(s, i, 6)
         else if (eq_ci_at(s, i, "Basic") && (i == 1 || !is_word(substr(s, i - 1, 1))) && (i + 5 > n || !is_word(substr(s, i + 5, 1)))) which = substr(s, i, 5)
         if (which != "") {
             j = i + length(which)
             if (j <= n && is_space(substr(s, j, 1))) {
                 while (j <= n && is_space(substr(s, j, 1))) j++
                 start = j
                 c = substr(s, j, 1)
                 if (c == "\"") {
                     tokend = read_dquoted(s, j)
                     if (tokend > 0) j = tokend
                     else j = start
                 } else if (c == "'") {
                     j++
                     while (j <= n && substr(s, j, 1) != "'") {
                         if (substr(s, j, 1) == "\\") j += 2
                         else j++
                     }
                     if (j <= n && substr(s, j, 1) == "'") j++
                     else j = start
                 } else if (c ~ /[A-Za-z0-9._~+\/=-]/) {
                     while (j <= n && substr(s, j, 1) ~ /[A-Za-z0-9._~+\/=-]/) j++
                 } else j = start
                 if (j > start) {
                     out = out substr(s, i, length(which)) " [REDACTED]"
                     i = j
                     continue
                 }
             }
         }
         out = out substr(s, i, 1)
         i++
     }
     return out
 }

 function match_short_u(s, j,    n, k, lastu, c) {
     n = length(s)
     if (substr(s, j, 1) != "-") return 0
     if (substr(s, j, 2) == "--") return 0
     k = j + 1
     lastu = 0
     while (k <= n && is_alpha(substr(s, k, 1))) {
         c = substr(s, k, 1)
         if (c == "u" || c == "U") lastu = k
         k++
     }
     if (lastu == 0) return 0
     k = lastu + 1
     c = (k <= n) ? substr(s, k, 1) : ""
     if (c == " " || c == "\t") {
         while (k <= n && is_space(substr(s, k, 1))) k++
         return k
     }
     if (c == "=") return k + 1
     return lastu + 1
 }

 function match_long_user(s, j,    n, k, c) {
     n = length(s)
     if (!eq_ci_at(s, j, "--user")) return 0
     k = j + 6
     c = (k <= n) ? substr(s, k, 1) : ""
     if (c == " " || c == "\t") {
         while (k <= n && is_space(substr(s, k, 1))) k++
         return k
     }
     if (c == "=") return k + 1
     return 0
 }

 function find_curl_user_opt(s, curl_at,    n, i, line_end, opt) {
     n = length(s)
     line_end = curl_at
     while (line_end <= n && !is_vert(substr(s, line_end, 1))) line_end++
     i = curl_at + 4
     while (i < line_end) {
         if (is_space(substr(s, i, 1))) {
             while (i < line_end && is_space(substr(s, i, 1))) i++
             opt = match_long_user(s, i)
             if (opt > 0 && opt <= line_end) return opt
             opt = match_short_u(s, i)
             if (opt > 0 && opt <= line_end) return opt
         }
         i++
     }
     return 0
 }

 function quote_boundary(s, p) {
     if (p <= 1) return 1
     c = substr(s, p - 1, 1)
     return is_ws(c) || c == "\"" || c == "'"
 }

 function find_curl_prefix(s, from,    n, p, opt, mend) {
     n = length(s)
     p = from
     while (p <= n) {
         if (eq_ci_at(s, p, "curl") && (p == 1 || !is_word(substr(s, p - 1, 1))) && (p + 4 > n || !is_word(substr(s, p + 4, 1)))) {
             opt = find_curl_user_opt(s, p)
             if (opt > 0) {
                 CURL_S = p
                 CURL_E = opt
                 return 1
             }
         }
         if (quote_boundary(s, p)) {
             mend = match_long_user(s, p)
             if (mend > 0) { CURL_S = p; CURL_E = mend; return 1 }
             if (substr(s, p, 2) == "-u" || substr(s, p, 2) == "-U") {
                 k = p + 2
                 c = (k <= n) ? substr(s, k, 1) : ""
                 if (c == " " || c == "\t") {
                     while (k <= n && is_space(substr(s, k, 1))) k++
                     CURL_S = p
                     CURL_E = k
                     return 1
                 }
                 if (c == "=") { CURL_S = p; CURL_E = k + 1; return 1 }
                 CURL_S = p
                 CURL_E = p + 2
                 return 1
             }
         }
         p++
     }
     return 0
 }

 function curl_accept(prefix, consumed,    low, c) {
     if (consumed == "") return 0
     low = tolower(prefix)
     if (index(low, "curl") > 0 || index(low, "--user") > 0) return 1
     if (index(consumed, ":") > 0) return 1
     c = substr(consumed, 1, 1)
     if (c == "'" || c == "\"" || c == "\\") return 1
     if (substr(consumed, 1, 10) == "[REDACTED]") return 1
     return 0
 }

 function redact_curl_user(s,    out, cursor, n, prefix, value, consumed, ncons) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         if (!find_curl_prefix(s, cursor)) {
             out = out substr(s, cursor)
             break
         }
         if (CURL_E <= CURL_S) {
             out = out substr(s, cursor, CURL_S - cursor + 1)
             cursor = CURL_S + 1
             continue
         }
         prefix = substr(s, CURL_S, CURL_E - CURL_S)
         value = substr(s, CURL_E)
         if (starts_container(value)) {
             ncons = scan_container(value, 1) - 1
         } else ncons = consume_scalar(value, 1)
         consumed = substr(value, 1, ncons)
         if (!curl_accept(prefix, consumed)) {
             out = out substr(s, cursor, CURL_S - cursor + 1)
             cursor = CURL_S + 1
             continue
         }
         out = out substr(s, cursor, CURL_S - cursor) append_redacted(prefix)
         cursor = CURL_E + ncons
     }
     return out
 }

 function cli_match_len(s, p,    rest, low) {
     if (!eq_ci_at(s, p, "--")) return 0
     rest = substr(s, p + 2)
     low = tolower(rest)
     if (match(low, /^([a-z0-9-]*-)?(password|passwd|pwd|pass|secret|token|apikey|api[_-]?key|credentials?|cookies?|session([_-]?(id|key|token|secret))?|webhook([_-]?(url|secret|token|key))?)([ \t]+|=)[ \t]*/)) {
         return 2 + RLENGTH
     }
     return 0
 }

 function redact_cli_flags(s,    n, out, cursor, p, mlen, prefix, value, ncons, consumed) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         p = cursor
         mlen = 0
         while (p <= n) {
             if (quote_boundary(s, p)) {
                 mlen = cli_match_len(s, p)
                 if (mlen > 0) break
             }
             p++
         }
         if (mlen == 0) {
             out = out substr(s, cursor)
             break
         }
         prefix = substr(s, p, mlen)
         value = substr(s, p + mlen)
         if (starts_container(value)) {
             ncons = scan_container(value, 1) - 1
         } else ncons = consume_scalar(value, 1)
         consumed = substr(value, 1, ncons)
         if (consumed == "") {
             out = out substr(s, cursor, p - cursor + 1)
             cursor = p + 1
             continue
         }
         out = out substr(s, cursor, p - cursor) append_redacted(prefix)
         cursor = p + mlen + ncons
     }
     return out
 }

 function redact_assignments(s,    n, out, cursor, p, kend, key, j, c, sep, value, ncons, consumed) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         p = cursor
         kend = 0
         while (p <= n) {
             if (p == 1 || !is_keychar(substr(s, p - 1, 1))) {
                 kend = key_at(s, p)
                 if (kend > p) {
                     key = substr(s, p, kend - p)
                     if (is_sensitive(key)) {
                         j = kend
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         c = substr(s, j, 1)
                         if (c == "=" || c == ":") {
                             sep = c
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             break
                         }
                     }
                 }
             }
             kend = 0
             p++
         }
         if (kend == 0 || p > n) {
             out = out substr(s, cursor)
             break
         }
         value = substr(s, j)
         if (is_header_name(key) || starts_container(value)) {
             out = out substr(s, cursor, j - cursor)
             cursor = j
             continue
         }
         ncons = consume_scalar(value, 1)
         consumed = substr(value, 1, ncons)
         if (consumed == "") {
             out = out substr(s, cursor, p - cursor + 1)
             cursor = p + 1
             continue
         }
         out = out substr(s, cursor, p - cursor) key sep "[REDACTED]"
         cursor = j + ncons
     }
     return out
 }

 function redact_json_scalars(s,    n, out, cursor, p, endq, key, j, value, ncons, consumed, quote, back) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         p = cursor
         endq = 0
         while (p <= n) {
             if (substr(s, p, 1) == "\"") {
                 endq = read_identifier_key(s, p)
                 if (endq > 0) {
                     key = parsed_key
                     if (is_sensitive(key)) {
                         j = endq
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         if (j <= n && substr(s, j, 1) == ":") {
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             break
                         }
                     }
                 }
             }
             endq = 0
             p++
         }
         if (endq == 0 || p > n) {
             out = out substr(s, cursor)
             break
         }
         value = substr(s, j)
         if (is_header_name(key) || starts_container(value)) {
             out = out substr(s, cursor, j - cursor)
             cursor = j
             continue
         }
         ncons = consume_scalar(value, 0)
         consumed = substr(value, 1, ncons)
         if (consumed == "") {
             out = out substr(s, cursor, p - cursor + 1)
             cursor = p + 1
             continue
         }
         quote = "\""
         back = p - 1
         while (back > 0 && substr(s, back, 1) == "\\") { quote = "\\" quote; back-- }
         out = out substr(s, cursor, j - cursor) quote "[REDACTED]" quote
         cursor = j + ncons
     }
     return out
 }

 function redact(s) {
     s = redact_urls(s)
     s = normalize_sensitive_json_keys(s)
     s = redact_headers(s)
     s = redact_bearer_from(s)
     s = redact_containers(s)
     s = redact_json_scalars(s)
     s = redact_curl_user(s)
     s = redact_cli_flags(s)
     s = redact_assignments(s)
     return s
 }

 {
     if (NR == 1) text = $0
     else text = text "\n" $0
 }
 END {
     if (NR == 0) text = ""
     printf "%s", redact(text)
 }
AWK
}

_af_redact_sed() {
    cat >/dev/null
    printf '%s' '[REDACTED]'
}

_af_redact_without_python() {
    if command -v awk >/dev/null 2>&1; then
        _af_redact_awk
    else
        _af_redact_sed
    fi
}

_af_redact_ascii_fallback() {
    _af_redact_without_python
}

_af_truncate_receipt_field() {
    local text
    IFS= read -r -N "$1" text || true
    printf '%s' "$text"
    cat >/dev/null
}

af_write_failure_receipt() {
    local rc="1" stage cat msg
    if [[ $# -ge 4 ]]; then
        rc="${1:-1}"
        stage="${2:-${AF_CURRENT_STAGE:-unknown}}"
        cat="${3:-installer}"
        msg="${4:-Installation failed at stage ${stage} (exit ${rc})}"
    elif [[ $# -eq 3 ]]; then
        rc="${1:-1}"
        stage="${AF_CURRENT_STAGE:-unknown}"
        cat="${2:-installer}"
        msg="${3:-Installation failed at stage ${stage} (exit ${rc})}"
    else
        rc="${1:-1}"
        stage="${AF_CURRENT_STAGE:-unknown}"
        cat="${2:-installer}"
        msg="${3:-Installation failed at stage ${stage} (exit ${rc})}"
    fi
    if [[ "$rc" -eq 0 ]]; then
        rc=1
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 /dev/fd/3 "$rc" 3<<'PY' < <(printf '%s\0%s\0%s' "$stage" "$cat" "$msg")
import os, sys, re, json

SENSITIVE_KEY = (
    r"(?:"
    r"[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|passphrase|credentials?|bearer|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|jwt[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass)[A-Za-z0-9_.-]*"
    r"|"
    r"(?:[A-Za-z0-9]+[_.-])*(?:pass[0-9]*|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|key)(?:[_.-][A-Za-z0-9]+)*"
    r")"
)
HEADER_NAMES = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
HEADER_RE = re.compile(
    r"(?im)(?P<pre>\\+[\"']|[\"'])?(?<![A-Za-z0-9_-])"
    r"(?P<hdr>Proxy-Authorization|Set-Cookie|X-Auth-Token|X-Api-Key|Authorization|Cookie)"
    r"[ \t]*:[ \t]*"
)
NEXT_H_RE = re.compile(
    r"[ \t]*-H[ \t]+\\*[\"']?"
    r"(?:Proxy-Authorization|Set-Cookie|X-Auth-Token|X-Api-Key|Authorization|Cookie)"
    r"[ \t]*:",
    re.I,
)
JSON_KEY_RE = re.compile(r'(?i)\\*"(' + SENSITIVE_KEY + r')\\*"\s*:\s*')
ASSIGN_RE = re.compile(
    r"(?i)(?:^|(?<=[^A-Za-z0-9_.-]))(" + SENSITIVE_KEY + r")\s*([:=])\s*"
)
CLI_RE = re.compile(
    r"(?i)(?:^|(?<=[\s\"']))--(?:[A-Za-z0-9-]*-)?"
    r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|cookies?|"
    r"session(?:[_-]?(?:id|key|token|secret))?|"
    r"webhook(?:[_-]?(?:url|secret|token|key))?|credentials?)"
    r"(?:\s+|=)\s*"
)
CURL_RE = re.compile(
    r"(?i)(?:"
    r"\bcurl\b[^\r\n]*?\s+(?:--user(?:\s+|=)|-[A-Za-z]*u(?:\s+|=)?)"
    r"|(?:^|(?<=[\s\"']))(?:--user(?:\s+|=)|-u(?:\s+|=))"
    r"|(?:^|(?<=[\s\"']))-u"
    r")"
)


def _decode_u00(raw):
    def repl(match):
        return chr(int(match.group(1), 16))

    return re.sub(r"\\+u00([0-9A-Fa-f]{2})", repl, raw)


def normalize_sensitive_json_keys(text):
    def repl(match):
        raw = match.group("body")
        decoded = _decode_u00(raw)
        if re.fullmatch(SENSITIVE_KEY, decoded, flags=re.I):
            return match.group("prefix") + decoded + match.group("suffix")
        return match.group(0)

    return re.sub(r'(?P<prefix>\\*")(?P<body>(?:\\+u00[0-9A-Fa-f]{2}|[A-Za-z0-9_.-])+)(?P<suffix>\\*"\s*:)', repl, text)


def find_unescaped_quote_end(value, quote):
    i = 0
    bs = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\":
            bs += 1
            i += 1
            continue
        if ch == quote and bs % 2 == 0:
            return i
        if ch in "\r\n":
            return None
        bs = 0
        i += 1
    return None


def find_escaped_header_close(value, n_bs, quote):
    i = 0
    n = len(value)
    while i < n:
        if value[i] != "\\":
            i += 1
            continue
        j = i
        bs = 0
        while j < n and value[j] == "\\":
            bs += 1
            j += 1
        if j < n and value[j] == quote and bs == n_bs:
            after = j + 1
            if after >= n or value[after] in " \t\r\n|":
                return i
            i = j + 1
            continue
        i = j + 1 if j < n else j
    return None


def scan_unquoted_header_value(value):
    i = 0
    n = len(value)
    while i < n:
        if value[i] in "\r\n|":
            return i
        if NEXT_H_RE.match(value, i):
            return i
        i += 1
    return n


def redact_headers(text):
    out = []
    cursor = 0
    while cursor < len(text):
        match = HEADER_RE.search(text, cursor)
        if not match:
            out.append(text[cursor:])
            break
        out.append(text[cursor:match.start()])
        pre = match.group("pre") or ""
        hdr = match.group("hdr")
        value = text[match.end():]
        if pre and not pre.startswith("\\"):
            rel = find_unescaped_quote_end(value, pre[-1])
            if rel is not None:
                out.append(pre + hdr + ": [REDACTED]" + pre)
                cursor = match.end() + rel + 1
                continue
        elif pre.startswith("\\"):
            n_bs = len(pre) - 1
            rel = find_escaped_header_close(value, n_bs, pre[-1])
            if rel is not None:
                close_len = n_bs + 1
                closing = value[rel:rel + close_len]
                out.append(pre + hdr + ": [REDACTED]" + closing)
                cursor = match.end() + rel + close_len
                continue
        rel = scan_unquoted_header_value(value)
        out.append(pre + hdr + ": [REDACTED]")
        cursor = match.end() + rel
    return "".join(out)


def scan_container(text, start):
    opener = text[start]
    if opener != "{" and opener != "[":
        return None
    stack = []
    i = start
    quote = None
    limit = len(text)
    while i < limit:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            continue
        if ch == "{" or ch == "[":
            stack.append("}" if ch == "{" else "]")
        elif ch == "}" or ch == "]":
            if not stack or stack[-1] != ch:
                return None
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    return None


def redact_containers(text):
    quote = '"'
    finder = re.compile(
        "(?i)(?:"
        + quote + "(" + SENSITIVE_KEY + ")" + quote + r"\s*:\s*"
        + r"|\\+" + quote + "(" + SENSITIVE_KEY + ")" + r"\\+" + quote + r"\s*[:=]\s*"
        + r"|\b(" + SENSITIVE_KEY + r")\s*[:=]\s*"
        + ")"
    )
    parts = []
    pos = 0
    redacted = quote + "[REDACTED]" + quote
    for match in finder.finditer(text):
        if match.start() < pos:
            continue
        if match.end() >= len(text) or (text[match.end()] != "{" and text[match.end()] != "["):
            continue
        if text.startswith("[REDACTED]", match.end()):
            continue
        end = scan_container(text, match.end())
        if end is None:
            end = len(text)
        parts.append(text[pos:match.end()])
        parts.append(redacted)
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


def consume_scalar_span(s, allow_comma=True):
    n = len(s)
    marker = "[REDACTED]"
    if s.startswith(marker) and not s.startswith("[REDACTED_URL]") and not s.startswith("[REDACTED_url]"):
        i = len(marker)
    else:
        i = 0
    while i < n:
        c = s[i]
        if c == "$" and i + 1 < n and s[i + 1] in ("'", '"'):
            q = s[i + 1]
            j = i + 2
            while j < n:
                if s[j] == "\\" and j + 1 < n and s[j + 1] not in "\r\n":
                    j += 2
                    continue
                if s[j] == q:
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "\\":
            j = i
            bs = 0
            while j < n and s[j] == "\\":
                bs += 1
                j += 1
            if j >= n:
                return n
            nxt = s[j]
            if nxt in "\r\n":
                return i
            if nxt in ("'", '"') and bs % 2 == 1:
                after = j + 1
                if i > 0 and nxt not in s[after:] and (after >= n or s[after] in " \t\r\n,}]"):
                    return i
                q = nxt
                k = j + 1
                while k < n:
                    t = k
                    bs2 = 0
                    while t < n and s[t] == "\\":
                        bs2 += 1
                        t += 1
                    if t < n and s[t] == q and bs2 % 2 == 1:
                        i = t + 1
                        break
                    if t >= n:
                        i = n
                        break
                    k = t + 1
                else:
                    i = n
                continue
            if nxt in ("'", '"') and bs % 2 == 0:
                i = j
                continue
            i = j + 1
            continue
        if c in ("'", '"'):
            nxt = s[i + 1] if i + 1 < n else ""
            if i > 0 and c not in s[i + 1:] and (nxt == "" or nxt in " \t\r\n,}]"):
                return i
            q = c
            j = i + 1
            bs = 0
            while j < n:
                if s[j] == "\\":
                    bs += 1
                    j += 1
                    continue
                if s[j] == q and bs % 2 == 0:
                    j += 1
                    break
                bs = 0
                j += 1
            i = j
            continue
        if c in " \t\r\n;}&]}":
            return i
        if c == ",":
            if not allow_comma:
                return i
            nxt = s[i + 1] if i + 1 < n else ""
            if nxt == "" or nxt in " \t\r\n,;}&]}\"'":
                return i
            i += 1
            continue
        i += 1
    return i


def _append_redacted(prefix):
    if prefix.endswith((" ", "\t", "=")):
        return prefix + "[REDACTED]"
    return prefix + " [REDACTED]"


def _curl_accept(prefix, consumed):
    if not consumed:
        return False
    low = prefix.lower()
    if "curl" in low or "--user" in low:
        return True
    return (
        ":" in consumed
        or consumed.startswith(("'", '"', "\\", "[REDACTED]"))
    )


def _replace_with_consumer(text, regex, accept, json_value=False):
    out = []
    cursor = 0
    while cursor < len(text):
        match = regex.search(text, cursor)
        if not match:
            out.append(text[cursor:])
            break
        if match.end() == match.start():
            out.append(text[cursor:cursor + 1])
            cursor += 1
            continue
        value = text[match.end():]
        if (value.startswith("{") or value.startswith("[")) and not value.startswith("[REDACTED]"):
            end = scan_container(text, match.end())
            out.append(text[cursor:match.start()])
            if json_value:
                out.append('"' + match.group(1) + '":"[REDACTED]"')
            elif regex is ASSIGN_RE:
                out.append(match.group(1) + match.group(2) + "[REDACTED]")
            else:
                out.append(_append_redacted(match.group(0)))
            cursor = end if end is not None else len(text)
            continue
        if json_value:
            key = match.group(1)
            if key.lower() in HEADER_NAMES:
                out.append(text[cursor:match.end()])
                cursor = match.end()
                continue
        if not json_value and regex is ASSIGN_RE and match.group(1).lower() in HEADER_NAMES:
            out.append(text[cursor:match.end()])
            cursor = match.end()
            continue
        n = consume_scalar_span(value, allow_comma=not json_value)
        consumed = value[:n] if n else ""
        prefix = match.group(0)
        if not accept(prefix, consumed):
            out.append(text[cursor:match.start() + 1])
            cursor = match.start() + 1
            continue
        out.append(text[cursor:match.start()])
        if json_value:
            quote = re.match(r'\\*"', match.group(0)).group(0)
            out.append(match.group(0) + quote + "[REDACTED]" + quote)
        elif regex is ASSIGN_RE:
            out.append(match.group(1) + match.group(2) + "[REDACTED]")
        else:
            out.append(_append_redacted(prefix))
        cursor = match.end() + n
    return "".join(out)


def redact_json_scalars(text):
    return _replace_with_consumer(text, JSON_KEY_RE, lambda prefix, consumed: bool(consumed), json_value=True)


def redact_curl_user(text):
    return _replace_with_consumer(text, CURL_RE, _curl_accept, json_value=False)


def redact_cli_flags(text):
    return _replace_with_consumer(text, CLI_RE, lambda prefix, consumed: bool(consumed), json_value=False)


def redact_assignments(text):
    return _replace_with_consumer(text, ASSIGN_RE, lambda prefix, consumed: bool(consumed), json_value=False)


def redact_urls(text):
    text = re.sub(r"://[^/@\s]+:[^/@\s]+@", "://[REDACTED]@", text)
    text = re.sub(
        r"(?i)\b(https?|ftp|redis|amqp|postgres(?:ql)?|mysql|mongodb)://[^/@\s]+@",
        r"\1://[REDACTED]@",
        text,
    )
    return text


def redact_bearer(text):
    return re.sub(
        r"(?i)\b(Bearer|Basic)\s+(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[A-Za-z0-9._~+/=-]+)",
        r"\1 [REDACTED]",
        text,
    )


def redact(text):
    text = redact_urls(text)
    text = normalize_sensitive_json_keys(text)
    text = redact_headers(text)
    text = redact_bearer(text)
    text = redact_containers(text)
    text = redact_json_scalars(text)
    text = redact_curl_user(text)
    text = redact_cli_flags(text)
    text = redact_assignments(text)
    return text

def safe_decode(s):
    if isinstance(s, bytes):
        return s.decode("utf-8", "replace")
    try:
        return os.fsencode(s).decode("utf-8", "replace")
    except Exception:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")

def sanitize(text):
    return re.sub(r"[\x00-\x1f\x7f]", " ", text)

def trunc_utf8(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", errors="ignore")

raw_stage, raw_category, raw_summary = sys.stdin.buffer.read().split(b"\0", 2)
stage = trunc_utf8(sanitize(redact(safe_decode(raw_stage))), 120)
try:
    rc = int(sys.argv[1])
    if rc == 0:
        rc = 1
except Exception:
    rc = 1
cat = trunc_utf8(sanitize(redact(safe_decode(raw_category))), 120)
msg = trunc_utf8(sanitize(redact(safe_decode(raw_summary))), 300)

payload = "AF_DIAG_FAILURE=" + json.dumps({"stage": stage, "exit_code": int(rc), "category": cat, "summary": msg}, ensure_ascii=False, separators=(",", ":"))
sys.stderr.write(payload + "\n")
PY
    else
        stage=$(printf '%s' "$stage" | _af_redact_without_python | LC_ALL=C tr '\000-\037\177' ' ' | LC_ALL=C tr -cd '\040-\176' | LC_ALL=C _af_truncate_receipt_field 120)
        cat=$(printf '%s' "$cat" | _af_redact_without_python | LC_ALL=C tr '\000-\037\177' ' ' | LC_ALL=C tr -cd '\040-\176' | LC_ALL=C _af_truncate_receipt_field 120)
        msg=$(printf '%s' "$msg" | _af_redact_without_python | LC_ALL=C tr '\000-\037\177' ' ' | LC_ALL=C tr -cd '\040-\176' | LC_ALL=C _af_truncate_receipt_field 300)
        stage="${stage//\\/\\\\}"
        stage="${stage//\"/\\\"}"
        cat="${cat//\\/\\\\}"
        cat="${cat//\"/\\\"}"
        msg="${msg//\\/\\\\}"
        msg="${msg//\"/\\\"}"
        printf 'AF_DIAG_FAILURE={"stage":"%s","exit_code":%d,"category":"%s","summary":"%s"}\n' "$stage" "$rc" "$cat" "$msg" >&2
    fi
}
af_cleanup_job_scratch() {
    local exit_code="${1:-$?}"
    if [[ -n "${AF_JOB_SCRATCH_DIR:-}" && -d "${AF_JOB_SCRATCH_DIR}" ]]; then
        if [[ "${AF_PRESERVE_SCRATCH:-0}" == "1" ]]; then
            return "$exit_code"
        fi
        if [[ "$exit_code" -ne 0 && ( -d "${AF_JOB_SCRATCH_DIR}/rollback" || -d "${AF_JOB_SCRATCH_DIR}/backup" ) ]]; then
            return "$exit_code"
        fi
        rm -rf --one-file-system "${AF_JOB_SCRATCH_DIR}" 2>/dev/null || true
    fi
    return "$exit_code"
}

af_prepare_job_scratch() {
    local app_id="${1:?af_prepare_job_scratch requires app_id}"
    local min_free_mb="${2:-1024}"
    local min_free_inodes="${3:-4096}"
    local scratch_root="${AF_JOB_SCRATCH_ROOT:-/var/tmp/aetherflow-scratch}"
    local expected_uid="0"
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        expected_uid="${EUID:-$(id -u)}"
    fi

    if [[ -L "$scratch_root" ]]; then
        af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} is a symlink"
        exit 28
    fi

    if [[ -e "$scratch_root" ]]; then
        if [[ ! -d "$scratch_root" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} is not a directory"
            exit 28
        fi
        local owner_uid
        owner_uid="$(stat -c '%u' "$scratch_root" 2>/dev/null || stat -f '%u' "$scratch_root" 2>/dev/null || true)"
        if [[ "$owner_uid" != "$expected_uid" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} owner ${owner_uid} does not match expected uid ${expected_uid}"
            exit 28
        fi
        chmod 0700 "$scratch_root" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to enforce permissions on ${scratch_root}"
            exit 28
        }
    else
        mkdir -p -m 0700 "$scratch_root" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to create scratch root ${scratch_root}"
            exit 28
        }
    fi

    local fs_type fs_lower
    if ! fs_type="$(stat -f -c '%T' "$scratch_root" 2>/dev/null)"; then
        af_write_failure_receipt 28 "preflight_capacity" "Failed to determine filesystem type for ${scratch_root}"
        return 1
    fi
    fs_lower="${fs_type,,}"
    if [[ -z "$fs_lower" || "$fs_lower" == *"unknown"* || "$fs_lower" == 0x* || "$fs_lower" == *"0x"* ]]; then
        af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} filesystem type (${fs_type:-empty}) is not allowed or unknown"
        return 1
    fi
    if [[ "$fs_lower" == *"tmpfs"* || "$fs_lower" == *"ramfs"* ]]; then
        if [[ "${AF_ALLOW_TMPFS_SCRATCH:-0}" != "1" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} filesystem type (${fs_type}) is not allowed or unknown"
            return 1
        fi
    fi

    if ! check_disk_space "$scratch_root" "${min_free_mb:-512}"; then
        af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} failed check_disk_space validation"
        return 1
    fi

    local check_path target_path
    for check_path in "$scratch_root" /opt /var/lib "${AF_BACKUP_ROOT:-/var/backups}"; do
        target_path="$check_path"
        while [[ ! -e "$target_path" && "$target_path" != "/" ]]; do
            target_path="$(dirname "$target_path")"
        done
        local free_mb free_inodes
        free_mb="$(df -Pm "$target_path" 2>/dev/null | awk 'NR==2 {print $4}')" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to check disk capacity for ${check_path}"
            exit 28
        }
        free_inodes="$(df -Pi "$target_path" 2>/dev/null | awk 'NR==2 {print $4}')" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to check inode capacity for ${check_path}"
            exit 28
        }
        if [[ -z "$free_mb" || -z "$free_inodes" || ! "$free_mb" =~ ^[0-9]+$ || ! "$free_inodes" =~ ^[0-9]+$ || "$free_mb" -lt "$min_free_mb" || "$free_inodes" -lt "$min_free_inodes" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Insufficient disk or inode capacity on ${check_path} (free: ${free_mb:-0}MB / ${free_inodes:-0} inodes, required: ${min_free_mb}MB / ${min_free_inodes} inodes)"
            exit 28
        fi
    done

    local scratch_dir
    scratch_dir="$(mktemp -d "${scratch_root}/${app_id}.XXXXXXXXXX")" || {
        af_write_failure_receipt 28 "preflight_capacity" "Failed to create scratch directory in ${scratch_root}"
        exit 28
    }
    chmod 0700 "$scratch_dir" || {
        af_write_failure_receipt 28 "preflight_capacity" "Failed to enforce permissions on scratch directory ${scratch_dir}"
        exit 28
    }

    AF_JOB_SCRATCH_DIR="$scratch_dir"
    export AF_JOB_SCRATCH_DIR
    trap 'set +e; af_cleanup_job_scratch "$?" || true' EXIT
    printf '%s\n' "$scratch_dir"
}

report_progress() {
    local pct="${1:-0}"
    local msg="${2:-}"
    printf '[PROGRESS:%d] %s\n' "$pct" "$msg"
    log_info "[PROGRESS:$pct] $msg"
}

github_latest_tag() {
    local repo="$1"
    local fallback="${2:-}"
    local strip_v="${3:-true}"
    if [[ "$fallback" == "true" || "$fallback" == "false" ]] && [[ $# -eq 2 ]]; then
        strip_v="$fallback"
        fallback=""
    fi
    local tag=""
    local eff_url=""

    if [[ -n "${AF_TARGET_VERSION:-}" ]]; then
        tag="${AF_TARGET_VERSION}"
        if [[ "$strip_v" == "true" ]]; then
            tag="${tag#release-v}"
            tag="${tag#[vV]}"
        else
            tag="${tag#release-}"
            if [[ "$tag" =~ ^[0-9] ]]; then
                tag="v${tag}"
            elif [[ "$tag" =~ ^V([0-9].*)$ ]]; then
                tag="v${BASH_REMATCH[1]}"
            fi
        fi
        printf '%s\n' "$tag"
        return 0
    fi

    eff_url="$(curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 5 --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" 2>/dev/null || true)"
    if [[ "$eff_url" == *"/releases/tag/"* ]]; then
        tag="${eff_url##*/releases/tag/}"
        tag="${tag%%\?*}"
        tag="${tag%%#*}"
    fi

    if [[ -z "$tag" ]]; then
        tag="$(af_github_curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 5 --max-time 15 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
            | grep -oP '"tag_name":\s*"\K[^"]+' | head -n1 || true)"
    fi

    if [[ -z "$tag" ]]; then
        if [[ "${AF_ALLOW_RELEASE_FALLBACK:-0}" == "1" && -n "$fallback" ]]; then
            if command -v print_warning >/dev/null 2>&1; then
                print_warning "Failed to query GitHub releases for ${repo}; using explicit opt-in fallback ${fallback}"
            elif command -v print_warn >/dev/null 2>&1; then
                print_warn "Failed to query GitHub releases for ${repo}; using explicit opt-in fallback ${fallback}"
            fi
            tag="$fallback"
        else
            print_error "Failed to discover latest GitHub release for ${repo}"
            return 1
        fi
    fi

    if [[ "$strip_v" == "true" ]]; then
        tag="${tag#release-v}"
        tag="${tag#[vV]}"
    else
        tag="${tag#release-}"
        if [[ "$tag" =~ ^[0-9] ]]; then
            tag="v${tag}"
        elif [[ "$tag" =~ ^V([0-9].*)$ ]]; then
            tag="v${BASH_REMATCH[1]}"
        fi
    fi

    printf '%s\n' "$tag"
}

sync_node_global_bins() {
    local npm_prefix=""
    if command_exists npm; then
        npm_prefix="$(npm config get prefix 2>/dev/null || true)"
        npm_prefix="${npm_prefix%/}"
    fi
    local bin_dir
    for bin_dir in "/usr/local/nodejs/bin" "${npm_prefix:+${npm_prefix}/bin}" "/usr/local/bin"; do
        [[ -n "$bin_dir" && -d "$bin_dir" ]] || continue
        case ":$PATH:" in
            *":${bin_dir}:"*) ;;
            *) export PATH="${bin_dir}:$PATH" ;;
        esac
        case "$bin_dir" in
            ""|/bin|/sbin|/usr/bin|/usr/sbin|/usr/local/bin) continue ;;
        esac
        local bin_path bin_name
        for bin_path in "$bin_dir"/*; do
            [[ -e "$bin_path" && -x "$bin_path" && ! -d "$bin_path" ]] || continue
            bin_name="$(basename "$bin_path")"
            if [[ ! -e "/usr/local/bin/${bin_name}" && ! -L "/usr/local/bin/${bin_name}" ]]; then
                ln -sf "$bin_path" "/usr/local/bin/${bin_name}" 2>/dev/null || true
            fi
        done
    done
    local core_bin
    for core_bin in node npm npx yarn yarnpkg pnpm corepack; do
        if [[ ! -x "/usr/bin/${core_bin}" ]]; then
            if [[ -x "/usr/local/bin/${core_bin}" ]]; then
                ln -sf "/usr/local/bin/${core_bin}" "/usr/bin/${core_bin}" 2>/dev/null || true
            elif [[ -x "/usr/local/nodejs/bin/${core_bin}" ]]; then
                ln -sf "/usr/local/nodejs/bin/${core_bin}" "/usr/bin/${core_bin}" 2>/dev/null || true
            fi
        fi
    done
}

ensure_node() {
    local want_major="${1:-22}"
    local have_major=0
    if [[ ! "$want_major" =~ ^[1-9][0-9]{0,2}$ ]]; then
        print_error "Invalid Node.js major version requested: $want_major"
        return 1
    fi
    # Native addons and Git prepare scripts need these on already-provisioned
    # Node hosts too, not just when Node itself is first installed.
    DEBIAN_FRONTEND=noninteractive af_logged apt-get install -y -qq \
        ca-certificates git build-essential python3 python3-setuptools pkg-config || return 1
    if command_exists node; then
        have_major=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1 || echo 0)
        [[ "$have_major" =~ ^[1-9][0-9]{0,2}$ ]] || have_major=0
    fi
    if [[ "${have_major:-0}" -lt "$want_major" ]]; then
        local nodesource_rev="42da07fa46a3e9649f47416743a5563f9f19028f"
        local nodesource_url nodesource_sha256="${AF_NODESOURCE_BOOTSTRAP_SHA256:-}"
        if [[ -n "$nodesource_sha256" ]]; then
            nodesource_url="https://deb.nodesource.com/setup_${want_major}.x"
        else
            case "$want_major" in
                20) nodesource_sha256="2c4c6683a17b6f4128898a7b521e3c8bb725a99ffaf1b5e32ac97c6fa7d381be" ;;
                22) nodesource_sha256="575583bbac2fccc0b5edd0dbc03e222d9f9dc8d724da996d22754d6411104fd1" ;;
                24) nodesource_sha256="6e3d580f5bd7ccf2aa1e8df8d35c60d78e873c3ff8beb282c9bebd914904ad72" ;;
                *)
                    print_error "Unsupported Node.js major version for pinned NodeSource bootstrap: $want_major (supported: 20, 22, 24)"
                    return 1
                    ;;
            esac
            nodesource_url="https://raw.githubusercontent.com/nodesource/distributions/${nodesource_rev}/scripts/deb/setup_${want_major}.x"
        fi
        ( umask 022; DEBIAN_FRONTEND=noninteractive fetch_and_run "$nodesource_url" "$nodesource_sha256" ) || return 1
        DEBIAN_FRONTEND=noninteractive af_logged apt-get install -y -qq nodejs || return 1
    fi
    sync_node_global_bins
}
