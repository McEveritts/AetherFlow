use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

type HmacSha256 = Hmac<Sha256>;

/// Shared header injected by the local reverse proxy (`RequestHeader set`) to authenticate
/// loopback `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto` headers when
/// `trusted_proxy_secret` is configured in `settings.toml`.
pub const PROXY_TOKEN_HEADER: &str = "x-aetherflow-proxy-token";
const PROXY_TOKEN_HMAC_DOMAIN: &[u8] = b"aetherflow-librespeed-proxy-token-v1";

static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
        .expect("valid IPv4 regex")
});

// Candidate scanner for tokens containing at least two colons; every match is validated
// through `Ipv6Addr::from_str` after stripping any `%zone` suffix so timestamps like
// `1731638400000: download started` never trigger false positives.
static IPV6_CANDIDATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[0-9a-fA-F:]+:[0-9a-fA-F:.]*(?:%[0-9a-zA-Z._-]+)?")
        .expect("valid IPv6 candidate regex")
});

static HOSTNAME_JSON_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""hostname"\s*:\s*"(?:[^"\\]|\\.)*""#).expect("valid hostname regex")
});

static HOSTNAME_ESCAPED_JSON_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\\"hostname\\"\s*:\s*\\"(?:[^"\\]|\\[^"])*?\\""#)
        .expect("valid escaped hostname regex")
});

pub fn parse_ip_token(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Some(canonicalize_ip_addr(sock.ip()));
    }

    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);

    // Strip IPv6 %zone_id for standard IpAddr::parse while preserving IPv4/IPv6 detection.
    let without_zone = unbracketed.split('%').next().unwrap_or(unbracketed).trim();

    if let Ok(ip) = without_zone.parse::<IpAddr>() {
        return Some(canonicalize_ip_addr(ip));
    }

    None
}

pub fn canonicalize_ip_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

pub fn normalize_ip_string(raw: &str) -> String {
    match parse_ip_token(raw) {
        Some(ip) => ip.to_string(),
        None => raw.trim().to_string(),
    }
}

pub fn peer_ip_key(peer_addr: Option<SocketAddr>) -> String {
    peer_addr
        .map(|s| canonicalize_ip_addr(s.ip()).to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

pub fn is_trusted_proxy_peer(peer_addr: Option<SocketAddr>, trusted_proxies: &[IpAddr]) -> bool {
    let Some(addr) = peer_addr else {
        return false;
    };
    let peer_ip = canonicalize_ip_addr(addr.ip());
    trusted_proxies
        .iter()
        .any(|trusted| canonicalize_ip_addr(*trusted) == peer_ip)
}

/// Verifies `X-AetherFlow-Proxy-Token` in constant time using HMAC-SHA256 when
/// `expected_secret` is non-empty. Rejects missing or duplicate token headers.
pub fn verify_proxy_secret(headers: &HeaderMap, expected_secret: &str) -> bool {
    let expected = expected_secret.trim();
    if expected.is_empty() {
        return true;
    }
    let mut iter = headers.get_all(PROXY_TOKEN_HEADER).iter();
    let Some(first) = iter.next() else {
        return false;
    };
    if iter.next().is_some() {
        return false;
    }
    let candidate = first.as_bytes().trim_ascii();
    let expected_tag = hmac_sha256_tag(expected.as_bytes());
    let candidate_tag = hmac_sha256_tag(candidate);
    let mut diff = 0u8;
    for (&a, &b) in expected_tag.iter().zip(candidate_tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn hmac_sha256_tag(input: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(PROXY_TOKEN_HMAC_DOMAIN).expect("HMAC accepts any key length");
    mac.update(input);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Extracts the canonical forwarded client IP ONLY when `peer_addr` is an
/// explicitly configured `trusted_proxies` peer (and `X-AetherFlow-Proxy-Token`
/// matches `proxy_secret` when configured).
///
/// Security invariants:
/// 1. `X-Forwarded-For` is walked right-to-left on raw header bytes (`b','`) so
///    non-ASCII (`obs-text`) bytes injected into untrusted leftward hops can never
///    invalidate the trusted proxy's appended rightmost hop or trigger a fallback
///    to a client-spoofed `X-Real-IP`.
/// 2. Explicit non-loopback `trusted_proxies` hops are peeled right-to-left to
///    support multi-tier ingress chains (e.g. `CDN/Edge -> Apache -> speedtest-backend`),
///    while loopback hops (`127.0.0.1` / `::1`) terminate peeling so a local
///    unprivileged user connecting via loopback Apache cannot spoof arbitrary
///    leftward `X-Forwarded-For` addresses.
/// 3. `X-Real-IP` is consulted ONLY when `X-Forwarded-For` is completely absent.
pub fn extract_trusted_forwarded_ip_with_secret(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
    proxy_secret: &str,
) -> Option<IpAddr> {
    if !is_trusted_proxy_peer(peer_addr, trusted_proxies)
        || !verify_proxy_secret(headers, proxy_secret)
    {
        return None;
    }
    let peer_is_loopback = peer_addr
        .map(|s| canonicalize_ip_addr(s.ip()).is_loopback())
        .unwrap_or(true);
    let allow_multi_hop_peeling = !peer_is_loopback || !proxy_secret.trim().is_empty();
    if headers.contains_key("x-forwarded-for") {
        let mut saw_any_hop = false;
        let mut fallback_trusted_hop: Option<IpAddr> = None;
        let xff_values: Vec<&axum::http::HeaderValue> =
            headers.get_all("x-forwarded-for").iter().collect();
        for hv in xff_values.into_iter().rev() {
            for raw_hop in hv.as_bytes().rsplit(|&b| b == b',') {
                let trimmed = raw_hop.trim_ascii();
                let hop_str = std::str::from_utf8(trimmed).ok()?;
                let ip = parse_ip_token(hop_str)?;
                saw_any_hop = true;
                let is_trusted_non_loopback = allow_multi_hop_peeling
                    && !ip.is_loopback()
                    && trusted_proxies
                        .iter()
                        .any(|trusted| canonicalize_ip_addr(*trusted) == ip);
                if is_trusted_non_loopback {
                    fallback_trusted_hop = Some(ip);
                    continue;
                }
                return Some(ip);
            }
        }
        return if saw_any_hop {
            fallback_trusted_hop
        } else {
            None
        };
    }

    let mut xri_iter = headers.get_all("x-real-ip").iter();
    let first_xri = xri_iter.next()?;
    if xri_iter.next().is_some() {
        return None;
    }
    first_xri.to_str().ok().and_then(parse_ip_token)
}

pub fn extract_trusted_forwarded_ip(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
) -> Option<IpAddr> {
    extract_trusted_forwarded_ip_with_secret(peer_addr, headers, trusted_proxies, "")
}

/// Resolves client IP from `peer_addr`, trusting `X-Forwarded-For` (strictly the
/// single rightmost hop appended by the trusted reverse proxy) and `X-Real-IP`
/// ONLY when the direct TCP peer IP is explicitly configured in `trusted_proxies`
/// and `proxy_secret` (when non-empty) matches `X-AetherFlow-Proxy-Token`.
pub fn resolve_client_ip_with_secret(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
    proxy_secret: &str,
) -> String {
    if let Some(forwarded) =
        extract_trusted_forwarded_ip_with_secret(peer_addr, headers, trusted_proxies, proxy_secret)
    {
        return forwarded.to_string();
    }

    peer_addr
        .map(|s| canonicalize_ip_addr(s.ip()).to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

pub fn resolve_client_ip(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
) -> String {
    resolve_client_ip_with_secret(peer_addr, headers, trusted_proxies, "")
}

pub fn classify_ip_note(ip: IpAddr) -> Option<&'static str> {
    match canonicalize_ip_addr(ip) {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(v4: Ipv4Addr) -> Option<&'static str> {
    if v4.is_loopback() {
        return Some("localhost IPv4 access");
    }
    if v4.is_private() {
        return Some("private IPv4 access");
    }
    if v4.is_link_local() {
        return Some("link-local IPv4 access");
    }
    let octets = v4.octets();
    // 100.64.0.0/10 carrier-grade NAT (RFC 6598)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return Some("carrier-grade NAT IPv4 access");
    }
    // TEST-NET-1/2/3 (RFC 5737)
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return Some("documentation IPv4 access");
    }
    None
}

fn classify_v6(v6: Ipv6Addr) -> Option<&'static str> {
    if v6.is_loopback() {
        return Some("localhost IPv6 access");
    }
    let segs = v6.segments();
    // fc00::/7 Unique Local Address (RFC 4193)
    if (segs[0] & 0xfe00) == 0xfc00 {
        return Some("private IPv6 access");
    }
    // fe80::/10 Link-Local
    if (segs[0] & 0xffc0) == 0xfe80 {
        return Some("link-local IPv6 access");
    }
    // 2001:db8::/32 Documentation
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return Some("documentation IPv6 access");
    }
    None
}

pub fn format_getip_display(ip_str: &str, redact: bool) -> String {
    if redact {
        return redact_single_ip(ip_str);
    }
    match parse_ip_token(ip_str) {
        Some(ip) => match classify_ip_note(ip) {
            Some(note) => format!("{ip} - {note}"),
            None => ip.to_string(),
        },
        None => ip_str.to_string(),
    }
}

pub fn redact_single_ip(ip_str: &str) -> String {
    match parse_ip_token(ip_str) {
        Some(IpAddr::V6(_)) => "::".to_string(),
        _ => "0.0.0.0".to_string(),
    }
}

fn is_ascii_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_verified_ipv6_subspan(input: &str, m_start: usize, m_end: usize) -> Option<(usize, usize)> {
    let raw = &input[m_start..m_end];
    let (core_rel_end, has_zone) = match raw.find('%') {
        Some(idx) => (idx, true),
        None => (raw.len(), false),
    };
    let core_abs_end = m_start + core_rel_end;
    if core_abs_end <= m_start {
        return None;
    }

    let bytes = input.as_bytes();
    let mut candidate_starts: Vec<usize> = Vec::with_capacity(6);
    if m_start == 0 || !is_ascii_word_byte(bytes[m_start - 1]) {
        candidate_starts.push(m_start);
    }

    // Also inspect positions immediately after leading separator colons or a single
    // hex-compatible label prefix (e.g. `peer:2001:db8::1`, `id:2001:db8::1`, `addr:::1`).
    for rel_idx in 0..core_rel_end.min(48) {
        if bytes[m_start + rel_idx] == b':' {
            let next_abs = m_start + rel_idx + 1;
            if next_abs < core_abs_end && !candidate_starts.contains(&next_abs) {
                candidate_starts.push(next_abs);
                if candidate_starts.len() >= 6 {
                    break;
                }
            }
        }
    }

    for start in candidate_starts {
        if start >= core_abs_end {
            continue;
        }
        let full_slice = &input[start..core_abs_end];
        if full_slice.bytes().filter(|&b| b == b':').count() >= 2
            && full_slice.parse::<Ipv6Addr>().is_ok()
        {
            let end = if has_zone { m_end } else { core_abs_end };
            return Some((start, end));
        }
        if !has_zone {
            if let Some(last_colon_rel) = full_slice.rfind(':') {
                let port_part = &full_slice[last_colon_rel + 1..];
                let trimmed_slice = &full_slice[..last_colon_rel];
                if !port_part.is_empty()
                    && port_part.len() <= 5
                    && port_part.bytes().all(|b| b.is_ascii_digit())
                    && trimmed_slice.bytes().filter(|&b| b == b':').count() >= 2
                    && trimmed_slice.parse::<Ipv6Addr>().is_ok()
                {
                    return Some((start, start + last_colon_rel));
                }
            }
        }
    }
    None
}

/// Redacts IPv4 addresses, verified IPv6 addresses (with optional `%zone` and
/// adjacent `label:` separators), and `"hostname":"..."` JSON values while leaving
/// Unix timestamps (`1731638400000: ...`) and MAC addresses untouched.
pub fn redact_freeform_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    // 1. Replace verified IPv6 tokens before IPv4 so IPv4-mapped IPv6 (`::ffff:1.2.3.4`)
    // collapses to `::` cleanly instead of `::ffff:0.0.0.0`.
    let mut after_v6 = String::with_capacity(input.len());
    let mut last = 0usize;
    for m in IPV6_CANDIDATE_RE.find_iter(input) {
        if let Some((v6_start, v6_end)) = find_verified_ipv6_subspan(input, m.start(), m.end()) {
            if v6_start >= last {
                after_v6.push_str(&input[last..v6_start]);
                after_v6.push_str("::");
                last = v6_end;
            }
        }
    }
    after_v6.push_str(&input[last..]);

    // 2. Replace IPv4 addresses.
    let after_v4 = IPV4_RE.replace_all(&after_v6, "0.0.0.0");

    // 3. Replace `"hostname":"..."` in both top-level JSON and stringified `rawIspInfo` JSON.
    let after_unescaped = HOSTNAME_JSON_RE.replace_all(&after_v4, r#""hostname":"REDACTED""#);
    HOSTNAME_ESCAPED_JSON_RE
        .replace_all(&after_unescaped, r#"\"hostname\":\"REDACTED\""#)
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn resolves_forwarded_headers_only_from_explicitly_trusted_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.5, 198.51.100.77"),
        );
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));

        let loopback = Some("127.0.0.1:42311".parse::<SocketAddr>().unwrap());
        // Default empty trusted_proxies ignores loopback XFF spoofing
        assert_eq!(resolve_client_ip(loopback, &headers, &[]), "127.0.0.1");

        let trusted = vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "::1".parse::<IpAddr>().unwrap(),
        ];
        assert_eq!(
            resolve_client_ip(loopback, &headers, &trusted),
            "198.51.100.77"
        );

        let loopback_v6 = Some("[::1]:42311".parse::<SocketAddr>().unwrap());
        assert_eq!(
            resolve_client_ip(loopback_v6, &headers, &trusted),
            "198.51.100.77"
        );

        // Single-hop rule: if local client connects via trusted proxy and injects leftmost XFF,
        // proxy appends 127.0.0.1 at the end; we take the single rightmost hop (127.0.0.1), NOT 8.8.8.8.
        let mut local_spoof = HeaderMap::new();
        local_spoof.insert(
            "x-forwarded-for",
            HeaderValue::from_static("8.8.8.8, 127.0.0.1"),
        );
        assert_eq!(
            resolve_client_ip(loopback, &local_spoof, &trusted),
            "127.0.0.1"
        );

        let external = Some("192.0.2.50:42311".parse::<SocketAddr>().unwrap());
        assert_eq!(
            resolve_client_ip(external, &headers, &trusted),
            "192.0.2.50"
        );

        // Multi-tier non-loopback ingress chain: Edge (10.10.0.2) -> Apache (127.0.0.1).
        // Unauthenticated loopback (empty proxy_secret) MUST NOT peel 10.10.0.2 (blocks local
        // client spoofing `X-Forwarded-For: 8.8.8.8, 10.10.0.2`), whereas authenticated
        // loopback (`X-AetherFlow-Proxy-Token`) or direct non-loopback proxy peer peels cleanly.
        let multi_tier_trusted = vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "::1".parse::<IpAddr>().unwrap(),
            "10.10.0.2".parse::<IpAddr>().unwrap(),
        ];
        let mut chain_headers = HeaderMap::new();
        chain_headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 203.0.113.44, 10.10.0.2"),
        );
        assert_eq!(
            resolve_client_ip(loopback, &chain_headers, &multi_tier_trusted),
            "10.10.0.2"
        );
        chain_headers.insert(
            PROXY_TOKEN_HEADER,
            HeaderValue::from_static("proxy-shared-secret"),
        );
        assert_eq!(
            resolve_client_ip_with_secret(
                loopback,
                &chain_headers,
                &multi_tier_trusted,
                "proxy-shared-secret"
            ),
            "203.0.113.44"
        );
        let edge_peer = Some("10.10.0.2:42311".parse::<SocketAddr>().unwrap());
        assert_eq!(
            resolve_client_ip(edge_peer, &chain_headers, &multi_tier_trusted),
            "203.0.113.44"
        );

        // obs-text (non-UTF8 bytes) injected into client XFF prefix must NOT fall through
        // to a client-spoofed X-Real-IP; rightmost proxy hop still resolves cleanly, and a
        // malformed rightmost XFF hop fails closed to peer_addr rather than X-Real-IP.
        let mut obs_prefix = HeaderMap::new();
        obs_prefix.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"\xffspoof, 198.51.100.88").unwrap(),
        );
        obs_prefix.insert("x-real-ip", HeaderValue::from_static("203.0.113.250"));
        assert_eq!(
            resolve_client_ip(loopback, &obs_prefix, &trusted),
            "198.51.100.88"
        );

        let mut obs_rightmost = HeaderMap::new();
        obs_rightmost.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"\xffbad").unwrap(),
        );
        obs_rightmost.insert("x-real-ip", HeaderValue::from_static("203.0.113.250"));
        assert_eq!(
            extract_trusted_forwarded_ip(loopback, &obs_rightmost, &trusted),
            None
        );
        assert_eq!(
            resolve_client_ip(loopback, &obs_rightmost, &trusted),
            "127.0.0.1"
        );

        // Shared proxy token secret rejects direct loopback XFF spoofing unless exact header matches
        assert_eq!(
            resolve_client_ip_with_secret(loopback, &headers, &trusted, "64hexsecret"),
            "127.0.0.1"
        );
        let mut wrong_tok = headers.clone();
        wrong_tok.insert(PROXY_TOKEN_HEADER, HeaderValue::from_static("forged"));
        assert_eq!(
            resolve_client_ip_with_secret(loopback, &wrong_tok, &trusted, "64hexsecret"),
            "127.0.0.1"
        );
        let mut dup_tok = headers.clone();
        dup_tok.append(PROXY_TOKEN_HEADER, HeaderValue::from_static("64hexsecret"));
        dup_tok.append(PROXY_TOKEN_HEADER, HeaderValue::from_static("64hexsecret"));
        assert_eq!(
            resolve_client_ip_with_secret(loopback, &dup_tok, &trusted, "64hexsecret"),
            "127.0.0.1"
        );
        let mut valid_tok = headers.clone();
        valid_tok.insert(PROXY_TOKEN_HEADER, HeaderValue::from_static("64hexsecret"));
        assert_eq!(
            resolve_client_ip_with_secret(loopback, &valid_tok, &trusted, "64hexsecret"),
            "198.51.100.77"
        );
    }

    #[test]
    fn normalizes_ipv4_mapped_and_classifies_ranges() {
        assert_eq!(normalize_ip_string("::ffff:10.0.0.42"), "10.0.0.42");
        assert_eq!(
            format_getip_display("10.0.0.42", false),
            "10.0.0.42 - private IPv4 access"
        );
        assert_eq!(
            format_getip_display("100.64.12.3", false),
            "100.64.12.3 - carrier-grade NAT IPv4 access"
        );
        assert_eq!(
            format_getip_display("fd12:3456:789a::1", false),
            "fd12:3456:789a::1 - private IPv6 access"
        );
        assert_eq!(format_getip_display("8.8.8.8", false), "8.8.8.8");
        assert_eq!(format_getip_display("8.8.8.8", true), "0.0.0.0");
        assert_eq!(format_getip_display("2001:db8::1", true), "::");
    }

    #[test]
    fn redacts_ips_and_hostnames_without_corrupting_timestamps() {
        let log = "1731638400000: connected from 203.0.113.42 via fe80::1%eth0 and ::ffff:192.0.2.9 and 2001:db8::abcd";
        let redacted_log = redact_freeform_text(log);
        assert_eq!(
            redacted_log,
            "1731638400000: connected from 0.0.0.0 via :: and :: and ::"
        );

        let isp = r#"{"processedString":"203.0.113.42 - Example","rawIspInfo":"{\"ip\":\"203.0.113.42\",\"hostname\":\"cpe-box.example.net\",\"org\":\"AS64500 FiberCo\"}"}"#;
        let redacted_isp = redact_freeform_text(isp);
        assert!(!redacted_isp.contains("203.0.113.42"));
        assert!(!redacted_isp.contains("cpe-box.example.net"));
        assert!(redacted_isp.contains("AS64500 FiberCo"));
    }

    #[test]
    fn redacts_colon_prefixed_and_label_attached_ipv6_tokens_without_false_positives() {
        let tricky = "peer:2001:4860:4860::8888 id:2001:db8::1 addr:::1 [2001:db8::abcd]:8443 peer:fe80::1%eth0 map:::ffff:198.51.100.9 mac=aa:bb:cc:dd:ee:ff ts=1731638400000: ok";
        let out = redact_freeform_text(tricky);
        assert_eq!(
            out,
            "peer::: id::: addr::: [::]:8443 peer::: map::: mac=aa:bb:cc:dd:ee:ff ts=1731638400000: ok"
        );
    }
}
