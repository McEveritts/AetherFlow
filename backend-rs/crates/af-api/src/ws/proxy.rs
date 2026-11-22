use axum::http::HeaderMap;

#[derive(Debug, Clone, Copy)]
pub struct InboundProxyForwarded(pub bool);

fn ip_matches_cidr_or_host(ip: std::net::IpAddr, raw_entry: &str) -> bool {
    let ip = ip.to_canonical();
    let trimmed = raw_entry.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Some((net_part, mask_part)) = trimmed.split_once('/') {
        let Ok(prefix_len) = mask_part.trim().parse::<u32>() else {
            return false;
        };
        let Ok(raw_net_ip) = net_part
            .trim()
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
        else {
            return false;
        };
        let net_ip = raw_net_ip.to_canonical();
        match (ip, net_ip) {
            (std::net::IpAddr::V4(v4), std::net::IpAddr::V4(net_v4)) if prefix_len <= 32 => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - prefix_len);
                (u32::from(v4) & mask) == (u32::from(net_v4) & mask)
            }
            (std::net::IpAddr::V6(v6), std::net::IpAddr::V6(net_v6)) if prefix_len <= 128 => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - prefix_len);
                (u128::from(v6) & mask) == (u128::from(net_v6) & mask)
            }
            _ => false,
        }
    } else if let Ok(exact_ip) = trimmed.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        ip == exact_ip.to_canonical()
    } else {
        false
    }
}

pub fn is_trusted_proxy_peer(ip: std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();
    if let Ok(raw) = std::env::var("TRUSTED_PROXIES") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed
                .split(',')
                .any(|entry| ip_matches_cidr_or_host(ip, entry));
        }
    }
    if let Ok(flag) = std::env::var("TRUST_PROXY_HEADERS") {
        let f = flag.trim();
        if f.eq_ignore_ascii_case("false") || f == "0" {
            return false;
        }
    }
    ip.is_loopback()
}

fn is_trusted_proxy_hop(ip: &std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();
    if let Ok(raw) = std::env::var("TRUSTED_PROXIES") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed
                .split(',')
                .any(|entry| ip_matches_cidr_or_host(ip, entry));
        }
    }
    ip.is_loopback()
}

fn extract_forwarded_ip_from_trusted_headers(headers: &HeaderMap) -> Option<std::net::IpAddr> {
    if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        // Walk right-to-left: skip trailing trusted proxy hops added locally, then pick the
        // rightmost untrusted client hop rather than any client-spoofable leftmost value.
        let mut rightmost_valid: Option<std::net::IpAddr> = None;
        for hop in xff.rsplit(',') {
            let trimmed = hop.trim().trim_matches(['[', ']']);
            let Ok(raw_ip) = trimmed.parse::<std::net::IpAddr>() else {
                continue;
            };
            let ip = raw_ip.to_canonical();
            if rightmost_valid.is_none() {
                rightmost_valid = Some(ip);
            }
            if !is_trusted_proxy_hop(&ip) {
                return Some(ip);
            }
        }
        if let Some(fallback_ip) = rightmost_valid {
            return Some(fallback_ip);
        }
    }
    if let Some(real_ip) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim().trim_matches(['[', ']']);
        if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
            return Some(ip.to_canonical());
        }
    }
    None
}

pub fn extract_client_ip(headers: &HeaderMap) -> String {
    extract_forwarded_ip_from_trusted_headers(headers)
        .map(|ip| ip.to_canonical().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

pub fn extract_client_ip_for_peer(
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
) -> String {
    let Some(raw_peer) = peer_ip else {
        return extract_client_ip(headers);
    };
    let peer = raw_peer.to_canonical();
    if !is_trusted_proxy_peer(peer) {
        return peer.to_string();
    }
    extract_forwarded_ip_from_trusted_headers(headers)
        .map(|ip| ip.to_canonical().to_string())
        .unwrap_or_else(|| peer.to_string())
}

pub fn normalize_request_forwarding_for_peer(req: &mut axum::extract::Request) {
    let had_inbound_forwarding = req.headers().contains_key("x-forwarded-for")
        || req.headers().contains_key("x-real-ip")
        || req.headers().contains_key("forwarded");
    req.extensions_mut()
        .insert(InboundProxyForwarded(had_inbound_forwarding));

    let Some(raw_peer) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip())
    else {
        return;
    };
    let peer = raw_peer.to_canonical();
    let trusted = is_trusted_proxy_peer(peer);
    let headers = req.headers_mut();
    if !trusted {
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-real-ip",
        ] {
            headers.remove(name);
        }
        if let Ok(hv) = axum::http::HeaderValue::from_str(&peer.to_string()) {
            headers.insert(axum::http::header::HeaderName::from_static("x-real-ip"), hv);
        }
    } else if extract_forwarded_ip_from_trusted_headers(headers).is_none() {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&peer.to_string()) {
            headers.insert(axum::http::header::HeaderName::from_static("x-real-ip"), hv);
        }
    }
}

pub fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    for val in headers.get_all(axum::http::header::COOKIE) {
        if let Ok(raw) = val.to_str() {
            for part in raw.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    if k.trim() == cookie_name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn build_set_cookie(
    name: &str,
    value: &str,
    max_age: i64,
    same_site: &str,
    secure: bool,
    http_only: bool,
) -> String {
    let mut parts = vec![
        format!("{}={}", name, value),
        "Path=/".to_string(),
        format!("Max-Age={}", max_age),
        format!("SameSite={}", same_site),
    ];
    if secure {
        parts.push("Secure".to_string());
    }
    if http_only {
        parts.push("HttpOnly".to_string());
    }
    parts.join("; ")
}
