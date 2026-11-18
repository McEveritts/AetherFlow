use super::*;

pub(super) fn strip_controls(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}
pub(super) fn wireguard_listen(value: &Value) -> String {
    let status = crate::tabs::contracts::decode::<crate::tabs::contracts::WireGuardStatus>(value);
    if status.listen_port.trim().is_empty() || status.listen_port == "0" {
        "Not configured".into()
    } else {
        format!("{} / UDP", status.listen_port)
    }
}
pub(super) fn wireguard_addresses(value: &Value) -> String {
    let status = crate::tabs::contracts::decode::<crate::tabs::contracts::WireGuardStatus>(value);
    let addresses = status.addresses.joined();
    if addresses.is_empty() {
        "None assigned".into()
    } else {
        addresses
    }
}
pub(super) fn wireguard_public_key(value: &Value) -> String {
    let key =
        crate::tabs::contracts::decode::<crate::tabs::contracts::WireGuardStatus>(value).public_key;
    if key.trim().is_empty() {
        "Not generated".into()
    } else {
        key
    }
}
pub(super) fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}
pub(super) fn safe_login_url(input: &str) -> bool {
    url::Url::parse(input).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("login.tailscale.com")
            && url.username().is_empty()
            && url.password().is_none()
            && url.port_or_known_default() == Some(443)
            && url.path().starts_with("/a/")
            && url.path().len() > 3
    })
}
pub(super) fn handshake_age(context: crate::state::AppContext, peer: &Value) -> String {
    let raw = text(peer, "latest_handshake");
    if raw.is_empty() || raw == "0" {
        return tt(context, "Never");
    }
    let timestamp = raw
        .parse::<f64>()
        .map(|value| value * 1000.0)
        .unwrap_or_else(|_| js_sys::Date::parse(&raw));
    if !timestamp.is_finite() {
        return raw;
    }
    let seconds = ((js_sys::Date::now() - timestamp) / 1000.0).max(0.0);
    if seconds < 60.0 {
        tt_with(context, "{n}s ago", &[("n", &format!("{:.0}", seconds))])
    } else if seconds < 3600.0 {
        tt_with(
            context,
            "{n}m ago",
            &[("n", &format!("{:.0}", seconds / 60.0))],
        )
    } else {
        tt_with(
            context,
            "{n}h ago",
            &[("n", &format!("{:.1}", seconds / 3600.0))],
        )
    }
}
pub(super) fn peer_form(status: &Value) -> Value {
    let host = web_sys::window()
        .and_then(|w| w.location().hostname().ok())
        .unwrap_or_default();
    let port = text(&status["wireguard"], "listen_port");
    json!({
        "name":"","public_key":"","allowed_ips":text(&status["wireguard"],"next_ip"),
        "endpoint":"","keepalive":"25",
        "client_endpoint":if port.is_empty(){String::new()}else{format!("{host}:{port}")},
        "dns":"1.1.1.1, 9.9.9.9","tunnel":"full_ipv4","split":""
    })
}
pub(super) fn client_config(
    sent: &Value,
    peer: &Value,
    private: &str,
    server: &Value,
) -> Result<String, String> {
    let address = strip_controls(&text(peer, "allowed_ips"));
    let server_key = strip_controls(&text(&server["wireguard"], "public_key"));
    if address.is_empty() || server_key.is_empty() || private.is_empty() {
        return Err("The peer was saved but its assigned address or server public key is missing. Refresh network status before exporting.".into());
    }
    let allowed = if sent["tunnel"] == "split" {
        let split = strip_controls(&text(sent, "split"));
        if split.is_empty() {
            return Err("Enter the split-tunnel CIDRs before exporting".into());
        }
        split
    } else {
        "0.0.0.0/0".into()
    };
    let endpoint = strip_controls(&text(sent, "client_endpoint"));
    if endpoint.is_empty() {
        return Err("Enter the public server endpoint before exporting".into());
    }
    let dns = strip_controls(&text(sent, "dns"));
    let mut config = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {address}\n",
        strip_controls(private)
    );
    if !dns.is_empty() {
        config.push_str(&format!("DNS = {dns}\n"));
    }
    config.push_str(&format!("\n[Peer]\nPublicKey = {server_key}\nAllowedIPs = {allowed}\nEndpoint = {endpoint}\nPersistentKeepalive = {}\n",strip_controls(&text(sent,"keepalive"))));
    Ok(config)
}
