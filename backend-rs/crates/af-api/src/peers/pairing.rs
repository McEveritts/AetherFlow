//! Peer pairing protocol: windows, single-use codes, public HTTPS bootstrap,
//! attempt-bound WireGuard hello/acknowledge handshake, retries, and pending cleanup.

use super::errors::PeerError;
use super::listener::{audit_listener_denial, TUNNEL_INTERNAL_BODY_LIMIT_BYTES};
use super::{
    capabilities, detect_local_endpoints, is_live_link_state, is_pending_link_state,
    is_revoked_or_revoking_state, is_revoked_state, is_revoking_state, is_wg_peer_owned, links,
    public_link_state, PeerRuntime, HEADER_LINK_TOKEN, MIN_PEER_PROTOCOL_VERSION,
    PEER_PROTOCOL_VERSION, PUBLIC_PAIRING_BODY_LIMIT_BYTES, STATE_PENDING, STATE_PENDING_OWNED,
    STATE_REVOKED, STATE_REVOKED_UNOWNED, STATE_REVOKING, STATE_REVOKING_UNOWNED,
};
use crate::auth::AuthUser;
use crate::ws::{extract_client_ip_for_peer, PeerIp};
use af_db::peers::{self as db_peers, PairingAttempt, PairingWindow, PeerIdentity, PeerLink};
use af_models::constant_time_eq;
use af_runner::{PeerCredentialSecret, PeerCredentialSlot, PeerNetworkError, PeerNetworkRequest};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Extension, Path, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use once_cell::sync::Lazy;
use rand::RngCore;
use regex::Regex;
use rusqlite::{params, Transaction, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

pub const PAIRING_STRING_PREFIX: &str = "afpair1:";
pub const PAIRING_WINDOW_TTL_SECS: i64 = 600;
pub const PAIRING_TOMBSTONE_RETENTION_SECS: i64 = 86_400;
pub const CLOCK_SKEW_MAX_SECS: i64 = 300;
pub const PAIRING_RATE_LIMIT_PER_MIN: usize = 5;
const PAIRING_RATE_LIMIT_MAX_KEYS: usize = 16_384;
const MAX_PAIRING_STRING_BYTES: usize = 4096;

static SAFE_CREDENTIAL_ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$").expect("constant peer credential id regex")
});

static SAFE_PEER_NAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$").expect("constant peer name regex")
});

// ─────────────────────────────────────────────────────────────────────────────
// Hashing, Secret Generation, Validation & Comparison Code
// ─────────────────────────────────────────────────────────────────────────────

fn zeroize_string(s: &mut String) {
    // SAFETY: Overwriting string bytes with zero bytes keeps valid UTF-8 before clearing.
    unsafe {
        for b in s.as_bytes_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    s.clear();
}

pub(crate) fn sha256_prefixed(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub(crate) fn mint_secret_token() -> PeerCredentialSecret {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = hex::encode(bytes);
    for b in &mut bytes {
        // SAFETY: `b` is a valid exclusive mutable reference within stack `bytes`.
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    PeerCredentialSecret::new(encoded)
}

/// Derives the 6-digit visual comparison code from `SHA-256(A_pubkey || B_pubkey)`.
///
/// Server A is always the initiator and server B is always the responder.
pub fn derive_comparison_code(initiator_a_pubkey: &str, responder_b_pubkey: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(initiator_a_pubkey.as_bytes());
    hasher.update(responder_b_pubkey.as_bytes());
    let digest = hasher.finalize();
    let num = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{num:06}")
}

pub(crate) fn is_valid_wg_pubkey(key: &str) -> bool {
    key.len() == 44
        && !key
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        && STANDARD
            .decode(key)
            .is_ok_and(|bytes| bytes.len() == 32 && bytes.iter().any(|b| *b != 0))
}

pub(crate) fn is_valid_credential_id(id: &str) -> bool {
    SAFE_CREDENTIAL_ID_RE.is_match(id)
}

/// Unified exclusive expiry boundary used across pairing windows, attempts, hello bootstrap/ack,
/// admin listings, and expiry sweeps: valid strictly when `now_ts < expires_at`.
#[inline]
pub(crate) const fn is_expired_at(now_ts: i64, expires_at: i64) -> bool {
    now_ts >= expires_at
}

/// Returns `true` strictly when an expiry timestamp is non-zero (never the `0` cleanup sentinel)
/// and strictly in the future under the exclusive boundary (`now_ts < expires_at`).
#[inline]
pub(crate) const fn is_active_expiry(expires_at: i64, now_ts: i64) -> bool {
    expires_at != 0 && !is_expired_at(now_ts, expires_at)
}

/// Returns `true` strictly when an optional `pending_expires_at` value is present, non-zero
/// (not cleanup-marked), and strictly in the future (`now_ts < expires_at`).
#[inline]
pub(crate) const fn has_active_pending_expiry(
    pending_expires_at: Option<i64>,
    now_ts: i64,
) -> bool {
    matches!(pending_expires_at, Some(exp) if is_active_expiry(exp, now_ts))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingExpiryStatus {
    Active(i64),
    CleanupMarked,
    Expired,
    Missing,
}

#[inline]
pub(crate) const fn classify_pending_expiry(
    pending_expires_at: Option<i64>,
    now_ts: i64,
) -> PendingExpiryStatus {
    match pending_expires_at {
        None => PendingExpiryStatus::Missing,
        Some(0) => PendingExpiryStatus::CleanupMarked,
        Some(exp) if is_expired_at(now_ts, exp) => PendingExpiryStatus::Expired,
        Some(exp) => PendingExpiryStatus::Active(exp),
    }
}

/// Authoritatively validates that a `pending`/`pending_owned` link (and any local responder
/// pairing attempt referenced by `pending_attempt_id`) has a current non-zero exclusive expiry
/// at `now_ts`.
pub(crate) fn ensure_active_pending_link_row(
    conn: &rusqlite::Connection,
    link: &PeerLink,
    now_ts: i64,
    server: &str,
    step: &str,
) -> Result<i64, PeerError> {
    let link_exp = match classify_pending_expiry(link.pending_expires_at, now_ts) {
        PendingExpiryStatus::Active(exp) => exp,
        PendingExpiryStatus::Expired => return Err(PeerError::code_expired(server, step)),
        PendingExpiryStatus::CleanupMarked => {
            return Err(PeerError::conflict(
                server,
                step,
                format!("Pending peer link '{}' is marked for cleanup", link.name),
                "Wait for cleanup to finish and restart pairing if needed",
            ));
        }
        PendingExpiryStatus::Missing => {
            return Err(PeerError::conflict(
                server,
                step,
                format!(
                    "Pending peer link '{}' has no active pairing expiry",
                    link.name
                ),
                "Restart pairing from the Cluster page",
            ));
        }
    };

    if let Some(att_id) = link.pending_attempt_id.as_deref() {
        if let Some(attempt) = db_peers::get_pairing_attempt(conn, att_id)
            .map_err(|err| PeerError::internal(server, step, err.to_string()))?
        {
            match attempt.status.as_str() {
                "cancelled" => return Err(PeerError::window_closed(server, step)),
                "failed" => {
                    return Err(PeerError::conflict(
                        server,
                        step,
                        "Pairing attempt for this pending link has already failed",
                        "Open a new pairing window and restart pairing",
                    ));
                }
                "expired" => return Err(PeerError::code_expired(server, step)),
                "pending" | "confirming" => {
                    if !is_active_expiry(attempt.expires_at, now_ts) {
                        return Err(PeerError::code_expired(server, step));
                    }
                    return Ok(link_exp.min(attempt.expires_at));
                }
                _ => {
                    return Err(PeerError::conflict(
                        server,
                        step,
                        "Pairing attempt for this pending link is no longer pending",
                        "Refresh the Cluster page and inspect the link state",
                    ));
                }
            }
        }
    }

    Ok(link_exp)
}

/// Atomically transitions a non-terminal pairing attempt (`pending` or `confirming`) to a
/// terminal status (`expired`, `cancelled`, `failed`), preserving any existing terminal or
/// completed status.
fn persist_attempt_terminal_status_conn(
    conn: &rusqlite::Connection,
    attempt_id: &str,
    attempt_status: &str,
    error_code: Option<&str>,
    require_expired_at: Option<i64>,
    server: &str,
    step: &str,
) -> Result<bool, PeerError> {
    let changed = if let Some(now_ts) = require_expired_at {
        conn.execute(
            "UPDATE peer_pairing_attempts \
             SET status = ?2, error_code = ?3 \
             WHERE id = ?1 AND status IN ('pending', 'confirming') \
               AND (expires_at = 0 OR expires_at <= ?4)",
            params![attempt_id, attempt_status, error_code, now_ts],
        )
    } else {
        conn.execute(
            "UPDATE peer_pairing_attempts \
             SET status = ?2, error_code = ?3 \
             WHERE id = ?1 AND status IN ('pending', 'confirming')",
            params![attempt_id, attempt_status, error_code],
        )
    }
    .map_err(|err| {
        PeerError::internal(
            server,
            step,
            format!("Failed updating pairing attempt status: {err}"),
        )
    })?;
    Ok(changed == 1)
}

async fn persist_attempt_terminal_status(
    runtime: &PeerRuntime,
    attempt_id: &str,
    attempt_status: &str,
    error_code: Option<&str>,
    require_expired_at: Option<i64>,
    step: &str,
) -> Result<bool, PeerError> {
    let server = runtime.local_server_name();
    let server_c = server.clone();
    let step_c = step.to_string();
    let att_id = attempt_id.to_string();
    let status_s = attempt_status.to_string();
    let code_s = error_code.map(str::to_string);
    runtime
        .db
        .write(&server, step, move |conn| {
            persist_attempt_terminal_status_conn(
                conn,
                &att_id,
                &status_s,
                code_s.as_deref(),
                require_expired_at,
                &server_c,
                &step_c,
            )
        })
        .await
}

/// Derives a runner-safe `PendingIssuerToken` credential ID strictly owned by a local `peer_links`
/// row ID, never keyed by a remote-provided attempt ID alone.
pub(crate) fn pending_issuer_credential_id(link_id: &str) -> String {
    if link_id.len() <= 59 && is_valid_credential_id(link_id) {
        format!("link-{link_id}")
    } else {
        let digest = sha256_prefixed(link_id);
        let hex_part = digest.strip_prefix("sha256:").unwrap_or(&digest);
        format!("link-{}", &hex_part[..48])
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let essence = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence == "application/json"
        || (essence.starts_with("application/") && essence.ends_with("+json"))
}

/// Enforces a strict byte cap, JSON media type, and sanitized typed JSON decoding without leaking
/// serde internals or request body fragments.
async fn extract_bounded_json<T: DeserializeOwned>(
    headers: &HeaderMap,
    body: axum::body::Body,
    max_bytes: usize,
    server: &str,
    step: &str,
) -> Result<T, PeerError> {
    if let Some(content_len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        if content_len > max_bytes {
            return Err(PeerError::payload_too_large(
                server,
                step,
                format!("Request body exceeds maximum allowed size of {max_bytes} bytes"),
                "Reduce the request payload size and retry",
            ));
        }
    }

    let collected = Limited::new(body, max_bytes)
        .collect()
        .await
        .map_err(|err| {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                PeerError::payload_too_large(
                    server,
                    step,
                    format!("Request body exceeds maximum allowed size of {max_bytes} bytes"),
                    "Reduce the request payload size and retry",
                )
            } else {
                PeerError::invalid_request(
                    server,
                    step,
                    "Request body could not be read",
                    "Retry sending a valid JSON request",
                )
            }
        })?;
    let bytes = collected.to_bytes();

    if !is_json_content_type(headers) {
        return Err(PeerError::unsupported_media_type(
            server,
            step,
            "Request Content-Type must be application/json",
            "Set Content-Type: application/json and retry",
        ));
    }

    serde_json::from_slice::<T>(&bytes).map_err(|_| {
        PeerError::invalid_request(
            server,
            step,
            "Request body must be valid JSON matching the expected schema",
            "Verify the JSON payload format and retry",
        )
    })
}

pub(crate) fn is_valid_peer_name(name: &str) -> bool {
    SAFE_PEER_NAME_RE.is_match(name)
}

pub(crate) fn validate_bare_ip(
    raw: &str,
    label: &str,
    server: &str,
    step: &str,
) -> Result<IpAddr, PeerError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains(',')
        || trimmed.chars().any(char::is_control)
    {
        return Err(PeerError::invalid_request(
            server,
            step,
            format!("{label} must be a bare IP address without a CIDR prefix"),
            "Provide a single IPv4 or IPv6 host address",
        ));
    }
    let ip: IpAddr = trimmed
        .parse::<IpAddr>()
        .map_err(|_| {
            PeerError::invalid_request(
                server,
                step,
                format!("{label} is not a valid IP address"),
                "Provide a valid IPv4 or IPv6 host address",
            )
        })?
        .to_canonical();
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(PeerError::invalid_request(
            server,
            step,
            format!("{label} must be a unicast host address"),
            "Provide a routable unicast IP address",
        ));
    }
    Ok(ip)
}

pub(crate) fn validate_endpoint_host(
    raw: &str,
    server: &str,
    step: &str,
) -> Result<String, PeerError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.starts_with('-')
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Endpoint must be a valid IP address or hostname",
            "Select a detected interface IP or enter a valid hostname without a port",
        ));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(PeerError::invalid_request(
                server,
                step,
                "Endpoint IP address cannot be unspecified or multicast",
                "Choose a reachable VLAN or public IP address",
            ));
        }
        return Ok(ip.to_string());
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(v6) = inner.parse::<Ipv6Addr>() {
            if v6.is_unspecified() || v6.is_multicast() {
                return Err(PeerError::invalid_request(
                    server,
                    step,
                    "Endpoint IPv6 address cannot be unspecified or multicast",
                    "Choose a reachable IPv6 address",
                ));
            }
            return Ok(v6.to_string());
        }
        return Err(PeerError::invalid_request(
            server,
            step,
            "Bracketed endpoint must be a valid IPv6 address",
            "Provide a valid IPv4, IPv6, or DNS hostname",
        ));
    }
    if trimmed.contains(':') || trimmed.contains('[') || trimmed.contains(']') {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Endpoint must be a bare IP address or hostname without an embedded port",
            "Supply the WireGuard UDP port separately",
        ));
    }
    let valid_host = !trimmed.ends_with('.')
        && trimmed.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !valid_host {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Endpoint must be a valid DNS hostname or IP address",
            "Enter a valid hostname or select a detected interface IP",
        ));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn format_endpoint_host_port(host: &str, port: u16) -> String {
    if let Ok(IpAddr::V6(v6)) = host.parse::<IpAddr>() {
        format!("[{v6}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn split_endpoint_host_port(raw: &str, default_port: u16) -> (String, u16) {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            if let Some(port_str) = after.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    if port > 0 {
                        return (host.to_string(), port);
                    }
                }
            }
            return (host.to_string(), default_port);
        }
    }
    if trimmed.matches(':').count() == 1 {
        if let Some((host, port_str)) = trimmed.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if port > 0 && !host.is_empty() {
                    return (host.to_string(), port);
                }
            }
        }
    }
    (trimmed.to_string(), default_port)
}

/// Validates and normalizes the public HTTPS base URL carried in a pairing string.
///
/// Enforces `https://`, forbids credentials, query strings, fragments, and non-root paths.
pub fn validate_public_https_url(raw: &str, server: &str, step: &str) -> Result<String, PeerError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Pairing HTTPS URL is missing or malformed",
            "Provide a valid https:// server origin URL",
        ));
    }
    let parsed = Url::parse(trimmed).map_err(|_| {
        PeerError::invalid_request(
            server,
            step,
            "Pairing HTTPS URL could not be parsed",
            "Provide a valid https:// server origin URL",
        )
    })?;
    if parsed.scheme() != "https" {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Public pairing requires a validated https:// URL",
            "Configure HTTPS (PUBLIC_URL) on the target server before generating a pairing string",
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Pairing HTTPS URL must be a bare origin without credentials, path, query, or fragment",
            "Use the server's root https:// origin URL",
        ));
    }
    let Some(host) = parsed.host_str() else {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Pairing HTTPS URL is missing a hostname",
            "Provide a valid https:// server origin URL",
        ));
    };
    let origin = match parsed.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    };
    Ok(origin)
}

pub(crate) fn build_public_pairing_request_url(
    https_base: &str,
    server: &str,
    step: &str,
) -> Result<Url, PeerError> {
    let origin = validate_public_https_url(https_base, server, step)?;
    Url::parse(&format!("{origin}/api/v1/peer-pairing/request")).map_err(|_| {
        PeerError::invalid_request(
            server,
            step,
            "Could not build public pairing request URL",
            "Verify the target server's HTTPS URL",
        )
    })
}

fn validate_secret_token_shape(raw: &str) -> bool {
    (32..=256).contains(&raw.len()) && raw.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

// ─────────────────────────────────────────────────────────────────────────────
// Pairing String Codec (`afpair1:<base64url(json)>`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPayload {
    pub https_url: String,
    pub wg_pubkey: String,
    pub endpoint: String,
    pub wg_port: u16,
    pub tunnel_ip: String,
    pub code: String,
}

impl Drop for PairingPayload {
    fn drop(&mut self) {
        zeroize_string(&mut self.code);
    }
}

impl fmt::Debug for PairingPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingPayload")
            .field("https_url", &self.https_url)
            .field("wg_pubkey", &self.wg_pubkey)
            .field("endpoint", &self.endpoint)
            .field("wg_port", &self.wg_port)
            .field("tunnel_ip", &self.tunnel_ip)
            .field("code", &"[REDACTED]")
            .finish()
    }
}

impl PairingPayload {
    pub fn encode(&self) -> Result<String, PeerError> {
        let json = serde_json::to_vec(self).map_err(|_| {
            PeerError::internal("local", "pairing_encode", "Failed encoding pairing payload")
        })?;
        Ok(format!(
            "{PAIRING_STRING_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(json)
        ))
    }

    pub fn decode(raw: &str, server: &str) -> Result<Self, PeerError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_PAIRING_STRING_BYTES {
            return Err(PeerError::invalid_request(
                server,
                "pairing_decode",
                "Pairing string is empty or exceeds the maximum length",
                "Copy the complete afpair1:... pairing string from the target server",
            ));
        }
        let Some(encoded) = trimmed.strip_prefix(PAIRING_STRING_PREFIX) else {
            return Err(PeerError::invalid_request(
                server,
                "pairing_decode",
                "Pairing string must start with 'afpair1:'",
                "Copy the pairing string generated on the target server",
            ));
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| URL_SAFE.decode(encoded))
            .map_err(|_| {
                PeerError::invalid_request(
                    server,
                    "pairing_decode",
                    "Pairing string is not valid base64url",
                    "Copy the pairing string again without truncating it",
                )
            })?;
        if bytes.len() > MAX_PAIRING_STRING_BYTES {
            return Err(PeerError::invalid_request(
                server,
                "pairing_decode",
                "Decoded pairing payload exceeds the size limit",
                "Generate a new pairing string on the target server",
            ));
        }
        let mut payload: Self = serde_json::from_slice(&bytes).map_err(|_| {
            PeerError::invalid_request(
                server,
                "pairing_decode",
                "Pairing string payload is malformed",
                "Generate a fresh pairing string on the target server",
            )
        })?;

        payload.https_url =
            validate_public_https_url(&payload.https_url, server, "pairing_decode")?;
        if !is_valid_wg_pubkey(&payload.wg_pubkey) {
            return Err(PeerError::invalid_request(
                server,
                "pairing_decode",
                "Pairing string contains an invalid WireGuard public key",
                "Generate a fresh pairing string on the target server",
            ));
        }
        payload.endpoint = validate_endpoint_host(&payload.endpoint, server, "pairing_decode")?;
        if payload.wg_port == 0 {
            return Err(PeerError::invalid_request(
                server,
                "pairing_decode",
                "Pairing string WireGuard port must be between 1 and 65535",
                "Generate a fresh pairing string on the target server",
            ));
        }
        let ip = validate_bare_ip(
            &payload.tunnel_ip,
            "Peer tunnel IP",
            server,
            "pairing_decode",
        )?;
        payload.tunnel_ip = ip.to_string();
        if !validate_secret_token_shape(&payload.code) {
            return Err(PeerError::invalid_request(
                server,
                "pairing_decode",
                "Pairing string contains an invalid single-use code",
                "Generate a fresh pairing string on the target server",
            ));
        }
        Ok(payload)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-Source-IP Sliding Window Rate Limiter (5 / minute, monotonic elapsed time)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct RateLimitState {
    timestamps: HashMap<String, Vec<Duration>>,
    oldest_first: BTreeSet<(Duration, String)>,
}

pub(crate) struct PairingRateLimiter {
    state: StdMutex<RateLimitState>,
    limit: usize,
    window: Duration,
}

impl PairingRateLimiter {
    pub(crate) fn new(limit: usize, window: Duration) -> Self {
        Self {
            state: StdMutex::new(RateLimitState::default()),
            limit,
            window,
        }
    }

    pub(crate) fn allow(&self, ip: &str, now: Duration) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let RateLimitState {
            timestamps,
            oldest_first,
        } = &mut *guard;

        while let Some((last_seen, _)) = oldest_first.first() {
            if now.saturating_sub(*last_seen) < self.window {
                break;
            }
            let (_, expired) = oldest_first.pop_first().expect("first entry exists");
            timestamps.remove(&expired);
        }

        if timestamps.len() >= PAIRING_RATE_LIMIT_MAX_KEYS && !timestamps.contains_key(ip) {
            if let Some((_, oldest)) = oldest_first.pop_first() {
                timestamps.remove(&oldest);
            }
        }

        let entry = timestamps.entry(ip.to_string()).or_default();
        let previous = entry.last().copied();
        entry.retain(|&ts| now.saturating_sub(ts) < self.window);
        if entry.len() >= self.limit {
            return false;
        }
        if let Some(prev) = previous {
            oldest_first.remove(&(prev, ip.to_string()));
        }
        entry.push(now);
        oldest_first.insert((now, ip.to_string()));
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request & Response DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenPairingWindowReq {
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub https_url: Option<String>,
    #[serde(default)]
    pub wg_port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartPairingReq {
    pub pairing_string: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub local_name: Option<String>,
}

impl Drop for StartPairingReq {
    fn drop(&mut self) {
        zeroize_string(&mut self.pairing_string);
    }
}

impl fmt::Debug for StartPairingReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartPairingReq")
            .field("pairing_string", &"[REDACTED]")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("local_name", &self.local_name)
            .finish()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmPairingReq {
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPairingRequest {
    pub code: String,
    pub name: String,
    pub wg_pubkey: String,
    pub endpoint: String,
    pub wg_port: u16,
    pub tunnel_ip: String,
    pub version: String,
    #[serde(default = "default_peer_protocol")]
    pub peer_protocol: i64,
    pub timestamp: i64,
}

fn default_peer_protocol() -> i64 {
    PEER_PROTOCOL_VERSION
}

impl Drop for PublicPairingRequest {
    fn drop(&mut self) {
        zeroize_string(&mut self.code);
    }
}

impl fmt::Debug for PublicPairingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicPairingRequest")
            .field("code", &"[REDACTED]")
            .field("name", &self.name)
            .field("wg_pubkey", &self.wg_pubkey)
            .field("endpoint", &self.endpoint)
            .field("wg_port", &self.wg_port)
            .field("tunnel_ip", &self.tunnel_ip)
            .field("version", &self.version)
            .field("peer_protocol", &self.peer_protocol)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPairingResponse {
    pub attempt_id: String,
    pub comparison_code: String,
    pub expires_at: i64,
    pub server_name: String,
    pub version: String,
    pub peer_protocol: i64,
}

impl fmt::Debug for PublicPairingResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicPairingResponse")
            .field("attempt_id", &self.attempt_id)
            .field("comparison_code", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("server_name", &self.server_name)
            .field("version", &self.version)
            .field("peer_protocol", &self.peer_protocol)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloPhase {
    Bootstrap,
    Acknowledge,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloRequest {
    pub phase: HelloPhase,
    pub attempt_id: String,
    pub wg_pubkey: String,
    #[serde(default)]
    pub tunnel_ip: Option<String>,
    pub version: String,
    pub peer_protocol: i64,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_token: Option<PeerCredentialSecret>,
}

impl fmt::Debug for HelloRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloRequest")
            .field("phase", &self.phase)
            .field("attempt_id", &self.attempt_id)
            .field("wg_pubkey", &self.wg_pubkey)
            .field("tunnel_ip", &self.tunnel_ip)
            .field("version", &self.version)
            .field("peer_protocol", &self.peer_protocol)
            .field("capabilities", &self.capabilities)
            .field(
                "link_token",
                &self.link_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct HelloResponse {
    pub phase: HelloPhase,
    pub attempt_id: String,
    pub acknowledged: bool,
    pub state: String,
    pub wg_pubkey: String,
    pub version: String,
    pub peer_protocol: i64,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_token: Option<PeerCredentialSecret>,
}

impl fmt::Debug for HelloResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloResponse")
            .field("phase", &self.phase)
            .field("attempt_id", &self.attempt_id)
            .field("acknowledged", &self.acknowledged)
            .field("state", &self.state)
            .field("wg_pubkey", &self.wg_pubkey)
            .field("version", &self.version)
            .field("peer_protocol", &self.peer_protocol)
            .field("capabilities", &self.capabilities)
            .field(
                "link_token",
                &self.link_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared Runner Helpers (Identity, Reconciliation & Cleanup)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn ensure_local_identity(
    runtime: &Arc<PeerRuntime>,
    avoid_tunnel_ips: &[String],
    wg_port: Option<u16>,
    step: &str,
) -> Result<PeerIdentity, PeerError> {
    let server = runtime.local_server_name();
    let existing = runtime
        .db
        .read(&server, step, |conn| {
            db_peers::get_peer_identity(conn)
                .map_err(|err| PeerError::internal("local", "ensure_identity", err.to_string()))
        })
        .await?;

    let req = PeerNetworkRequest::EnsureIdentity {
        tunnel_ip: existing.as_ref().map(|id| id.tunnel_ip.clone()),
        avoid_tunnel_ips: avoid_tunnel_ips.to_vec(),
        wg_port: wg_port.or_else(|| existing.as_ref().map(|id| id.wg_port)),
        tunnel_cidr: None,
    };

    let identity_resp = runtime
        .runner
        .dispatch(&req)
        .await
        .and_then(|resp| resp.into_identity())
        .map_err(|err| map_runner_error(err, &server, step))?;

    let created_at = existing
        .map(|id| id.created_at)
        .unwrap_or_else(|| runtime.now().to_rfc3339());
    let identity = PeerIdentity {
        wg_pubkey: identity_resp.public_key,
        tunnel_ip: identity_resp.tunnel_ip,
        wg_port: identity_resp.wg_port,
        created_at,
    };

    let to_store = identity.clone();
    runtime
        .db
        .write(&server, step, move |conn| {
            db_peers::upsert_peer_identity(conn, &to_store).map_err(|err| {
                PeerError::internal(
                    "local",
                    "ensure_identity",
                    format!("Failed saving peer identity: {err}"),
                )
            })
        })
        .await?;

    let _ = runtime.ensure_listener_started().await?;
    Ok(identity)
}

pub(crate) fn map_runner_error(err: PeerNetworkError, server: &str, step: &str) -> PeerError {
    match err {
        PeerNetworkError::TunnelIpConflict(msg) => PeerError::tunnel_ip_conflict(server, step, msg),
        PeerNetworkError::Busy(msg) => PeerError::busy(server, step, msg),
        PeerNetworkError::InvalidInput(msg) => PeerError::invalid_request(
            server,
            step,
            msg,
            "Correct the peer network parameters and retry",
        ),
        PeerNetworkError::PeerAlreadyExists(msg) | PeerNetworkError::Conflict(msg) => {
            PeerError::key_mismatch(server, step, msg)
        }
        PeerNetworkError::PeerNotFound(msg) | PeerNetworkError::NotFound(msg) => {
            PeerError::not_found(server, step, msg)
        }
        PeerNetworkError::Runtime(msg) => PeerError::internal(server, step, msg),
    }
}

/// Removes a WireGuard peer via the runner, treating `PeerNotFound` / `NotFound` as
/// already-completed cleanup.
pub(crate) async fn remove_wg_peer_idempotent(
    runtime: &PeerRuntime,
    pubkey: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    if !is_valid_wg_pubkey(pubkey) {
        return Ok(());
    }
    let req = PeerNetworkRequest::RemovePeer {
        pubkey: pubkey.to_string(),
    };
    match runtime.runner.dispatch(&req).await {
        Ok(_) => Ok(()),
        Err(PeerNetworkError::PeerNotFound(_)) | Err(PeerNetworkError::NotFound(_)) => Ok(()),
        Err(err) => Err(map_runner_error(err, server, step)),
    }
}

/// Consumes the removal authorization before dispatch. Only a runner lock refusal
/// proves that dispatch made no mutation and leaves the operation safe to retry.
pub(crate) async fn remove_owned_wg_peer_locked(
    runtime: &PeerRuntime,
    link: &PeerLink,
    step: &str,
) -> Result<(), PeerError> {
    let (owned, released) = match link.state.as_str() {
        STATE_PENDING_OWNED => (STATE_PENDING_OWNED, STATE_PENDING),
        STATE_REVOKED => (STATE_REVOKED, STATE_REVOKED_UNOWNED),
        STATE_REVOKING => (STATE_REVOKING, STATE_REVOKING_UNOWNED),
        _ => return Ok(()),
    };

    set_cleanup_link_state(runtime, link, owned, released, step).await?;
    let result =
        remove_wg_peer_idempotent(runtime, &link.wg_pubkey, &runtime.local_server_name(), step)
            .await;
    if let Err(err) = &result {
        if err.code() == "PEER_BUSY" {
            set_cleanup_link_state(runtime, link, released, owned, step).await?;
        } else {
            tracing::warn!(
                link_id = %link.id,
                code = err.code(),
                "WireGuard removal could not be confirmed; inspect afpeer0 before re-pairing"
            );
        }
    }
    result
}

async fn set_cleanup_link_state(
    runtime: &PeerRuntime,
    link: &PeerLink,
    expected_state: &'static str,
    next_state: &'static str,
    step: &str,
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let server_c = server.clone();
    let step_c = step.to_string();
    let link_id = link.id.clone();
    let pubkey = link.wg_pubkey.clone();
    let attempt_id = link.pending_attempt_id.clone();
    let now = runtime.now().to_rfc3339();
    runtime
        .db
        .write(&server, step, move |conn| {
            let changed = conn
                .execute(
                    "UPDATE peer_links SET state = ?5, pending_expires_at = 0, updated_at = ?6
                     WHERE id = ?1 AND wg_pubkey = ?2 AND pending_attempt_id IS ?3 AND state = ?4
                       AND NOT EXISTS (
                           SELECT 1 FROM peer_links WHERE wg_pubkey = ?2 AND id != ?1
                       )",
                    params![link_id, pubkey, attempt_id, expected_state, next_state, now],
                )
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
            if changed != 1 {
                return Err(PeerError::conflict(
                    &server_c,
                    &step_c,
                    "Peer link changed during cleanup",
                    "Refresh the Cluster page and retry",
                ));
            }
            Ok(())
        })
        .await
}

/// Removes held outbound link/grant credentials for `link_id`, treating `NotFound` as already
/// cleaned up and propagating transient runner errors.
pub(crate) async fn delete_link_credentials_idempotent(
    runtime: &PeerRuntime,
    link_id: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    if !is_valid_credential_id(link_id) {
        return Ok(());
    }
    match runtime
        .runner
        .dispatch(&PeerNetworkRequest::DeleteLinkCredentials {
            link_id: link_id.to_string(),
        })
        .await
    {
        Ok(_) | Err(PeerNetworkError::NotFound(_)) => Ok(()),
        Err(err) => Err(map_runner_error(err, server, step)),
    }
}

/// Removes the link-namespaced temporary `PendingIssuerToken`, treating `NotFound` as already
/// cleaned up and propagating transient runner errors.
pub(crate) async fn delete_pending_issuer_credential_idempotent(
    runtime: &PeerRuntime,
    link_id: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    let cred_id = pending_issuer_credential_id(link_id);
    match runtime
        .runner
        .dispatch(&PeerNetworkRequest::DeleteCredential {
            slot: PeerCredentialSlot::PendingIssuerToken,
            id: cred_id,
        })
        .await
    {
        Ok(_) | Err(PeerNetworkError::NotFound(_)) => Ok(()),
        Err(err) => Err(map_runner_error(err, server, step)),
    }
}

/// Reconciles `PeerAlreadyExists` from `AddPeer` against the pending peer's expected key and
/// tunnel IP by inspecting live/persistent runner status.
async fn reconcile_existing_pending_peer(
    runtime: &PeerRuntime,
    expected_pubkey: &str,
    expected_tunnel_ip: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    let status = runtime
        .runner
        .dispatch(&PeerNetworkRequest::Status)
        .await
        .and_then(|resp| resp.into_status())
        .map_err(|err| map_runner_error(err, server, step))?;

    let expected_ip: IpAddr = expected_tunnel_ip
        .trim()
        .parse()
        .map_err(|_| PeerError::key_mismatch(server, step, "Invalid pending peer tunnel IP"))?;

    let matched = status
        .peers
        .iter()
        .find(|p| p.public_key == expected_pubkey);
    let Some(peer) = matched else {
        return Err(PeerError::key_mismatch(
            server,
            step,
            "WireGuard reported an existing peer but status did not contain the expected key",
        ));
    };

    let allowed_matches = peer.allowed_ips.split(',').any(|entry| {
        let bare = entry.trim().split('/').next().unwrap_or("");
        bare.parse::<IpAddr>().ok() == Some(expected_ip)
    });
    if !allowed_matches {
        return Err(PeerError::tunnel_ip_conflict(
            server,
            step,
            "Existing WireGuard peer entry uses a different tunnel IP than the pending attempt",
        ));
    }
    Ok(())
}

/// Records affirmative durable WireGuard peer ownership (`pending_owned`) strictly after a
/// definitive successful `PeerNetworkRequest::AddPeer` (`Ok(Mutation)`).
///
/// This is a cleanup-only ownership recording, never an authorizing transition: it preserves
/// `pending_expires_at` (never reviving `0` or an expired TTL) and returns the committed row's
/// authoritative `pending_expires_at` so callers can immediately abort and clean up if the
/// allocation expired or was marked for cleanup during `AddPeer`.
///
/// On ownership DB write failure:
/// - Never removes an unverified peer (row missing, non-pending, mismatched key/IP/attempt, or
///   shared pubkey).
/// - If the verified row is already `pending_owned`, delegates exclusively to
///   `cleanup_pending_link_locked` so `remove_owned_wg_peer_locked` durably consumes removal
///   authority before dispatching at most one `RemovePeer`.
/// - If the verified row is still `pending` (unowned because this write failed), deletes
///   credentials first, issues at most one direct `RemovePeer`, then cleans up the unowned DB row
///   (which cannot reissue `RemovePeer`).
async fn commit_pending_wg_ownership_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    wg_pubkey: &str,
    tunnel_ip: &str,
    expected_attempt_id: Option<&str>,
    step: &str,
) -> Result<Option<i64>, PeerError> {
    let server = runtime.local_server_name();
    let lid_c = link_id.to_string();
    let pk_c = wg_pubkey.to_string();
    let ip_c = tunnel_ip.to_string();
    let att_c = expected_attempt_id.map(str::to_string);
    let clock = Arc::clone(&runtime.clock);
    let server_c = server.clone();
    let step_c = step.to_string();

    let commit_res = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        &step_c,
                        format!("Failed starting ownership persistence transaction: {err}"),
                    )
                },
            )?;
            let now_rfc = clock().to_rfc3339();
            let changed = tx
                .execute(
                    "UPDATE peer_links \
                     SET state = 'pending_owned', updated_at = ?5 \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND state IN ('pending', 'pending_owned') \
                       AND pending_attempt_id IS ?4",
                    params![lid_c, pk_c, ip_c, att_c, now_rfc],
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        &step_c,
                        format!("Failed persisting durable WireGuard peer ownership: {err}"),
                    )
                })?;
            if changed != 1 {
                return Err(PeerError::conflict(
                    &server_c,
                    &step_c,
                    "Pending peer link changed or disappeared before WireGuard ownership could be persisted",
                    "Retry pairing from the Cluster page",
                ));
            }
            let committed_expires_at: Option<i64> = tx
                .query_row(
                    "SELECT pending_expires_at FROM peer_links WHERE id = ?1",
                    params![lid_c],
                    |r| r.get(0),
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        &step_c,
                        format!("Failed reading committed pending expiry: {err}"),
                    )
                })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    &step_c,
                    format!("Failed committing durable WireGuard peer ownership: {err}"),
                )
            })?;
            Ok(committed_expires_at)
        })
        .await;

    match commit_res {
        Ok(committed_expires_at) => Ok(committed_expires_at),
        Err(err) => {
            enum OwnershipFallbackAction {
                UnverifiedDoNotRemove,
                CleanupOwnedViaCheckpoint,
                DirectRollbackUnowned,
            }

            let pk_check = wg_pubkey.to_string();
            let lid_check = link_id.to_string();
            let ip_check = tunnel_ip.to_string();
            let att_check = expected_attempt_id.map(str::to_string);
            let fallback_action = runtime
                .db
                .read(&server, step, move |conn| {
                    let Some(row) = db_peers::get_peer_link(conn, &lid_check).map_err(|e| {
                        PeerError::internal("local", "pending_ownership", e.to_string())
                    })?
                    else {
                        return Ok(OwnershipFallbackAction::UnverifiedDoNotRemove);
                    };
                    if !is_pending_link_state(&row.state)
                        || row.wg_pubkey != pk_check
                        || row.tunnel_ip != ip_check
                        || row.pending_attempt_id != att_check
                    {
                        return Ok(OwnershipFallbackAction::UnverifiedDoNotRemove);
                    }
                    let other_owners: i64 = conn
                        .query_row(
                            "SELECT COUNT(*) FROM peer_links WHERE wg_pubkey = ?1 AND id != ?2",
                            params![pk_check, lid_check],
                            |r| r.get(0),
                        )
                        .map_err(|e| {
                            PeerError::internal("local", "pending_ownership", e.to_string())
                        })?;
                    if other_owners != 0 {
                        return Ok(OwnershipFallbackAction::UnverifiedDoNotRemove);
                    }
                    if row.state == STATE_PENDING_OWNED {
                        Ok(OwnershipFallbackAction::CleanupOwnedViaCheckpoint)
                    } else {
                        Ok(OwnershipFallbackAction::DirectRollbackUnowned)
                    }
                })
                .await
                .unwrap_or(OwnershipFallbackAction::UnverifiedDoNotRemove);

            match fallback_action {
                OwnershipFallbackAction::UnverifiedDoNotRemove => {
                    tracing::warn!(
                        link_id = %link_id,
                        code = err.code(),
                        "Skipping WireGuard rollback after ownership DB error because peer row could not be verified"
                    );
                }
                OwnershipFallbackAction::CleanupOwnedViaCheckpoint => {
                    // Row already has durable `pending_owned`; let `cleanup_pending_link_locked`
                    // consume removal authority before issuing at most one `RemovePeer`.
                    let _ = cleanup_pending_link_locked(
                        runtime,
                        link_id,
                        wg_pubkey,
                        expected_attempt_id,
                        "failed",
                        Some(err.code()),
                    )
                    .await;
                }
                OwnershipFallbackAction::DirectRollbackUnowned => {
                    // Row is verified `pending` (unowned because our DB write failed). Delete
                    // credentials first, issue a single rollback `RemovePeer`, then clean up the
                    // unowned DB row (which sees `pending` and can never reissue `RemovePeer`).
                    let creds_ok =
                        delete_link_credentials_idempotent(runtime, link_id, &server, step)
                            .await
                            .is_ok()
                            && delete_pending_issuer_credential_idempotent(
                                runtime, link_id, &server, step,
                            )
                            .await
                            .is_ok();
                    if creds_ok {
                        if let Err(rm_err) =
                            remove_wg_peer_idempotent(runtime, wg_pubkey, &server, step).await
                        {
                            tracing::warn!(
                                link_id = %link_id,
                                %rm_err,
                                "Rollback of newly added WireGuard peer failed after ownership DB commit error; reconcile afpeer0 before re-pairing"
                            );
                        }
                    } else {
                        tracing::warn!(
                            link_id = %link_id,
                            "Skipping direct WireGuard rollback after ownership DB error because credential deletion failed; reconcile afpeer0 before re-pairing"
                        );
                    }
                    if cleanup_pending_link_locked(
                        runtime,
                        link_id,
                        wg_pubkey,
                        expected_attempt_id,
                        "failed",
                        Some(err.code()),
                    )
                    .await
                    .is_err()
                    {
                        if let Some(att_id) = expected_attempt_id {
                            let _ = persist_attempt_terminal_status(
                                runtime,
                                att_id,
                                "failed",
                                Some(err.code()),
                                None,
                                step,
                            )
                            .await;
                        }
                    }
                }
            }
            Err(err)
        }
    }
}

/// Durably demotes a pending peer link to unowned (`pending`) with immediate cleanup expiry (`0`)
/// and promptly persists terminal attempt failure before running cleanup after a conflicting or
/// failed `AddPeer`/reconciliation outcome.
///
/// Guarantees neither immediate cleanup nor any subsequent in-process or post-restart retry can
/// remove an unrelated WireGuard peer.
async fn demote_pending_wg_ownership_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    wg_pubkey: &str,
    expected_attempt_id: Option<&str>,
    error_code: Option<&str>,
    reason: &str,
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let server_c = server.clone();
    let lid_c = link_id.to_string();
    let pk_c = wg_pubkey.to_string();
    let att_c = expected_attempt_id.map(str::to_string);
    let err_code_c = error_code.map(str::to_string);
    let reason_c = reason.to_string();
    let now_rfc = runtime.now().to_rfc3339();
    runtime
        .db
        .write(&server, "pending_cleanup", move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        "pending_cleanup",
                        format!("Failed starting unowned pending cleanup transaction: {err}"),
                    )
                },
            )?;
            let changed = tx
                .execute(
                    "UPDATE peer_links \
                     SET state = 'pending', pending_expires_at = 0, last_error = ?4, updated_at = ?5 \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND state IN ('pending', 'pending_owned') \
                       AND pending_attempt_id IS ?3",
                    params![lid_c, pk_c, att_c, reason_c, now_rfc],
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        "pending_cleanup",
                        format!("Failed recording unowned pending cleanup state: {err}"),
                    )
                })?;
            if changed == 1 {
                if let Some(ref att_id) = att_c {
                    persist_attempt_terminal_status_conn(
                        &tx,
                        att_id,
                        "failed",
                        err_code_c.as_deref(),
                        None,
                        &server_c,
                        "pending_cleanup",
                    )?;
                }
            }
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    "pending_cleanup",
                    format!("Failed committing unowned pending cleanup state: {err}"),
                )
            })?;
            Ok(())
        })
        .await
}

/// Marks a contended pending rollback for the next sweep, preserving ownership and optionally
/// persisting terminal pairing attempt status in the same transaction.
async fn mark_pending_cleanup_retry(
    runtime: &PeerRuntime,
    link_id: &str,
    expected_pubkey: &str,
    expected_attempt_id: Option<&str>,
    attempt_terminal: Option<(&str, Option<&str>)>,
    reason: &str,
) {
    let server = runtime.local_server_name();
    let server_c = server.clone();
    let link_id_s = link_id.to_string();
    let pk_s = expected_pubkey.to_string();
    let att_s = expected_attempt_id.map(str::to_string);
    let att_terminal =
        attempt_terminal.map(|(st, code)| (st.to_string(), code.map(str::to_string)));
    let reason_s = reason.to_string();
    let now_rfc = runtime.now().to_rfc3339();
    if let Err(err) = runtime
        .db
        .write(&server, "pending_cleanup", move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| PeerError::internal(&server_c, "pending_cleanup", err.to_string()),
            )?;
            tx.execute(
                "UPDATE peer_links SET pending_expires_at = 0, last_error = ?4, updated_at = ?5
                 WHERE id = ?1 AND wg_pubkey = ?2 AND state IN ('pending', 'pending_owned')
                   AND pending_attempt_id IS ?3",
                params![link_id_s, pk_s, att_s, reason_s, now_rfc],
            )
            .map_err(|err| PeerError::internal(&server_c, "pending_cleanup", err.to_string()))?;
            if let (Some(ref att_id), Some((ref status, ref code))) = (&att_s, &att_terminal) {
                persist_attempt_terminal_status_conn(
                    &tx,
                    att_id,
                    status,
                    code.as_deref(),
                    None,
                    &server_c,
                    "pending_cleanup",
                )?;
            }
            tx.commit().map_err(|err| {
                PeerError::internal(&server_c, "pending_cleanup", err.to_string())
            })?;
            Ok(())
        })
        .await
    {
        tracing::warn!(
            link_id,
            code = err.code(),
            "Could not persist pending cleanup marker"
        );
    }
}

/// Cleans up a single currently owned pending link and its associated runner-managed credentials,
/// removing the WireGuard peer strictly when the authoritative SQLite row records affirmative
/// durable ownership (`state = 'pending_owned'`).
///
/// Caller MUST hold `runtime.lock_link(link_id)` (and `runtime.lock_attempt(att)` first if
/// `expected_attempt_id.is_some()`). On transient runner failure, keeps durable cleanup ownership
/// in SQLite (`pending_expires_at = 0`) and promptly persisted terminal attempt status while
/// preserving (or demoting after `RemovePeer`) the durable WireGuard ownership marker, and
/// propagates the error.
pub(crate) async fn cleanup_pending_link_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    expected_pubkey: &str,
    expected_attempt_id: Option<&str>,
    attempt_status: &str,
    error_code: Option<&str>,
) -> Result<bool, PeerError> {
    let server = runtime.local_server_name();
    let step = "pending_cleanup";

    let link_id_check = link_id.to_string();
    let pk_check = expected_pubkey.to_string();
    let att_check = expected_attempt_id.map(str::to_string);
    let pending_link = runtime
        .db
        .read(&server, step, move |conn| {
            let current = db_peers::get_peer_link(conn, &link_id_check)
                .map_err(|err| PeerError::internal("local", "pending_cleanup", err.to_string()))?;
            let Some(row) = current else {
                return Ok(None);
            };
            if !is_pending_link_state(&row.state)
                || row.wg_pubkey != pk_check
                || row.pending_attempt_id != att_check
            {
                return Ok(None);
            }
            let other_owner_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM peer_links WHERE wg_pubkey = ?1 AND id != ?2",
                    params![pk_check, link_id_check],
                    |r| r.get(0),
                )
                .map_err(|err| PeerError::internal("local", "pending_cleanup", err.to_string()))?;
            if other_owner_count != 0 {
                return Ok(None);
            }
            Ok(Some(row))
        })
        .await?;

    let Some(link) = pending_link else {
        return Ok(false);
    };

    // Make the cleanup eligible for a sweep and persist terminal attempt status before any runner
    // call can fail transiently.
    if link.pending_expires_at != Some(0) {
        let state = if is_wg_peer_owned(&link.state) {
            STATE_PENDING_OWNED
        } else {
            STATE_PENDING
        };
        set_cleanup_link_state(runtime, &link, state, state, step).await?;
    }
    if let Some(att_id) = expected_attempt_id {
        persist_attempt_terminal_status(runtime, att_id, attempt_status, error_code, None, step)
            .await?;
    }
    delete_link_credentials_idempotent(runtime, link_id, &server, step).await?;
    delete_pending_issuer_credential_idempotent(runtime, link_id, &server, step).await?;
    remove_owned_wg_peer_locked(runtime, &link, step).await?;

    let link_id_del = link_id.to_string();
    let pk_del = expected_pubkey.to_string();
    let att_del = expected_attempt_id.map(str::to_string);
    let attempt_status_s = attempt_status.to_string();
    let error_code_s = error_code.map(str::to_string);
    let server_c = server.clone();

    let deleted = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        "pending_cleanup",
                        format!("Failed starting pending cleanup transaction: {err}"),
                    )
                },
            )?;

            let changed = tx
                .execute(
                    "DELETE FROM peer_links \
                     WHERE id = ?1 AND state IN ('pending', 'pending_owned') \
                       AND wg_pubkey = ?2 AND pending_attempt_id IS ?3",
                    params![link_id_del, pk_del, att_del],
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        "pending_cleanup",
                        format!("Failed deleting pending peer link: {err}"),
                    )
                })?;

            if changed == 1 {
                if let Some(ref att_id) = att_del {
                    persist_attempt_terminal_status_conn(
                        &tx,
                        att_id,
                        &attempt_status_s,
                        error_code_s.as_deref(),
                        None,
                        &server_c,
                        "pending_cleanup",
                    )?;
                }
            }

            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    "pending_cleanup",
                    format!("Failed committing pending cleanup transaction: {err}"),
                )
            })?;
            Ok(changed == 1)
        })
        .await?;

    Ok(deleted)
}

/// Sweeps pending revocation cleanups, expired pending links, expired pairing attempts,
/// stale temporary issuer credentials, and expired acknowledgement windows on active/down links.
pub(crate) async fn cleanup_expired_pending(runtime: &PeerRuntime) {
    let now_ts = runtime.now().timestamp();
    let server = runtime.local_server_name();

    let snapshot = runtime
        .db
        .read(&server, "pending_sweep", |conn| {
            let links = db_peers::list_peer_links(conn).unwrap_or_default();
            let attempts = db_peers::list_pairing_attempts(conn).unwrap_or_default();
            Ok((links, attempts))
        })
        .await;

    let Ok((links, attempts)) = snapshot else {
        return;
    };

    for link in links {
        // 1. Retry any pending revocation cleanups (`revoking*` or `revoked*` with pending marker).
        if is_revoking_state(&link.state)
            || (is_revoked_state(&link.state) && link.pending_expires_at.is_some())
        {
            if let Err(error) = links::retry_revocation_cleanup(runtime, &link.id).await {
                tracing::warn!(
                    link_id = %link.id,
                    %error,
                    "Pending revocation cleanup retry failed; will retry on next sweep"
                );
            }
            continue;
        }

        // 2. Clean up expired pending links under canonical lock ordering (attempt -> link).
        if is_pending_link_state(&link.state) {
            if !link
                .pending_expires_at
                .is_some_and(|exp| !is_active_expiry(exp, now_ts))
            {
                continue;
            }
            let _att_guard = match link.pending_attempt_id.as_deref() {
                Some(att_id) => match runtime.lock_attempt(att_id, "pending_sweep").await {
                    Ok(g) => Some(g),
                    Err(_) => continue,
                },
                None => None,
            };
            let Ok(_link_guard) = runtime.lock_link(&link.id, "pending_sweep").await else {
                continue;
            };

            let id_c = link.id.clone();
            let current = match runtime
                .db
                .read(&server, "pending_sweep", move |conn| {
                    db_peers::get_peer_link(conn, &id_c).map_err(|err| {
                        PeerError::internal("local", "pending_sweep", err.to_string())
                    })
                })
                .await
            {
                Ok(Some(row)) => row,
                _ => continue,
            };

            let fresh_now_ts = runtime.now().timestamp();
            if !is_pending_link_state(&current.state)
                || !current
                    .pending_expires_at
                    .is_some_and(|exp| !is_active_expiry(exp, fresh_now_ts))
            {
                continue;
            }
            if current.pending_attempt_id != link.pending_attempt_id {
                continue;
            }

            if let Err(error) = cleanup_pending_link_locked(
                runtime,
                &current.id,
                &current.wg_pubkey,
                current.pending_attempt_id.as_deref(),
                "expired",
                Some("CODE_EXPIRED"),
            )
            .await
            {
                tracing::warn!(
                    link_id = %current.id,
                    %error,
                    "Failed cleaning up expired pending peer link; retained durable retry state"
                );
            }
            continue;
        }

        // 3. Clean up expired ack windows / residual PendingIssuerToken on active or down links.
        if is_live_link_state(&link.state)
            && (link.pending_attempt_id.is_some() || link.pending_expires_at.is_some())
            && !has_active_pending_expiry(link.pending_expires_at, now_ts)
        {
            let _att_guard = match link.pending_attempt_id.as_deref() {
                Some(att_id) => match runtime.lock_attempt(att_id, "pending_sweep").await {
                    Ok(g) => Some(g),
                    Err(_) => continue,
                },
                None => None,
            };
            let Ok(_link_guard) = runtime.lock_link(&link.id, "pending_sweep").await else {
                continue;
            };

            let id_c = link.id.clone();
            let current = match runtime
                .db
                .read(&server, "pending_sweep", move |conn| {
                    db_peers::get_peer_link(conn, &id_c).map_err(|err| {
                        PeerError::internal("local", "pending_sweep", err.to_string())
                    })
                })
                .await
            {
                Ok(Some(row)) => row,
                _ => continue,
            };

            let fresh_now_ts = runtime.now().timestamp();
            if !is_live_link_state(&current.state)
                || (current.pending_attempt_id.is_none() && current.pending_expires_at.is_none())
                || has_active_pending_expiry(current.pending_expires_at, fresh_now_ts)
            {
                continue;
            }

            // Only clear DB tracking columns once PendingIssuerToken removal succeeds.
            if let Err(error) = delete_pending_issuer_credential_idempotent(
                runtime,
                &current.id,
                &server,
                "pending_sweep",
            )
            .await
            {
                tracing::warn!(
                    link_id = %current.id,
                    %error,
                    "Transient error removing residual PendingIssuerToken; will retry on next sweep"
                );
                continue;
            }

            let upd_id = current.id.clone();
            let expected_att = current.pending_attempt_id.clone();
            let expected_exp = current.pending_expires_at;
            let now_rfc = runtime.now().to_rfc3339();
            let _ = runtime
                .db
                .write(&server, "pending_sweep", move |conn| {
                    let _ = conn.execute(
                        "UPDATE peer_links \
                         SET pending_attempt_id = NULL, pending_expires_at = NULL, updated_at = ?4 \
                         WHERE id = ?1 AND state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                           AND pending_attempt_id IS ?2 AND pending_expires_at IS ?3",
                        params![upd_id, expected_att, expected_exp, now_rfc],
                    );
                    Ok(())
                })
                .await;
        }
    }

    // 4. Expire unlinked pairing attempts without touching any WireGuard peer owned by another link.
    for attempt in attempts {
        if !matches!(attempt.status.as_str(), "pending" | "confirming")
            || is_active_expiry(attempt.expires_at, now_ts)
        {
            continue;
        }
        let Ok(_att_guard) = runtime.lock_attempt(&attempt.id, "pending_sweep").await else {
            continue;
        };

        let att_id = attempt.id.clone();
        let linked_pending = match runtime
            .db
            .read(&server, "pending_sweep", move |conn| {
                let link = db_peers::list_peer_links(conn)
                    .unwrap_or_default()
                    .into_iter()
                    .find(|l| {
                        is_pending_link_state(&l.state)
                            && l.pending_attempt_id.as_deref() == Some(att_id.as_str())
                    });
                Ok(link)
            })
            .await
        {
            Ok(val) => val,
            Err(_) => continue,
        };

        let fresh_now_ts = runtime.now().timestamp();
        if let Some(pending_link) = linked_pending {
            let Ok(_link_guard) = runtime.lock_link(&pending_link.id, "pending_sweep").await else {
                let _ = persist_attempt_terminal_status(
                    runtime,
                    &attempt.id,
                    "expired",
                    Some("CODE_EXPIRED"),
                    Some(fresh_now_ts),
                    "pending_sweep",
                )
                .await;
                continue;
            };
            let _ = cleanup_pending_link_locked(
                runtime,
                &pending_link.id,
                &pending_link.wg_pubkey,
                Some(&attempt.id),
                "expired",
                Some("CODE_EXPIRED"),
            )
            .await;
        } else {
            let _ = persist_attempt_terminal_status(
                runtime,
                &attempt.id,
                "expired",
                Some("CODE_EXPIRED"),
                Some(fresh_now_ts),
                "pending_sweep",
            )
            .await;
        }
    }

    // Prune pairing window tombstones older than 24h so recently expired/used codes still yield
    // distinct CODE_EXPIRED / CODE_USED errors.
    let tombstone_cutoff = now_ts.saturating_sub(PAIRING_TOMBSTONE_RETENTION_SECS);
    let _ = runtime
        .db
        .write(&server, "pending_sweep", move |conn| {
            let _ = conn.execute(
                "DELETE FROM peer_pairing_windows WHERE expires_at < ?1 AND (consumed_at IS NULL OR consumed_at < ?1)",
                params![tombstone_cutoff],
            );
            Ok(())
        })
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1: Open & Close Pairing Window (Server B)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn open_pairing_window(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    payload: Option<Json<OpenPairingWindowReq>>,
) -> Response {
    let req = payload.map(|Json(v)| v).unwrap_or_default();
    match open_pairing_window_inner(&runtime, &auth_user, peer_ip, &headers, req).await {
        Ok(val) => (
            StatusCode::CREATED,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn open_pairing_window_inner(
    runtime: &Arc<PeerRuntime>,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    req: OpenPairingWindowReq,
) -> Result<serde_json::Value, PeerError> {
    let server = runtime.local_server_name();
    let step = "open_pairing_window";

    let raw_https = match req.https_url {
        Some(url) => url,
        None => crate::oidc::get_base_url_for_peer(headers, peer_ip),
    };
    let https_url = validate_public_https_url(&raw_https, &server, step)?;

    let endpoint = match req.endpoint {
        Some(ep) => validate_endpoint_host(&ep, &server, step)?,
        None => {
            if let Some(detected) = detect_local_endpoints().into_iter().next() {
                detected.address
            } else {
                let parsed = Url::parse(&https_url).map_err(|_| {
                    PeerError::invalid_request(
                        &server,
                        step,
                        "Could not derive a WireGuard endpoint from the HTTPS URL",
                        "Specify an explicit endpoint IP address or hostname",
                    )
                })?;
                let host = parsed.host_str().ok_or_else(|| {
                    PeerError::invalid_request(
                        &server,
                        step,
                        "No local WireGuard endpoint could be detected",
                        "Specify an explicit endpoint IP address or hostname",
                    )
                })?;
                validate_endpoint_host(host, &server, step)?
            }
        }
    };

    if req.wg_port == Some(0) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "WireGuard port must be between 1 and 65535",
            "Leave wg_port empty for default 51821 or provide a valid UDP port",
        ));
    }

    cleanup_expired_pending(runtime).await;
    let identity = ensure_local_identity(runtime, &[], req.wg_port, step).await?;

    let code_secret = mint_secret_token();
    let code_hash = sha256_prefixed(code_secret.expose_secret());
    let now_ts = runtime.now().timestamp();
    let expires_at = now_ts + PAIRING_WINDOW_TTL_SECS;
    let window_id = Uuid::new_v4().to_string();

    let window = PairingWindow {
        id: window_id.clone(),
        code_hash,
        expires_at,
        consumed_at: None,
    };

    runtime
        .db
        .write(&server, step, move |conn| {
            db_peers::insert_pairing_window(conn, &window).map_err(|err| {
                PeerError::internal(
                    "local",
                    "open_pairing_window",
                    format!("Failed persisting pairing window: {err}"),
                )
            })
        })
        .await?;

    let pairing_payload = PairingPayload {
        https_url: https_url.clone(),
        wg_pubkey: identity.wg_pubkey.clone(),
        endpoint: endpoint.clone(),
        wg_port: identity.wg_port,
        tunnel_ip: identity.tunnel_ip.clone(),
        code: code_secret.expose_secret().to_string(),
    };
    let pairing_string = pairing_payload.encode()?;
    drop(code_secret);

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_pairing_window_opened".to_string(),
            "peer_pairing_window".to_string(),
            window_id.clone(),
            format!("Opened 10-minute pairing window expiring at {expires_at}"),
            client_ip,
            String::new(),
        )
        .await;

    Ok(serde_json::json!({
        "window_id": window_id,
        "expires_at": expires_at,
        "ttl_seconds": PAIRING_WINDOW_TTL_SECS,
        "pairing_string": pairing_string,
        "https_url": https_url,
        "endpoint": endpoint,
        "wg_port": identity.wg_port,
        "tunnel_ip": identity.tunnel_ip,
        "wg_pubkey": identity.wg_pubkey,
    }))
}

pub async fn close_all_pairing_windows(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
) -> Response {
    let server = runtime.local_server_name();
    let res = runtime
        .db
        .write(&server, "close_pairing_window", |conn| {
            let closed = conn
                .execute(
                    "DELETE FROM peer_pairing_windows WHERE consumed_at IS NULL",
                    [],
                )
                .map_err(|err| {
                    PeerError::internal(
                        "local",
                        "close_pairing_window",
                        format!("Failed closing pairing windows: {err}"),
                    )
                })?;
            Ok(closed)
        })
        .await;

    match res {
        Ok(closed) => {
            let client_ip = extract_client_ip_for_peer(&headers, peer_ip);
            runtime
                .db
                .record_audit(
                    auth_user.user_id,
                    auth_user.username.clone(),
                    "peer_pairing_window_closed".to_string(),
                    "peer_pairing_window".to_string(),
                    "all".to_string(),
                    format!("Closed {closed} open pairing window(s)"),
                    client_ip,
                    String::new(),
                )
                .await;
            (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({ "closed": closed })),
            )
                .into_response()
        }
        Err(err) => err.into_response(),
    }
}

pub async fn close_pairing_window(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(window_id): Path<String>,
) -> Response {
    let server = runtime.local_server_name();
    if !is_valid_credential_id(&window_id) {
        return PeerError::invalid_request(
            &server,
            "close_pairing_window",
            "Invalid pairing window ID",
            "Provide a valid pairing window identifier",
        )
        .into_response();
    }

    let wid = window_id.clone();
    let res = runtime
        .db
        .write(&server, "close_pairing_window", move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM peer_pairing_windows WHERE id = ?1 AND consumed_at IS NULL",
                    params![wid],
                )
                .map_err(|err| {
                    PeerError::internal(
                        "local",
                        "close_pairing_window",
                        format!("Failed closing pairing window: {err}"),
                    )
                })?;
            Ok(changed > 0)
        })
        .await;

    match res {
        Ok(true) => {
            let client_ip = extract_client_ip_for_peer(&headers, peer_ip);
            runtime
                .db
                .record_audit(
                    auth_user.user_id,
                    auth_user.username.clone(),
                    "peer_pairing_window_closed".to_string(),
                    "peer_pairing_window".to_string(),
                    window_id.clone(),
                    "Closed open pairing window".to_string(),
                    client_ip,
                    String::new(),
                )
                .await;
            (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({ "closed": true, "window_id": window_id })),
            )
                .into_response()
        }
        Ok(false) => PeerError::not_found(
            &server,
            "close_pairing_window",
            "Open pairing window not found",
        )
        .into_response(),
        Err(err) => err.into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2 & 3 (B-side): Public Pairing Bootstrap (`POST /api/v1/peer-pairing/request`)
// ─────────────────────────────────────────────────────────────────────────────

async fn audit_public_pairing_denial(runtime: &PeerRuntime, source_ip: &str, err_code: &str) {
    runtime
        .db
        .record_audit(
            0,
            "peer-pairing-public".to_string(),
            "peer_pairing_denied".to_string(),
            "peer_pairing".to_string(),
            source_ip.to_string(),
            format!("Rejected public pairing request with {err_code}"),
            source_ip.to_string(),
            String::new(),
        )
        .await;
}

pub async fn public_pairing_request(
    State(runtime): State<Arc<PeerRuntime>>,
    PeerIp(peer_ip): PeerIp,
    req: Request,
) -> Response {
    let server = runtime.local_server_name();
    let step = "public_pairing_request";
    let source_ip = extract_client_ip_for_peer(req.headers(), peer_ip);

    // Enforce 5 attempts per minute per trusted source IP BEFORE body reading, media-type
    // checking, JSON parsing, or any database work (including audit logging).
    if !runtime
        .pairing_rate_limiter
        .allow(&source_ip, runtime.monotonic_now())
    {
        return PeerError::rate_limited(&server, step).into_response();
    }

    let (parts, body) = req.into_parts();
    let parsed_req: PublicPairingRequest = match extract_bounded_json(
        &parts.headers,
        body,
        PUBLIC_PAIRING_BODY_LIMIT_BYTES,
        &server,
        step,
    )
    .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            audit_public_pairing_denial(&runtime, &source_ip, err.code()).await;
            return err.into_response();
        }
    };

    match public_pairing_request_inner(&runtime, &source_ip, parsed_req).await {
        Ok(resp) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(resp),
        )
            .into_response(),
        Err(err) => {
            audit_public_pairing_denial(&runtime, &source_ip, err.code()).await;
            err.into_response()
        }
    }
}

async fn public_pairing_request_inner(
    runtime: &PeerRuntime,
    source_ip: &str,
    req: PublicPairingRequest,
) -> Result<PublicPairingResponse, PeerError> {
    let server = runtime.local_server_name();
    let step = "public_pairing_request";
    let now = runtime.now();
    let now_ts = now.timestamp();

    // Validate request shape before inspecting windows.
    let remote_name = req.name.trim();
    if !is_valid_peer_name(remote_name) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Remote server name must be 1-64 ASCII letters, digits, '.', '_' or '-'",
            "Provide a valid peer name and retry pairing",
        ));
    }
    if !is_valid_wg_pubkey(&req.wg_pubkey) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Remote WireGuard public key is invalid",
            "Verify the initiator's WireGuard identity and retry pairing",
        ));
    }
    let remote_ip = validate_bare_ip(&req.tunnel_ip, "Remote tunnel IP", &server, step)?;
    let remote_endpoint_host = validate_endpoint_host(&req.endpoint, &server, step)?;
    if req.wg_port == 0 {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Remote WireGuard port must be between 1 and 65535",
            "Configure a valid AF_PEER_WG_PORT and retry pairing",
        ));
    }
    if !validate_secret_token_shape(&req.code) {
        return Err(PeerError::unauthorized(
            &server,
            step,
            "Pairing code is malformed or invalid",
        ));
    }
    if req.version.trim().is_empty() || req.version.len() > 64 {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Remote server version is missing or invalid",
            "Retry pairing from a supported AetherFlow build",
        ));
    }

    let code_hash = sha256_prefixed(&req.code);
    let remote_name_owned = remote_name.to_string();
    let remote_pubkey_owned = req.wg_pubkey.clone();
    let remote_tunnel_ip_str = remote_ip.to_string();
    let remote_endpoint_packed = format_endpoint_host_port(&remote_endpoint_host, req.wg_port);
    let source_ip_owned = source_ip.to_string();
    let req_timestamp = req.timestamp;
    let req_protocol = req.peer_protocol;
    let server_c = server.clone();
    let now_rfc3339 = now.to_rfc3339();

    let (attempt_id, attempt_expires_at, b_pubkey) = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting pairing transaction: {err}"),
                    )
                },
            )?;

            let window = db_peers::get_pairing_window_by_code_hash(&tx, &code_hash).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed looking up pairing window: {err}"),
                    )
                },
            )?;

            let Some(window) = window else {
                let any_open: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM peer_pairing_windows WHERE consumed_at IS NULL AND expires_at != 0 AND expires_at > ?1)",
                        params![now_ts],
                        |r| r.get(0),
                    )
                    .unwrap_or(false);
                if !any_open {
                    return Err(PeerError::window_closed(&server_c, step));
                }
                return Err(PeerError::unauthorized(
                    &server_c,
                    step,
                    "Pairing code does not match any open pairing window",
                ));
            };

            if window.consumed_at.is_some() {
                return Err(PeerError::code_used(&server_c, step));
            }
            if !is_active_expiry(window.expires_at, now_ts) {
                return Err(PeerError::code_expired(&server_c, step));
            }

            // Clock skew check (over 5 minutes).
            let skew = now_ts.saturating_sub(req_timestamp).saturating_abs();
            if skew > CLOCK_SKEW_MAX_SECS {
                return Err(PeerError::clock_skew(&server_c, step, skew));
            }

            // Protocol compatibility check.
            if req_protocol < MIN_PEER_PROTOCOL_VERSION {
                return Err(PeerError::version_incompatible(
                    &server_c,
                    step,
                    format!(
                        "Peer protocol version {req_protocol} is below minimum supported version {MIN_PEER_PROTOCOL_VERSION}"
                    ),
                ));
            }

            let Some(identity) = db_peers::get_peer_identity(&tx).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed reading local peer identity: {err}"),
                )
            })? else {
                return Err(PeerError::window_closed(&server_c, step));
            };

            if remote_pubkey_owned == identity.wg_pubkey {
                return Err(PeerError::key_mismatch(
                    &server_c,
                    step,
                    "Cannot pair a server with its own WireGuard public key",
                ));
            }
            if remote_tunnel_ip_str == identity.tunnel_ip {
                return Err(PeerError::tunnel_ip_conflict(
                    &server_c,
                    step,
                    format!(
                        "Remote tunnel IP {remote_tunnel_ip_str} collides with {server_c}'s tunnel IP"
                    ),
                ));
            }

            let existing_links = db_peers::list_peer_links(&tx).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed inspecting existing peer links: {err}"),
                )
            })?;
            for existing in existing_links {
                if is_revoked_state(&existing.state) && existing.pending_expires_at.is_none() {
                    continue;
                }
                if is_pending_link_state(&existing.state)
                    && !has_active_pending_expiry(existing.pending_expires_at, now_ts)
                {
                    continue;
                }
                if existing.tunnel_ip == remote_tunnel_ip_str {
                    return Err(PeerError::tunnel_ip_conflict(
                        &server_c,
                        step,
                        format!(
                            "Remote tunnel IP {remote_tunnel_ip_str} is already assigned to peer '{}'",
                            existing.name
                        ),
                    ));
                }
                if existing.wg_pubkey == remote_pubkey_owned {
                    return Err(PeerError::key_mismatch(
                        &server_c,
                        step,
                        format!(
                            "Peer WireGuard key is already linked as '{}'",
                            existing.name
                        ),
                    ));
                }
                if existing.name == remote_name_owned {
                    return Err(PeerError::key_mismatch(
                        &server_c,
                        step,
                        format!(
                            "Peer name '{}' is already in use by another WireGuard key",
                            existing.name
                        ),
                    ));
                }
            }

            // Atomic single-use window consumption (ported from legacy cluster_daemon::membership).
            let consumed = db_peers::consume_pairing_window(&tx, &window.id, now_ts).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed consuming pairing window: {err}"),
                    )
                },
            )?;
            if !consumed {
                let refreshed = db_peers::get_pairing_window(&tx, &window.id)
                    .ok()
                    .flatten();
                if refreshed.is_some_and(|w| w.consumed_at.is_some()) {
                    return Err(PeerError::code_used(&server_c, step));
                }
                return Err(PeerError::code_expired(&server_c, step));
            }

            let mut attempt_id = Uuid::new_v4().to_string();
            for _ in 0..8 {
                let collides: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM peer_links WHERE pending_attempt_id = ?1) \
                         OR EXISTS(SELECT 1 FROM peer_pairing_attempts WHERE id = ?1)",
                        params![attempt_id],
                        |r| r.get(0),
                    )
                    .unwrap_or(false);
                if !collides {
                    break;
                }
                attempt_id = Uuid::new_v4().to_string();
            }
            let attempt_expires_at = now_ts.saturating_add(PAIRING_WINDOW_TTL_SECS);
            let attempt = PairingAttempt {
                id: attempt_id.clone(),
                window_id: Some(window.id),
                remote_name: Some(remote_name_owned.clone()),
                remote_pubkey: Some(remote_pubkey_owned.clone()),
                remote_tunnel_ip: Some(remote_tunnel_ip_str.clone()),
                remote_endpoint: Some(remote_endpoint_packed),
                source_ip: Some(source_ip_owned),
                status: "pending".to_string(),
                error_code: None,
                expires_at: attempt_expires_at,
                created_at: now_rfc3339,
            };
            db_peers::insert_pairing_attempt(&tx, &attempt).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed recording pairing attempt: {err}"),
                )
            })?;

            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing pairing attempt: {err}"),
                )
            })?;

            Ok((attempt_id, attempt_expires_at, identity.wg_pubkey))
        })
        .await?;

    let comparison_code = derive_comparison_code(&req.wg_pubkey, &b_pubkey);

    runtime
        .db
        .record_audit(
            0,
            "peer-pairing-public".to_string(),
            "peer_pairing_requested".to_string(),
            "peer_pairing_attempt".to_string(),
            attempt_id.clone(),
            format!("Pairing request received from '{remote_name}'"),
            source_ip.to_string(),
            String::new(),
        )
        .await;

    Ok(PublicPairingResponse {
        attempt_id,
        comparison_code,
        expires_at: attempt_expires_at,
        server_name: server,
        version: runtime.local_version(),
        peer_protocol: PEER_PROTOCOL_VERSION,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2 (A-side): Start Pairing (`POST /api/v1/admin/peers/pair`)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn start_pairing(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Json(req): Json<StartPairingReq>,
) -> Response {
    match start_pairing_inner(&runtime, &auth_user, peer_ip, &headers, req).await {
        Ok(val) => (
            StatusCode::CREATED,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn start_pairing_inner(
    runtime: &Arc<PeerRuntime>,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    req: StartPairingReq,
) -> Result<serde_json::Value, PeerError> {
    start_pairing_with_link_id(
        runtime,
        auth_user,
        peer_ip,
        headers,
        req,
        Uuid::new_v4().to_string(),
    )
    .await
}

pub(crate) async fn start_pairing_with_link_id(
    runtime: &Arc<PeerRuntime>,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    req: StartPairingReq,
    link_id: String,
) -> Result<serde_json::Value, PeerError> {
    let local_server = runtime.local_server_name();
    let step = "start_pairing";

    let payload = PairingPayload::decode(&req.pairing_string, &local_server)?;
    let target_url = build_public_pairing_request_url(&payload.https_url, &local_server, step)?;
    let target_host_label = target_url.host_str().unwrap_or("remote-server").to_string();

    let peer_name = match req.name.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            if !is_valid_peer_name(trimmed) {
                return Err(PeerError::invalid_request(
                    &local_server,
                    step,
                    "Peer name must be 1-64 ASCII letters, digits, '.', '_' or '-'",
                    "Enter a valid display name for the remote server",
                ));
            }
            trimmed.to_string()
        }
        None => {
            let fallback: String = target_host_label
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                .take(64)
                .collect();
            if is_valid_peer_name(&fallback) {
                fallback
            } else {
                "peer-server".to_string()
            }
        }
    };

    let advertised_local_name = match req.local_name.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            if !is_valid_peer_name(trimmed) {
                return Err(PeerError::invalid_request(
                    &local_server,
                    step,
                    "Local server name must be 1-64 ASCII letters, digits, '.', '_' or '-'",
                    "Provide a valid local server name",
                ));
            }
            trimmed.to_string()
        }
        None => local_server.clone(),
    };

    let local_endpoint = match req.endpoint.as_deref() {
        Some(raw) => validate_endpoint_host(raw, &local_server, step)?,
        None => detect_local_endpoints()
            .into_iter()
            .next()
            .map(|d| d.address)
            .ok_or_else(|| {
                PeerError::invalid_request(
                    &local_server,
                    step,
                    "Local WireGuard endpoint is required when no host interface address was detected",
                    "Provide this server's reachable VLAN or public IP address",
                )
            })?,
    };

    cleanup_expired_pending(runtime).await;

    let identity = ensure_local_identity(
        runtime,
        std::slice::from_ref(&payload.tunnel_ip),
        None,
        step,
    )
    .await?;

    if identity.wg_pubkey == payload.wg_pubkey {
        return Err(PeerError::key_mismatch(
            &local_server,
            step,
            "Cannot pair this server with its own WireGuard public key",
        ));
    }
    if identity.tunnel_ip == payload.tunnel_ip {
        return Err(PeerError::tunnel_ip_conflict(
            &local_server,
            step,
            format!(
                "Remote tunnel IP {} collides with this server's tunnel IP {}",
                payload.tunnel_ip, identity.tunnel_ip
            ),
        ));
    }

    // Retry any pending revocation cleanups on conflicting revoked/revoking links first so
    // incomplete runner cleanup is never discarded by re-pairing.
    let conflicting_cleanup_ids: Vec<String> = {
        let name_check = peer_name.clone();
        let pk_check = payload.wg_pubkey.clone();
        let ip_check = payload.tunnel_ip.clone();
        let server_c = local_server.clone();
        runtime
            .db
            .read(&local_server, step, move |conn| {
                let existing = db_peers::list_peer_links(conn).map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed listing peer links: {err}"),
                    )
                })?;
                Ok(existing
                    .into_iter()
                    .filter(|link| {
                        (link.name == name_check
                            || link.wg_pubkey == pk_check
                            || link.tunnel_ip == ip_check)
                            && (is_revoking_state(&link.state)
                                || (is_revoked_state(&link.state)
                                    && link.pending_expires_at.is_some()))
                    })
                    .map(|l| l.id)
                    .collect())
            })
            .await?
    };
    for stale_id in conflicting_cleanup_ids {
        links::retry_revocation_cleanup(runtime, &stale_id).await?;
    }

    // Acquire the initial per-link lock BEFORE reserving the pending row in SQLite and hold it
    // continuously across reservation and `AddPeer` so lock contention cannot strand a freshly
    // reserved normal-TTL pending row prior to WireGuard setup.
    let start_now = runtime.now();
    let start_now_ts = start_now.timestamp();
    let local_max_expires_at = start_now_ts.saturating_add(PAIRING_WINDOW_TTL_SECS);
    let now_rfc3339 = start_now.to_rfc3339();
    let pending_link = PeerLink {
        id: link_id.clone(),
        name: peer_name.clone(),
        wg_pubkey: payload.wg_pubkey.clone(),
        tunnel_ip: payload.tunnel_ip.clone(),
        endpoint: payload.endpoint.clone(),
        wg_port: payload.wg_port,
        state: STATE_PENDING.to_string(),
        peer_version: None,
        peer_protocol: None,
        capabilities: None,
        rtt_ms: None,
        last_ok_at: None,
        last_error: None,
        consecutive_failures: 0,
        inbound_token_hash: None,
        pending_attempt_id: None,
        pending_expires_at: Some(local_max_expires_at),
        created_at: now_rfc3339.clone(),
        updated_at: now_rfc3339,
    };

    {
        let _initial_link_guard = runtime.lock_link(&pending_link.id, step).await?;

        let name_check = peer_name.clone();
        let pk_check = payload.wg_pubkey.clone();
        let ip_check = payload.tunnel_ip.clone();
        let server_c = local_server.clone();
        let insert_link = pending_link.clone();
        runtime
            .db
            .write(&local_server, step, move |conn| {
                let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                    |err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed starting pairing reservation transaction: {err}"),
                        )
                    },
                )?;
                let existing = db_peers::list_peer_links(&tx).map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed listing peer links: {err}"),
                    )
                })?;
                for link in existing {
                    let matches_any = link.name == name_check
                        || link.wg_pubkey == pk_check
                        || link.tunnel_ip == ip_check;
                    if !matches_any {
                        continue;
                    }
                    if is_revoked_state(&link.state) && link.pending_expires_at.is_none() {
                        tx.execute(
                            "DELETE FROM peer_links \
                             WHERE id = ?1 AND state IN ('revoked', 'revoked_unowned') \
                               AND pending_expires_at IS NULL",
                            params![link.id],
                        )
                        .map_err(|err| {
                            PeerError::internal(
                                &server_c,
                                step,
                                format!("Failed removing stale revoked link: {err}"),
                            )
                        })?;
                        continue;
                    }
                    if is_revoking_state(&link.state)
                        || (is_revoked_state(&link.state) && link.pending_expires_at.is_some())
                    {
                        return Err(PeerError::busy(
                            &server_c,
                            step,
                            format!(
                                "Revocation cleanup is still pending for '{}'; retry shortly",
                                link.name
                            ),
                        ));
                    }
                    if link.tunnel_ip == ip_check {
                        return Err(PeerError::tunnel_ip_conflict(
                            &server_c,
                            step,
                            format!(
                                "Tunnel IP {} is already assigned to peer '{}'",
                                ip_check, link.name
                            ),
                        ));
                    }
                    if link.wg_pubkey == pk_check {
                        return Err(PeerError::key_mismatch(
                            &server_c,
                            step,
                            format!("Remote WireGuard key is already linked as '{}'", link.name),
                        ));
                    }
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        format!("A peer link named '{}' already exists", link.name),
                        "Choose a distinct peer name or remove the existing link first",
                    ));
                }

                db_peers::insert_peer_link(&tx, &insert_link).map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed recording pending peer link: {err}"),
                    )
                })?;
                tx.commit().map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed committing pending peer link: {err}"),
                    )
                })?;
                Ok(())
            })
            .await?;

        // Add B's pinned WireGuard key & tunnel IP to afpeer0 while holding `_initial_link_guard`.
        // Newly reserved rows default to `pending` (unowned); ONLY a definitive successful
        // `AddPeer` (`Ok(Mutation)`) promotes the row to `pending_owned`.
        let add_req = PeerNetworkRequest::AddPeer {
            pubkey: payload.wg_pubkey.clone(),
            endpoint: payload.endpoint.clone(),
            port: payload.wg_port,
            tunnel_ip: payload.tunnel_ip.clone(),
        };
        let stage1_expires_at = match runtime.runner.dispatch(&add_req).await {
            Ok(resp) => {
                if let Err(err) = resp
                    .into_mutation()
                    .map_err(|e| map_runner_error(e, &local_server, step))
                {
                    let _ = cleanup_pending_link_locked(
                        runtime,
                        &pending_link.id,
                        &pending_link.wg_pubkey,
                        None,
                        "failed",
                        Some(err.code()),
                    )
                    .await;
                    return Err(err);
                }
                commit_pending_wg_ownership_locked(
                    runtime,
                    &pending_link.id,
                    &pending_link.wg_pubkey,
                    &pending_link.tunnel_ip,
                    None,
                    step,
                )
                .await?
            }
            Err(PeerNetworkError::PeerAlreadyExists(_)) => {
                if let Err(err) = reconcile_existing_pending_peer(
                    runtime,
                    &payload.wg_pubkey,
                    &payload.tunnel_ip,
                    &local_server,
                    step,
                )
                .await
                {
                    // Row remains unowned (`pending`); cleanup deletes DB row/creds only.
                    let _ = cleanup_pending_link_locked(
                        runtime,
                        &pending_link.id,
                        &pending_link.wg_pubkey,
                        None,
                        "failed",
                        Some(err.code()),
                    )
                    .await;
                    return Err(err);
                }
                // Reconciled preexisting WireGuard peer stays unowned (`pending`).
                let lid_check = pending_link.id.clone();
                runtime
                    .db
                    .read(&local_server, step, move |conn| {
                        Ok(db_peers::get_peer_link(conn, &lid_check)
                            .map_err(|err| PeerError::internal("local", step, err.to_string()))?
                            .and_then(|l| l.pending_expires_at))
                    })
                    .await?
            }
            Err(err) => {
                // AddPeer failed or returned an uncertain outcome (Conflict, TunnelIpConflict,
                // Busy, Runtime, etc.): row remains unowned (`pending`), so neither immediate
                // cleanup nor retry/restart can remove an unrelated or unverified WG peer.
                let mapped = map_runner_error(err, &local_server, step);
                let _ = cleanup_pending_link_locked(
                    runtime,
                    &pending_link.id,
                    &pending_link.wg_pubkey,
                    None,
                    "failed",
                    Some(mapped.code()),
                )
                .await;
                return Err(mapped);
            }
        };

        // Revalidate after runner I/O while still holding `_initial_link_guard` so an allocation
        // that expired or was marked for cleanup during `AddPeer`/reconciliation is cleaned up
        // immediately rather than advancing to outbound HTTPS.
        let stage1_now_ts = runtime.now().timestamp();
        match classify_pending_expiry(stage1_expires_at, stage1_now_ts) {
            PendingExpiryStatus::Active(_) => {}
            PendingExpiryStatus::Expired => {
                let _ = cleanup_pending_link_locked(
                    runtime,
                    &pending_link.id,
                    &pending_link.wg_pubkey,
                    None,
                    "expired",
                    Some("CODE_EXPIRED"),
                )
                .await;
                return Err(PeerError::code_expired(&local_server, step));
            }
            PendingExpiryStatus::CleanupMarked | PendingExpiryStatus::Missing => {
                let _ = cleanup_pending_link_locked(
                    runtime,
                    &pending_link.id,
                    &pending_link.wg_pubkey,
                    None,
                    "failed",
                    Some("PEER_CONFLICT"),
                )
                .await;
                return Err(PeerError::conflict(
                    &local_server,
                    step,
                    "Pending peer link was marked for cleanup before pairing could continue",
                    "Restart pairing from the Cluster page",
                ));
            }
        }
    }

    // Helper for rolling back only durably owned resources after `_initial_link_guard` is
    // released. If `link_lock` is contended, immediately persists guarded zero-expiry cleanup
    // (`pending_expires_at = 0`, preserving ownership state) so no 10-minute normal TTL orphan
    // survives and the next sweep cleans up as soon as contention clears.
    let rollback_start_link = |error_code: String, link_already_contended: bool| {
        let rt = Arc::clone(runtime);
        let lid = pending_link.id.clone();
        let pk = pending_link.wg_pubkey.clone();
        async move {
            let lock_res = if link_already_contended {
                rt.try_lock_link(&lid, "start_pairing_rollback")
            } else {
                rt.lock_link(&lid, "start_pairing_rollback").await
            };
            match lock_res {
                Ok(_link_guard) => {
                    if let Err(cleanup_err) = cleanup_pending_link_locked(
                        &rt,
                        &lid,
                        &pk,
                        None,
                        "failed",
                        Some(&error_code),
                    )
                    .await
                    {
                        tracing::warn!(
                            link_id = %lid,
                            %cleanup_err,
                            "Pending rollback failed transiently; durable cleanup state retained for sweep"
                        );
                    }
                }
                Err(lock_err) => {
                    tracing::warn!(
                        link_id = %lid,
                        %lock_err,
                        "Pending start_pairing rollback could not acquire link lock; persisting guarded zero-expiry cleanup marker"
                    );
                    mark_pending_cleanup_retry(
                        &rt,
                        &lid,
                        &pk,
                        None,
                        None,
                        &format!("Pending rollback deferred due to lock contention ({error_code})"),
                    )
                    .await;
                }
            }
        }
    };

    // Send public HTTPS bootstrap request to B (with no shared lock held across outbound I/O).
    let public_req = PublicPairingRequest {
        code: payload.code.clone(),
        name: advertised_local_name,
        wg_pubkey: identity.wg_pubkey.clone(),
        endpoint: local_endpoint,
        wg_port: identity.wg_port,
        tunnel_ip: identity.tunnel_ip.clone(),
        version: runtime.local_version(),
        peer_protocol: PEER_PROTOCOL_VERSION,
        timestamp: start_now_ts,
    };
    let req_bytes = match serde_json::to_vec(&public_req) {
        Ok(b) => b,
        Err(_) => {
            rollback_start_link("PEER_INTERNAL_ERROR".to_string(), false).await;
            return Err(PeerError::internal(
                &local_server,
                step,
                "Failed serializing pairing request",
            ));
        }
    };

    let remote_result = runtime
        .public_transport
        .post_pairing_request(target_url, req_bytes)
        .await;

    let (status, resp_bytes) = match remote_result {
        Ok(res) => res,
        Err(transport_err) => {
            rollback_start_link("ENDPOINT_UNREACHABLE".to_string(), false).await;
            return Err(PeerError::endpoint_unreachable(
                &peer_name,
                step,
                format!("Could not reach {peer_name} over HTTPS: {transport_err}"),
            ));
        }
    };

    if !status.is_success() {
        let remote_err = PeerError::from_remote_http(status, &resp_bytes, &peer_name, step);
        rollback_start_link(remote_err.code().to_string(), false).await;
        return Err(remote_err);
    }

    let remote_resp: PublicPairingResponse = match serde_json::from_slice(&resp_bytes) {
        Ok(parsed) => parsed,
        Err(_) => {
            rollback_start_link("VERSION_INCOMPATIBLE".to_string(), false).await;
            return Err(PeerError::version_incompatible(
                &peer_name,
                step,
                format!("{peer_name} returned an unreadable pairing response"),
            ));
        }
    };

    if !is_valid_credential_id(&remote_resp.attempt_id) {
        rollback_start_link("INVALID_REQUEST".to_string(), false).await;
        return Err(PeerError::invalid_request(
            &peer_name,
            step,
            format!("{peer_name} returned an invalid pairing attempt identifier"),
            "Verify both servers run compatible AetherFlow versions and retry",
        ));
    }
    if remote_resp.peer_protocol < MIN_PEER_PROTOCOL_VERSION {
        rollback_start_link("VERSION_INCOMPATIBLE".to_string(), false).await;
        return Err(PeerError::version_incompatible(
            &peer_name,
            step,
            format!(
                "{peer_name} reported peer protocol {}, below minimum {MIN_PEER_PROTOCOL_VERSION}",
                remote_resp.peer_protocol
            ),
        ));
    }

    let expected_code = derive_comparison_code(&identity.wg_pubkey, &payload.wg_pubkey);
    if !constant_time_eq(
        remote_resp.comparison_code.as_bytes(),
        expected_code.as_bytes(),
    ) {
        rollback_start_link("KEY_MISMATCH".to_string(), false).await;
        return Err(PeerError::key_mismatch(
            &peer_name,
            step,
            format!("Comparison code from {peer_name} did not match the pinned WireGuard keys"),
        ));
    }

    // Validate remote expiry against the local bounded attempt window: reject already-expired
    // or zero replies and cap stored lifetime to `start_now_ts + PAIRING_WINDOW_TTL_SECS`.
    let post_now_ts = runtime.now().timestamp();
    if !is_active_expiry(remote_resp.expires_at, post_now_ts) {
        rollback_start_link("CODE_EXPIRED".to_string(), false).await;
        return Err(PeerError::code_expired(&peer_name, step));
    }
    let effective_expires_at = remote_resp.expires_at.min(local_max_expires_at);
    if !is_active_expiry(effective_expires_at, post_now_ts) {
        rollback_start_link("CODE_EXPIRED".to_string(), false).await;
        return Err(PeerError::code_expired(&local_server, step));
    }

    // Atomically record `pending_attempt_id` under canonical lock order (`attempt_lock` ->
    // `link_lock`), routing ANY lock acquisition or commit failure into `rollback_start_link`
    // (never escaping via `?` before rollback or guarded zero-expiry persistence).
    enum Stage2CommitError {
        AttemptLockContended(PeerError),
        LinkLockContended(PeerError),
        CommitFailed(PeerError),
    }

    let commit_result: Result<i64, Stage2CommitError> = async {
        let _att_guard = runtime
            .lock_attempt(&remote_resp.attempt_id, step)
            .await
            .map_err(Stage2CommitError::AttemptLockContended)?;
        let _link_guard = runtime
            .lock_link(&pending_link.id, step)
            .await
            .map_err(Stage2CommitError::LinkLockContended)?;

        let lid_c = pending_link.id.clone();
        let pk_c = pending_link.wg_pubkey.clone();
        let ip_c = pending_link.tunnel_ip.clone();
        let att_c = remote_resp.attempt_id.clone();
        let ver_c = remote_resp.version.clone();
        let proto_c = remote_resp.peer_protocol;
        let remote_expires_at = remote_resp.expires_at;
        let peer_name_c = peer_name.clone();
        let clock = Arc::clone(&runtime.clock);
        let server_c = local_server.clone();

        runtime
            .db
            .write(&local_server, step, move |conn| {
                let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                    |err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed starting attempt-recording transaction: {err}"),
                        )
                    },
                )?;

                // Revalidate both effective remote expiry and the authoritative lock-held pending
                // row at actual commit time so lock waits or concurrent cleanup markers (`0`) can
                // never be revived.
                let commit_now = clock();
                let commit_now_ts = commit_now.timestamp();
                let updated_at = commit_now.to_rfc3339();
                if !is_active_expiry(remote_expires_at, commit_now_ts) {
                    return Err(PeerError::code_expired(&peer_name_c, step));
                }
                if !is_active_expiry(effective_expires_at, commit_now_ts) {
                    return Err(PeerError::code_expired(&server_c, step));
                }

                let local_attempt_collision: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM peer_pairing_attempts WHERE id = ?1)",
                        params![att_c],
                        |r| r.get(0),
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed checking local pairing attempt uniqueness: {err}"),
                        )
                    })?;
                if local_attempt_collision {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Remote pairing attempt ID collides with a local pairing attempt",
                        "Open a fresh pairing window on the target server and retry",
                    ));
                }

                let other_link_collision: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM peer_links WHERE pending_attempt_id = ?1 AND id != ?2)",
                        params![att_c, lid_c],
                        |r| r.get(0),
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed checking peer link attempt uniqueness: {err}"),
                        )
                    })?;
                if other_link_collision {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Remote pairing attempt ID collides with another active or pending peer link",
                        "Open a fresh pairing window on the target server and retry",
                    ));
                }

                let current_row = db_peers::get_peer_link(&tx, &lid_c).map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed reading pending peer link before commit: {err}"),
                    )
                })?;
                let Some(row) = current_row else {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Pending peer link was removed before attempt ID could be recorded",
                        "Restart pairing from the Cluster page",
                    ));
                };
                if !is_pending_link_state(&row.state)
                    || row.wg_pubkey != pk_c
                    || row.tunnel_ip != ip_c
                    || row.pending_attempt_id.is_some()
                {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Pending peer link was modified or cancelled before attempt ID could be recorded",
                        "Restart pairing from the Cluster page",
                    ));
                }
                let row_exp =
                    ensure_active_pending_link_row(&tx, &row, commit_now_ts, &server_c, step)?;
                let final_expires_at = effective_expires_at.min(row_exp);

                let changed = tx
                    .execute(
                        "UPDATE peer_links SET \
                            pending_attempt_id = ?4, \
                            pending_expires_at = ?5, \
                            peer_version = ?6, \
                            peer_protocol = ?7, \
                            updated_at = ?8 \
                         WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                           AND state IN ('pending', 'pending_owned') \
                           AND pending_attempt_id IS NULL \
                           AND pending_expires_at IS NOT NULL \
                           AND pending_expires_at != 0 \
                           AND pending_expires_at > ?9",
                        params![
                            lid_c,
                            pk_c,
                            ip_c,
                            att_c,
                            final_expires_at,
                            ver_c,
                            proto_c,
                            updated_at,
                            commit_now_ts,
                        ],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed recording pairing attempt on pending link: {err}"),
                        )
                    })?;

                if changed != 1 {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Pending peer link was modified or cancelled before attempt ID could be recorded",
                        "Restart pairing from the Cluster page",
                    ));
                }

                tx.commit().map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed committing pairing attempt record: {err}"),
                    )
                })?;
                Ok(final_expires_at)
            })
            .await
            .map_err(Stage2CommitError::CommitFailed)
    }
    .await;

    let committed_expires_at = match commit_result {
        Ok(exp) => exp,
        Err(stage2_err) => {
            let (err, link_contended) = match stage2_err {
                Stage2CommitError::AttemptLockContended(e) | Stage2CommitError::CommitFailed(e) => {
                    (e, false)
                }
                Stage2CommitError::LinkLockContended(e) => (e, true),
            };
            rollback_start_link(err.code().to_string(), link_contended).await;
            return Err(err);
        }
    };

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_pairing_started".to_string(),
            "peer_link".to_string(),
            link_id.clone(),
            format!(
                "Started pairing with '{}' (attempt {})",
                peer_name, remote_resp.attempt_id
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(serde_json::json!({
        "link_id": link_id,
        "attempt_id": remote_resp.attempt_id,
        "name": peer_name,
        "remote_server_name": remote_resp.server_name,
        "comparison_code": expected_code,
        "expires_at": committed_expires_at,
        "state": "pending",
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 4 & 5 (B-side): Confirm Pairing (`POST /api/v1/admin/peers/pairing/:attempt/confirm`)
// ─────────────────────────────────────────────────────────────────────────────

enum ConfirmPendingState {
    Active(Box<PeerLink>),
    Expired {
        has_matching_pending_link: bool,
    },
    Cancelled {
        has_matching_pending_link: bool,
    },
    Failed {
        has_matching_pending_link: bool,
        error_code: Option<String>,
    },
    CleanupMarked,
    Revoked(String),
    Conflict(&'static str),
    MissingLink,
}

/// Authoritatively inspects both the responder pairing attempt and its bound pending link row at
/// `now_ts` so confirm phases 1, 2, and 4 share one validation rule without duplicated checklists.
fn inspect_confirm_pending_state(
    conn: &rusqlite::Connection,
    link_id: &str,
    attempt_id: &str,
    expected_pubkey: &str,
    now_ts: i64,
    server: &str,
    step: &str,
) -> Result<ConfirmPendingState, PeerError> {
    let attempt = db_peers::get_pairing_attempt(conn, attempt_id)
        .map_err(|err| PeerError::internal(server, step, err.to_string()))?;
    let link = db_peers::get_peer_link(conn, link_id)
        .map_err(|err| PeerError::internal(server, step, err.to_string()))?;

    let has_matching_pending_link = link.as_ref().is_some_and(|l| {
        is_pending_link_state(&l.state)
            && l.wg_pubkey == expected_pubkey
            && l.pending_attempt_id.as_deref() == Some(attempt_id)
    });

    let Some(attempt) = attempt else {
        return Ok(ConfirmPendingState::Conflict(
            "Pairing attempt was removed concurrently",
        ));
    };

    match attempt.status.as_str() {
        "cancelled" => {
            return Ok(ConfirmPendingState::Cancelled {
                has_matching_pending_link,
            });
        }
        "failed" => {
            return Ok(ConfirmPendingState::Failed {
                has_matching_pending_link,
                error_code: attempt.error_code,
            });
        }
        "expired" => {
            return Ok(ConfirmPendingState::Expired {
                has_matching_pending_link,
            });
        }
        "pending" | "confirming" => {
            if !is_active_expiry(attempt.expires_at, now_ts) {
                return Ok(ConfirmPendingState::Expired {
                    has_matching_pending_link,
                });
            }
        }
        _ => {
            return Ok(ConfirmPendingState::Conflict(
                "Pairing attempt changed concurrently before confirmation could commit",
            ));
        }
    }

    let Some(link) = link else {
        return Ok(ConfirmPendingState::MissingLink);
    };
    if is_revoked_or_revoking_state(&link.state) {
        return Ok(ConfirmPendingState::Revoked(link.name));
    }
    if !is_pending_link_state(&link.state)
        || link.wg_pubkey != expected_pubkey
        || link.pending_attempt_id.as_deref() != Some(attempt_id)
    {
        return Ok(ConfirmPendingState::Conflict(
            "Pending peer link state changed concurrently",
        ));
    }

    match classify_pending_expiry(link.pending_expires_at, now_ts) {
        PendingExpiryStatus::Active(_) => Ok(ConfirmPendingState::Active(Box::new(link))),
        PendingExpiryStatus::Expired => Ok(ConfirmPendingState::Expired {
            has_matching_pending_link: true,
        }),
        PendingExpiryStatus::CleanupMarked => Ok(ConfirmPendingState::CleanupMarked),
        PendingExpiryStatus::Missing => Ok(ConfirmPendingState::Conflict(
            "Pending peer link is missing its expiry deadline",
        )),
    }
}

/// Converts any non-active [`ConfirmPendingState`] into its typed [`PeerError`] while the caller
/// holds `attempt_lock -> link_lock`, promptly persisting terminal attempt status and cleaning up
/// expired/cancelled/failed pending links without advancing or reviving cleanup-marked (`0`) rows.
async fn resolve_non_active_confirm_state_locked(
    runtime: &PeerRuntime,
    state: ConfirmPendingState,
    link_id: &str,
    remote_pubkey: &str,
    attempt_id: &str,
    step: &str,
) -> PeerError {
    let local_server = runtime.local_server_name();
    match state {
        ConfirmPendingState::Active(_) => PeerError::conflict(
            &local_server,
            step,
            "Pending peer link changed concurrently",
            "Refresh the Cluster page and retry confirmation",
        ),
        ConfirmPendingState::Expired {
            has_matching_pending_link,
        } => {
            let _ = persist_attempt_terminal_status(
                runtime,
                attempt_id,
                "expired",
                Some("CODE_EXPIRED"),
                None,
                step,
            )
            .await;
            if has_matching_pending_link {
                let _ = cleanup_pending_link_locked(
                    runtime,
                    link_id,
                    remote_pubkey,
                    Some(attempt_id),
                    "expired",
                    Some("CODE_EXPIRED"),
                )
                .await;
            }
            PeerError::code_expired(&local_server, step)
        }
        ConfirmPendingState::Cancelled {
            has_matching_pending_link,
        } => {
            if has_matching_pending_link {
                let _ = cleanup_pending_link_locked(
                    runtime,
                    link_id,
                    remote_pubkey,
                    Some(attempt_id),
                    "cancelled",
                    None,
                )
                .await;
            }
            PeerError::window_closed(&local_server, step)
        }
        ConfirmPendingState::Failed {
            has_matching_pending_link,
            error_code,
        } => {
            if has_matching_pending_link {
                let _ = cleanup_pending_link_locked(
                    runtime,
                    link_id,
                    remote_pubkey,
                    Some(attempt_id),
                    "failed",
                    error_code.as_deref(),
                )
                .await;
            }
            PeerError::conflict(
                &local_server,
                step,
                "This pairing attempt previously failed and was cleaned up",
                "Open a new pairing window and start pairing again",
            )
        }
        ConfirmPendingState::CleanupMarked => PeerError::conflict(
            &local_server,
            step,
            "Pending peer link is already marked for cleanup",
            "Open a new pairing window and start pairing again",
        ),
        ConfirmPendingState::Revoked(name) => {
            PeerError::link_revoked(&name, step, format!("Link '{name}' has been revoked"))
        }
        ConfirmPendingState::MissingLink => PeerError::not_found(
            &local_server,
            step,
            "Pending peer link was removed concurrently",
        ),
        ConfirmPendingState::Conflict(msg) => PeerError::conflict(
            &local_server,
            step,
            msg,
            "Refresh the Cluster page and inspect the link state",
        ),
    }
}

/// Fresh pre-I/O guard for responder confirm phases holding `attempt_lock -> link_lock`.
async fn ensure_confirm_pending_active_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    remote_pubkey: &str,
    attempt_id: &str,
    step: &str,
) -> Result<PeerLink, PeerError> {
    let local_server = runtime.local_server_name();
    let server_c = local_server.clone();
    let step_c = step.to_string();
    let lid_c = link_id.to_string();
    let att_c = attempt_id.to_string();
    let pk_c = remote_pubkey.to_string();
    let clock = Arc::clone(&runtime.clock);

    let inspected = runtime
        .db
        .read(&local_server, step, move |conn| {
            let now_ts = clock().timestamp();
            inspect_confirm_pending_state(conn, &lid_c, &att_c, &pk_c, now_ts, &server_c, &step_c)
        })
        .await?;

    match inspected {
        ConfirmPendingState::Active(link) => Ok(*link),
        other => Err(resolve_non_active_confirm_state_locked(
            runtime,
            other,
            link_id,
            remote_pubkey,
            attempt_id,
            step,
        )
        .await),
    }
}

/// Guarded SQL commit for responder issuer digest in confirm Phase 1 (both reused and newly minted
/// `PendingIssuerToken` paths), enforcing nonzero exclusive expiry on both link and attempt.
async fn commit_confirm_issuer_digest_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    remote_pubkey: &str,
    attempt_id: &str,
    digest: &str,
    step: &str,
) -> Result<(), PeerError> {
    let local_server = runtime.local_server_name();
    let server_c = local_server.clone();
    let step_c = step.to_string();
    let lid_u = link_id.to_string();
    let pk_u = remote_pubkey.to_string();
    let att_u = attempt_id.to_string();
    let digest_u = digest.to_string();
    let clock = Arc::clone(&runtime.clock);

    let write_outcome = runtime
        .db
        .write(&local_server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
            let commit_now = clock();
            let commit_now_ts = commit_now.timestamp();
            let now_u = commit_now.to_rfc3339();
            let changed = tx
                .execute(
                    "UPDATE peer_links \
                     SET inbound_token_hash = ?4, updated_at = ?5 \
                     WHERE id = ?1 AND wg_pubkey = ?2 \
                       AND state IN ('pending', 'pending_owned') \
                       AND pending_attempt_id = ?3 AND inbound_token_hash IS NULL \
                       AND pending_expires_at IS NOT NULL \
                       AND pending_expires_at != 0 \
                       AND pending_expires_at > ?6 \
                       AND EXISTS ( \
                           SELECT 1 FROM peer_pairing_attempts \
                           WHERE id = ?3 AND status IN ('pending', 'confirming') \
                             AND expires_at != 0 AND expires_at > ?6 \
                       )",
                    params![lid_u, pk_u, att_u, digest_u, now_u, commit_now_ts],
                )
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
            if changed == 1 {
                tx.commit()
                    .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
                return Ok(Ok(()));
            }
            let _ = tx.rollback();
            let state = inspect_confirm_pending_state(
                conn,
                &lid_u,
                &att_u,
                &pk_u,
                commit_now_ts,
                &server_c,
                &step_c,
            )?;
            Ok(Err(state))
        })
        .await?;

    match write_outcome {
        Ok(()) => Ok(()),
        Err(state) => Err(resolve_non_active_confirm_state_locked(
            runtime,
            state,
            link_id,
            remote_pubkey,
            attempt_id,
            step,
        )
        .await),
    }
}

/// Promptly persists `expired` status for an attempt while holding `attempt_lock` (before
/// `link_lock` is held) and cleans up any linked pending row (or marks zero-expiry retry under
/// lock contention).
async fn expire_confirm_attempt_locked(
    runtime: &PeerRuntime,
    attempt_id: &str,
    step: &str,
) -> PeerError {
    let local_server = runtime.local_server_name();
    let _ = persist_attempt_terminal_status(
        runtime,
        attempt_id,
        "expired",
        Some("CODE_EXPIRED"),
        None,
        step,
    )
    .await;

    let att_id_exp = attempt_id.to_string();
    let linked_pending = runtime
        .db
        .read(&local_server, step, move |conn| {
            Ok(db_peers::list_peer_links(conn)
                .unwrap_or_default()
                .into_iter()
                .find(|l| {
                    is_pending_link_state(&l.state)
                        && l.pending_attempt_id.as_deref() == Some(att_id_exp.as_str())
                }))
        })
        .await
        .ok()
        .flatten();
    if let Some(pending_link) = linked_pending {
        if let Ok(_link_guard) = runtime.lock_link(&pending_link.id, step).await {
            let _ = cleanup_pending_link_locked(
                runtime,
                &pending_link.id,
                &pending_link.wg_pubkey,
                Some(attempt_id),
                "expired",
                Some("CODE_EXPIRED"),
            )
            .await;
        } else {
            mark_pending_cleanup_retry(
                runtime,
                &pending_link.id,
                &pending_link.wg_pubkey,
                Some(attempt_id),
                Some(("expired", Some("CODE_EXPIRED"))),
                "Expired confirm cleanup deferred due to lock contention",
            )
            .await;
        }
    }
    PeerError::code_expired(&local_server, step)
}

async fn confirm_completed_attempt_response(
    runtime: &PeerRuntime,
    attempt_id: &str,
    remote_pubkey: &str,
    step: &str,
) -> Result<serde_json::Value, PeerError> {
    let local_server = runtime.local_server_name();
    let remote_pubkey = remote_pubkey.to_string();
    let existing = runtime
        .db
        .read(&local_server, step, move |conn| {
            db_peers::get_peer_link_by_pubkey(conn, &remote_pubkey)
                .map_err(|err| PeerError::internal("local", "confirm_pairing", err.to_string()))
        })
        .await?;
    match existing {
        Some(link) if is_live_link_state(&link.state) => Ok(serde_json::json!({
            "link_id": link.id,
            "name": link.name,
            "state": public_link_state(&link.state),
            "attempt_id": attempt_id,
            "confirmed": true,
        })),
        Some(link) if is_revoked_or_revoking_state(&link.state) => Err(PeerError::link_revoked(
            &link.name,
            step,
            format!("Link '{}' from this attempt has been revoked", link.name),
        )),
        _ => Err(PeerError::conflict(
            &local_server,
            step,
            "This pairing attempt already completed and its link is no longer active",
            "Open a new pairing window to re-pair the server",
        )),
    }
}

pub async fn confirm_pairing(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(attempt_id): Path<String>,
    payload: Option<Json<ConfirmPairingReq>>,
) -> Response {
    let req = payload.map(|Json(v)| v).unwrap_or_default();
    match confirm_pairing_inner(&runtime, &auth_user, peer_ip, &headers, &attempt_id, req).await {
        Ok(val) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn confirm_pairing_inner(
    runtime: &Arc<PeerRuntime>,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    attempt_id: &str,
    req: ConfirmPairingReq,
) -> Result<serde_json::Value, PeerError> {
    let local_server = runtime.local_server_name();
    let step = "confirm_pairing";

    if !is_valid_credential_id(attempt_id) {
        return Err(PeerError::invalid_request(
            &local_server,
            step,
            "Invalid pairing attempt identifier",
            "Refresh the Cluster page and select a valid pending pairing request",
        ));
    }

    // Run global expiry/cleanup sweep BEFORE acquiring attempt_lock so there is no self-deadlock.
    cleanup_expired_pending(runtime).await;

    // Serialize all local confirmations, cancellations, and sweeps for this attempt ID.
    let _attempt_guard = runtime.lock_attempt(attempt_id, step).await?;

    let att_id = attempt_id.to_string();
    let attempt = runtime
        .db
        .read(&local_server, step, move |conn| {
            db_peers::get_pairing_attempt(conn, &att_id).map_err(|err| {
                PeerError::internal(
                    "local",
                    "confirm_pairing",
                    format!("Failed loading pairing attempt: {err}"),
                )
            })
        })
        .await?
        .ok_or_else(|| {
            PeerError::not_found(&local_server, step, "Pairing attempt was not found")
        })?;

    let now_ts = runtime.now().timestamp();

    if attempt.status == "completed" {
        let remote_pubkey = attempt.remote_pubkey.clone().unwrap_or_default();
        return confirm_completed_attempt_response(runtime, attempt_id, &remote_pubkey, step).await;
    }

    if attempt.status == "cancelled" {
        return Err(PeerError::window_closed(&local_server, step));
    }
    if attempt.status == "failed" {
        return Err(PeerError::conflict(
            &local_server,
            step,
            "This pairing attempt previously failed and was cleaned up",
            "Open a new pairing window and start pairing again",
        ));
    }

    if attempt.status == "expired" || !is_active_expiry(attempt.expires_at, now_ts) {
        return Err(expire_confirm_attempt_locked(runtime, attempt_id, step).await);
    }

    let remote_pubkey = attempt.remote_pubkey.clone().ok_or_else(|| {
        PeerError::invalid_request(
            &local_server,
            step,
            "Pairing attempt is missing remote WireGuard public key",
            "Cancel this attempt and start pairing again",
        )
    })?;
    let remote_tunnel_ip = attempt.remote_tunnel_ip.clone().ok_or_else(|| {
        PeerError::invalid_request(
            &local_server,
            step,
            "Pairing attempt is missing remote tunnel IP",
            "Cancel this attempt and start pairing again",
        )
    })?;
    let remote_endpoint_raw = attempt.remote_endpoint.clone().ok_or_else(|| {
        PeerError::invalid_request(
            &local_server,
            step,
            "Pairing attempt is missing remote endpoint",
            "Cancel this attempt and start pairing again",
        )
    })?;
    let (remote_endpoint_host, remote_wg_port) = split_endpoint_host_port(
        &remote_endpoint_raw,
        af_runner::peer_network::DEFAULT_PEER_WG_PORT,
    );
    let peer_name = match req.name {
        Some(custom) => {
            let trimmed = custom.trim();
            if !is_valid_peer_name(trimmed) {
                return Err(PeerError::invalid_request(
                    &local_server,
                    step,
                    "Peer name must be 1-64 ASCII letters, digits, '.', '_' or '-'",
                    "Provide a valid peer name",
                ));
            }
            trimmed.to_string()
        }
        None => attempt
            .remote_name
            .clone()
            .filter(|n| is_valid_peer_name(n))
            .unwrap_or_else(|| "peer-server".to_string()),
    };

    let identity = ensure_local_identity(runtime, &[], None, step).await?;

    // Retry any pending revocation cleanups on conflicting revoked/revoking links first.
    let conflicting_cleanup_ids: Vec<String> = {
        let pk_c = remote_pubkey.clone();
        let ip_c = remote_tunnel_ip.clone();
        let name_c = peer_name.clone();
        let server_c = local_server.clone();
        runtime
            .db
            .read(&local_server, step, move |conn| {
                let existing = db_peers::list_peer_links(conn).map_err(|err| {
                    PeerError::internal(&server_c, step, format!("Failed listing links: {err}"))
                })?;
                Ok(existing
                    .into_iter()
                    .filter(|l| {
                        (l.wg_pubkey == pk_c || l.tunnel_ip == ip_c || l.name == name_c)
                            && (is_revoking_state(&l.state)
                                || (is_revoked_state(&l.state) && l.pending_expires_at.is_some()))
                    })
                    .map(|l| l.id)
                    .collect())
            })
            .await?
    };
    for stale_id in conflicting_cleanup_ids {
        links::retry_revocation_cleanup(runtime, &stale_id).await?;
    }

    // Pre-acquire the link lock for a newly reserved candidate link (preserving canonical
    // `attempt_lock -> link_lock` order) so a freshly reserved pending row cannot be stranded by
    // link-lock contention between reservation and Phase 1 setup.
    let candidate_link_id = Uuid::new_v4().to_string();
    let candidate_link_guard = runtime.lock_link(&candidate_link_id, step).await?;

    enum ReserveConfirmOutcome {
        Pending { link: PeerLink, is_existing: bool },
        AlreadyLive(PeerLink),
        Completed,
        Expired,
    }

    // Revalidate the attempt and find an existing active pending link (idempotent retry) or
    // atomically reserve one at the actual commit clock after identity/revocation I/O.
    let att_id_c = attempt_id.to_string();
    let pk_c = remote_pubkey.clone();
    let ip_c = remote_tunnel_ip.clone();
    let name_c = peer_name.clone();
    let ep_c = remote_endpoint_host.clone();
    let clock = Arc::clone(&runtime.clock);
    let server_c = local_server.clone();
    let candidate_link_id_c = candidate_link_id.clone();

    let reserve_outcome = runtime
        .db
        .write(&local_server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting confirmation transaction: {err}"),
                    )
                },
            )?;
            let tx_now = clock();
            let tx_now_ts = tx_now.timestamp();
            let tx_now_rfc = tx_now.to_rfc3339();

            let Some(fresh_attempt) = db_peers::get_pairing_attempt(&tx, &att_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
            else {
                return Err(PeerError::not_found(
                    &server_c,
                    step,
                    "Pairing attempt was removed concurrently",
                ));
            };
            match fresh_attempt.status.as_str() {
                "completed" => return Ok(ReserveConfirmOutcome::Completed),
                "cancelled" => return Err(PeerError::window_closed(&server_c, step)),
                "failed" => {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "This pairing attempt previously failed and was cleaned up",
                        "Open a new pairing window and start pairing again",
                    ));
                }
                "expired" => return Ok(ReserveConfirmOutcome::Expired),
                "pending" | "confirming" => {
                    if !is_active_expiry(fresh_attempt.expires_at, tx_now_ts) {
                        persist_attempt_terminal_status_conn(
                            &tx,
                            &att_id_c,
                            "expired",
                            Some("CODE_EXPIRED"),
                            None,
                            &server_c,
                            step,
                        )?;
                        tx.commit()
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        return Ok(ReserveConfirmOutcome::Expired);
                    }
                }
                _ => {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Pairing attempt status changed concurrently",
                        "Refresh the Cluster page and inspect the pairing status",
                    ));
                }
            }

            let links_list = db_peers::list_peer_links(&tx).map_err(|err| {
                PeerError::internal(&server_c, step, format!("Failed listing links: {err}"))
            })?;
            if let Some(existing) = links_list
                .iter()
                .find(|l| l.pending_attempt_id.as_deref() == Some(att_id_c.as_str()))
            {
                if existing.wg_pubkey != pk_c || existing.tunnel_ip != ip_c {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Existing link for this attempt does not match the recorded peer identity",
                        "Cancel the attempt and start pairing again",
                    ));
                }
                if is_live_link_state(&existing.state) {
                    return Ok(ReserveConfirmOutcome::AlreadyLive(existing.clone()));
                }
                if is_revoked_or_revoking_state(&existing.state) {
                    return Err(PeerError::link_revoked(
                        &existing.name,
                        step,
                        format!("Link '{}' has been revoked", existing.name),
                    ));
                }
                if is_pending_link_state(&existing.state) {
                    match classify_pending_expiry(existing.pending_expires_at, tx_now_ts) {
                        PendingExpiryStatus::Active(_) => {
                            return Ok(ReserveConfirmOutcome::Pending {
                                link: existing.clone(),
                                is_existing: true,
                            });
                        }
                        PendingExpiryStatus::Expired => {
                            persist_attempt_terminal_status_conn(
                                &tx,
                                &att_id_c,
                                "expired",
                                Some("CODE_EXPIRED"),
                                None,
                                &server_c,
                                step,
                            )?;
                            tx.commit().map_err(|err| {
                                PeerError::internal(&server_c, step, err.to_string())
                            })?;
                            return Ok(ReserveConfirmOutcome::Expired);
                        }
                        PendingExpiryStatus::CleanupMarked => {
                            return Err(PeerError::conflict(
                                &server_c,
                                step,
                                "Pending peer link is already marked for cleanup",
                                "Open a new pairing window and start pairing again",
                            ));
                        }
                        PendingExpiryStatus::Missing => {
                            return Err(PeerError::conflict(
                                &server_c,
                                step,
                                "Pending peer link is missing its expiry deadline",
                                "Open a new pairing window and start pairing again",
                            ));
                        }
                    }
                }
                return Err(PeerError::conflict(
                    &server_c,
                    step,
                    "Existing link for this attempt is not in a confirmable state",
                    "Refresh the Cluster page and inspect the link state",
                ));
            }
            for link in &links_list {
                let conflict =
                    link.wg_pubkey == pk_c || link.tunnel_ip == ip_c || link.name == name_c;
                if !conflict {
                    continue;
                }
                if is_revoked_state(&link.state) && link.pending_expires_at.is_none() {
                    tx.execute(
                        "DELETE FROM peer_links \
                         WHERE id = ?1 AND state IN ('revoked', 'revoked_unowned') \
                           AND pending_expires_at IS NULL",
                        params![link.id],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed removing stale revoked link: {err}"),
                        )
                    })?;
                    continue;
                }
                if is_revoking_state(&link.state)
                    || (is_revoked_state(&link.state) && link.pending_expires_at.is_some())
                {
                    return Err(PeerError::busy(
                        &server_c,
                        step,
                        format!(
                            "Revocation cleanup is still pending for '{}'; retry shortly",
                            link.name
                        ),
                    ));
                }
                if link.tunnel_ip == ip_c {
                    return Err(PeerError::tunnel_ip_conflict(
                        &server_c,
                        step,
                        format!(
                            "Tunnel IP {ip_c} is already assigned to peer '{}'",
                            link.name
                        ),
                    ));
                }
                if link.wg_pubkey == pk_c {
                    return Err(PeerError::key_mismatch(
                        &server_c,
                        step,
                        format!("WireGuard key is already linked as '{}'", link.name),
                    ));
                }
                return Err(PeerError::conflict(
                    &server_c,
                    step,
                    format!("Peer name '{}' is already in use", link.name),
                    "Supply a distinct peer name when confirming",
                ));
            }

            let new_link = PeerLink {
                id: candidate_link_id_c,
                name: name_c,
                wg_pubkey: pk_c,
                tunnel_ip: ip_c,
                endpoint: ep_c,
                wg_port: remote_wg_port,
                state: STATE_PENDING.to_string(),
                peer_version: None,
                peer_protocol: None,
                capabilities: None,
                rtt_ms: None,
                last_ok_at: None,
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: None,
                pending_attempt_id: Some(att_id_c),
                pending_expires_at: Some(fresh_attempt.expires_at),
                created_at: tx_now_rfc.clone(),
                updated_at: tx_now_rfc,
            };
            db_peers::insert_peer_link(&tx, &new_link).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed saving pending peer link: {err}"),
                )
            })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing pending peer link: {err}"),
                )
            })?;
            Ok(ReserveConfirmOutcome::Pending {
                link: new_link,
                is_existing: false,
            })
        })
        .await?;

    let (b_link, is_existing_attempt_link) = match reserve_outcome {
        ReserveConfirmOutcome::Pending { link, is_existing } => (link, is_existing),
        ReserveConfirmOutcome::AlreadyLive(link) => {
            return Ok(serde_json::json!({
                "link_id": link.id,
                "name": link.name,
                "state": public_link_state(&link.state),
                "attempt_id": attempt_id,
                "confirmed": true,
            }));
        }
        ReserveConfirmOutcome::Completed => {
            drop(candidate_link_guard);
            return confirm_completed_attempt_response(runtime, attempt_id, &remote_pubkey, step)
                .await;
        }
        ReserveConfirmOutcome::Expired => {
            drop(candidate_link_guard);
            return Err(expire_confirm_attempt_locked(runtime, attempt_id, step).await);
        }
    };

    // Phase 1 local setup under canonical lock order (`attempt_lock` -> `link_lock`):
    // reuse/mint link-namespaced PendingIssuerToken, add/reconcile WireGuard peer, and load any
    // previously persisted outbound held token before releasing link_lock for tunnel HTTP.
    let (b_inbound_token, existing_held_a_token) = {
        let _link_guard = if is_existing_attempt_link {
            drop(candidate_link_guard);
            runtime.lock_link(&b_link.id, step).await?
        } else {
            candidate_link_guard
        };

        let current_b_link = ensure_confirm_pending_active_locked(
            runtime,
            &b_link.id,
            &remote_pubkey,
            attempt_id,
            step,
        )
        .await?;

        // Check first whether B already received and stored A's held outbound link token during
        // an earlier confirmation whose acknowledgement timed out. If so, B only needs to retry
        // Phase 3 (Acknowledge) and does not require `PendingIssuerToken` to still exist.
        let existing_held_a_token = runtime
            .runner
            .dispatch(&PeerNetworkRequest::ReadCredential {
                slot: PeerCredentialSlot::LinkToken,
                id: b_link.id.clone(),
            })
            .await
            .and_then(|resp| resp.into_credential_read())
            .map_err(|err| map_runner_error(err, &local_server, step))?
            .into_secret();

        let b_inbound_token = if existing_held_a_token.is_some() {
            if current_b_link.inbound_token_hash.is_none() {
                return Err(PeerError::unauthorized(
                    &local_server,
                    step,
                    "Pending link is missing its incoming link credential digest; restart pairing",
                ));
            }
            None
        } else {
            let pending_cred_id = pending_issuer_credential_id(&b_link.id);
            let existing_issuer_cred = runtime
                .runner
                .dispatch(&PeerNetworkRequest::ReadCredential {
                    slot: PeerCredentialSlot::PendingIssuerToken,
                    id: pending_cred_id.clone(),
                })
                .await
                .and_then(|resp| resp.into_credential_read())
                .map_err(|err| map_runner_error(err, &local_server, step))?;

            let token = if let Some(secret) = existing_issuer_cred.into_secret() {
                let digest = sha256_prefixed(secret.expose_secret());
                match current_b_link.inbound_token_hash.as_deref() {
                    Some(stored) if constant_time_eq(stored.as_bytes(), digest.as_bytes()) => {
                        secret
                    }
                    Some(_) => {
                        return Err(PeerError::unauthorized(
                            &local_server,
                            step,
                            "Stored incoming link digest does not match temporary issuer credential",
                        ));
                    }
                    None => {
                        commit_confirm_issuer_digest_locked(
                            runtime,
                            &b_link.id,
                            &remote_pubkey,
                            attempt_id,
                            &digest,
                            step,
                        )
                        .await?;
                        secret
                    }
                }
            } else {
                if current_b_link.inbound_token_hash.is_some() {
                    return Err(PeerError::unauthorized(
                        &local_server,
                        step,
                        "Temporary issuer credential for this pending confirmation is no longer available; restart pairing",
                    ));
                }
                // Recheck row/attempt expiry before minting & writing a temporary issuer token.
                let _ = ensure_confirm_pending_active_locked(
                    runtime,
                    &b_link.id,
                    &remote_pubkey,
                    attempt_id,
                    step,
                )
                .await?;
                let minted = mint_secret_token();
                let digest = sha256_prefixed(minted.expose_secret());
                runtime
                    .runner
                    .dispatch(&PeerNetworkRequest::WriteCredential {
                        slot: PeerCredentialSlot::PendingIssuerToken,
                        id: pending_cred_id.clone(),
                        value: minted.expose_secret().to_string(),
                    })
                    .await
                    .and_then(|resp| resp.into_credential_written())
                    .map_err(|err| map_runner_error(err, &local_server, step))?;

                commit_confirm_issuer_digest_locked(
                    runtime,
                    &b_link.id,
                    &remote_pubkey,
                    attempt_id,
                    &digest,
                    step,
                )
                .await?;
                minted
            };
            Some(token)
        };

        // Recheck row/attempt expiry before mutating WireGuard with `AddPeer`.
        let _ = ensure_confirm_pending_active_locked(
            runtime,
            &b_link.id,
            &remote_pubkey,
            attempt_id,
            step,
        )
        .await?;

        // Add A's pinned key & tunnel IP to B's afpeer0; ONLY a definitive successful `AddPeer`
        // (`Ok(Mutation)`) establishes durable `pending_owned` ownership. Reconciling an existing
        // peer preserves prior durable state without ever promoting `pending` -> `pending_owned`,
        // and conflicts/failed reconciliation durably demote to `pending` before cleanup so no
        // immediate retry or restart can remove an unrelated WireGuard peer.
        let add_req = PeerNetworkRequest::AddPeer {
            pubkey: remote_pubkey.clone(),
            endpoint: remote_endpoint_host.clone(),
            port: remote_wg_port,
            tunnel_ip: remote_tunnel_ip.clone(),
        };
        match runtime.runner.dispatch(&add_req).await {
            Ok(resp) => {
                if let Err(err) = resp
                    .into_mutation()
                    .map_err(|e| map_runner_error(e, &local_server, step))
                {
                    if demote_pending_wg_ownership_locked(
                        runtime,
                        &b_link.id,
                        &remote_pubkey,
                        Some(attempt_id),
                        Some(err.code()),
                        &format!(
                            "Ambiguous AddPeer response during confirmation: {}",
                            err.code()
                        ),
                    )
                    .await
                    .is_ok()
                    {
                        let _ = cleanup_pending_link_locked(
                            runtime,
                            &b_link.id,
                            &remote_pubkey,
                            Some(attempt_id),
                            "failed",
                            Some(err.code()),
                        )
                        .await;
                    }
                    return Err(err);
                }
                let _ = commit_pending_wg_ownership_locked(
                    runtime,
                    &b_link.id,
                    &remote_pubkey,
                    &remote_tunnel_ip,
                    Some(attempt_id),
                    step,
                )
                .await?;
            }
            Err(PeerNetworkError::PeerAlreadyExists(_)) => {
                if let Err(err) = reconcile_existing_pending_peer(
                    runtime,
                    &remote_pubkey,
                    &remote_tunnel_ip,
                    &local_server,
                    step,
                )
                .await
                {
                    if !err.is_terminal_for_confirm() {
                        return Err(err);
                    }
                    // Do not remove an unrelated conflicting WireGuard peer; durably ensure
                    // `state = 'pending'` (unowned) before cleaning up DB link and credentials.
                    if demote_pending_wg_ownership_locked(
                        runtime,
                        &b_link.id,
                        &remote_pubkey,
                        Some(attempt_id),
                        Some(err.code()),
                        &format!(
                            "Existing WireGuard peer failed reconciliation: {}",
                            err.code()
                        ),
                    )
                    .await
                    .is_ok()
                    {
                        let _ = cleanup_pending_link_locked(
                            runtime,
                            &b_link.id,
                            &remote_pubkey,
                            Some(attempt_id),
                            "failed",
                            Some(err.code()),
                        )
                        .await;
                    }
                    return Err(err);
                }
                // Preserve existing durable ownership (`pending_owned` stays `pending_owned` on
                // legitimate confirm retry; preexisting `pending` stays `pending` and is never
                // promoted).
            }
            Err(PeerNetworkError::Busy(msg)) => {
                return Err(PeerError::busy(&local_server, step, msg));
            }
            Err(err) => {
                // AddPeer failed without establishing ownership (e.g. Conflict / TunnelIpConflict);
                // durably ensure `state = 'pending'` (unowned) so neither immediate cleanup nor
                // any retry or restart can remove an unrelated WireGuard peer.
                let mapped = map_runner_error(err, &local_server, step);
                if demote_pending_wg_ownership_locked(
                    runtime,
                    &b_link.id,
                    &remote_pubkey,
                    Some(attempt_id),
                    Some(mapped.code()),
                    &format!("AddPeer rejected during confirmation: {}", mapped.code()),
                )
                .await
                .is_ok()
                {
                    let _ = cleanup_pending_link_locked(
                        runtime,
                        &b_link.id,
                        &remote_pubkey,
                        Some(attempt_id),
                        "failed",
                        Some(mapped.code()),
                    )
                    .await;
                }
                return Err(mapped);
            }
        }

        // Mark attempt as confirming via guarded column-scoped SQL once AddPeer succeeds,
        // revalidating both attempt and link nonzero exclusive expiry at actual commit time.
        let att_id_c = attempt_id.to_string();
        let lid_c = b_link.id.clone();
        let pk_c = remote_pubkey.clone();
        let clock = Arc::clone(&runtime.clock);
        let server_c = local_server.clone();
        let confirming_outcome = runtime
            .db
            .write(&local_server, step, move |conn| {
                let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                    .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                let confirm_now_ts = clock().timestamp();
                let changed = tx
                    .execute(
                        "UPDATE peer_pairing_attempts \
                         SET status = 'confirming' \
                         WHERE id = ?1 AND status IN ('pending', 'confirming') \
                           AND expires_at != 0 AND expires_at > ?2 \
                           AND EXISTS ( \
                               SELECT 1 FROM peer_links \
                               WHERE id = ?3 AND wg_pubkey = ?4 \
                                 AND state IN ('pending', 'pending_owned') \
                                 AND pending_attempt_id = ?1 \
                                 AND pending_expires_at IS NOT NULL \
                                 AND pending_expires_at != 0 \
                                 AND pending_expires_at > ?2 \
                           )",
                        params![att_id_c, confirm_now_ts, lid_c, pk_c],
                    )
                    .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                if changed == 1 {
                    tx.commit()
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    return Ok(Ok(()));
                }
                let _ = tx.rollback();
                let state = inspect_confirm_pending_state(
                    conn,
                    &lid_c,
                    &att_id_c,
                    &pk_c,
                    confirm_now_ts,
                    &server_c,
                    step,
                )?;
                Ok(Err(state))
            })
            .await?;

        if let Err(state) = confirming_outcome {
            return Err(resolve_non_active_confirm_state_locked(
                runtime,
                state,
                &b_link.id,
                &remote_pubkey,
                attempt_id,
                step,
            )
            .await);
        }

        (b_inbound_token, existing_held_a_token)
    };

    // Helper for terminal cleanup during handshake phases (acquires link_lock while holding
    // attempt_lock, strictly preserving canonical lock order and durable WG peer ownership).
    let cleanup_confirm_terminal = |error_code: String| {
        let rt = Arc::clone(runtime);
        let lid = b_link.id.clone();
        let pk = remote_pubkey.clone();
        let att = attempt_id.to_string();
        async move {
            let attempt_status = if error_code == "CODE_EXPIRED" {
                "expired"
            } else {
                "failed"
            };
            match rt.lock_link(&lid, "confirm_terminal_cleanup").await {
                Ok(_link_guard) => {
                    if let Err(cleanup_err) = cleanup_pending_link_locked(
                        &rt,
                        &lid,
                        &pk,
                        Some(&att),
                        attempt_status,
                        Some(&error_code),
                    )
                    .await
                    {
                        tracing::warn!(
                            link_id = %lid,
                            %cleanup_err,
                            "Terminal confirm cleanup failed transiently; durable retry state retained"
                        );
                    }
                }
                Err(lock_err) => {
                    tracing::warn!(
                        link_id = %lid,
                        %lock_err,
                        "Terminal confirm cleanup could not acquire link lock; persisting guarded zero-expiry cleanup marker"
                    );
                    mark_pending_cleanup_retry(
                        &rt,
                        &lid,
                        &pk,
                        Some(&att),
                        Some((attempt_status, Some(&error_code))),
                        &format!(
                            "Terminal confirm cleanup deferred due to lock contention ({error_code})"
                        ),
                    )
                    .await;
                }
            }
        }
    };

    let held_a_token = if let Some(existing_token) = existing_held_a_token {
        existing_token
    } else {
        let b_inbound_secret = b_inbound_token.as_ref().ok_or_else(|| {
            PeerError::internal(
                &local_server,
                step,
                "Missing temporary issuer token for hello bootstrap",
            )
        })?;
        // Phase 2: Bootstrap hello over WireGuard tunnel (link_lock released across outbound HTTP).
        let bootstrap_req = HelloRequest {
            phase: HelloPhase::Bootstrap,
            attempt_id: attempt_id.to_string(),
            wg_pubkey: identity.wg_pubkey.clone(),
            tunnel_ip: Some(identity.tunnel_ip.clone()),
            version: runtime.local_version(),
            peer_protocol: PEER_PROTOCOL_VERSION,
            capabilities: capabilities().into_iter().map(str::to_string).collect(),
            link_token: Some(b_inbound_secret.clone()),
        };
        let bootstrap_bytes = serde_json::to_vec(&bootstrap_req).map_err(|_| {
            PeerError::internal(&local_server, step, "Failed serializing hello bootstrap")
        })?;

        let (status, resp_bytes, rtt_ms) = runtime
            .send_tunnel_request(
                Method::POST,
                &b_link.tunnel_ip,
                "/peer/v1/hello",
                None,
                Some(bootstrap_bytes),
                runtime.tunnel_request_timeout,
            )
            .await
            .map_err(|err| {
                PeerError::handshake_timeout(
                    &b_link.name,
                    "tunnel_hello_bootstrap",
                    format!(
                        "Tunnel bootstrap to {} did not complete: {}",
                        b_link.name,
                        err.message()
                    ),
                )
            })?;

        if !status.is_success() {
            let remote_err = PeerError::from_remote_http(
                status,
                &resp_bytes,
                &b_link.name,
                "tunnel_hello_bootstrap",
            );
            if remote_err.is_terminal_for_confirm() {
                cleanup_confirm_terminal(remote_err.code().to_string()).await;
            }
            return Err(remote_err);
        }

        let hello_resp: HelloResponse = match serde_json::from_slice(&resp_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                let err = PeerError::version_incompatible(
                    &b_link.name,
                    "tunnel_hello_bootstrap",
                    format!(
                        "{} returned an invalid hello bootstrap payload",
                        b_link.name
                    ),
                );
                cleanup_confirm_terminal(err.code().to_string()).await;
                return Err(err);
            }
        };

        if hello_resp.phase != HelloPhase::Bootstrap
            || hello_resp.attempt_id != attempt_id
            || hello_resp.acknowledged
            || hello_resp.state != "pending"
        {
            let err = PeerError::version_incompatible(
                &b_link.name,
                "tunnel_hello_bootstrap",
                format!(
                    "{} returned an unexpected hello bootstrap phase, attempt, or state",
                    b_link.name
                ),
            );
            cleanup_confirm_terminal(err.code().to_string()).await;
            return Err(err);
        }
        if hello_resp.wg_pubkey != remote_pubkey {
            let err = PeerError::key_mismatch(
                &b_link.name,
                "tunnel_hello_bootstrap",
                format!(
                    "{} responded with a different WireGuard key than pinned in the pairing attempt",
                    b_link.name
                ),
            );
            cleanup_confirm_terminal(err.code().to_string()).await;
            return Err(err);
        }
        if hello_resp.peer_protocol < MIN_PEER_PROTOCOL_VERSION {
            let err = PeerError::version_incompatible(
                &b_link.name,
                "tunnel_hello_bootstrap",
                format!(
                    "{} reported incompatible peer protocol {}",
                    b_link.name, hello_resp.peer_protocol
                ),
            );
            cleanup_confirm_terminal(err.code().to_string()).await;
            return Err(err);
        }

        let Some(a_token) = hello_resp.link_token else {
            let err = PeerError::unauthorized(
                &b_link.name,
                "tunnel_hello_bootstrap",
                format!(
                    "{} did not issue an independent incoming link token",
                    b_link.name
                ),
            );
            cleanup_confirm_terminal(err.code().to_string()).await;
            return Err(err);
        };
        if !validate_secret_token_shape(a_token.expose_secret())
            || constant_time_eq(
                a_token.expose_secret().as_bytes(),
                b_inbound_secret.expose_secret().as_bytes(),
            )
        {
            let err = PeerError::unauthorized(
                &b_link.name,
                "tunnel_hello_bootstrap",
                format!(
                    "{} returned an invalid or non-independent link token",
                    b_link.name
                ),
            );
            cleanup_confirm_terminal(err.code().to_string()).await;
            return Err(err);
        }

        // Persist A's held outbound token and peer metadata under link_lock with fresh pre-I/O
        // and guarded SQL expiry checks.
        {
            let _link_guard = runtime.lock_link(&b_link.id, step).await?;
            let _ = ensure_confirm_pending_active_locked(
                runtime,
                &b_link.id,
                &remote_pubkey,
                attempt_id,
                step,
            )
            .await?;

            runtime
                .runner
                .dispatch(&PeerNetworkRequest::WriteCredential {
                    slot: PeerCredentialSlot::LinkToken,
                    id: b_link.id.clone(),
                    value: a_token.expose_secret().to_string(),
                })
                .await
                .and_then(|resp| resp.into_credential_written())
                .map_err(|err| map_runner_error(err, &local_server, step))?;

            let lid_u = b_link.id.clone();
            let pk_u = remote_pubkey.clone();
            let att_u = attempt_id.to_string();
            let peer_ver = hello_resp.version;
            let peer_proto = hello_resp.peer_protocol;
            let caps_json = serde_json::to_string(&hello_resp.capabilities).ok();
            let clock = Arc::clone(&runtime.clock);
            let server_c = local_server.clone();
            let metadata_outcome = runtime
                .db
                .write(&local_server, step, move |conn| {
                    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    let commit_now = clock();
                    let commit_now_ts = commit_now.timestamp();
                    let now_u = commit_now.to_rfc3339();
                    let changed = tx
                        .execute(
                            "UPDATE peer_links \
                             SET peer_version = ?4, peer_protocol = ?5, capabilities = ?6, \
                                 rtt_ms = ?7, updated_at = ?8 \
                             WHERE id = ?1 AND wg_pubkey = ?2 \
                               AND state IN ('pending', 'pending_owned') \
                               AND pending_attempt_id = ?3 \
                               AND pending_expires_at IS NOT NULL \
                               AND pending_expires_at != 0 \
                               AND pending_expires_at > ?9 \
                               AND EXISTS ( \
                                   SELECT 1 FROM peer_pairing_attempts \
                                   WHERE id = ?3 AND status IN ('pending', 'confirming') \
                                     AND expires_at != 0 AND expires_at > ?9 \
                               )",
                            params![
                                lid_u,
                                pk_u,
                                att_u,
                                peer_ver,
                                peer_proto,
                                caps_json,
                                rtt_ms,
                                now_u,
                                commit_now_ts,
                            ],
                        )
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    if changed == 1 {
                        tx.commit()
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        return Ok(Ok(()));
                    }
                    let _ = tx.rollback();
                    let state = inspect_confirm_pending_state(
                        conn,
                        &lid_u,
                        &att_u,
                        &pk_u,
                        commit_now_ts,
                        &server_c,
                        step,
                    )?;
                    Ok(Err(state))
                })
                .await?;

            if let Err(state) = metadata_outcome {
                return Err(resolve_non_active_confirm_state_locked(
                    runtime,
                    state,
                    &b_link.id,
                    &remote_pubkey,
                    attempt_id,
                    step,
                )
                .await);
            }
        }

        a_token
    };

    // Phase 3: Send authenticated acknowledgement through `/peer/v1/hello` using A's newly issued
    // link token in `X-AF-Link-Token` (link_lock released across outbound HTTP).
    let ack_req = HelloRequest {
        phase: HelloPhase::Acknowledge,
        attempt_id: attempt_id.to_string(),
        wg_pubkey: identity.wg_pubkey.clone(),
        tunnel_ip: Some(identity.tunnel_ip.clone()),
        version: runtime.local_version(),
        peer_protocol: PEER_PROTOCOL_VERSION,
        capabilities: capabilities().into_iter().map(str::to_string).collect(),
        link_token: None,
    };
    let ack_bytes = serde_json::to_vec(&ack_req).map_err(|_| {
        PeerError::internal(
            &local_server,
            step,
            "Failed serializing hello acknowledgement",
        )
    })?;

    let (ack_status, ack_resp_bytes, ack_rtt_ms) = runtime
        .send_tunnel_request(
            Method::POST,
            &b_link.tunnel_ip,
            "/peer/v1/hello",
            Some(&held_a_token),
            Some(ack_bytes),
            runtime.tunnel_request_timeout,
        )
        .await
        .map_err(|err| {
            PeerError::handshake_timeout(
                &b_link.name,
                "tunnel_hello_acknowledge",
                format!(
                    "Tunnel acknowledgement to {} timed out: {}",
                    b_link.name,
                    err.message()
                ),
            )
        })?;

    drop(held_a_token);
    drop(b_inbound_token);

    if !ack_status.is_success() {
        let remote_err = PeerError::from_remote_http(
            ack_status,
            &ack_resp_bytes,
            &b_link.name,
            "tunnel_hello_acknowledge",
        );
        if remote_err.is_terminal_for_confirm() {
            cleanup_confirm_terminal(remote_err.code().to_string()).await;
        }
        return Err(remote_err);
    }

    let ack_resp: HelloResponse = match serde_json::from_slice::<HelloResponse>(&ack_resp_bytes) {
        Ok(parsed) => parsed,
        Err(_) => {
            let err = PeerError::version_incompatible(
                &b_link.name,
                "tunnel_hello_acknowledge",
                format!(
                    "{} returned an unreadable hello acknowledgement payload",
                    b_link.name
                ),
            );
            cleanup_confirm_terminal(err.code().to_string()).await;
            return Err(err);
        }
    };

    // Strictly validate ack identity, phase, attempt, protocol, state, and response envelope.
    if ack_resp.wg_pubkey != remote_pubkey {
        let err = PeerError::key_mismatch(
            &b_link.name,
            "tunnel_hello_acknowledge",
            format!(
                "{} responded to acknowledgement with a different WireGuard key than pinned",
                b_link.name
            ),
        );
        cleanup_confirm_terminal(err.code().to_string()).await;
        return Err(err);
    }
    if ack_resp.peer_protocol < MIN_PEER_PROTOCOL_VERSION {
        let err = PeerError::version_incompatible(
            &b_link.name,
            "tunnel_hello_acknowledge",
            format!(
                "{} reported incompatible peer protocol {} during acknowledgement",
                b_link.name, ack_resp.peer_protocol
            ),
        );
        cleanup_confirm_terminal(err.code().to_string()).await;
        return Err(err);
    }
    if ack_resp.phase != HelloPhase::Acknowledge
        || ack_resp.attempt_id != attempt_id
        || !ack_resp.acknowledged
        || !matches!(ack_resp.state.as_str(), "active" | "down")
        || ack_resp.link_token.is_some()
        || ack_resp.version.trim().is_empty()
        || ack_resp.version.len() > 64
    {
        let err = PeerError::version_incompatible(
            &b_link.name,
            "tunnel_hello_acknowledge",
            format!(
                "{} did not return a valid pairing activation acknowledgement",
                b_link.name
            ),
        );
        cleanup_confirm_terminal(err.code().to_string()).await;
        return Err(err);
    }

    // Phase 4: Atomically activate B's link and complete the attempt in a single SQLite
    // transaction under `link_lock` with fresh nonzero exclusive expiry guards on both rows,
    // then remove B's link-namespaced PendingIssuerToken (retaining durable retry metadata on
    // transient runner error).
    {
        let _link_guard = runtime.lock_link(&b_link.id, step).await?;
        let lid_c = b_link.id.clone();
        let pk_c = remote_pubkey.clone();
        let att_c = attempt_id.to_string();
        let peer_ver = ack_resp.version;
        let peer_proto = ack_resp.peer_protocol;
        let caps_json = serde_json::to_string(&ack_resp.capabilities).ok();
        let clock = Arc::clone(&runtime.clock);
        let server_c = local_server.clone();

        let activation_outcome = runtime
            .db
            .write(&local_server, step, move |conn| {
                let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                    |err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed starting activation transaction: {err}"),
                        )
                    },
                )?;
                let commit_now = clock();
                let commit_now_ts = commit_now.timestamp();
                let activated_at = commit_now.to_rfc3339();

                let attempt_changed = tx
                    .execute(
                        "UPDATE peer_pairing_attempts \
                         SET status = 'completed', error_code = NULL \
                         WHERE id = ?1 AND status IN ('pending', 'confirming') \
                           AND expires_at != 0 AND expires_at > ?2",
                        params![att_c, commit_now_ts],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed completing pairing attempt: {err}"),
                        )
                    })?;

                let link_changed = if attempt_changed == 1 {
                    tx.execute(
                        "UPDATE peer_links SET \
                            state = CASE state \
                                WHEN 'pending_owned' THEN 'active' \
                                WHEN 'pending' THEN 'active_unowned' \
                            END, \
                            peer_version = COALESCE(?4, peer_version), \
                            peer_protocol = COALESCE(?5, peer_protocol), \
                            capabilities = COALESCE(?6, capabilities), \
                            rtt_ms = ?7, \
                            last_ok_at = ?8, \
                            last_error = NULL, \
                            consecutive_failures = 0, \
                            pending_expires_at = 0, \
                            updated_at = ?8 \
                         WHERE id = ?1 AND wg_pubkey = ?2 \
                           AND state IN ('pending', 'pending_owned') \
                           AND pending_attempt_id = ?3 AND inbound_token_hash IS NOT NULL \
                           AND pending_expires_at IS NOT NULL \
                           AND pending_expires_at != 0 \
                           AND pending_expires_at > ?9",
                        params![
                            lid_c,
                            pk_c,
                            att_c,
                            peer_ver,
                            peer_proto,
                            caps_json,
                            ack_rtt_ms,
                            activated_at,
                            commit_now_ts,
                        ],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed activating peer link: {err}"),
                        )
                    })?
                } else {
                    0
                };

                if attempt_changed == 1 && link_changed == 1 {
                    tx.commit().map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed committing link activation: {err}"),
                        )
                    })?;
                    return Ok(Ok(()));
                }

                let _ = tx.rollback();
                let state = inspect_confirm_pending_state(
                    conn,
                    &lid_c,
                    &att_c,
                    &pk_c,
                    commit_now_ts,
                    &server_c,
                    step,
                )?;
                Ok(Err(state))
            })
            .await?;

        if let Err(state) = activation_outcome {
            return Err(resolve_non_active_confirm_state_locked(
                runtime,
                state,
                &b_link.id,
                &remote_pubkey,
                attempt_id,
                step,
            )
            .await);
        }

        match delete_pending_issuer_credential_idempotent(runtime, &b_link.id, &local_server, step)
            .await
        {
            Ok(()) => {
                let lid_clr = b_link.id.clone();
                let att_clr = attempt_id.to_string();
                let now_clr = runtime.now().to_rfc3339();
                let _ = runtime
                    .db
                    .write(&local_server, step, move |conn| {
                        let _ = conn.execute(
                            "UPDATE peer_links \
                             SET pending_attempt_id = NULL, pending_expires_at = NULL, updated_at = ?3 \
                             WHERE id = ?1 AND state NOT IN ('pending', 'pending_owned') \
                               AND pending_attempt_id = ?2",
                            params![lid_clr, att_clr, now_clr],
                        );
                        Ok(())
                    })
                    .await;
            }
            Err(error) => {
                tracing::warn!(
                    link_id = %b_link.id,
                    %error,
                    "Transient failure deleting temporary issuer credential after activation; sweep will retry"
                );
            }
        }
    }

    drop(_attempt_guard);

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_pairing_confirmed".to_string(),
            "peer_link".to_string(),
            b_link.id.clone(),
            format!(
                "Confirmed pairing and activated link with '{}' (attempt {})",
                b_link.name, attempt_id
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(serde_json::json!({
        "link_id": b_link.id,
        "name": b_link.name,
        "state": "active",
        "attempt_id": attempt_id,
        "confirmed": true,
        "rtt_ms": ack_rtt_ms,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancel Pending Pairing Attempt (`DELETE /api/v1/admin/peers/pairing/:attempt`)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn cancel_pairing(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(attempt_id): Path<String>,
) -> Response {
    match cancel_pairing_inner(&runtime, &auth_user, peer_ip, &headers, &attempt_id).await {
        Ok(val) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn cancel_pairing_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    attempt_id: &str,
) -> Result<serde_json::Value, PeerError> {
    let server = runtime.local_server_name();
    let step = "cancel_pairing";

    if !is_valid_credential_id(attempt_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid pairing attempt identifier",
            "Provide a valid pairing attempt identifier",
        ));
    }

    let _attempt_guard = runtime.lock_attempt(attempt_id, step).await?;

    let att_id_c = attempt_id.to_string();
    let (attempt_opt, matching_link_opt) = runtime
        .db
        .read(&server, step, move |conn| {
            let attempt = db_peers::get_pairing_attempt(conn, &att_id_c)
                .map_err(|err| PeerError::internal("local", "cancel_pairing", err.to_string()))?;
            let link = db_peers::list_peer_links(conn)
                .map_err(|err| PeerError::internal("local", "cancel_pairing", err.to_string()))?
                .into_iter()
                .find(|l| l.pending_attempt_id.as_deref() == Some(att_id_c.as_str()));
            Ok((attempt, link))
        })
        .await?;

    if attempt_opt.is_none() && matching_link_opt.is_none() {
        return Err(PeerError::not_found(
            &server,
            step,
            "Pending pairing attempt was not found",
        ));
    }

    let mut committed_cancel = false;
    if let Some(link) = matching_link_opt {
        let _link_guard = runtime.lock_link(&link.id, step).await?;
        let lid_c = link.id.clone();
        let current = runtime
            .db
            .read(&server, step, move |conn| {
                db_peers::get_peer_link(conn, &lid_c)
                    .map_err(|err| PeerError::internal("local", "cancel_pairing", err.to_string()))
            })
            .await?;

        match current {
            Some(row)
                if is_pending_link_state(&row.state)
                    && row.pending_attempt_id.as_deref() == Some(attempt_id) =>
            {
                committed_cancel = cleanup_pending_link_locked(
                    runtime,
                    &row.id,
                    &row.wg_pubkey,
                    Some(attempt_id),
                    "cancelled",
                    None,
                )
                .await?;
            }
            Some(_) => {
                return Err(PeerError::conflict(
                    &server,
                    step,
                    "Pairing attempt has already activated a peer link",
                    "Delete the peer link instead if you want to revoke access",
                ));
            }
            None => {
                return Err(PeerError::not_found(
                    &server,
                    step,
                    "Pending pairing attempt was already removed",
                ));
            }
        }
    } else if let Some(attempt) = attempt_opt {
        if attempt.status == "completed" {
            return Err(PeerError::conflict(
                &server,
                step,
                "Pairing attempt has already completed",
                "Delete the active peer link instead if you want to revoke access",
            ));
        }
        // No pending peer_links row is owned by this attempt, so NEVER touch WireGuard peers or
        // link credentials (a later active link may legitimately share the same remote pubkey).
        if matches!(attempt.status.as_str(), "pending" | "confirming") {
            let att_upd = attempt.id.clone();
            let server_c = server.clone();
            let changed = runtime
                .db
                .write(&server, step, move |conn| {
                    conn.execute(
                        "UPDATE peer_pairing_attempts \
                         SET status = 'cancelled', error_code = NULL \
                         WHERE id = ?1 AND status IN ('pending', 'confirming')",
                        params![att_upd],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed cancelling pairing attempt: {err}"),
                        )
                    })
                })
                .await?;
            committed_cancel = changed == 1;
        }
    }

    drop(_attempt_guard);

    if committed_cancel {
        let client_ip = extract_client_ip_for_peer(headers, peer_ip);
        runtime
            .db
            .record_audit(
                auth_user.user_id,
                auth_user.username.clone(),
                "peer_pairing_cancelled".to_string(),
                "peer_pairing_attempt".to_string(),
                attempt_id.to_string(),
                "Cancelled pending pairing attempt and cleaned up owned pending credentials"
                    .to_string(),
                client_ip,
                String::new(),
            )
            .await;
    }

    Ok(serde_json::json!({
        "cancelled": true,
        "attempt_id": attempt_id,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tunnel Listener Pre-Activation Bootstrap & Acknowledge (`POST /peer/v1/hello`)
// ─────────────────────────────────────────────────────────────────────────────

const HELLO_AUDIT_ROUTE_LABEL: &str = "POST /peer/v1/hello";

pub(crate) async fn handle_tunnel_hello(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request,
) -> Response {
    let local_server = runtime.local_server_name();
    let step = "tunnel_hello";

    // Check tunnel source IP, peer registration, revocation state, and per-link permit BEFORE
    // reading or parsing any request body.
    let Some(ConnectInfo(remote_addr)) = connect_info else {
        let err =
            PeerError::unauthorized(&local_server, step, "Tunnel source address is unavailable");
        audit_listener_denial(&runtime, HELLO_AUDIT_ROUTE_LABEL, "unknown", err.code()).await;
        return err.into_response();
    };
    let source_ip = remote_addr.ip().to_canonical();
    let source_ip_str = source_ip.to_string();

    let ip_lookup = source_ip_str.clone();
    let initial_link = match runtime
        .db
        .read(&local_server, step, move |conn| {
            db_peers::get_peer_link_by_tunnel_ip(conn, &ip_lookup)
                .map_err(|err| PeerError::internal("local", "tunnel_hello", err.to_string()))
        })
        .await
    {
        Ok(Some(link)) => link,
        Ok(None) => {
            let err = PeerError::unauthorized(
                &local_server,
                step,
                "Tunnel source IP does not match any pending peer link",
            );
            audit_listener_denial(
                &runtime,
                HELLO_AUDIT_ROUTE_LABEL,
                &source_ip_str,
                err.code(),
            )
            .await;
            return err.into_response();
        }
        Err(err) => {
            audit_listener_denial(
                &runtime,
                HELLO_AUDIT_ROUTE_LABEL,
                &source_ip_str,
                err.code(),
            )
            .await;
            return err.into_response();
        }
    };

    if is_revoked_or_revoking_state(&initial_link.state) {
        let err = PeerError::link_revoked(
            &local_server,
            step,
            format!("Link with '{}' has been revoked", initial_link.name),
        );
        audit_listener_denial(
            &runtime,
            HELLO_AUDIT_ROUTE_LABEL,
            &source_ip_str,
            err.code(),
        )
        .await;
        return err.into_response();
    }

    let Some(_permit) = runtime.acquire_link_permit(&initial_link.id) else {
        let err = PeerError::busy(
            &local_server,
            step,
            "Per-link concurrency limit reached on peer tunnel listener",
        );
        audit_listener_denial(
            &runtime,
            HELLO_AUDIT_ROUTE_LABEL,
            &source_ip_str,
            err.code(),
        )
        .await;
        return err.into_response();
    };

    let (parts, body) = req.into_parts();
    let parsed_req: HelloRequest = match extract_bounded_json(
        &parts.headers,
        body,
        TUNNEL_INTERNAL_BODY_LIMIT_BYTES,
        &local_server,
        step,
    )
    .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            audit_listener_denial(
                &runtime,
                HELLO_AUDIT_ROUTE_LABEL,
                &source_ip_str,
                err.code(),
            )
            .await;
            return err.into_response();
        }
    };

    match handle_tunnel_hello_inner(
        &runtime,
        &initial_link.id,
        source_ip,
        &parts.headers,
        parsed_req,
    )
    .await
    {
        Ok(resp) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(resp),
        )
            .into_response(),
        Err(err) => {
            audit_listener_denial(
                &runtime,
                HELLO_AUDIT_ROUTE_LABEL,
                &source_ip_str,
                err.code(),
            )
            .await;
            err.into_response()
        }
    }
}

/// Handles an expired or cleanup-marked link inside `handle_tunnel_hello_inner` while holding
/// `link_lock`, cleaning up pending links or clearing expired ack-retry metadata on live links.
async fn expire_hello_link_locked(
    runtime: &PeerRuntime,
    link: &PeerLink,
    issuer_already_deleted: bool,
    step: &str,
) -> PeerError {
    let local_server = runtime.local_server_name();
    if is_pending_link_state(&link.state) {
        let _ = cleanup_pending_link_locked(
            runtime,
            &link.id,
            &link.wg_pubkey,
            link.pending_attempt_id.as_deref(),
            "expired",
            Some("CODE_EXPIRED"),
        )
        .await;
    } else {
        let issuer_deleted = if issuer_already_deleted {
            true
        } else {
            delete_pending_issuer_credential_idempotent(runtime, &link.id, &local_server, step)
                .await
                .is_ok()
        };
        if issuer_deleted {
            let lid_clr = link.id.clone();
            let att_clr = link.pending_attempt_id.clone();
            let exp_clr = link.pending_expires_at;
            let now_rfc = runtime.now().to_rfc3339();
            let _ = runtime
                .db
                .write(&local_server, step, move |conn| {
                    let _ = conn.execute(
                        "UPDATE peer_links \
                         SET pending_attempt_id = NULL, pending_expires_at = NULL, updated_at = ?4 \
                         WHERE id = ?1 AND state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                           AND pending_attempt_id IS ?2 AND pending_expires_at IS ?3",
                        params![lid_clr, att_clr, exp_clr, now_rfc],
                    );
                    Ok(())
                })
                .await;
        }
    }
    PeerError::code_expired(&local_server, step)
}

async fn handle_tunnel_hello_inner(
    runtime: &PeerRuntime,
    link_id: &str,
    source_ip: IpAddr,
    headers: &HeaderMap,
    req: HelloRequest,
) -> Result<HelloResponse, PeerError> {
    let local_server = runtime.local_server_name();
    let step = "tunnel_hello";

    if !is_valid_credential_id(&req.attempt_id) {
        return Err(PeerError::invalid_request(
            &local_server,
            step,
            "Invalid pairing attempt identifier",
            "Retry pairing from a compatible server",
        ));
    }
    if !is_valid_wg_pubkey(&req.wg_pubkey) {
        return Err(PeerError::key_mismatch(
            &local_server,
            step,
            "Hello request carried an invalid WireGuard public key",
        ));
    }
    if let Some(ref claimed_ip) = req.tunnel_ip {
        let parsed = validate_bare_ip(claimed_ip, "Claimed tunnel IP", &local_server, step)?;
        if parsed != source_ip {
            return Err(PeerError::unauthorized(
                &local_server,
                step,
                "Claimed tunnel IP does not match the WireGuard peer source IP",
            ));
        }
    }

    // Serialize all local bootstrap, acknowledgement, cancellation, and expiry operations on this
    // owned peer link under `link_lock` before reading authoritative state.
    let _link_guard = runtime.lock_link(link_id, step).await?;

    let lid_lookup = link_id.to_string();
    let source_ip_str = source_ip.to_string();
    let attempt_id = req.attempt_id.clone();
    let (link, responder_attempt) = runtime
        .db
        .read(&local_server, step, move |conn| {
            let link = db_peers::get_peer_link(conn, &lid_lookup)
                .map_err(|err| PeerError::internal("local", "tunnel_hello", err.to_string()))?;
            let responder_attempt = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM peer_pairing_attempts WHERE id = ?1)",
                    [&attempt_id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|err| PeerError::internal("local", "tunnel_hello", err.to_string()))?;
            Ok((link, responder_attempt))
        })
        .await?;
    let Some(link) = link else {
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Peer link is no longer registered",
        ));
    };

    if link.tunnel_ip != source_ip_str {
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Tunnel source IP does not match the registered peer link",
        ));
    }

    if is_revoked_or_revoking_state(&link.state) {
        return Err(PeerError::link_revoked(
            &local_server,
            step,
            format!("Link with '{}' has been revoked", link.name),
        ));
    }

    // Bind to the pinned WireGuard public key and matching attempt ID.
    if link.wg_pubkey != req.wg_pubkey {
        return Err(PeerError::key_mismatch(
            &local_server,
            step,
            "WireGuard public key does not match the pinned peer for this tunnel IP",
        ));
    }
    if link.pending_attempt_id.as_deref() != Some(req.attempt_id.as_str()) {
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Pairing attempt ID does not match the pending pairing attempt for this peer",
        ));
    }
    if responder_attempt {
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Only the pairing initiator accepts tunnel hello callbacks",
        ));
    }

    let now_ts = runtime.now().timestamp();
    if !has_active_pending_expiry(link.pending_expires_at, now_ts) {
        return Err(expire_hello_link_locked(runtime, &link, false, step).await);
    }

    if req.peer_protocol < MIN_PEER_PROTOCOL_VERSION {
        return Err(PeerError::version_incompatible(
            &local_server,
            step,
            format!(
                "Peer protocol {} is below minimum supported version {MIN_PEER_PROTOCOL_VERSION}",
                req.peer_protocol
            ),
        ));
    }

    let identity = runtime
        .db
        .read(&local_server, step, |conn| {
            db_peers::get_peer_identity(conn)
                .map_err(|err| PeerError::internal("local", "tunnel_hello", err.to_string()))
        })
        .await?
        .ok_or_else(|| {
            PeerError::internal(&local_server, step, "Local peer identity is not configured")
        })?;

    match req.phase {
        HelloPhase::Bootstrap => {
            if !is_pending_link_state(&link.state) {
                return Err(PeerError::unauthorized(
                    &local_server,
                    step,
                    "Unauthenticated bootstrap is only allowed while the peer link is pending",
                ));
            }
            let Some(peer_issued_token) = req.link_token else {
                return Err(PeerError::invalid_request(
                    &local_server,
                    step,
                    "Hello bootstrap requires the remote peer's incoming link token",
                    "Retry pairing confirmation from the target server",
                ));
            };
            if !validate_secret_token_shape(peer_issued_token.expose_secret()) {
                return Err(PeerError::invalid_request(
                    &local_server,
                    step,
                    "Hello bootstrap link token has an invalid format",
                    "Retry pairing confirmation from the target server",
                ));
            }

            // Store (or verify on retry) B's held outbound link token in runner-managed file.
            let existing_held = runtime
                .runner
                .dispatch(&PeerNetworkRequest::ReadCredential {
                    slot: PeerCredentialSlot::LinkToken,
                    id: link.id.clone(),
                })
                .await
                .and_then(|resp| resp.into_credential_read())
                .map_err(|err| map_runner_error(err, &local_server, step))?
                .into_secret();

            if let Some(existing) = existing_held {
                if !constant_time_eq(
                    existing.expose_secret().as_bytes(),
                    peer_issued_token.expose_secret().as_bytes(),
                ) {
                    return Err(PeerError::unauthorized(
                        &local_server,
                        step,
                        "Retry presented a different link credential for the same attempt",
                    ));
                }
            } else {
                if !has_active_pending_expiry(link.pending_expires_at, runtime.now().timestamp()) {
                    return Err(expire_hello_link_locked(runtime, &link, false, step).await);
                }
                runtime
                    .runner
                    .dispatch(&PeerNetworkRequest::WriteCredential {
                        slot: PeerCredentialSlot::LinkToken,
                        id: link.id.clone(),
                        value: peer_issued_token.expose_secret().to_string(),
                    })
                    .await
                    .and_then(|resp| resp.into_credential_written())
                    .map_err(|err| map_runner_error(err, &local_server, step))?;
            }

            // Reuse or mint A's distinct incoming link token under the local link-namespaced
            // PendingIssuerToken key, never keyed by remote attempt_id alone.
            let pending_cred_id = pending_issuer_credential_id(&link.id);
            let existing_issuer = runtime
                .runner
                .dispatch(&PeerNetworkRequest::ReadCredential {
                    slot: PeerCredentialSlot::PendingIssuerToken,
                    id: pending_cred_id.clone(),
                })
                .await
                .and_then(|resp| resp.into_credential_read())
                .map_err(|err| map_runner_error(err, &local_server, step))?
                .into_secret();

            let (a_inbound_token, expected_digest) = if let Some(secret) = existing_issuer {
                let digest = sha256_prefixed(secret.expose_secret());
                if let Some(ref stored_hash) = link.inbound_token_hash {
                    if !constant_time_eq(stored_hash.as_bytes(), digest.as_bytes()) {
                        return Err(PeerError::unauthorized(
                            &local_server,
                            step,
                            "Stored incoming link digest does not match temporary issuer credential",
                        ));
                    }
                }
                (secret, digest)
            } else {
                if link.inbound_token_hash.is_some() {
                    return Err(PeerError::unauthorized(
                        &local_server,
                        step,
                        "Temporary issuer credential for this pending attempt is no longer available; restart pairing",
                    ));
                }
                if !has_active_pending_expiry(link.pending_expires_at, runtime.now().timestamp()) {
                    return Err(expire_hello_link_locked(runtime, &link, false, step).await);
                }
                let mut minted = mint_secret_token();
                while constant_time_eq(
                    minted.expose_secret().as_bytes(),
                    peer_issued_token.expose_secret().as_bytes(),
                ) {
                    minted = mint_secret_token();
                }
                let digest = sha256_prefixed(minted.expose_secret());
                runtime
                    .runner
                    .dispatch(&PeerNetworkRequest::WriteCredential {
                        slot: PeerCredentialSlot::PendingIssuerToken,
                        id: pending_cred_id,
                        value: minted.expose_secret().to_string(),
                    })
                    .await
                    .and_then(|resp| resp.into_credential_written())
                    .map_err(|err| map_runner_error(err, &local_server, step))?;
                (minted, digest)
            };

            // Recheck with a fresh clock after all awaited credential I/O at the decisive commit
            // before issuing A's link token back to B.
            let lid_u = link.id.clone();
            let pk_u = link.wg_pubkey.clone();
            let ip_u = link.tunnel_ip.clone();
            let att_u = req.attempt_id.clone();
            let peer_ver = req.version;
            let peer_proto = req.peer_protocol;
            let caps_json = serde_json::to_string(&req.capabilities).ok();
            let clock = Arc::clone(&runtime.clock);
            let server_c = local_server.clone();

            let expired_row = runtime
                .db
                .write(&local_server, step, move |conn| {
                    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    let commit_now = clock();
                    let commit_now_ts = commit_now.timestamp();
                    let now_rfc = commit_now.to_rfc3339();
                    let changed = tx
                        .execute(
                            "UPDATE peer_links SET \
                                inbound_token_hash = COALESCE(inbound_token_hash, ?4), \
                                peer_version = ?5, \
                                peer_protocol = ?6, \
                                capabilities = ?7, \
                                updated_at = ?8 \
                             WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                               AND state IN ('pending', 'pending_owned') AND pending_attempt_id = ?9 \
                               AND pending_expires_at IS NOT NULL \
                               AND pending_expires_at != 0 \
                               AND pending_expires_at > ?10 \
                               AND (inbound_token_hash IS NULL OR inbound_token_hash = ?4)",
                            params![
                                lid_u,
                                pk_u,
                                ip_u,
                                expected_digest,
                                peer_ver,
                                peer_proto,
                                caps_json,
                                now_rfc,
                                att_u,
                                commit_now_ts,
                            ],
                        )
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    if changed == 1 {
                        tx.commit()
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        return Ok(None);
                    }
                    let current = db_peers::get_peer_link(&tx, &lid_u)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    let _ = tx.rollback();
                    if let Some(cur) = current {
                        if is_pending_link_state(&cur.state)
                            && cur.wg_pubkey == pk_u
                            && cur.tunnel_ip == ip_u
                            && cur.pending_attempt_id.as_deref() == Some(att_u.as_str())
                            && !has_active_pending_expiry(cur.pending_expires_at, commit_now_ts)
                        {
                            return Ok(Some(cur));
                        }
                    }
                    Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Pending peer link changed or expired before bootstrap could commit",
                        "Retry pairing from the Cluster page",
                    ))
                })
                .await?;

            if let Some(expired_link) = expired_row {
                return Err(expire_hello_link_locked(runtime, &expired_link, false, step).await);
            }

            Ok(HelloResponse {
                phase: HelloPhase::Bootstrap,
                attempt_id: req.attempt_id,
                acknowledged: false,
                state: "pending".to_string(),
                wg_pubkey: identity.wg_pubkey,
                version: runtime.local_version(),
                peer_protocol: PEER_PROTOCOL_VERSION,
                capabilities: capabilities().into_iter().map(str::to_string).collect(),
                link_token: Some(a_inbound_token),
            })
        }
        HelloPhase::Acknowledge => {
            if req.link_token.is_some() {
                return Err(PeerError::invalid_request(
                    &local_server,
                    step,
                    "Hello acknowledgement must not include a body link token",
                    "Send the issued link token only in the X-AF-Link-Token header",
                ));
            }

            // Acknowledgement requires A's newly issued link token in X-AF-Link-Token.
            let presented = headers
                .get(HEADER_LINK_TOKEN)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    PeerError::unauthorized(
                        &local_server,
                        step,
                        "Hello acknowledgement requires X-AF-Link-Token",
                    )
                })?;

            let Some(expected_hash) = link.inbound_token_hash.as_deref() else {
                return Err(PeerError::unauthorized(
                    &local_server,
                    step,
                    "Link has no issued incoming credential to acknowledge",
                ));
            };
            let presented_hash = sha256_prefixed(presented);
            if !constant_time_eq(presented_hash.as_bytes(), expected_hash.as_bytes()) {
                return Err(PeerError::unauthorized(
                    &local_server,
                    step,
                    "Presented link token does not match the issued incoming credential",
                ));
            }

            // Allow bounded authenticated acknowledgement retries for `pending*`, `active*`, and
            // `down*` (e.g., if a health tick transitioned an already-activated link to `down`
            // while the peer retried after a lost ack response).
            if !is_pending_link_state(&link.state) && !is_live_link_state(&link.state) {
                return Err(PeerError::unauthorized(
                    &local_server,
                    step,
                    "Peer link is not eligible for pairing acknowledgement",
                ));
            }

            // Remove the link-namespaced temporary issuer credential before committing activation
            // or returning an acknowledgement so the final fresh-clock expiry check covers all
            // awaited credential work. Because B just authenticated with A's issued token, B will
            // never retry unauthenticated Bootstrap. On transient runner error,
            // `pending_attempt_id`/`pending_expires_at` remain so the sweep retries deletion.
            let issuer_deleted = match delete_pending_issuer_credential_idempotent(
                runtime,
                &link.id,
                &local_server,
                step,
            )
            .await
            {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(
                        link_id = %link.id,
                        %error,
                        "Transient failure deleting temporary issuer credential during hello ack; sweep will retry"
                    );
                    false
                }
            };

            let resp_state = if is_pending_link_state(&link.state) {
                enum AckCommitOutcome {
                    Activated,
                    Expired(Box<PeerLink>),
                }

                let lid_u = link.id.clone();
                let pk_u = link.wg_pubkey.clone();
                let ip_u = link.tunnel_ip.clone();
                let att_u = req.attempt_id.clone();
                let expected_hash_s = expected_hash.to_string();
                let peer_ver = req.version;
                let peer_proto = req.peer_protocol;
                let caps_json = serde_json::to_string(&req.capabilities).ok();
                let clock = Arc::clone(&runtime.clock);
                let server_c = local_server.clone();

                let outcome = runtime
                    .db
                    .write(&local_server, step, move |conn| {
                        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        let commit_now = clock();
                        let commit_now_ts = commit_now.timestamp();
                        let now_rfc = commit_now.to_rfc3339();
                        // Retain pending_attempt_id and pending_expires_at until expiry so a
                        // bounded authenticated ack retry for the same attempt succeeds cleanly,
                        // while preserving durable WireGuard peer ownership across activation.
                        let changed = tx
                            .execute(
                                "UPDATE peer_links SET \
                                    state = CASE state \
                                        WHEN 'pending_owned' THEN 'active' \
                                        WHEN 'pending' THEN 'active_unowned' \
                                    END, \
                                    peer_version = ?4, \
                                    peer_protocol = ?5, \
                                    capabilities = ?6, \
                                    last_ok_at = ?7, \
                                    last_error = NULL, \
                                    consecutive_failures = 0, \
                                    updated_at = ?7 \
                                 WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                                   AND state IN ('pending', 'pending_owned') AND pending_attempt_id = ?8 \
                                   AND pending_expires_at IS NOT NULL \
                                   AND pending_expires_at != 0 \
                                   AND pending_expires_at > ?9 \
                                   AND inbound_token_hash = ?10",
                                params![
                                    lid_u,
                                    pk_u,
                                    ip_u,
                                    peer_ver,
                                    peer_proto,
                                    caps_json,
                                    now_rfc,
                                    att_u,
                                    commit_now_ts,
                                    expected_hash_s,
                                ],
                            )
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        if changed == 1 {
                            tx.commit().map_err(|err| {
                                PeerError::internal(&server_c, step, err.to_string())
                            })?;
                            return Ok(AckCommitOutcome::Activated);
                        }
                        let current = db_peers::get_peer_link(&tx, &lid_u)
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        let _ = tx.rollback();
                        if let Some(cur) = current {
                            if is_revoked_or_revoking_state(&cur.state) {
                                return Err(PeerError::link_revoked(
                                    &server_c,
                                    step,
                                    format!("Link with '{}' has been revoked", cur.name),
                                ));
                            }
                            if is_pending_link_state(&cur.state)
                                && cur.wg_pubkey == pk_u
                                && cur.tunnel_ip == ip_u
                                && cur.pending_attempt_id.as_deref() == Some(att_u.as_str())
                                && !has_active_pending_expiry(cur.pending_expires_at, commit_now_ts)
                            {
                                return Ok(AckCommitOutcome::Expired(Box::new(cur)));
                            }
                        }
                        Err(PeerError::conflict(
                            &server_c,
                            step,
                            "Pending peer link changed or expired before activation could commit",
                            "Retry pairing confirmation",
                        ))
                    })
                    .await?;

                match outcome {
                    AckCommitOutcome::Activated => {}
                    AckCommitOutcome::Expired(expired_link) => {
                        return Err(expire_hello_link_locked(
                            runtime,
                            &expired_link,
                            issuer_deleted,
                            step,
                        )
                        .await);
                    }
                }

                runtime
                    .db
                    .record_audit(
                        0,
                        format!("peer-{}", link.name),
                        "peer_link_activated".to_string(),
                        "peer_link".to_string(),
                        link.id.clone(),
                        format!(
                            "Activated peer link '{}' after authenticated hello acknowledgement (attempt {})",
                            link.name, req.attempt_id
                        ),
                        source_ip.to_string(),
                        String::new(),
                    )
                    .await;
                "active".to_string()
            } else {
                // Active/down ack retry: recheck authoritative state and nonzero exclusive expiry
                // with a fresh clock AFTER awaited credential deletion before acknowledging.
                let lid_u = link.id.clone();
                let pk_u = link.wg_pubkey.clone();
                let ip_u = link.tunnel_ip.clone();
                let att_u = req.attempt_id.clone();
                let expected_hash_s = expected_hash.to_string();
                let clock = Arc::clone(&runtime.clock);
                let server_c = local_server.clone();

                runtime
                    .db
                    .write(&local_server, step, move |conn| {
                        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        let commit_now = clock();
                        let commit_now_ts = commit_now.timestamp();
                        let now_rfc = commit_now.to_rfc3339();

                        let Some(cur) = db_peers::get_peer_link(&tx, &lid_u)
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                        else {
                            return Err(PeerError::unauthorized(
                                &server_c,
                                step,
                                "Peer link is no longer registered",
                            ));
                        };
                        if is_revoked_or_revoking_state(&cur.state) {
                            return Err(PeerError::link_revoked(
                                &server_c,
                                step,
                                format!("Link with '{}' has been revoked", cur.name),
                            ));
                        }
                        if !is_live_link_state(&cur.state)
                            || cur.wg_pubkey != pk_u
                            || cur.tunnel_ip != ip_u
                            || cur.pending_attempt_id.as_deref() != Some(att_u.as_str())
                            || cur.inbound_token_hash.as_deref() != Some(expected_hash_s.as_str())
                        {
                            return Err(PeerError::unauthorized(
                                &server_c,
                                step,
                                "Peer link state changed before acknowledgement retry completed",
                            ));
                        }
                        if !has_active_pending_expiry(cur.pending_expires_at, commit_now_ts) {
                            if issuer_deleted {
                                let _ = tx.execute(
                                    "UPDATE peer_links \
                                     SET pending_attempt_id = NULL, pending_expires_at = NULL, updated_at = ?4 \
                                     WHERE id = ?1 AND state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                                       AND pending_attempt_id IS ?2 AND pending_expires_at IS ?3",
                                    params![
                                        lid_u,
                                        cur.pending_attempt_id,
                                        cur.pending_expires_at,
                                        now_rfc,
                                    ],
                                );
                                let _ = tx.commit();
                            }
                            return Err(PeerError::code_expired(&server_c, step));
                        }
                        Ok(public_link_state(&cur.state).to_string())
                    })
                    .await?
            };

            Ok(HelloResponse {
                phase: HelloPhase::Acknowledge,
                attempt_id: req.attempt_id,
                acknowledged: true,
                state: resp_state,
                wg_pubkey: identity.wg_pubkey,
                version: runtime.local_version(),
                peer_protocol: PEER_PROTOCOL_VERSION,
                capabilities: capabilities().into_iter().map(str::to_string).collect(),
                link_token: None,
            })
        }
    }
}
