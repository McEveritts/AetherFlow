//! Typed peer clustering errors with actionable server/step guidance and secret redaction.

use axum::extract::rejection::{BytesRejection, JsonRejection};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;

const REDACTED: &str = "[REDACTED]";

static SECRET_REDACT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(afpair1:[A-Za-z0-9_-]+=*)|(x-af-(?:link|grant)-token\s*[:=]\s*)\S+|(PrivateKey\s*=\s*)\S+|(PresharedKey\s*=\s*)\S+|\b[0-9a-f]{64}\b",
    )
    .expect("constant peer error redaction regex")
});

/// Redacts pairing payloads, link/grant tokens, WireGuard private keys, and 256-bit hex secrets
/// before text can reach HTTP responses, logs, or audit entries.
pub fn redact_sensitive_text(input: &str) -> String {
    SECRET_REDACT_RE
        .replace_all(input, |caps: &regex::Captures<'_>| {
            if let Some(prefix) = caps.get(2).or_else(|| caps.get(3)).or_else(|| caps.get(4)) {
                format!("{}{REDACTED}", prefix.as_str())
            } else {
                REDACTED.to_string()
            }
        })
        .into_owned()
}

/// Structured detail carried by every [`PeerError`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerErrorDetail {
    pub server: String,
    pub step: String,
    pub message: String,
    pub action: String,
}

impl PeerErrorDetail {
    pub fn new(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            server: sanitize_field(server.into(), "local"),
            step: sanitize_field(step.into(), "peer"),
            message: sanitize_field(message.into(), "Peer operation failed"),
            action: sanitize_field(action.into(), "Retry the operation"),
        }
    }
}

fn sanitize_field(raw: String, fallback: &str) -> String {
    let redacted = redact_sensitive_text(raw.trim());
    let cleaned: String = redacted
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(512)
        .collect();
    if cleaned.trim().is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

/// JSON error envelope returned by [`PeerError::into_response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerErrorBody {
    pub code: String,
    pub server: String,
    pub step: String,
    pub message: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Typed peer clustering errors covering pairing, tunnel authorization, health, and lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    CodeExpired(PeerErrorDetail),
    CodeUsed(PeerErrorDetail),
    WindowClosed(PeerErrorDetail),
    KeyMismatch(PeerErrorDetail),
    TunnelIpConflict(PeerErrorDetail),
    EndpointUnreachable(PeerErrorDetail),
    HandshakeTimeout(PeerErrorDetail),
    VersionIncompatible(PeerErrorDetail),
    ClockSkew(PeerErrorDetail),
    PeerScopeDenied(PeerErrorDetail),
    PeerRouteUnclassified(PeerErrorDetail),
    LinkDown(PeerErrorDetail),
    LinkRevoked(PeerErrorDetail),
    RateLimited(PeerErrorDetail),
    Unauthorized(PeerErrorDetail),
    NotFound(PeerErrorDetail),
    InvalidRequest(PeerErrorDetail),
    PayloadTooLarge(PeerErrorDetail),
    UnsupportedMediaType(PeerErrorDetail),
    Conflict(PeerErrorDetail),
    Busy(PeerErrorDetail),
    Internal(PeerErrorDetail),
}

impl PeerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CodeExpired(_) => "CODE_EXPIRED",
            Self::CodeUsed(_) => "CODE_USED",
            Self::WindowClosed(_) => "WINDOW_CLOSED",
            Self::KeyMismatch(_) => "KEY_MISMATCH",
            Self::TunnelIpConflict(_) => "TUNNEL_IP_CONFLICT",
            Self::EndpointUnreachable(_) => "ENDPOINT_UNREACHABLE",
            Self::HandshakeTimeout(_) => "HANDSHAKE_TIMEOUT",
            Self::VersionIncompatible(_) => "VERSION_INCOMPATIBLE",
            Self::ClockSkew(_) => "CLOCK_SKEW",
            Self::PeerScopeDenied(_) => "PEER_SCOPE_DENIED",
            Self::PeerRouteUnclassified(_) => "PEER_ROUTE_UNCLASSIFIED",
            Self::LinkDown(_) => "LINK_DOWN",
            Self::LinkRevoked(_) => "LINK_REVOKED",
            Self::RateLimited(_) => "RATE_LIMITED",
            Self::Unauthorized(_) => "PEER_UNAUTHORIZED",
            Self::NotFound(_) => "PEER_NOT_FOUND",
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
            Self::UnsupportedMediaType(_) => "UNSUPPORTED_MEDIA_TYPE",
            Self::Conflict(_) => "PEER_CONFLICT",
            Self::Busy(_) => "PEER_BUSY",
            Self::Internal(_) => "PEER_INTERNAL_ERROR",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::CodeExpired(_) | Self::WindowClosed(_) => StatusCode::GONE,
            Self::CodeUsed(_)
            | Self::KeyMismatch(_)
            | Self::TunnelIpConflict(_)
            | Self::Conflict(_) => StatusCode::CONFLICT,
            Self::EndpointUnreachable(_) | Self::LinkDown(_) => StatusCode::BAD_GATEWAY,
            Self::HandshakeTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::VersionIncompatible(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::ClockSkew(_) | Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::PeerScopeDenied(_) | Self::PeerRouteUnclassified(_) | Self::LinkRevoked(_) => {
                StatusCode::FORBIDDEN
            }
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn detail(&self) -> &PeerErrorDetail {
        match self {
            Self::CodeExpired(d)
            | Self::CodeUsed(d)
            | Self::WindowClosed(d)
            | Self::KeyMismatch(d)
            | Self::TunnelIpConflict(d)
            | Self::EndpointUnreachable(d)
            | Self::HandshakeTimeout(d)
            | Self::VersionIncompatible(d)
            | Self::ClockSkew(d)
            | Self::PeerScopeDenied(d)
            | Self::PeerRouteUnclassified(d)
            | Self::LinkDown(d)
            | Self::LinkRevoked(d)
            | Self::RateLimited(d)
            | Self::Unauthorized(d)
            | Self::NotFound(d)
            | Self::InvalidRequest(d)
            | Self::PayloadTooLarge(d)
            | Self::UnsupportedMediaType(d)
            | Self::Conflict(d)
            | Self::Busy(d)
            | Self::Internal(d) => d,
        }
    }

    pub fn body(&self) -> PeerErrorBody {
        let d = self.detail();
        PeerErrorBody {
            code: self.code().to_string(),
            server: d.server.clone(),
            step: d.step.clone(),
            message: d.message.clone(),
            action: d.action.clone(),
            request_id: af_runner::current_runner_request_id(),
        }
    }

    /// Returns `true` when this error is terminal for an in-progress pairing confirmation and
    /// pending WireGuard/credential state for the attempt should be cleaned up immediately.
    pub fn is_terminal_for_confirm(&self) -> bool {
        !matches!(
            self,
            Self::HandshakeTimeout(_)
                | Self::EndpointUnreachable(_)
                | Self::Busy(_)
                | Self::RateLimited(_)
                | Self::LinkDown(_)
        )
    }

    pub fn code_expired(server: impl Into<String>, step: impl Into<String>) -> Self {
        let server = server.into();
        let step = step.into();
        Self::CodeExpired(PeerErrorDetail::new(
            server.clone(),
            step.clone(),
            format!("Pairing window or attempt on {server} expired during {step}"),
            "Open a new pairing window and start pairing again",
        ))
    }

    pub fn code_used(server: impl Into<String>, step: impl Into<String>) -> Self {
        let server = server.into();
        let step = step.into();
        Self::CodeUsed(PeerErrorDetail::new(
            server.clone(),
            step.clone(),
            format!("Pairing code on {server} was already consumed during {step}"),
            "Open a fresh pairing window to generate a new single-use pairing string",
        ))
    }

    pub fn window_closed(server: impl Into<String>, step: impl Into<String>) -> Self {
        let server = server.into();
        let step = step.into();
        Self::WindowClosed(PeerErrorDetail::new(
            server.clone(),
            step.clone(),
            format!("No open pairing window is available on {server} during {step}"),
            "Open a pairing window on the target server before pasting the pairing string",
        ))
    }

    pub fn key_mismatch(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::KeyMismatch(PeerErrorDetail::new(
            server,
            step,
            message,
            "Verify the peer WireGuard identity, remove any conflicting peer entry, and re-pair",
        ))
    }

    pub fn tunnel_ip_conflict(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::TunnelIpConflict(PeerErrorDetail::new(
            server,
            step,
            message,
            "Verify AF_PEER_TUNNEL_CIDR addresses do not overlap and retry pairing",
        ))
    }

    pub fn endpoint_unreachable(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::EndpointUnreachable(PeerErrorDetail::new(
            server,
            step,
            message,
            "Confirm the server URL, TLS certificate, and firewall reachability, then retry",
        ))
    }

    pub fn handshake_timeout(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::HandshakeTimeout(PeerErrorDetail::new(
            server,
            step,
            message,
            "Confirm UDP port 51821 and the selected endpoint are reachable between both servers, then retry confirmation",
        ))
    }

    pub fn version_incompatible(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::VersionIncompatible(PeerErrorDetail::new(
            server,
            step,
            message,
            "Update both AetherFlow servers to a compatible peer protocol version and retry",
        ))
    }

    pub fn clock_skew(server: impl Into<String>, step: impl Into<String>, skew_secs: i64) -> Self {
        let server = server.into();
        let step = step.into();
        Self::ClockSkew(PeerErrorDetail::new(
            server.clone(),
            step,
            format!("System clocks differ by {skew_secs}s with {server}, exceeding the 300s limit"),
            "Synchronize system clocks with NTP on both servers and retry pairing",
        ))
    }

    pub fn peer_scope_denied(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::PeerScopeDenied(PeerErrorDetail::new(
            server,
            step,
            message,
            "Configure an active grant with the required access level before calling management routes",
        ))
    }

    pub fn peer_route_unclassified(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::PeerRouteUnclassified(PeerErrorDetail::new(
            server,
            step,
            message,
            "Only explicitly permitted peer internal routes are reachable on the tunnel listener",
        ))
    }

    pub fn link_down(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::LinkDown(PeerErrorDetail::new(
            server,
            step,
            message,
            "Check afpeer0 status and connectivity between both servers, then retry",
        ))
    }

    pub fn link_revoked(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::LinkRevoked(PeerErrorDetail::new(
            server,
            step,
            message,
            "Remove the revoked link and re-pair the servers if access is still needed",
        ))
    }

    pub fn rate_limited(server: impl Into<String>, step: impl Into<String>) -> Self {
        let server = server.into();
        Self::RateLimited(PeerErrorDetail::new(
            server.clone(),
            step,
            format!("Too many pairing attempts to {server}; limit is 5 per minute per source IP"),
            "Wait 60 seconds before trying again",
        ))
    }

    pub fn unauthorized(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Unauthorized(PeerErrorDetail::new(
            server,
            step,
            message,
            "Verify peer credentials and tunnel identity before retrying",
        ))
    }

    pub fn not_found(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::NotFound(PeerErrorDetail::new(
            server,
            step,
            message,
            "Refresh the Cluster page and verify the peer or pairing attempt still exists",
        ))
    }

    pub fn invalid_request(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self::InvalidRequest(PeerErrorDetail::new(server, step, message, action))
    }

    pub fn payload_too_large(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self::PayloadTooLarge(PeerErrorDetail::new(server, step, message, action))
    }

    pub fn unsupported_media_type(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self::UnsupportedMediaType(PeerErrorDetail::new(server, step, message, action))
    }

    pub fn conflict(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self::Conflict(PeerErrorDetail::new(server, step, message, action))
    }

    pub fn busy(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Busy(PeerErrorDetail::new(
            server,
            step,
            message,
            "Wait a moment for the in-progress WireGuard operation to finish and retry",
        ))
    }

    pub fn internal(
        server: impl Into<String>,
        step: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Internal(PeerErrorDetail::new(
            server,
            step,
            message,
            "Check AetherFlow API and runner logs and retry the operation",
        ))
    }

    /// Parses a typed remote error body returned over HTTP and preserves its typed code.
    pub fn from_remote_http(
        status: StatusCode,
        body: &[u8],
        fallback_server: &str,
        fallback_step: &str,
    ) -> Self {
        if let Ok(parsed) = serde_json::from_slice::<PeerErrorBody>(body) {
            let detail = PeerErrorDetail::new(
                if parsed.server.trim().is_empty() {
                    fallback_server.to_string()
                } else {
                    parsed.server
                },
                if parsed.step.trim().is_empty() {
                    fallback_step.to_string()
                } else {
                    parsed.step
                },
                parsed.message,
                parsed.action,
            );
            return match parsed.code.as_str() {
                "CODE_EXPIRED" => Self::CodeExpired(detail),
                "CODE_USED" => Self::CodeUsed(detail),
                "WINDOW_CLOSED" => Self::WindowClosed(detail),
                "KEY_MISMATCH" => Self::KeyMismatch(detail),
                "TUNNEL_IP_CONFLICT" => Self::TunnelIpConflict(detail),
                "ENDPOINT_UNREACHABLE" => Self::EndpointUnreachable(detail),
                "HANDSHAKE_TIMEOUT" => Self::HandshakeTimeout(detail),
                "VERSION_INCOMPATIBLE" => Self::VersionIncompatible(detail),
                "CLOCK_SKEW" => Self::ClockSkew(detail),
                "PEER_SCOPE_DENIED" => Self::PeerScopeDenied(detail),
                "PEER_ROUTE_UNCLASSIFIED" => Self::PeerRouteUnclassified(detail),
                "LINK_DOWN" => Self::LinkDown(detail),
                "LINK_REVOKED" => Self::LinkRevoked(detail),
                "RATE_LIMITED" => Self::RateLimited(detail),
                "PEER_UNAUTHORIZED" => Self::Unauthorized(detail),
                "PEER_NOT_FOUND" => Self::NotFound(detail),
                "INVALID_REQUEST" => Self::InvalidRequest(detail),
                "PAYLOAD_TOO_LARGE" => Self::PayloadTooLarge(detail),
                "UNSUPPORTED_MEDIA_TYPE" => Self::UnsupportedMediaType(detail),
                "PEER_CONFLICT" => Self::Conflict(detail),
                "PEER_BUSY" => Self::Busy(detail),
                _ => Self::Internal(detail),
            };
        }

        match status {
            StatusCode::TOO_MANY_REQUESTS => Self::rate_limited(fallback_server, fallback_step),
            StatusCode::NOT_FOUND => Self::version_incompatible(
                fallback_server,
                fallback_step,
                format!(
                    "{fallback_server} returned HTTP 404 during {fallback_step}; it may be running an older AetherFlow release"
                ),
            ),
            StatusCode::UNAUTHORIZED => Self::unauthorized(
                fallback_server,
                fallback_step,
                format!("{fallback_server} rejected peer authentication (HTTP 401)"),
            ),
            StatusCode::FORBIDDEN => Self::peer_scope_denied(
                fallback_server,
                fallback_step,
                format!("{fallback_server} rejected the request (HTTP 403)"),
            ),
            StatusCode::PAYLOAD_TOO_LARGE => Self::payload_too_large(
                fallback_server,
                fallback_step,
                format!("{fallback_server} rejected the pairing payload as too large (HTTP 413)"),
                "Reduce the server name or endpoint length and retry",
            ),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Self::unsupported_media_type(
                fallback_server,
                fallback_step,
                format!("{fallback_server} rejected the request media type (HTTP 415)"),
                "Send a JSON payload with Content-Type: application/json",
            ),
            StatusCode::SERVICE_UNAVAILABLE => Self::busy(
                fallback_server,
                fallback_step,
                format!("{fallback_server} is temporarily unavailable (HTTP 503)"),
            ),
            _ => Self::endpoint_unreachable(
                fallback_server,
                fallback_step,
                format!(
                    "{fallback_server} returned unexpected HTTP {} during {fallback_step}",
                    status.as_u16()
                ),
            ),
        }
    }
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.detail();
        write!(
            f,
            "{} ({} / {}): {} — {}",
            self.code(),
            d.server,
            d.step,
            d.message,
            d.action
        )
    }
}

impl std::error::Error for PeerError {}

impl IntoResponse for PeerError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let is_rate_limited = matches!(self, Self::RateLimited(_));
        let body = self.body();
        let mut resp = (status, Json(body)).into_response();
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if is_rate_limited {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        if matches!(self, Self::PeerScopeDenied(_)) {
            resp.extensions_mut().insert(self);
        }
        resp
    }
}

pub(crate) fn is_json_content_type(headers: &HeaderMap) -> bool {
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

pub(crate) fn bytes_rejection_to_peer_error(
    err: BytesRejection,
    server: &str,
    step: &str,
) -> PeerError {
    if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
        PeerError::payload_too_large(
            server,
            step,
            "Request body exceeds the maximum allowed size",
            "Reduce the request payload size and retry",
        )
    } else {
        PeerError::invalid_request(
            server,
            step,
            "Request body could not be read",
            "Retry sending a valid request body",
        )
    }
}

pub(crate) fn json_rejection_to_peer_error(
    err: JsonRejection,
    server: &str,
    step: &str,
) -> PeerError {
    match err {
        JsonRejection::MissingJsonContentType(_) => PeerError::unsupported_media_type(
            server,
            step,
            "Request Content-Type must be application/json",
            "Set Content-Type: application/json and retry",
        ),
        JsonRejection::BytesRejection(bytes_err) => {
            bytes_rejection_to_peer_error(bytes_err, server, step)
        }
        JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_) | _ => {
            PeerError::invalid_request(
                server,
                step,
                "Request body must be valid JSON matching the expected schema",
                "Verify the JSON payload format and retry",
            )
        }
    }
}

pub(crate) fn parse_optional_json_bytes<T: DeserializeOwned + Default>(
    headers: &HeaderMap,
    body: &[u8],
    server: &str,
    step: &str,
) -> Result<T, PeerError> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(T::default());
    }
    parse_required_json_bytes(headers, body, server, step)
}

pub(crate) fn parse_required_json_bytes<T: DeserializeOwned>(
    headers: &HeaderMap,
    body: &[u8],
    server: &str,
    step: &str,
) -> Result<T, PeerError> {
    if !is_json_content_type(headers) {
        return Err(PeerError::unsupported_media_type(
            server,
            step,
            "Request Content-Type must be application/json",
            "Set Content-Type: application/json and retry",
        ));
    }
    serde_json::from_slice::<T>(body).map_err(|_| {
        PeerError::invalid_request(
            server,
            step,
            "Request body must be valid JSON matching the expected schema",
            "Verify the JSON payload format and retry",
        )
    })
}
