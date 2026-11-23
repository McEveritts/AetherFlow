//! Exhaustive peer grant route/method scope classification and single-pass canonicalization.
//!
//! Every request entering the WireGuard tunnel listener targeting a management endpoint is:
//! 1. Canonicalized once (`canonicalize`), failing closed on controls, backslashes, whitespace,
//!    encoded separators (`%2f`/`%5c`), `.` or `..` segments, malformed percent escapes, or
//!    double-encoded traversal/separator ambiguity.
//! 2. Classified (`classify`) against an explicit forbidden list and an explicit `(Method, route)`
//!    allowlist strictly under `/api/v1/*`. Non-versioned `/api/*`, top-level routes, unknown
//!    paths, and unknown methods fail closed (`RouteDecision::Unclassified` -> `403 PEER_ROUTE_UNCLASSIFIED`).
//! 3. Reconciled (`reconcile_uri`) so the forwarded `axum::extract::Request` URI matches the exact
//!    validated canonical path before entering `routes::build_router()`.

use af_db::peers::{AccessLevel, AccessMap};
use axum::http::{Method, Uri};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Area {
    Services,
    Marketplace,
    Settings,
    Files,
    Users,
    Network,
    Updates,
    Transcoding,
}

impl Area {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Services => "services",
            Self::Marketplace => "marketplace",
            Self::Settings => "settings",
            Self::Files => "files",
            Self::Users => "users",
            Self::Network => "network",
            Self::Updates => "updates",
            Self::Transcoding => "transcoding",
        }
    }

    pub const fn level_in(self, access: &AccessMap) -> AccessLevel {
        match self {
            Self::Services => access.services,
            Self::Marketplace => access.marketplace,
            Self::Settings => access.settings,
            Self::Files => access.files,
            Self::Users => access.users,
            Self::Network => access.network,
            Self::Updates => access.updates,
            Self::Transcoding => access.transcoding,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Read,
    Write,
}

impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeRequirement {
    /// Requires the specific area at `Read` (`read | write`) or `Write` (`write`).
    Area(Area, Mode),
    /// Requires every listed area at its specified access level.
    All(&'static [(Area, Mode)]),
    /// Read-only overview endpoint requiring at least one area in the grant to have `read` or `write`.
    /// All-`none` grants are denied.
    AnyReadAccess,
}

impl ScopeRequirement {
    pub fn label(self) -> String {
        match self {
            Self::Area(area, mode) => format!("{}:{}", area.as_str(), mode.as_str()),
            Self::All(areas) => areas
                .iter()
                .map(|(area, mode)| format!("{}:{}", area.as_str(), mode.as_str()))
                .collect::<Vec<_>>()
                .join(" + "),
            Self::AnyReadAccess => "overview:any_read".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    Allowed(ScopeRequirement),
    Forbidden,
    Unclassified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizeError {
    MissingLeadingSlash,
    ControlOrWhitespace,
    Backslash,
    InvalidPercentEncoding,
    EncodedSeparatorOrControl,
    DotSegment,
    DoubleEncodedAmbiguity,
    InvalidUtf8,
}

impl fmt::Display for CanonicalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLeadingSlash => write!(f, "request path must start with '/'"),
            Self::ControlOrWhitespace => write!(f, "request path contains control or whitespace"),
            Self::Backslash => write!(f, "request path contains disallowed backslash"),
            Self::InvalidPercentEncoding => {
                write!(f, "request path contains invalid percent escape")
            }
            Self::EncodedSeparatorOrControl => {
                write!(f, "request path contains encoded separator or control byte")
            }
            Self::DotSegment => write!(f, "request path contains disallowed dot segment"),
            Self::DoubleEncodedAmbiguity => {
                write!(f, "request path contains ambiguous double-encoded sequence")
            }
            Self::InvalidUtf8 => write!(f, "request path is not valid UTF-8"),
        }
    }
}

/// Validated, single-decoded, slash-collapsed, dot-free canonical URI path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    path: String,
    segments: Vec<String>,
}

impl CanonicalPath {
    pub fn as_str(&self) -> &str {
        &self.path
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Canonicalizes a raw request URI path once and fails closed on any path-smuggling ambiguity.
pub fn canonicalize(raw_path: &str) -> Result<CanonicalPath, CanonicalizeError> {
    if !raw_path.starts_with('/') {
        return Err(CanonicalizeError::MissingLeadingSlash);
    }
    if raw_path
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || b.is_ascii_whitespace() || b == b'?' || b == b'#')
    {
        return Err(CanonicalizeError::ControlOrWhitespace);
    }
    if raw_path.contains('\\') {
        return Err(CanonicalizeError::Backslash);
    }

    let mut segments: Vec<String> = Vec::new();
    for raw_seg in raw_path.split('/') {
        // Collapses leading, trailing, and consecutive slashes (`//` -> `/`).
        if raw_seg.is_empty() {
            continue;
        }
        let bytes = raw_seg.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if i + 2 >= bytes.len() {
                    return Err(CanonicalizeError::InvalidPercentEncoding);
                }
                let hi =
                    hex_nibble(bytes[i + 1]).ok_or(CanonicalizeError::InvalidPercentEncoding)?;
                let lo =
                    hex_nibble(bytes[i + 2]).ok_or(CanonicalizeError::InvalidPercentEncoding)?;
                let ch = (hi << 4) | lo;
                if ch == b'/' || ch == b'\\' || ch < 0x20 || ch == 0x7f {
                    return Err(CanonicalizeError::EncodedSeparatorOrControl);
                }
                decoded.push(ch);
                i += 3;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
        let seg = String::from_utf8(decoded).map_err(|_| CanonicalizeError::InvalidUtf8)?;
        if seg == "." || seg == ".." {
            return Err(CanonicalizeError::DotSegment);
        }
        // Reject double-encoded separators, dot segments, or NUL bytes so downstream percent-
        // decoding can never reinterpret a segment after validation.
        let lower = seg.to_ascii_lowercase();
        if lower.contains("%2f")
            || lower.contains("%5c")
            || lower.contains("%2e")
            || lower.contains("%00")
            || lower.contains('/')
            || lower.contains('\\')
        {
            return Err(CanonicalizeError::DoubleEncodedAmbiguity);
        }
        segments.push(seg);
    }

    let path = if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    };

    Ok(CanonicalPath { path, segments })
}

fn is_safe_uri_segment_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':' | b'@')
}

/// Builds a reconciled `axum::http::Uri` strictly from the validated `CanonicalPath` (re-encoding
/// non-URI-safe segment bytes without introducing slashes or dot ambiguity) while preserving any
/// safe query string from `original_uri`.
pub fn reconcile_uri(original_uri: &Uri, canonical: &CanonicalPath) -> Option<Uri> {
    let mut encoded_path = String::with_capacity(canonical.as_str().len() + 8);
    if canonical.segments().is_empty() {
        encoded_path.push('/');
    } else {
        for seg in canonical.segments() {
            encoded_path.push('/');
            for &b in seg.as_bytes() {
                if is_safe_uri_segment_byte(b) {
                    encoded_path.push(b as char);
                } else {
                    encoded_path.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }

    let path_and_query = match original_uri.query() {
        Some(q) => {
            if q.bytes().any(|b| b < 0x20 || b == 0x7f) {
                return None;
            }
            format!("{encoded_path}?{q}")
        }
        None => encoded_path,
    };

    path_and_query.parse().ok()
}

/// Checks whether `access` satisfies `requirement`.
pub fn access_allows(access: &AccessMap, requirement: ScopeRequirement) -> bool {
    match requirement {
        ScopeRequirement::AnyReadAccess => access.has_any_access(),
        ScopeRequirement::Area(area, mode) => area_allows(access, area, mode),
        ScopeRequirement::All(areas) => areas
            .iter()
            .all(|&(area, mode)| area_allows(access, area, mode)),
    }
}

fn area_allows(access: &AccessMap, area: Area, mode: Mode) -> bool {
    let level = area.level_in(access);
    match mode {
        Mode::Read => level.allows_read(),
        Mode::Write => level.allows_write(),
    }
}

#[derive(Debug, Clone, Copy)]
struct ForbiddenRule {
    /// `None` forbids EVERY HTTP method on this pattern; `Some(m)` forbids only method `m`.
    method: Option<&'static str>,
    pattern: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct AllowedRule {
    method: &'static str,
    pattern: &'static str,
    requirement: ScopeRequirement,
}

/// Routes under `/api/v1/*` that are NEVER reachable through a peer grant.
/// Evaluated BEFORE `ALLOWED_RULES` (and case-insensitively on static path segments) so a peer
/// cannot widen its own grant, hop to a third peer, mint/revoke sessions or plugin tokens, alter
/// OIDC trust or MFA, execute arbitrary plugin proxies, or use browser-only app launches.
const FORBIDDEN_RULES: &[ForbiddenRule] = &[
    // Peer control plane, multi-hop remote proxy, and public pairing bootstrap
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/admin/peers",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/admin/peers/*",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/peers",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/peers/*",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/peer-pairing/request",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/peer-pairing/*",
    },
    // Public auth, OIDC, CSRF, OpenAPI viewer, and anonymous McBrowser share redemption
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/public/auth/*",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/public/oidc/*",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/public/csrf-token",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/public/openapi.yaml",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/public/swagger",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/public/swagger/*",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/public/mcbrowser/shares/*",
    },
    // Session, credential, MFA, profile, OIDC consent, and own-quota routes
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/session",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/refresh",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/sessions",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/sessions/:jti",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/logout",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/profile",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/profile/*",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/user/quota",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/user/2fa/*",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/oidc/*",
    },
    // Trust / credential / token / arbitrary proxy / host-cookie app launch handlers
    ForbiddenRule {
        method: Some("POST"),
        pattern: "/api/v1/admin/oidc/clients",
    },
    ForbiddenRule {
        method: Some("DELETE"),
        pattern: "/api/v1/admin/oidc/clients/:id",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/admin/plugins/:id/token",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/admin/apps/launch",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/plugins/:id/ui",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/plugins/:id/proxy",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/plugins/:id/proxy/*",
    },
    // WebSocket endpoints are deferred to P6 (File 34) and fail closed in P5
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/ws",
    },
    ForbiddenRule {
        method: None,
        pattern: "/api/v1/auth/ws/*",
    },
];

/// Exhaustive allowlist of versioned `/api/v1/*` management routes mapped to exact HTTP methods
/// and required area/mode scopes.
const ALLOWED_RULES: &[AllowedRule] = &[
    // ── Read-only overview routes (require some effective read/write access; all-none denied) ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/ready",
        requirement: ScopeRequirement::AnyReadAccess,
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/system/metrics",
        requirement: ScopeRequirement::AnyReadAccess,
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/system/metrics",
        requirement: ScopeRequirement::AnyReadAccess,
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/system/metrics/history",
        requirement: ScopeRequirement::AnyReadAccess,
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/system/hardware",
        requirement: ScopeRequirement::AnyReadAccess,
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/system/topology",
        requirement: ScopeRequirement::AnyReadAccess,
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/notifications",
        requirement: ScopeRequirement::AnyReadAccess,
    },
    // ── Services, logs, pending actions, plugin lifecycle, streaming observability/control ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/services",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/services",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/services/restart/status",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/services/:name/control",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/logs",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/logs/sources",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/logs/bookmarks",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/logs/bookmarks",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/actions/pending",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/actions/:id",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/actions/:id/approve",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/actions/:id/reject",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/plugins",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/plugins",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/plugins/:id/control",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/dashboard",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/history",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/history/export",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/patterns",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/patterns/activity",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/patterns/concurrency",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/drilldown",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/drilldown/users",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/drilldown/clients",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/drilldown/items",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/drilldown/libraries",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/drilldown/genres",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/streaming/artwork/:itemId",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/servers/:provider/sync",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/sessions/:sessionId/command",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/demo",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/streaming/imports/status",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/imports/events",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/reconciliation/preview",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/reconciliation/apply",
        requirement: ScopeRequirement::Area(Area::Services, Mode::Write),
    },
    // ── Marketplace, packages, deployments, blueprints ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/public/marketplace",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/packages/:id/progress",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/deploy/stream",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/deploy/stream",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/deploy/:appName",
        requirement: ScopeRequirement::All(&[
            (Area::Marketplace, Mode::Write),
            (Area::Services, Mode::Write),
            (Area::Network, Mode::Write),
        ]),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/blueprints",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/blueprints/:appName",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/blueprints/:appName/sync",
        requirement: ScopeRequirement::All(&[
            (Area::Marketplace, Mode::Write),
            (Area::Network, Mode::Write),
        ]),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/packages/:id/install",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/packages/:id/reinstall",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/packages/:id/uninstall",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/packages/:id/update",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/packages/:id/check-update",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/packages/updates/check",
        requirement: ScopeRequirement::Area(Area::Marketplace, Mode::Write),
    },
    // ── Settings, backups, notifications, AI, streaming configuration & portability ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/settings",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/settings",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/settings",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/settings/test-ai",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/audit-log",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/oidc/clients",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/backup/list",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/backup/run",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    // Sensitive password-recheck backup downloads require `settings: write` on BOTH GET and POST
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/backup/download/:filename",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/backup/download/:filename",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/backup/upload/:filename",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/auth/notifications/:id/read",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/notifications/dismiss-all",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/notifications/rules",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/notifications/rules",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/notifications/rules/:id",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/admin/notifications/rules/:id",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/notifications/channels",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/notifications/channels",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/notifications/channels/:id/test",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/admin/notifications/channels/:id",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/ai/chat",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/ai/support",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/ai/metadata/status",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/ai/metadata/results",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/ai/metadata/scan",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/ai/bandwidth/analyze",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/ai/predictions",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/ai/predictions/analyze",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/ai/predictions/history",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/ai/backup/optimal-window",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/ai/backup/schedule",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/ai/backup/schedule",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/streaming/servers/:provider",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/servers/test",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/streaming/portability/export",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/portability/preview",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/portability/restore",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/streaming/imports/upstream-probe",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/streaming/policies",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/streaming/policies",
        requirement: ScopeRequirement::Area(Area::Settings, Mode::Write),
    },
    // ── Files, Fileshare, and McBrowser (including merged submodules) ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/fs",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/fs",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/fileshare",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/fileshare/download/:filename",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/fileshare/download/:filename",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/fileshare/upload",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/admin/fileshare/:filename",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/entries",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/directory",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/rename",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/auth/mcbrowser/entry",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/download",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/preview",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/auth/mcbrowser/upload",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/policy",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/policy/:user_id",
        requirement: ScopeRequirement::All(&[(Area::Files, Mode::Read), (Area::Users, Mode::Read)]),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/auth/mcbrowser/policy/:user_id",
        requirement: ScopeRequirement::All(&[
            (Area::Files, Mode::Write),
            (Area::Users, Mode::Write),
        ]),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/preferences",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/auth/mcbrowser/preferences",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/usage",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/events",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/audit-events",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/events/settings",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/auth/mcbrowser/events/settings",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/events/queue",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/events/queue/:event_id/ack",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/actions",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/uploads",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/uploads",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "HEAD",
        pattern: "/api/v1/auth/mcbrowser/uploads/:id",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "PATCH",
        pattern: "/api/v1/auth/mcbrowser/uploads/:id",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/auth/mcbrowser/uploads/:id",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/search",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/copy",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/delete-recursive",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/info",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/archive",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/archive-ticket",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    // Mutating GET: redeems and consumes single-use archive ticket
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/archive/:ticket",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/content",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/auth/mcbrowser/content",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/file",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/media",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/media-info",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/thumbnail",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/preview/thumb",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/preview/big",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/subtitle",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/subtitles",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/csv",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/epub",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/mcbrowser/shares",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/auth/mcbrowser/shares",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/auth/mcbrowser/shares/:id",
        requirement: ScopeRequirement::Area(Area::Files, Mode::Write),
    },
    // ── Users, quotas, streaming user links ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/users",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/users/:id/role",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/admin/users/:id",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/quotas",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/quotas/:id",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/quotas/:id/refresh",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/streaming/user-links",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/streaming/user-links",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/admin/streaming/user-links",
        requirement: ScopeRequirement::Area(Area::Users, Mode::Write),
    },
    // ── Network, WireGuard (user VPN), Tailscale, Ingress, Bandwidth QoS ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/network/status",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/network/wireguard/peers",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/wireguard/peers",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/network/wireguard/peers/:key",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "DELETE",
        pattern: "/api/v1/admin/network/wireguard/peers/:key",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/wireguard/keygen",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/network/tailscale/status",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/network/tailscale/peers",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/network/tailscale/routes",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/tailscale/routes",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/tailscale/connect",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/tailscale/disconnect",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/tailscale/logout",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/tailscale/settings",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/network/:provider/service",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/network/diagnostics",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/ai/bandwidth/apply",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/ingress/configs",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/admin/ingress/apps/:appName",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/ingress/configs",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Read),
    },
    AllowedRule {
        method: "PUT",
        pattern: "/api/v1/ingress/apps/:appName",
        requirement: ScopeRequirement::Area(Area::Network, Mode::Write),
    },
    // ── System updates ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/system/update/check",
        requirement: ScopeRequirement::Area(Area::Updates, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/auth/system/update/status",
        requirement: ScopeRequirement::Area(Area::Updates, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/system/update/check",
        requirement: ScopeRequirement::Area(Area::Updates, Mode::Read),
    },
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/system/update/status",
        requirement: ScopeRequirement::Area(Area::Updates, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/system/update/run",
        requirement: ScopeRequirement::Area(Area::Updates, Mode::Write),
    },
    // ── Transcoding / MediaFlow ──
    AllowedRule {
        method: "GET",
        pattern: "/api/v1/admin/mediaflow/queue",
        requirement: ScopeRequirement::Area(Area::Transcoding, Mode::Read),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/mediaflow/scan",
        requirement: ScopeRequirement::Area(Area::Transcoding, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/mediaflow/approve/:id",
        requirement: ScopeRequirement::Area(Area::Transcoding, Mode::Write),
    },
    AllowedRule {
        method: "POST",
        pattern: "/api/v1/admin/mediaflow/decline/:id",
        requirement: ScopeRequirement::Area(Area::Transcoding, Mode::Write),
    },
];

/// Matches a canonical `/api/v1/...` path against a route pattern.
///
/// For static and trailing `/*` patterns without `:param` placeholders, this delegates directly
/// to `crate::plugins::route_pattern_matches` strictly AFTER enforcing the `/api/v1/` prefix
/// (preventing legacy `/api/` equivalence). For parameterized templates containing `:param`,
/// literal segments are matched segment-by-segment.
fn pattern_matches(pattern: &str, canonical: &CanonicalPath, case_insensitive: bool) -> bool {
    let path_str = canonical.as_str();
    if !path_str.starts_with("/api/v1/") {
        return false;
    }
    if !pattern.contains(':') {
        if case_insensitive {
            let lower_path = path_str.to_ascii_lowercase();
            let lower_pat = pattern.to_ascii_lowercase();
            return crate::plugins::route_pattern_matches(&lower_pat, &lower_path);
        }
        return crate::plugins::route_pattern_matches(pattern, path_str);
    }

    let pat_segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let req_segs = canonical.segments();
    for (idx, &p_seg) in pat_segs.iter().enumerate() {
        if p_seg == "*" || p_seg.starts_with('*') {
            return idx < req_segs.len();
        }
        let Some(r_seg) = req_segs.get(idx) else {
            return false;
        };
        if p_seg.starts_with(':') {
            if r_seg.is_empty() {
                return false;
            }
            continue;
        }
        let eq = if case_insensitive {
            p_seg.eq_ignore_ascii_case(r_seg)
        } else {
            p_seg == r_seg
        };
        if !eq {
            return false;
        }
    }
    pat_segs.len() == req_segs.len()
}

/// Classifies `(method, canonical_path)` into an explicit allow requirement, forbidden decision,
/// or fail-closed unclassified decision.
pub fn classify(method: &Method, canonical: &CanonicalPath) -> RouteDecision {
    let path_str = canonical.as_str();
    if !path_str.starts_with("/api/v1/") {
        return RouteDecision::Unclassified;
    }

    let req_method = method.as_str();

    // Forbidden rules are evaluated first and match case-insensitively on static segments.
    for rule in FORBIDDEN_RULES {
        if rule.method.is_none_or(|m| {
            m.eq_ignore_ascii_case(req_method) || (method == Method::HEAD && m == "GET")
        }) && pattern_matches(rule.pattern, canonical, true)
        {
            return RouteDecision::Forbidden;
        }
    }

    for rule in ALLOWED_RULES {
        if rule.method == req_method && pattern_matches(rule.pattern, canonical, false) {
            return RouteDecision::Allowed(rule.requirement);
        }
    }

    // Axum supplies HEAD for GET registrations without an explicit HEAD handler.
    // Inherit its authorization requirement, including any write requirement.
    if method != Method::HEAD {
        return RouteDecision::Unclassified;
    }
    ALLOWED_RULES
        .iter()
        .find(|rule| rule.method == "GET" && pattern_matches(rule.pattern, canonical, false))
        .map_or(RouteDecision::Unclassified, |rule| {
            RouteDecision::Allowed(rule.requirement)
        })
}

#[cfg(test)]
pub(crate) fn instantiate_registered_path(registered_path: &str) -> String {
    let mut out = Vec::new();
    for seg in registered_path.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg.starts_with(':') {
            out.push("sample-id");
        } else if seg.starts_with('*') {
            out.push("sample");
            out.push("tail");
        } else {
            out.push(seg);
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

#[cfg(test)]
pub(crate) fn verify_production_route_coverage(
    routes: &[crate::routes::RegisteredRoute],
) -> Result<(), Vec<String>> {
    use std::collections::HashSet;

    let mut errors = Vec::new();
    let mut matched_allowed_indices: HashSet<usize> = HashSet::new();

    for route in routes {
        let concrete = instantiate_registered_path(&route.path);
        let canonical = match canonicalize(&concrete) {
            Ok(c) => c,
            Err(err) => {
                errors.push(format!(
                    "registered route {} {} failed canonicalization ({concrete}): {err}",
                    route.method, route.path
                ));
                continue;
            }
        };

        if !route.path.starts_with("/api/v1/") {
            let decision = classify(&route.method, &canonical);
            if decision != RouteDecision::Unclassified {
                errors.push(format!(
                    "non-versioned route {} {} must classify as Unclassified, got {decision:?}",
                    route.method, route.path
                ));
            }
            continue;
        }

        let decision = classify(&route.method, &canonical);
        match decision {
            RouteDecision::Unclassified => {
                errors.push(format!(
                    "unclassified production route: {} {} (concrete {concrete})",
                    route.method, route.path
                ));
            }
            RouteDecision::Forbidden => {
                // Verify an allowed rule does not also claim this forbidden route
                if let Some(dup) = ALLOWED_RULES.iter().find(|r| {
                    r.method == route.method.as_str()
                        && pattern_matches(r.pattern, &canonical, false)
                }) {
                    errors.push(format!(
                        "forbidden route {} {} is shadowed in ALLOWED_RULES by {} {}",
                        route.method, route.path, dup.method, dup.pattern
                    ));
                }
            }
            RouteDecision::Allowed(_) => {
                if let Some((idx, _)) = ALLOWED_RULES.iter().enumerate().find(|(_, r)| {
                    r.method == route.method.as_str()
                        && pattern_matches(r.pattern, &canonical, false)
                }) {
                    matched_allowed_indices.insert(idx);
                } else {
                    errors.push(format!(
                        "route {} {} returned Allowed without a matching ALLOWED_RULES entry",
                        route.method, route.path
                    ));
                }
            }
        }
    }

    for (idx, rule) in ALLOWED_RULES.iter().enumerate() {
        if !matched_allowed_indices.contains(&idx) {
            errors.push(format!(
                "stale ALLOWED_RULES entry not present in production router: {} {}",
                rule.method, rule.pattern
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::RegisteredRoute;

    #[test]
    fn every_registered_production_route_and_method_is_explicitly_classified() {
        let routes = crate::routes::registered_production_routes();
        assert!(
            routes.len() > 150,
            "expected complete production route inventory including merged routers, got {}",
            routes.len()
        );
        // Spot-check that merged mcbrowser and peers routers are actually present
        assert!(routes
            .iter()
            .any(|r| r.method == Method::GET && r.path == "/api/v1/auth/mcbrowser/entries"));
        assert!(routes
            .iter()
            .any(|r| r.method == Method::HEAD && r.path == "/api/v1/auth/mcbrowser/uploads/:id"));
        assert!(routes
            .iter()
            .any(|r| r.method == Method::PUT && r.path == "/api/v1/admin/peers/:id/grant"));
        assert!(routes
            .iter()
            .any(|r| r.method == Method::POST && r.path == "/api/v1/admin/peers/:id/grant-offer"));

        if let Err(problems) = verify_production_route_coverage(&routes) {
            panic!(
                "Production route coverage check failed ({} issues):\n{}",
                problems.len(),
                problems.join("\n")
            );
        }
    }

    #[test]
    fn added_unclassified_route_or_method_fails_coverage_check() {
        let mut with_new_route = crate::routes::registered_production_routes();
        with_new_route.push(RegisteredRoute {
            method: Method::GET,
            path: "/api/v1/admin/newly-added-unclassified-endpoint".to_string(),
        });
        let err = verify_production_route_coverage(&with_new_route)
            .expect_err("adding an unclassified route must fail coverage check");
        assert!(
            err.iter()
                .any(|e| e.contains("newly-added-unclassified-endpoint")),
            "expected failure naming added route, got: {err:?}"
        );

        let mut with_new_method = crate::routes::registered_production_routes();
        with_new_method.push(RegisteredRoute {
            method: Method::DELETE,
            path: "/api/v1/admin/services".to_string(),
        });
        let err = verify_production_route_coverage(&with_new_method)
            .expect_err("adding an unclassified HTTP method on an existing route must fail");
        assert!(
            err.iter()
                .any(|e| e.contains("DELETE /api/v1/admin/services")),
            "expected failure naming added method, got: {err:?}"
        );
    }

    #[test]
    fn canonicalize_rejects_smuggling_traversal_and_ambiguity() {
        assert_eq!(
            canonicalize("//api///v1//admin//services/")
                .unwrap()
                .as_str(),
            "/api/v1/admin/services"
        );
        assert_eq!(
            canonicalize("/api/v1/admin/services/my%20svc/control")
                .unwrap()
                .as_str(),
            "/api/v1/admin/services/my svc/control"
        );

        for bad in [
            "api/v1/admin/services",
            "/api/v1/admin/../admin/peers",
            "/api/v1/admin/%2e%2e/admin/peers",
            "/api/v1/admin/%2E/services",
            "/api/v1/admin/./services",
            "/api/v1/admin%2fpeers",
            "/api/v1/admin%2Fpeers",
            "/api/v1/admin\\peers",
            "/api/v1/admin%5cpeers",
            "/api/v1/admin/%252e%252e/peers",
            "/api/v1/admin/%252fpeers",
            "/api/v1/admin/services%00",
            "/api/v1/admin/services\r\n",
            "/api/v1/admin/services ",
            "/api/v1/admin/%ZZ",
            "/api/v1/admin/services?foo=bar",
            "/api/v1/admin/services#frag",
        ] {
            assert!(
                canonicalize(bad).is_err(),
                "expected canonicalize to reject ambiguous/malicious path: {bad:?}"
            );
        }
    }

    #[test]
    fn upload_discovery_and_resume_require_write_and_head_inherits_get_scope() {
        for (method, path) in [
            (Method::GET, "/api/v1/auth/mcbrowser/uploads"),
            (Method::HEAD, "/api/v1/auth/mcbrowser/uploads"),
            (Method::HEAD, "/api/v1/auth/mcbrowser/uploads/sample-id"),
        ] {
            let canonical = canonicalize(path).unwrap();
            assert_eq!(
                classify(&method, &canonical),
                RouteDecision::Allowed(ScopeRequirement::Area(Area::Files, Mode::Write))
            );
            assert!(!access_allows(
                &AccessMap::read_only_all(),
                ScopeRequirement::Area(Area::Files, Mode::Write),
            ));
        }
        assert_eq!(
            classify(
                &Method::HEAD,
                &canonicalize("/api/v1/admin/settings").unwrap()
            ),
            RouteDecision::Allowed(ScopeRequirement::Area(Area::Settings, Mode::Read)),
        );
        assert_eq!(
            classify(
                &Method::HEAD,
                &canonicalize("/api/v1/auth/session").unwrap()
            ),
            RouteDecision::Forbidden,
        );
    }

    #[test]
    fn cross_area_routes_require_access_in_every_affected_area() {
        use af_db::peers::AccessLevel::Write;
        let mut access = AccessMap {
            marketplace: Write,
            files: Write,
            ..AccessMap::none()
        };
        let cases = [
            (Method::POST, "/api/v1/auth/deploy/sample-app"),
            (Method::POST, "/api/v1/admin/blueprints/sample-app/sync"),
            (Method::GET, "/api/v1/auth/mcbrowser/policy/1"),
            (Method::PUT, "/api/v1/auth/mcbrowser/policy/1"),
        ];
        let requirements = cases.map(|(method, path)| {
            let RouteDecision::Allowed(requirement) =
                classify(&method, &canonicalize(path).unwrap())
            else {
                panic!("missing scope requirement for {method} {path}")
            };
            assert!(!access_allows(&access, requirement));
            requirement
        });
        access.network = Write;
        assert!(!access_allows(&access, requirements[0]));
        assert!(access_allows(&access, requirements[1]));
        access.services = Write;
        access.users = Write;
        assert!(requirements
            .iter()
            .all(|&requirement| access_allows(&access, requirement)));
    }

    #[test]
    fn reconcile_uri_preserves_query_and_eliminates_ambiguity() {
        let orig: Uri = "//api//v1/admin/services/foo%20bar/control?dry=1"
            .parse()
            .unwrap();
        let canonical = canonicalize(orig.path()).unwrap();
        let reconciled = reconcile_uri(&orig, &canonical).unwrap();
        assert_eq!(
            reconciled.to_string(),
            "/api/v1/admin/services/foo%20bar/control?dry=1"
        );
    }

    #[test]
    fn classify_enforces_forbidden_mutating_gets_overview_and_non_versioned_rules() {
        // Non-versioned & top-level paths always Unclassified
        for p in [
            "/api/admin/services",
            "/api/auth/mcbrowser/entries",
            "/health",
            "/metrics",
            "/plugins/demo/proxy/foo",
            "/.well-known/openid-configuration",
            "/API/V1/admin/services",
        ] {
            let c = canonicalize(p).unwrap();
            assert_eq!(
                classify(&Method::GET, &c),
                RouteDecision::Unclassified,
                "expected non-versioned/top-level {p} to be Unclassified"
            );
        }

        // Forbidden routes (including case variants and trailing slash)
        for (method, p) in [
            (Method::GET, "/api/v1/admin/peers"),
            (Method::GET, "/api/v1/admin/peers/"),
            (Method::PUT, "/api/v1/admin/peers/link-1/grant"),
            (Method::POST, "/api/v1/admin/PEERS/link-1/grant-offer"),
            (Method::GET, "/api/v1/peers/link-1/admin/services"),
            (Method::POST, "/api/v1/peer-pairing/request"),
            (Method::GET, "/api/v1/auth/session"),
            (Method::POST, "/api/v1/auth/refresh"),
            (Method::GET, "/api/v1/auth/sessions"),
            (Method::DELETE, "/api/v1/auth/sessions/jti-1"),
            (Method::POST, "/api/v1/auth/logout"),
            (Method::PUT, "/api/v1/auth/profile/password"),
            (Method::POST, "/api/v1/auth/user/2fa/disable"),
            (Method::POST, "/api/v1/admin/oidc/clients"),
            (Method::DELETE, "/api/v1/admin/oidc/clients/client-1"),
            (Method::POST, "/api/v1/admin/plugins/demo/token"),
            (Method::POST, "/api/v1/admin/apps/launch"),
            (Method::GET, "/api/v1/auth/plugins/demo/ui"),
            (Method::GET, "/api/v1/auth/plugins/demo/proxy"),
            (Method::POST, "/api/v1/auth/plugins/demo/proxy/sub/path"),
            (Method::GET, "/api/v1/auth/ws"),
            (Method::GET, "/api/v1/auth/ws/ticket"),
            (Method::GET, "/api/v1/public/csrf-token"),
            (Method::POST, "/api/v1/public/auth/login"),
            (Method::GET, "/api/v1/public/mcbrowser/shares/tok-1"),
        ] {
            let c = canonicalize(p).unwrap();
            assert_eq!(
                classify(&method, &c),
                RouteDecision::Forbidden,
                "expected {method} {p} to be Forbidden"
            );
        }

        // Mutating/sensitive GETs require write access
        assert_eq!(
            classify(
                &Method::GET,
                &canonicalize("/api/v1/admin/backup/download/a.sqlite").unwrap()
            ),
            RouteDecision::Allowed(ScopeRequirement::Area(Area::Settings, Mode::Write))
        );
        assert_eq!(
            classify(
                &Method::GET,
                &canonicalize("/api/v1/auth/mcbrowser/archive/ticket-123").unwrap()
            ),
            RouteDecision::Allowed(ScopeRequirement::Area(Area::Files, Mode::Write))
        );
        assert_eq!(
            classify(
                &Method::GET,
                &canonicalize("/api/v1/admin/oidc/clients").unwrap()
            ),
            RouteDecision::Allowed(ScopeRequirement::Area(Area::Settings, Mode::Read))
        );

        // Read overview routes require some effective access (all-none denied)
        let overview = classify(
            &Method::GET,
            &canonicalize("/api/v1/auth/system/metrics").unwrap(),
        );
        assert_eq!(
            overview,
            RouteDecision::Allowed(ScopeRequirement::AnyReadAccess)
        );
        assert!(!access_allows(
            &AccessMap::none(),
            ScopeRequirement::AnyReadAccess
        ));
        let mut partial = AccessMap::none();
        partial.files = AccessLevel::Read;
        assert!(access_allows(&partial, ScopeRequirement::AnyReadAccess));
        assert!(!access_allows(
            &partial,
            ScopeRequirement::Area(Area::Services, Mode::Read)
        ));
    }
}
