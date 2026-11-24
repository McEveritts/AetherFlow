mod logs;
mod proxy;
mod telemetry;
mod tickets;

pub use logs::handle_log_websocket;
#[cfg(test)]
use logs::open_confined_live_log_file;
pub(crate) use logs::websocket_origin_matches_host;
pub use proxy::{
    build_set_cookie, extract_client_ip, extract_client_ip_for_peer, extract_cookie,
    is_trusted_proxy_peer, normalize_request_forwarding_for_peer, InboundProxyForwarded,
};
#[cfg(all(test, target_os = "linux"))]
use std::time::Duration;
pub use telemetry::{
    broadcast_ws_message, sanitize_diagnostic_text_fields, sanitize_log_line,
    start_metrics_broadcast_loop,
};
pub(crate) use telemetry::{package_diagnostics_allowed, sanitize_services_for_viewer};
#[cfg(test)]
use telemetry::{websocket_message_for_peer_session, websocket_message_for_session, Telemetry};
#[cfg(test)]
use tickets::{
    classify_revocation_recv, consume_live_ws_ticket, refresh_ws_authorization,
    RevocationWakeOutcome, WsPeerBinding, WsTicketEntry,
};
pub use tickets::{
    handle_issue_ws_ticket, handle_websocket, issue_ws_ticket_for_session,
    issue_ws_ticket_for_user, PeerIp, WsTicketQuery,
};

#[cfg(test)]
mod client_ip_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(all(test, target_os = "linux"))]
#[path = "log_authorization_regressions.rs"]
mod log_authorization_regressions;
#[cfg(test)]
mod telemetry_tests;
