mod approvals;
mod handlers;
mod planning;
mod restore;
mod snapshot;
mod types;

#[cfg(test)]
mod tests;

pub const EXPORT_ROUTE: &str = "/streaming/portability/export";
pub const PREVIEW_ROUTE: &str = "/streaming/portability/preview";
pub const RESTORE_ROUTE: &str = "/streaming/portability/restore";

pub(crate) const HEADER_ARCHIVE_TELEMETRY: &str = "x-aetherflow-archive-telemetry";
pub(crate) const HEADER_OMITTED_SESSION_SAMPLES: &str = "x-aetherflow-omitted-session-samples";
pub(crate) const HEADER_OMITTED_BANDWIDTH_SAMPLES: &str = "x-aetherflow-omitted-bandwidth-samples";

const ARCHIVE_FORMAT: &str = "aetherflow.streaming-history";
const ARCHIVE_FORMAT_VERSION: u16 = 1;
const DATABASE_SCHEMA_VERSION: u16 = 20;
const PROVENANCE_VERSION: u16 = 1;
pub const MAX_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PORTABILITY_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_REQUEST_BODY_BYTES: usize = MAX_PORTABILITY_BODY_BYTES;
const MAX_BODY_BYTES: usize = MAX_ARCHIVE_BYTES;
const MAX_PORTABLE_ROWS: usize = 100_000;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_APPROVALS: usize = 512;
const APPROVAL_TTL_SECS: i64 = 300;

const REDACTED_FIELDS: &[&str] = &[
    "streaming_history.device_name",
    "streaming_history.device_id",
    "streaming_history.ip_address",
    "streaming_servers.api_key",
];
const OMITTED_TABLES: &[&str] = &[
    "streaming_servers (connection settings and credentials)",
    "streaming_user_links (AetherFlow-local user IDs)",
    "streaming_import_checkpoints (destination-specific cursors)",
    "streaming_history_audit (destination-local audit trail)",
    "streaming_history_revision (destination-local revision counter)",
];

pub use handlers::{export_handler, preview_handler, restore_handler};
#[cfg(test)]
pub(crate) use snapshot::export_archive_json_with_budget;
