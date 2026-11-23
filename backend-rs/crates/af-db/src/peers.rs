use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) const PEER_CLUSTERING_MIGRATION_25_SQL: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS peer_identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        wg_pubkey TEXT NOT NULL,
        tunnel_ip TEXT NOT NULL,
        wg_port INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_links (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        wg_pubkey TEXT NOT NULL UNIQUE,
        tunnel_ip TEXT NOT NULL UNIQUE,
        endpoint TEXT NOT NULL,
        wg_port INTEGER NOT NULL,
        state TEXT NOT NULL,
        peer_version TEXT,
        peer_protocol INTEGER,
        capabilities TEXT,
        rtt_ms REAL,
        last_ok_at TEXT,
        last_error TEXT,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        inbound_token_hash TEXT,
        pending_attempt_id TEXT,
        pending_expires_at INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_grants (
        id TEXT PRIMARY KEY,
        link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
        run_as_user_id INTEGER NOT NULL,
        access TEXT NOT NULL,
        token_hash TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        revoked_at TEXT
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_pairing_windows (
        id TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_pairing_attempts (
        id TEXT PRIMARY KEY,
        window_id TEXT,
        remote_name TEXT,
        remote_pubkey TEXT,
        remote_tunnel_ip TEXT,
        remote_endpoint TEXT,
        source_ip TEXT,
        status TEXT NOT NULL,
        error_code TEXT,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_exports (
        id TEXT PRIMARY KEY,
        link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        writable INTEGER NOT NULL DEFAULT 0,
        squash_uid INTEGER,
        squash_gid INTEGER,
        created_at TEXT NOT NULL
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_mounts (
        id TEXT PRIMARY KEY,
        link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
        remote_path TEXT NOT NULL,
        mount_path TEXT NOT NULL UNIQUE,
        unit_name TEXT NOT NULL,
        writable INTEGER NOT NULL DEFAULT 0,
        purpose TEXT NOT NULL,
        state TEXT NOT NULL,
        last_error TEXT
    );"#,
    r#"CREATE TABLE IF NOT EXISTS transcode_workers (
        link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
        enabled INTEGER NOT NULL DEFAULT 0,
        weight INTEGER NOT NULL DEFAULT 1,
        max_jobs INTEGER NOT NULL DEFAULT 2,
        ffmpeg_version TEXT,
        encoders TEXT,
        render_node TEXT,
        parity_ok INTEGER NOT NULL DEFAULT 0,
        parity_error TEXT
    );"#,
    r#"CREATE TABLE IF NOT EXISTS transcode_jobs (
        id TEXT PRIMARY KEY,
        link_id TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        exit_code INTEGER,
        request_id TEXT,
        ran_locally INTEGER NOT NULL
    );"#,
    "ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'human';",
];

pub(crate) const PEER_GRANT_METADATA_MIGRATION_27_SQL: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS peer_received_grants (
        link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
        grant_id TEXT NOT NULL,
        run_as_user_id INTEGER NOT NULL,
        access TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        generation INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT,
        credential_id TEXT,
        updated_at TEXT NOT NULL
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_received_grant_cleanups (
        link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
        credential_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (link_id, credential_id)
    );"#,
    r#"CREATE TABLE IF NOT EXISTS peer_grant_epochs (
        link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
        issuer_generation INTEGER NOT NULL DEFAULT 0,
        active_op_id TEXT,
        updated_at TEXT NOT NULL
    );"#,
];

/// Ensures additive unreleased Migration 27 columns and tables exist even for pre-existing
/// databases or isolated test schemas created before staged-slot grant metadata was added.
pub fn ensure_peer_grant_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    let has_received_grants: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'peer_received_grants')",
        [],
        |r| r.get(0),
    )?;
    if has_received_grants {
        crate::schema::ensure_column(conn, "peer_received_grants", "credential_id", "TEXT")?;
    }
    let has_links: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'peer_links')",
        [],
        |r| r.get(0),
    )?;
    if has_links {
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS peer_received_grant_cleanups (
                link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
                credential_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (link_id, credential_id)
            );"#,
            [],
        )?;
    }
    Ok(())
}

const REDACTED_DIGEST: &str = "[REDACTED]";

// ─────────────────────────────────────────────────────────────────────────────
// Grant Access Map
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    #[default]
    None,
    Read,
    Write,
}

impl AccessLevel {
    pub const fn allows_read(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }

    pub const fn allows_write(self) -> bool {
        matches!(self, Self::Write)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessMap {
    #[serde(default)]
    pub services: AccessLevel,
    #[serde(default)]
    pub marketplace: AccessLevel,
    #[serde(default)]
    pub settings: AccessLevel,
    #[serde(default)]
    pub files: AccessLevel,
    #[serde(default)]
    pub users: AccessLevel,
    #[serde(default)]
    pub network: AccessLevel,
    #[serde(default)]
    pub updates: AccessLevel,
    #[serde(default)]
    pub transcoding: AccessLevel,
}

impl AccessMap {
    pub const fn none() -> Self {
        Self {
            services: AccessLevel::None,
            marketplace: AccessLevel::None,
            settings: AccessLevel::None,
            files: AccessLevel::None,
            users: AccessLevel::None,
            network: AccessLevel::None,
            updates: AccessLevel::None,
            transcoding: AccessLevel::None,
        }
    }

    pub const fn read_only_all() -> Self {
        Self {
            services: AccessLevel::Read,
            marketplace: AccessLevel::Read,
            settings: AccessLevel::Read,
            files: AccessLevel::Read,
            users: AccessLevel::Read,
            network: AccessLevel::Read,
            updates: AccessLevel::Read,
            transcoding: AccessLevel::Read,
        }
    }

    pub const fn read_write_all() -> Self {
        Self {
            services: AccessLevel::Write,
            marketplace: AccessLevel::Write,
            settings: AccessLevel::Write,
            files: AccessLevel::Write,
            users: AccessLevel::Write,
            network: AccessLevel::Write,
            updates: AccessLevel::Write,
            transcoding: AccessLevel::Write,
        }
    }

    pub fn get(&self, area: &str) -> AccessLevel {
        match area {
            "services" => self.services,
            "marketplace" => self.marketplace,
            "settings" => self.settings,
            "files" => self.files,
            "users" => self.users,
            "network" => self.network,
            "updates" => self.updates,
            "transcoding" => self.transcoding,
            _ => AccessLevel::None,
        }
    }

    pub fn set(&mut self, area: &str, level: AccessLevel) -> bool {
        match area {
            "services" => self.services = level,
            "marketplace" => self.marketplace = level,
            "settings" => self.settings = level,
            "files" => self.files = level,
            "users" => self.users = level,
            "network" => self.network = level,
            "updates" => self.updates = level,
            "transcoding" => self.transcoding = level,
            _ => return false,
        }
        true
    }

    pub const fn has_any_access(&self) -> bool {
        self.services.allows_read()
            || self.marketplace.allows_read()
            || self.settings.allows_read()
            || self.files.allows_read()
            || self.users.allows_read()
            || self.network.allows_read()
            || self.updates.allows_read()
            || self.transcoding.allows_read()
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json(raw: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed Row Structs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub wg_port: u16,
    pub created_at: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerLink {
    pub id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub endpoint: String,
    pub wg_port: u16,
    pub state: String,
    pub peer_version: Option<String>,
    pub peer_protocol: Option<i64>,
    pub capabilities: Option<String>,
    pub rtt_ms: Option<f64>,
    pub last_ok_at: Option<String>,
    pub last_error: Option<String>,
    pub consecutive_failures: i64,
    #[serde(default, skip_serializing)]
    pub inbound_token_hash: Option<String>,
    pub pending_attempt_id: Option<String>,
    pub pending_expires_at: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

impl fmt::Debug for PeerLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerLink")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("wg_pubkey", &self.wg_pubkey)
            .field("tunnel_ip", &self.tunnel_ip)
            .field("endpoint", &self.endpoint)
            .field("wg_port", &self.wg_port)
            .field("state", &self.state)
            .field("peer_version", &self.peer_version)
            .field("peer_protocol", &self.peer_protocol)
            .field("capabilities", &self.capabilities)
            .field("rtt_ms", &self.rtt_ms)
            .field("last_ok_at", &self.last_ok_at)
            .field("last_error", &self.last_error)
            .field("consecutive_failures", &self.consecutive_failures)
            .field(
                "inbound_token_hash",
                &self.inbound_token_hash.as_ref().map(|_| REDACTED_DIGEST),
            )
            .field("pending_attempt_id", &self.pending_attempt_id)
            .field("pending_expires_at", &self.pending_expires_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerGrant {
    pub id: String,
    pub link_id: String,
    pub run_as_user_id: i64,
    pub access: AccessMap,
    #[serde(default, skip_serializing)]
    pub token_hash: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

impl fmt::Debug for PeerGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerGrant")
            .field("id", &self.id)
            .field("link_id", &self.link_id)
            .field("run_as_user_id", &self.run_as_user_id)
            .field("access", &self.access)
            .field(
                "token_hash",
                &self.token_hash.as_ref().map(|_| REDACTED_DIGEST),
            )
            .field("created_by", &self.created_by)
            .field("created_at", &self.created_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReceivedGrant {
    pub link_id: String,
    pub grant_id: String,
    pub run_as_user_id: i64,
    pub access: AccessMap,
    pub created_by: String,
    pub created_at: String,
    pub generation: i64,
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    pub updated_at: String,
}

impl PeerReceivedGrant {
    /// Returns the runner `GrantToken` credential ID committed for this grant, falling back to
    /// the canonical `link_id` slot for legacy rows where `credential_id` is `None`.
    pub fn effective_credential_id(&self) -> &str {
        self.credential_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .unwrap_or(self.link_id.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReceivedGrantCleanup {
    pub link_id: String,
    pub credential_id: String,
    pub generation: i64,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerGrantEpoch {
    pub link_id: String,
    pub issuer_generation: i64,
    pub active_op_id: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingWindow {
    pub id: String,
    #[serde(default, skip_serializing)]
    pub code_hash: String,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
}

impl fmt::Debug for PairingWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingWindow")
            .field("id", &self.id)
            .field("code_hash", &REDACTED_DIGEST)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingAttempt {
    pub id: String,
    pub window_id: Option<String>,
    pub remote_name: Option<String>,
    pub remote_pubkey: Option<String>,
    pub remote_tunnel_ip: Option<String>,
    pub remote_endpoint: Option<String>,
    pub source_ip: Option<String>,
    pub status: String,
    pub error_code: Option<String>,
    pub expires_at: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerExport {
    pub id: String,
    pub link_id: String,
    pub path: String,
    pub writable: bool,
    pub squash_uid: Option<u32>,
    pub squash_gid: Option<u32>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMount {
    pub id: String,
    pub link_id: String,
    pub remote_path: String,
    pub mount_path: String,
    pub unit_name: String,
    pub writable: bool,
    pub purpose: String,
    pub state: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeWorker {
    pub link_id: String,
    pub enabled: bool,
    pub weight: i64,
    pub max_jobs: i64,
    pub ffmpeg_version: Option<String>,
    pub encoders: Option<String>,
    pub render_node: Option<String>,
    pub parity_ok: bool,
    pub parity_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeJob {
    pub id: String,
    pub link_id: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub exit_code: Option<i32>,
    pub request_id: Option<String>,
    pub ran_locally: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Row Mappers
// ─────────────────────────────────────────────────────────────────────────────

const PEER_LINK_COLUMNS: &str = "id, name, wg_pubkey, tunnel_ip, endpoint, wg_port, state, \
    peer_version, peer_protocol, capabilities, rtt_ms, last_ok_at, last_error, \
    consecutive_failures, inbound_token_hash, pending_attempt_id, pending_expires_at, \
    created_at, updated_at";

const PEER_GRANT_COLUMNS: &str =
    "id, link_id, run_as_user_id, access, token_hash, created_by, created_at, revoked_at";

const PEER_RECEIVED_GRANT_COLUMNS: &str =
    "link_id, grant_id, run_as_user_id, access, created_by, created_at, generation, revoked_at, credential_id, updated_at";

const PEER_RECEIVED_GRANT_CLEANUP_COLUMNS: &str = "link_id, credential_id, generation, updated_at";

const PEER_GRANT_EPOCH_COLUMNS: &str = "link_id, issuer_generation, active_op_id, updated_at";

const PAIRING_WINDOW_COLUMNS: &str = "id, code_hash, expires_at, consumed_at";

const PAIRING_ATTEMPT_COLUMNS: &str = "id, window_id, remote_name, remote_pubkey, \
    remote_tunnel_ip, remote_endpoint, source_ip, status, error_code, expires_at, created_at";

const PEER_EXPORT_COLUMNS: &str = "id, link_id, path, writable, squash_uid, squash_gid, created_at";

const PEER_MOUNT_COLUMNS: &str =
    "id, link_id, remote_path, mount_path, unit_name, writable, purpose, state, last_error";

const TRANSCODE_WORKER_COLUMNS: &str = "link_id, enabled, weight, max_jobs, ffmpeg_version, \
    encoders, render_node, parity_ok, parity_error";

const TRANSCODE_JOB_COLUMNS: &str =
    "id, link_id, started_at, ended_at, exit_code, request_id, ran_locally";

fn map_peer_identity_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerIdentity> {
    Ok(PeerIdentity {
        wg_pubkey: row.get(0)?,
        tunnel_ip: row.get(1)?,
        wg_port: row.get(2)?,
        created_at: row.get(3)?,
    })
}

fn map_peer_link_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerLink> {
    Ok(PeerLink {
        id: row.get(0)?,
        name: row.get(1)?,
        wg_pubkey: row.get(2)?,
        tunnel_ip: row.get(3)?,
        endpoint: row.get(4)?,
        wg_port: row.get(5)?,
        state: row.get(6)?,
        peer_version: row.get(7)?,
        peer_protocol: row.get(8)?,
        capabilities: row.get(9)?,
        rtt_ms: row.get(10)?,
        last_ok_at: row.get(11)?,
        last_error: row.get(12)?,
        consecutive_failures: row.get(13)?,
        inbound_token_hash: row.get(14)?,
        pending_attempt_id: row.get(15)?,
        pending_expires_at: row.get(16)?,
        created_at: row.get(17)?,
        updated_at: row.get(18)?,
    })
}

fn map_peer_grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerGrant> {
    let access_json: String = row.get(3)?;
    let access: AccessMap = serde_json::from_str(&access_json).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(err))
    })?;
    Ok(PeerGrant {
        id: row.get(0)?,
        link_id: row.get(1)?,
        run_as_user_id: row.get(2)?,
        access,
        token_hash: row.get(4)?,
        created_by: row.get(5)?,
        created_at: row.get(6)?,
        revoked_at: row.get(7)?,
    })
}

fn map_peer_received_grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerReceivedGrant> {
    let access_json: String = row.get(3)?;
    let access: AccessMap = serde_json::from_str(&access_json).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(err))
    })?;
    Ok(PeerReceivedGrant {
        link_id: row.get(0)?,
        grant_id: row.get(1)?,
        run_as_user_id: row.get(2)?,
        access,
        created_by: row.get(4)?,
        created_at: row.get(5)?,
        generation: row.get(6)?,
        revoked_at: row.get(7)?,
        credential_id: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn map_peer_received_grant_cleanup_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PeerReceivedGrantCleanup> {
    Ok(PeerReceivedGrantCleanup {
        link_id: row.get(0)?,
        credential_id: row.get(1)?,
        generation: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

fn map_peer_grant_epoch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerGrantEpoch> {
    Ok(PeerGrantEpoch {
        link_id: row.get(0)?,
        issuer_generation: row.get(1)?,
        active_op_id: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

fn map_pairing_window_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PairingWindow> {
    Ok(PairingWindow {
        id: row.get(0)?,
        code_hash: row.get(1)?,
        expires_at: row.get(2)?,
        consumed_at: row.get(3)?,
    })
}

fn map_pairing_attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PairingAttempt> {
    Ok(PairingAttempt {
        id: row.get(0)?,
        window_id: row.get(1)?,
        remote_name: row.get(2)?,
        remote_pubkey: row.get(3)?,
        remote_tunnel_ip: row.get(4)?,
        remote_endpoint: row.get(5)?,
        source_ip: row.get(6)?,
        status: row.get(7)?,
        error_code: row.get(8)?,
        expires_at: row.get(9)?,
        created_at: row.get(10)?,
    })
}

fn map_peer_export_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerExport> {
    Ok(PeerExport {
        id: row.get(0)?,
        link_id: row.get(1)?,
        path: row.get(2)?,
        writable: row.get(3)?,
        squash_uid: row.get(4)?,
        squash_gid: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn map_peer_mount_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerMount> {
    Ok(PeerMount {
        id: row.get(0)?,
        link_id: row.get(1)?,
        remote_path: row.get(2)?,
        mount_path: row.get(3)?,
        unit_name: row.get(4)?,
        writable: row.get(5)?,
        purpose: row.get(6)?,
        state: row.get(7)?,
        last_error: row.get(8)?,
    })
}

fn map_transcode_worker_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TranscodeWorker> {
    Ok(TranscodeWorker {
        link_id: row.get(0)?,
        enabled: row.get(1)?,
        weight: row.get(2)?,
        max_jobs: row.get(3)?,
        ffmpeg_version: row.get(4)?,
        encoders: row.get(5)?,
        render_node: row.get(6)?,
        parity_ok: row.get(7)?,
        parity_error: row.get(8)?,
    })
}

fn map_transcode_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TranscodeJob> {
    Ok(TranscodeJob {
        id: row.get(0)?,
        link_id: row.get(1)?,
        started_at: row.get(2)?,
        ended_at: row.get(3)?,
        exit_code: row.get(4)?,
        request_id: row.get(5)?,
        ran_locally: row.get(6)?,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerIdentity CRUD (singleton id = 1)
// ─────────────────────────────────────────────────────────────────────────────

pub fn get_peer_identity(conn: &Connection) -> anyhow::Result<Option<PeerIdentity>> {
    Ok(conn
        .query_row(
            "SELECT wg_pubkey, tunnel_ip, wg_port, created_at FROM peer_identity WHERE id = 1",
            [],
            map_peer_identity_row,
        )
        .optional()?)
}

pub fn upsert_peer_identity(conn: &Connection, identity: &PeerIdentity) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO peer_identity (id, wg_pubkey, tunnel_ip, wg_port, created_at) \
         VALUES (1, ?1, ?2, ?3, ?4) \
         ON CONFLICT(id) DO UPDATE SET \
             wg_pubkey = excluded.wg_pubkey, \
             tunnel_ip = excluded.tunnel_ip, \
             wg_port = excluded.wg_port, \
             created_at = excluded.created_at",
        params![
            identity.wg_pubkey,
            identity.tunnel_ip,
            identity.wg_port,
            identity.created_at,
        ],
    )?;
    Ok(())
}

pub fn delete_peer_identity(conn: &Connection) -> anyhow::Result<bool> {
    let changed = conn.execute("DELETE FROM peer_identity WHERE id = 1", [])?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerLink CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn insert_peer_link(conn: &Connection, link: &PeerLink) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO peer_links (\
            id, name, wg_pubkey, tunnel_ip, endpoint, wg_port, state, \
            peer_version, peer_protocol, capabilities, rtt_ms, last_ok_at, last_error, \
            consecutive_failures, inbound_token_hash, pending_attempt_id, pending_expires_at, \
            created_at, updated_at\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        params![
            link.id,
            link.name,
            link.wg_pubkey,
            link.tunnel_ip,
            link.endpoint,
            link.wg_port,
            link.state,
            link.peer_version,
            link.peer_protocol,
            link.capabilities,
            link.rtt_ms,
            link.last_ok_at,
            link.last_error,
            link.consecutive_failures,
            link.inbound_token_hash,
            link.pending_attempt_id,
            link.pending_expires_at,
            link.created_at,
            link.updated_at,
        ],
    )?;
    Ok(())
}

pub fn get_peer_link(conn: &Connection, id: &str) -> anyhow::Result<Option<PeerLink>> {
    let sql = format!("SELECT {PEER_LINK_COLUMNS} FROM peer_links WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], map_peer_link_row)
        .optional()?)
}

pub fn get_peer_link_by_name(conn: &Connection, name: &str) -> anyhow::Result<Option<PeerLink>> {
    let sql = format!("SELECT {PEER_LINK_COLUMNS} FROM peer_links WHERE name = ?1");
    Ok(conn
        .query_row(&sql, params![name], map_peer_link_row)
        .optional()?)
}

pub fn get_peer_link_by_tunnel_ip(
    conn: &Connection,
    tunnel_ip: &str,
) -> anyhow::Result<Option<PeerLink>> {
    let sql = format!("SELECT {PEER_LINK_COLUMNS} FROM peer_links WHERE tunnel_ip = ?1");
    Ok(conn
        .query_row(&sql, params![tunnel_ip], map_peer_link_row)
        .optional()?)
}

pub fn get_peer_link_by_pubkey(
    conn: &Connection,
    wg_pubkey: &str,
) -> anyhow::Result<Option<PeerLink>> {
    let sql = format!("SELECT {PEER_LINK_COLUMNS} FROM peer_links WHERE wg_pubkey = ?1");
    Ok(conn
        .query_row(&sql, params![wg_pubkey], map_peer_link_row)
        .optional()?)
}

pub fn list_peer_links(conn: &Connection) -> anyhow::Result<Vec<PeerLink>> {
    let sql = format!("SELECT {PEER_LINK_COLUMNS} FROM peer_links ORDER BY created_at ASC, id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_peer_link_row)?;
    let mut links = Vec::new();
    for row in rows {
        links.push(row?);
    }
    Ok(links)
}

pub fn update_peer_link(conn: &Connection, link: &PeerLink) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_links SET \
            name = ?2, \
            wg_pubkey = ?3, \
            tunnel_ip = ?4, \
            endpoint = ?5, \
            wg_port = ?6, \
            state = ?7, \
            peer_version = ?8, \
            peer_protocol = ?9, \
            capabilities = ?10, \
            rtt_ms = ?11, \
            last_ok_at = ?12, \
            last_error = ?13, \
            consecutive_failures = ?14, \
            inbound_token_hash = ?15, \
            pending_attempt_id = ?16, \
            pending_expires_at = ?17, \
            updated_at = ?18 \
         WHERE id = ?1",
        params![
            link.id,
            link.name,
            link.wg_pubkey,
            link.tunnel_ip,
            link.endpoint,
            link.wg_port,
            link.state,
            link.peer_version,
            link.peer_protocol,
            link.capabilities,
            link.rtt_ms,
            link.last_ok_at,
            link.last_error,
            link.consecutive_failures,
            link.inbound_token_hash,
            link.pending_attempt_id,
            link.pending_expires_at,
            link.updated_at,
        ],
    )?;
    Ok(changed > 0)
}

pub fn clear_peer_link_inbound_token_hash(
    conn: &Connection,
    id: &str,
    updated_at: &str,
) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_links SET inbound_token_hash = NULL, updated_at = ?2 WHERE id = ?1",
        params![id, updated_at],
    )?;
    Ok(changed > 0)
}

pub fn delete_peer_link(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute("DELETE FROM peer_links WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerGrant CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn insert_peer_grant(conn: &Connection, grant: &PeerGrant) -> anyhow::Result<()> {
    let access_json = grant.access.to_json()?;
    conn.execute(
        "INSERT INTO peer_grants (\
            id, link_id, run_as_user_id, access, token_hash, created_by, created_at, revoked_at\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            grant.id,
            grant.link_id,
            grant.run_as_user_id,
            access_json,
            grant.token_hash,
            grant.created_by,
            grant.created_at,
            grant.revoked_at,
        ],
    )?;
    Ok(())
}

pub fn get_peer_grant(conn: &Connection, id: &str) -> anyhow::Result<Option<PeerGrant>> {
    let sql = format!("SELECT {PEER_GRANT_COLUMNS} FROM peer_grants WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], map_peer_grant_row)
        .optional()?)
}

pub fn get_active_peer_grant_for_link(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Option<PeerGrant>> {
    let sql = format!(
        "SELECT {PEER_GRANT_COLUMNS} FROM peer_grants \
         WHERE link_id = ?1 AND revoked_at IS NULL AND token_hash IS NOT NULL \
         ORDER BY created_at DESC, id DESC LIMIT 1"
    );
    Ok(conn
        .query_row(&sql, params![link_id], map_peer_grant_row)
        .optional()?)
}

pub fn list_peer_grants(conn: &Connection) -> anyhow::Result<Vec<PeerGrant>> {
    let sql =
        format!("SELECT {PEER_GRANT_COLUMNS} FROM peer_grants ORDER BY created_at ASC, id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_peer_grant_row)?;
    let mut grants = Vec::new();
    for row in rows {
        grants.push(row?);
    }
    Ok(grants)
}

pub fn list_peer_grants_for_link(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Vec<PeerGrant>> {
    let sql = format!(
        "SELECT {PEER_GRANT_COLUMNS} FROM peer_grants WHERE link_id = ?1 ORDER BY created_at ASC, id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![link_id], map_peer_grant_row)?;
    let mut grants = Vec::new();
    for row in rows {
        grants.push(row?);
    }
    Ok(grants)
}

pub fn update_peer_grant(conn: &Connection, grant: &PeerGrant) -> anyhow::Result<bool> {
    let access_json = grant.access.to_json()?;
    let changed = conn.execute(
        "UPDATE peer_grants SET \
            run_as_user_id = ?2, \
            access = ?3, \
            token_hash = ?4, \
            revoked_at = ?5 \
         WHERE id = ?1",
        params![
            grant.id,
            grant.run_as_user_id,
            access_json,
            grant.token_hash,
            grant.revoked_at,
        ],
    )?;
    Ok(changed > 0)
}

pub fn clear_peer_grant_token_hash(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_grants SET token_hash = NULL WHERE id = ?1",
        params![id],
    )?;
    Ok(changed > 0)
}

pub fn revoke_peer_grant(conn: &Connection, id: &str, revoked_at: &str) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_grants SET token_hash = NULL, revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
        params![id, revoked_at],
    )?;
    Ok(changed > 0)
}

pub fn revoke_active_peer_grants_for_link(
    conn: &Connection,
    link_id: &str,
    revoked_at: &str,
) -> anyhow::Result<Vec<PeerGrant>> {
    let sql = format!(
        "SELECT {PEER_GRANT_COLUMNS} FROM peer_grants \
         WHERE link_id = ?1 AND revoked_at IS NULL \
         ORDER BY created_at ASC, id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![link_id], map_peer_grant_row)?;
    let mut active = Vec::new();
    for row in rows {
        active.push(row?);
    }
    if !active.is_empty() {
        conn.execute(
            "UPDATE peer_grants SET token_hash = NULL, revoked_at = ?2 \
             WHERE link_id = ?1 AND revoked_at IS NULL",
            params![link_id, revoked_at],
        )?;
    }
    Ok(active)
}

pub fn delete_peer_grant(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute("DELETE FROM peer_grants WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerReceivedGrant & PeerGrantEpoch CRUD (Migration 27)
// ─────────────────────────────────────────────────────────────────────────────

pub fn upsert_peer_received_grant(
    conn: &Connection,
    grant: &PeerReceivedGrant,
) -> anyhow::Result<()> {
    let access_json = grant.access.to_json()?;
    conn.execute(
        "INSERT INTO peer_received_grants (\
            link_id, grant_id, run_as_user_id, access, created_by, created_at, \
            generation, revoked_at, credential_id, updated_at\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(link_id) DO UPDATE SET \
            grant_id = excluded.grant_id, \
            run_as_user_id = excluded.run_as_user_id, \
            access = excluded.access, \
            created_by = excluded.created_by, \
            created_at = excluded.created_at, \
            generation = excluded.generation, \
            revoked_at = excluded.revoked_at, \
            credential_id = excluded.credential_id, \
            updated_at = excluded.updated_at",
        params![
            grant.link_id,
            grant.grant_id,
            grant.run_as_user_id,
            access_json,
            grant.created_by,
            grant.created_at,
            grant.generation,
            grant.revoked_at,
            grant.credential_id,
            grant.updated_at,
        ],
    )?;
    Ok(())
}

pub fn get_peer_received_grant(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Option<PeerReceivedGrant>> {
    let sql = format!(
        "SELECT {PEER_RECEIVED_GRANT_COLUMNS} FROM peer_received_grants WHERE link_id = ?1"
    );
    Ok(conn
        .query_row(&sql, params![link_id], map_peer_received_grant_row)
        .optional()?)
}

pub fn get_active_peer_received_grant_for_link(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Option<PeerReceivedGrant>> {
    let sql = format!(
        "SELECT {PEER_RECEIVED_GRANT_COLUMNS} FROM peer_received_grants \
         WHERE link_id = ?1 AND revoked_at IS NULL"
    );
    Ok(conn
        .query_row(&sql, params![link_id], map_peer_received_grant_row)
        .optional()?)
}

pub fn list_peer_received_grants(conn: &Connection) -> anyhow::Result<Vec<PeerReceivedGrant>> {
    let sql = format!(
        "SELECT {PEER_RECEIVED_GRANT_COLUMNS} FROM peer_received_grants ORDER BY link_id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_peer_received_grant_row)?;
    let mut grants = Vec::new();
    for row in rows {
        grants.push(row?);
    }
    Ok(grants)
}

/// Persists durable cleanup intent for a staged, retired, or revoked runner `GrantToken` slot.
/// Never stores raw secrets—only the opaque safe runner credential slot identifier.
pub fn upsert_peer_received_grant_cleanup(
    conn: &Connection,
    link_id: &str,
    credential_id: &str,
    generation: i64,
    updated_at: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO peer_received_grant_cleanups (link_id, credential_id, generation, updated_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(link_id, credential_id) DO UPDATE SET \
            generation = CASE \
                WHEN excluded.generation > peer_received_grant_cleanups.generation \
                    THEN excluded.generation \
                ELSE peer_received_grant_cleanups.generation \
            END, \
            updated_at = excluded.updated_at",
        params![link_id, credential_id, generation, updated_at],
    )?;
    Ok(())
}

pub fn get_peer_received_grant_cleanup(
    conn: &Connection,
    link_id: &str,
    credential_id: &str,
) -> anyhow::Result<Option<PeerReceivedGrantCleanup>> {
    let sql = format!(
        "SELECT {PEER_RECEIVED_GRANT_CLEANUP_COLUMNS} FROM peer_received_grant_cleanups \
         WHERE link_id = ?1 AND credential_id = ?2"
    );
    Ok(conn
        .query_row(
            &sql,
            params![link_id, credential_id],
            map_peer_received_grant_cleanup_row,
        )
        .optional()?)
}

pub fn list_peer_received_grant_cleanups(
    conn: &Connection,
) -> anyhow::Result<Vec<PeerReceivedGrantCleanup>> {
    let sql = format!(
        "SELECT {PEER_RECEIVED_GRANT_CLEANUP_COLUMNS} FROM peer_received_grant_cleanups \
         ORDER BY link_id ASC, generation ASC, credential_id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_peer_received_grant_cleanup_row)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    Ok(items)
}

pub fn list_peer_received_grant_cleanups_for_link(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Vec<PeerReceivedGrantCleanup>> {
    let sql = format!(
        "SELECT {PEER_RECEIVED_GRANT_CLEANUP_COLUMNS} FROM peer_received_grant_cleanups \
         WHERE link_id = ?1 ORDER BY generation ASC, credential_id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![link_id], map_peer_received_grant_cleanup_row)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    Ok(items)
}

/// Removes a cleanup row only when `(link_id, credential_id, generation)` matches exactly.
pub fn delete_peer_received_grant_cleanup_if_matches(
    conn: &Connection,
    link_id: &str,
    credential_id: &str,
    generation: i64,
) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "DELETE FROM peer_received_grant_cleanups \
         WHERE link_id = ?1 AND credential_id = ?2 AND generation = ?3",
        params![link_id, credential_id, generation],
    )?;
    Ok(changed > 0)
}

/// Removes a staged cleanup intent row when promoting that exact `credential_id` to the active
/// committed grant slot inside an atomic `IMMEDIATE` transaction.
pub fn delete_peer_received_grant_cleanup_slot(
    conn: &Connection,
    link_id: &str,
    credential_id: &str,
) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "DELETE FROM peer_received_grant_cleanups \
         WHERE link_id = ?1 AND credential_id = ?2",
        params![link_id, credential_id],
    )?;
    Ok(changed > 0)
}

/// Clears all received-grant cleanup rows for `link_id` after full link revocation cleanup has
/// verified deletion of all staged and canonical credentials.
pub fn clear_peer_received_grant_cleanups_for_link(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<usize> {
    let removed = conn.execute(
        "DELETE FROM peer_received_grant_cleanups WHERE link_id = ?1",
        params![link_id],
    )?;
    Ok(removed)
}

/// Applies a received grant revocation fence for `link_id` if `generation` is at least the
/// currently recorded generation (or if no row exists yet), atomically queuing durable runner
/// credential cleanup for the committed slot (or canonical `link_id` fallback).
/// Returns `Ok(true)` when applied and `Ok(false)` when rejected as stale (`generation < existing.generation`).
pub fn mark_peer_received_grant_revoked(
    conn: &Connection,
    link_id: &str,
    generation: i64,
    revoked_at: &str,
) -> anyhow::Result<bool> {
    let existing = get_peer_received_grant(conn, link_id)?;
    if let Some(current) = existing {
        if generation < current.generation {
            return Ok(false);
        }
        let changed = conn.execute(
            "UPDATE peer_received_grants \
             SET generation = ?2, \
                 revoked_at = COALESCE(revoked_at, ?3), \
                 credential_id = NULL, \
                 updated_at = ?3 \
             WHERE link_id = ?1 AND generation <= ?2",
            params![link_id, generation, revoked_at],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        if current.revoked_at.is_none() {
            let slot_id = current.effective_credential_id();
            upsert_peer_received_grant_cleanup(conn, link_id, slot_id, generation, revoked_at)?;
        } else {
            if let Some(ref cid) = current.credential_id {
                if !cid.is_empty() {
                    upsert_peer_received_grant_cleanup(conn, link_id, cid, generation, revoked_at)?;
                }
            }
            let pending = list_peer_received_grant_cleanups_for_link(conn, link_id)?;
            if pending.is_empty() {
                upsert_peer_received_grant_cleanup(conn, link_id, link_id, generation, revoked_at)?;
            } else {
                for item in pending {
                    upsert_peer_received_grant_cleanup(
                        conn,
                        link_id,
                        &item.credential_id,
                        generation,
                        revoked_at,
                    )?;
                }
            }
        }
        Ok(true)
    } else {
        let empty_access = AccessMap::none().to_json()?;
        conn.execute(
            "INSERT INTO peer_received_grants (\
                link_id, grant_id, run_as_user_id, access, created_by, created_at, \
                generation, revoked_at, credential_id, updated_at\
             ) VALUES (?1, '', 0, ?2, '', '', ?3, ?4, NULL, ?4)",
            params![link_id, empty_access, generation, revoked_at],
        )?;
        upsert_peer_received_grant_cleanup(conn, link_id, link_id, generation, revoked_at)?;
        Ok(true)
    }
}

pub fn delete_peer_received_grant(conn: &Connection, link_id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "DELETE FROM peer_received_grants WHERE link_id = ?1",
        params![link_id],
    )?;
    Ok(changed > 0)
}

pub fn get_peer_grant_epoch(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Option<PeerGrantEpoch>> {
    let sql =
        format!("SELECT {PEER_GRANT_EPOCH_COLUMNS} FROM peer_grant_epochs WHERE link_id = ?1");
    Ok(conn
        .query_row(&sql, params![link_id], map_peer_grant_epoch_row)
        .optional()?)
}

pub fn begin_peer_grant_op(
    conn: &Connection,
    link_id: &str,
    op_id: &str,
    updated_at: &str,
) -> anyhow::Result<i64> {
    let next_generation = get_peer_grant_epoch(conn, link_id)?
        .map(|row| row.issuer_generation.saturating_add(1))
        .unwrap_or(1);
    conn.execute(
        "INSERT INTO peer_grant_epochs (link_id, issuer_generation, active_op_id, updated_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(link_id) DO UPDATE SET \
            issuer_generation = excluded.issuer_generation, \
            active_op_id = excluded.active_op_id, \
            updated_at = excluded.updated_at",
        params![link_id, next_generation, op_id, updated_at],
    )?;
    Ok(next_generation)
}

pub fn clear_peer_grant_op_if_matches(
    conn: &Connection,
    link_id: &str,
    generation: i64,
    op_id: &str,
    updated_at: &str,
) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_grant_epochs \
         SET active_op_id = NULL, updated_at = ?4 \
         WHERE link_id = ?1 AND issuer_generation = ?2 AND active_op_id = ?3",
        params![link_id, generation, op_id, updated_at],
    )?;
    Ok(changed > 0)
}

pub fn bump_peer_grant_epoch_for_revoke(
    conn: &Connection,
    link_id: &str,
    updated_at: &str,
) -> anyhow::Result<i64> {
    let next_generation = get_peer_grant_epoch(conn, link_id)?
        .map(|row| row.issuer_generation.saturating_add(1))
        .unwrap_or(1);
    conn.execute(
        "INSERT INTO peer_grant_epochs (link_id, issuer_generation, active_op_id, updated_at) \
         VALUES (?1, ?2, NULL, ?3) \
         ON CONFLICT(link_id) DO UPDATE SET \
            issuer_generation = excluded.issuer_generation, \
            active_op_id = NULL, \
            updated_at = excluded.updated_at",
        params![link_id, next_generation, updated_at],
    )?;
    Ok(next_generation)
}

// ─────────────────────────────────────────────────────────────────────────────
// PairingWindow CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn insert_pairing_window(conn: &Connection, window: &PairingWindow) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO peer_pairing_windows (id, code_hash, expires_at, consumed_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            window.id,
            window.code_hash,
            window.expires_at,
            window.consumed_at,
        ],
    )?;
    Ok(())
}

pub fn get_pairing_window(conn: &Connection, id: &str) -> anyhow::Result<Option<PairingWindow>> {
    let sql = format!("SELECT {PAIRING_WINDOW_COLUMNS} FROM peer_pairing_windows WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], map_pairing_window_row)
        .optional()?)
}

pub fn get_pairing_window_by_code_hash(
    conn: &Connection,
    code_hash: &str,
) -> anyhow::Result<Option<PairingWindow>> {
    let sql =
        format!("SELECT {PAIRING_WINDOW_COLUMNS} FROM peer_pairing_windows WHERE code_hash = ?1");
    Ok(conn
        .query_row(&sql, params![code_hash], map_pairing_window_row)
        .optional()?)
}

pub fn list_pairing_windows(conn: &Connection) -> anyhow::Result<Vec<PairingWindow>> {
    let sql = format!(
        "SELECT {PAIRING_WINDOW_COLUMNS} FROM peer_pairing_windows ORDER BY expires_at ASC, id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_pairing_window_row)?;
    let mut windows = Vec::new();
    for row in rows {
        windows.push(row?);
    }
    Ok(windows)
}

pub fn update_pairing_window(conn: &Connection, window: &PairingWindow) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_pairing_windows SET code_hash = ?2, expires_at = ?3, consumed_at = ?4 WHERE id = ?1",
        params![window.id, window.code_hash, window.expires_at, window.consumed_at],
    )?;
    Ok(changed > 0)
}

pub fn consume_pairing_window(
    conn: &Connection,
    id: &str,
    consumed_at: i64,
) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_pairing_windows SET consumed_at = ?2 \
         WHERE id = ?1 AND consumed_at IS NULL AND expires_at > ?2",
        params![id, consumed_at],
    )?;
    Ok(changed > 0)
}

pub fn delete_pairing_window(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "DELETE FROM peer_pairing_windows WHERE id = ?1",
        params![id],
    )?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// PairingAttempt CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn insert_pairing_attempt(conn: &Connection, attempt: &PairingAttempt) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO peer_pairing_attempts (\
            id, window_id, remote_name, remote_pubkey, remote_tunnel_ip, remote_endpoint, \
            source_ip, status, error_code, expires_at, created_at\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            attempt.id,
            attempt.window_id,
            attempt.remote_name,
            attempt.remote_pubkey,
            attempt.remote_tunnel_ip,
            attempt.remote_endpoint,
            attempt.source_ip,
            attempt.status,
            attempt.error_code,
            attempt.expires_at,
            attempt.created_at,
        ],
    )?;
    Ok(())
}

pub fn get_pairing_attempt(conn: &Connection, id: &str) -> anyhow::Result<Option<PairingAttempt>> {
    let sql = format!("SELECT {PAIRING_ATTEMPT_COLUMNS} FROM peer_pairing_attempts WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], map_pairing_attempt_row)
        .optional()?)
}

pub fn list_pairing_attempts(conn: &Connection) -> anyhow::Result<Vec<PairingAttempt>> {
    let sql = format!(
        "SELECT {PAIRING_ATTEMPT_COLUMNS} FROM peer_pairing_attempts ORDER BY created_at ASC, id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_pairing_attempt_row)?;
    let mut attempts = Vec::new();
    for row in rows {
        attempts.push(row?);
    }
    Ok(attempts)
}

pub fn list_pairing_attempts_for_window(
    conn: &Connection,
    window_id: &str,
) -> anyhow::Result<Vec<PairingAttempt>> {
    let sql = format!(
        "SELECT {PAIRING_ATTEMPT_COLUMNS} FROM peer_pairing_attempts \
         WHERE window_id = ?1 ORDER BY created_at ASC, id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![window_id], map_pairing_attempt_row)?;
    let mut attempts = Vec::new();
    for row in rows {
        attempts.push(row?);
    }
    Ok(attempts)
}

pub fn update_pairing_attempt(conn: &Connection, attempt: &PairingAttempt) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_pairing_attempts SET \
            window_id = ?2, \
            remote_name = ?3, \
            remote_pubkey = ?4, \
            remote_tunnel_ip = ?5, \
            remote_endpoint = ?6, \
            source_ip = ?7, \
            status = ?8, \
            error_code = ?9, \
            expires_at = ?10 \
         WHERE id = ?1",
        params![
            attempt.id,
            attempt.window_id,
            attempt.remote_name,
            attempt.remote_pubkey,
            attempt.remote_tunnel_ip,
            attempt.remote_endpoint,
            attempt.source_ip,
            attempt.status,
            attempt.error_code,
            attempt.expires_at,
        ],
    )?;
    Ok(changed > 0)
}

pub fn delete_pairing_attempt(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "DELETE FROM peer_pairing_attempts WHERE id = ?1",
        params![id],
    )?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerExport CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn insert_peer_export(conn: &Connection, export: &PeerExport) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO peer_exports (id, link_id, path, writable, squash_uid, squash_gid, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            export.id,
            export.link_id,
            export.path,
            export.writable,
            export.squash_uid,
            export.squash_gid,
            export.created_at,
        ],
    )?;
    Ok(())
}

pub fn get_peer_export(conn: &Connection, id: &str) -> anyhow::Result<Option<PeerExport>> {
    let sql = format!("SELECT {PEER_EXPORT_COLUMNS} FROM peer_exports WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], map_peer_export_row)
        .optional()?)
}

pub fn list_peer_exports(conn: &Connection) -> anyhow::Result<Vec<PeerExport>> {
    let sql =
        format!("SELECT {PEER_EXPORT_COLUMNS} FROM peer_exports ORDER BY created_at ASC, id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_peer_export_row)?;
    let mut exports = Vec::new();
    for row in rows {
        exports.push(row?);
    }
    Ok(exports)
}

pub fn list_peer_exports_for_link(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Vec<PeerExport>> {
    let sql = format!(
        "SELECT {PEER_EXPORT_COLUMNS} FROM peer_exports WHERE link_id = ?1 ORDER BY created_at ASC, id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![link_id], map_peer_export_row)?;
    let mut exports = Vec::new();
    for row in rows {
        exports.push(row?);
    }
    Ok(exports)
}

pub fn update_peer_export(conn: &Connection, export: &PeerExport) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_exports SET path = ?2, writable = ?3, squash_uid = ?4, squash_gid = ?5 WHERE id = ?1",
        params![
            export.id,
            export.path,
            export.writable,
            export.squash_uid,
            export.squash_gid,
        ],
    )?;
    Ok(changed > 0)
}

pub fn delete_peer_export(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute("DELETE FROM peer_exports WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerMount CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn insert_peer_mount(conn: &Connection, mount: &PeerMount) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO peer_mounts (\
            id, link_id, remote_path, mount_path, unit_name, writable, purpose, state, last_error\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            mount.id,
            mount.link_id,
            mount.remote_path,
            mount.mount_path,
            mount.unit_name,
            mount.writable,
            mount.purpose,
            mount.state,
            mount.last_error,
        ],
    )?;
    Ok(())
}

pub fn get_peer_mount(conn: &Connection, id: &str) -> anyhow::Result<Option<PeerMount>> {
    let sql = format!("SELECT {PEER_MOUNT_COLUMNS} FROM peer_mounts WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], map_peer_mount_row)
        .optional()?)
}

pub fn get_peer_mount_by_mount_path(
    conn: &Connection,
    mount_path: &str,
) -> anyhow::Result<Option<PeerMount>> {
    let sql = format!("SELECT {PEER_MOUNT_COLUMNS} FROM peer_mounts WHERE mount_path = ?1");
    Ok(conn
        .query_row(&sql, params![mount_path], map_peer_mount_row)
        .optional()?)
}

pub fn list_peer_mounts(conn: &Connection) -> anyhow::Result<Vec<PeerMount>> {
    let sql =
        format!("SELECT {PEER_MOUNT_COLUMNS} FROM peer_mounts ORDER BY mount_path ASC, id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_peer_mount_row)?;
    let mut mounts = Vec::new();
    for row in rows {
        mounts.push(row?);
    }
    Ok(mounts)
}

pub fn list_peer_mounts_for_link(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Vec<PeerMount>> {
    let sql = format!(
        "SELECT {PEER_MOUNT_COLUMNS} FROM peer_mounts WHERE link_id = ?1 ORDER BY mount_path ASC, id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![link_id], map_peer_mount_row)?;
    let mut mounts = Vec::new();
    for row in rows {
        mounts.push(row?);
    }
    Ok(mounts)
}

pub fn update_peer_mount(conn: &Connection, mount: &PeerMount) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE peer_mounts SET \
            remote_path = ?2, \
            mount_path = ?3, \
            unit_name = ?4, \
            writable = ?5, \
            purpose = ?6, \
            state = ?7, \
            last_error = ?8 \
         WHERE id = ?1",
        params![
            mount.id,
            mount.remote_path,
            mount.mount_path,
            mount.unit_name,
            mount.writable,
            mount.purpose,
            mount.state,
            mount.last_error,
        ],
    )?;
    Ok(changed > 0)
}

pub fn delete_peer_mount(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute("DELETE FROM peer_mounts WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// TranscodeWorker CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn upsert_transcode_worker(conn: &Connection, worker: &TranscodeWorker) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO transcode_workers (\
            link_id, enabled, weight, max_jobs, ffmpeg_version, encoders, render_node, \
            parity_ok, parity_error\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
         ON CONFLICT(link_id) DO UPDATE SET \
            enabled = excluded.enabled, \
            weight = excluded.weight, \
            max_jobs = excluded.max_jobs, \
            ffmpeg_version = excluded.ffmpeg_version, \
            encoders = excluded.encoders, \
            render_node = excluded.render_node, \
            parity_ok = excluded.parity_ok, \
            parity_error = excluded.parity_error",
        params![
            worker.link_id,
            worker.enabled,
            worker.weight,
            worker.max_jobs,
            worker.ffmpeg_version,
            worker.encoders,
            worker.render_node,
            worker.parity_ok,
            worker.parity_error,
        ],
    )?;
    Ok(())
}

pub fn get_transcode_worker(
    conn: &Connection,
    link_id: &str,
) -> anyhow::Result<Option<TranscodeWorker>> {
    let sql =
        format!("SELECT {TRANSCODE_WORKER_COLUMNS} FROM transcode_workers WHERE link_id = ?1");
    Ok(conn
        .query_row(&sql, params![link_id], map_transcode_worker_row)
        .optional()?)
}

pub fn list_transcode_workers(conn: &Connection) -> anyhow::Result<Vec<TranscodeWorker>> {
    let sql =
        format!("SELECT {TRANSCODE_WORKER_COLUMNS} FROM transcode_workers ORDER BY link_id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_transcode_worker_row)?;
    let mut workers = Vec::new();
    for row in rows {
        workers.push(row?);
    }
    Ok(workers)
}

pub fn update_transcode_worker(
    conn: &Connection,
    worker: &TranscodeWorker,
) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE transcode_workers SET \
            enabled = ?2, \
            weight = ?3, \
            max_jobs = ?4, \
            ffmpeg_version = ?5, \
            encoders = ?6, \
            render_node = ?7, \
            parity_ok = ?8, \
            parity_error = ?9 \
         WHERE link_id = ?1",
        params![
            worker.link_id,
            worker.enabled,
            worker.weight,
            worker.max_jobs,
            worker.ffmpeg_version,
            worker.encoders,
            worker.render_node,
            worker.parity_ok,
            worker.parity_error,
        ],
    )?;
    Ok(changed > 0)
}

pub fn delete_transcode_worker(conn: &Connection, link_id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "DELETE FROM transcode_workers WHERE link_id = ?1",
        params![link_id],
    )?;
    Ok(changed > 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// TranscodeJob CRUD
// ─────────────────────────────────────────────────────────────────────────────

pub fn insert_transcode_job(conn: &Connection, job: &TranscodeJob) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO transcode_jobs (\
            id, link_id, started_at, ended_at, exit_code, request_id, ran_locally\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            job.id,
            job.link_id,
            job.started_at,
            job.ended_at,
            job.exit_code,
            job.request_id,
            job.ran_locally,
        ],
    )?;
    Ok(())
}

pub fn get_transcode_job(conn: &Connection, id: &str) -> anyhow::Result<Option<TranscodeJob>> {
    let sql = format!("SELECT {TRANSCODE_JOB_COLUMNS} FROM transcode_jobs WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], map_transcode_job_row)
        .optional()?)
}

pub fn list_transcode_jobs(conn: &Connection, limit: usize) -> anyhow::Result<Vec<TranscodeJob>> {
    let sql = format!(
        "SELECT {TRANSCODE_JOB_COLUMNS} FROM transcode_jobs ORDER BY started_at DESC, id DESC LIMIT ?1"
    );
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![limit_i64], map_transcode_job_row)?;
    let mut jobs = Vec::new();
    for row in rows {
        jobs.push(row?);
    }
    Ok(jobs)
}

pub fn list_transcode_jobs_for_link(
    conn: &Connection,
    link_id: &str,
    limit: usize,
) -> anyhow::Result<Vec<TranscodeJob>> {
    let sql = format!(
        "SELECT {TRANSCODE_JOB_COLUMNS} FROM transcode_jobs \
         WHERE link_id = ?1 ORDER BY started_at DESC, id DESC LIMIT ?2"
    );
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![link_id, limit_i64], map_transcode_job_row)?;
    let mut jobs = Vec::new();
    for row in rows {
        jobs.push(row?);
    }
    Ok(jobs)
}

pub fn update_transcode_job(conn: &Connection, job: &TranscodeJob) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "UPDATE transcode_jobs SET \
            link_id = ?2, \
            ended_at = ?3, \
            exit_code = ?4, \
            request_id = ?5, \
            ran_locally = ?6 \
         WHERE id = ?1",
        params![
            job.id,
            job.link_id,
            job.ended_at,
            job.exit_code,
            job.request_id,
            job.ran_locally,
        ],
    )?;
    Ok(changed > 0)
}

pub fn delete_transcode_job(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let changed = conn.execute("DELETE FROM transcode_jobs WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

pub fn prune_transcode_jobs_before(
    conn: &Connection,
    cutoff_started_at: &str,
) -> anyhow::Result<usize> {
    let removed = conn.execute(
        "DELETE FROM transcode_jobs WHERE started_at < ?1",
        params![cutoff_started_at],
    )?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::migrate;

    fn open_migrated_in_memory_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL
             );
             CREATE TABLE schema_versions (
                 version INTEGER PRIMARY KEY,
                 description TEXT NOT NULL,
                 applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
             );",
        )
        .expect("seed base tables");
        migrate(
            &conn,
            25,
            "Peer clustering",
            PEER_CLUSTERING_MIGRATION_25_SQL,
        )
        .expect("apply migration 25");
        migrate(
            &conn,
            27,
            "Peer grant direction metadata",
            PEER_GRANT_METADATA_MIGRATION_27_SQL,
        )
        .expect("apply migration 27");
        conn
    }

    fn sample_link(id: &str, name: &str, pubkey: &str, tunnel_ip: &str) -> PeerLink {
        PeerLink {
            id: id.to_string(),
            name: name.to_string(),
            wg_pubkey: pubkey.to_string(),
            tunnel_ip: tunnel_ip.to_string(),
            endpoint: "198.51.100.10".to_string(),
            wg_port: 51821,
            state: "pending".to_string(),
            peer_version: Some("4.0.0".to_string()),
            peer_protocol: Some(1),
            capabilities: Some(r#"["links"]"#.to_string()),
            rtt_ms: Some(1.75),
            last_ok_at: Some("2026-11-23T05:00:00Z".to_string()),
            last_error: None,
            consecutive_failures: 0,
            inbound_token_hash: Some("sha256-link-secret-digest-alpha".to_string()),
            pending_attempt_id: Some("attempt-1".to_string()),
            pending_expires_at: Some(1_800_000_600),
            created_at: "2026-11-23T04:55:00Z".to_string(),
            updated_at: "2026-11-23T05:00:00Z".to_string(),
        }
    }

    #[test]
    fn access_map_json_presets_defaults_and_fail_closed_parsing() {
        let default_map = AccessMap::default();
        assert_eq!(default_map, AccessMap::none());
        assert!(!default_map.has_any_access());
        assert_eq!(default_map.get("services"), AccessLevel::None);
        assert_eq!(default_map.get("unknown_area"), AccessLevel::None);

        let ro = AccessMap::read_only_all();
        assert!(ro.has_any_access());
        assert!(ro.services.allows_read());
        assert!(!ro.services.allows_write());
        assert_eq!(ro.services.as_str(), "read");
        let ro_json = ro.to_json().unwrap();
        assert_eq!(AccessMap::from_json(&ro_json).unwrap(), ro);

        let rw = AccessMap::read_write_all();
        assert!(rw.transcoding.allows_read());
        assert!(rw.transcoding.allows_write());
        assert_eq!(rw.transcoding.as_str(), "write");
        let rw_json = rw.to_json().unwrap();
        assert_eq!(AccessMap::from_json(&rw_json).unwrap(), rw);

        // Partial JSON defaults omitted areas to none (fail closed); unknown fields are rejected
        let partial = AccessMap::from_json(r#"{"services":"read","transcoding":"write"}"#).unwrap();
        assert_eq!(partial.services, AccessLevel::Read);
        assert_eq!(partial.transcoding, AccessLevel::Write);
        assert_eq!(partial.marketplace, AccessLevel::None);
        assert_eq!(partial.settings, AccessLevel::None);
        assert_eq!(partial.files, AccessLevel::None);
        assert_eq!(partial.users, AccessLevel::None);
        assert_eq!(partial.network, AccessLevel::None);
        assert_eq!(partial.updates, AccessLevel::None);
        assert!(AccessMap::from_json(
            r#"{"services":"read","transcoding":"write","future_area":"write"}"#,
        )
        .is_err());

        let mut mutable = AccessMap::none();
        assert!(mutable.set("files", AccessLevel::Write));
        assert_eq!(mutable.get("files"), AccessLevel::Write);
        assert!(!mutable.set("not_a_real_area", AccessLevel::Write));

        // Invalid access level string must fail deserialization
        assert!(AccessMap::from_json(r#"{"services":"admin"}"#).is_err());
        assert!(AccessMap::from_json("not-json").is_err());
    }

    #[test]
    fn peer_identity_singleton_crud() {
        let conn = open_migrated_in_memory_db();
        assert_eq!(get_peer_identity(&conn).unwrap(), None);
        assert!(!delete_peer_identity(&conn).unwrap());

        let first = PeerIdentity {
            wg_pubkey: "pubkey-server-a".to_string(),
            tunnel_ip: "10.231.0.1".to_string(),
            wg_port: 51821,
            created_at: "2026-11-23T05:00:00Z".to_string(),
        };
        upsert_peer_identity(&conn, &first).unwrap();
        assert_eq!(get_peer_identity(&conn).unwrap(), Some(first));

        let updated = PeerIdentity {
            wg_pubkey: "pubkey-server-a-v2".to_string(),
            tunnel_ip: "10.231.0.2".to_string(),
            wg_port: 51822,
            created_at: "2026-11-23T05:10:00Z".to_string(),
        };
        upsert_peer_identity(&conn, &updated).unwrap();
        assert_eq!(get_peer_identity(&conn).unwrap(), Some(updated));

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM peer_identity", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        assert!(conn
            .execute(
                "INSERT INTO peer_identity (id, wg_pubkey, tunnel_ip, wg_port, created_at)
                 VALUES (2, 'fixture-key', '10.231.0.3', 51821, '2026-11-23T05:00:00Z')",
                [],
            )
            .is_err());

        assert!(delete_peer_identity(&conn).unwrap());
        assert_eq!(get_peer_identity(&conn).unwrap(), None);
    }

    #[test]
    fn peer_link_crud_lookups_constraints_and_token_clearing() {
        let conn = open_migrated_in_memory_db();
        assert_eq!(get_peer_link(&conn, "missing").unwrap(), None);
        assert!(!delete_peer_link(&conn, "missing").unwrap());
        assert!(
            !clear_peer_link_inbound_token_hash(&conn, "missing", "2026-11-23T05:00:00Z").unwrap()
        );

        let mut link = sample_link("link-1", "media-2", "pk-media-2", "10.231.0.2");
        insert_peer_link(&conn, &link).unwrap();

        assert_eq!(get_peer_link(&conn, "link-1").unwrap(), Some(link.clone()));
        assert_eq!(
            get_peer_link_by_name(&conn, "media-2").unwrap(),
            Some(link.clone())
        );
        assert_eq!(
            get_peer_link_by_tunnel_ip(&conn, "10.231.0.2").unwrap(),
            Some(link.clone())
        );
        assert_eq!(
            get_peer_link_by_pubkey(&conn, "pk-media-2").unwrap(),
            Some(link.clone())
        );

        // Unique constraints on name, wg_pubkey, and tunnel_ip must be enforced
        let dup_name = sample_link("link-dup-1", "media-2", "pk-other-1", "10.231.0.9");
        assert!(insert_peer_link(&conn, &dup_name).is_err());
        let dup_pubkey = sample_link("link-dup-2", "other-2", "pk-media-2", "10.231.0.10");
        assert!(insert_peer_link(&conn, &dup_pubkey).is_err());
        let dup_ip = sample_link("link-dup-3", "other-3", "pk-other-3", "10.231.0.2");
        assert!(insert_peer_link(&conn, &dup_ip).is_err());

        // Update link to active state and clear pending attempt fields
        link.state = "active".to_string();
        link.pending_attempt_id = None;
        link.pending_expires_at = None;
        link.consecutive_failures = 1;
        link.last_error = Some("transient timeout".to_string());
        link.updated_at = "2026-11-23T05:05:00Z".to_string();
        assert!(update_peer_link(&conn, &link).unwrap());
        assert_eq!(get_peer_link(&conn, "link-1").unwrap(), Some(link.clone()));

        // Updating a non-existent link returns Ok(false)
        let missing = sample_link("link-missing", "ghost", "pk-ghost", "10.231.0.99");
        assert!(!update_peer_link(&conn, &missing).unwrap());

        // Clear inbound token digest on revocation
        assert!(
            clear_peer_link_inbound_token_hash(&conn, "link-1", "2026-11-23T05:06:00Z").unwrap()
        );
        let cleared = get_peer_link(&conn, "link-1").unwrap().unwrap();
        assert_eq!(cleared.inbound_token_hash, None);
        assert_eq!(cleared.updated_at, "2026-11-23T05:06:00Z");

        assert_eq!(list_peer_links(&conn).unwrap().len(), 1);
        assert!(delete_peer_link(&conn, "link-1").unwrap());
        assert_eq!(get_peer_link(&conn, "link-1").unwrap(), None);
    }

    #[test]
    fn peer_grant_crud_access_json_and_revocation_clears_token_hash() {
        let conn = open_migrated_in_memory_db();
        let link = sample_link("link-1", "media-2", "pk-media-2", "10.231.0.2");
        insert_peer_link(&conn, &link).unwrap();

        let mut access = AccessMap::none();
        access.services = AccessLevel::Read;
        access.transcoding = AccessLevel::Write;

        let mut grant = PeerGrant {
            id: "grant-1".to_string(),
            link_id: "link-1".to_string(),
            run_as_user_id: 42,
            access,
            token_hash: Some("sha256-grant-secret-digest".to_string()),
            created_by: "alice".to_string(),
            created_at: "2026-11-23T05:00:00Z".to_string(),
            revoked_at: None,
        };
        insert_peer_grant(&conn, &grant).unwrap();

        let loaded = get_peer_grant(&conn, "grant-1").unwrap().unwrap();
        assert_eq!(loaded, grant);
        assert_eq!(list_peer_grants(&conn).unwrap(), vec![grant.clone()]);
        assert_eq!(
            list_peer_grants_for_link(&conn, "link-1").unwrap(),
            vec![grant.clone()]
        );
        assert!(list_peer_grants_for_link(&conn, "missing")
            .unwrap()
            .is_empty());
        assert_eq!(
            get_active_peer_grant_for_link(&conn, "link-1").unwrap(),
            Some(grant.clone())
        );

        // Verify stored access column is valid JSON
        let raw_access: String = conn
            .query_row(
                "SELECT access FROM peer_grants WHERE id = 'grant-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let parsed_val: serde_json::Value = serde_json::from_str(&raw_access).unwrap();
        assert_eq!(parsed_val["services"], "read");
        assert_eq!(parsed_val["transcoding"], "write");
        assert_eq!(parsed_val["users"], "none");

        // Update grant access
        grant.access = AccessMap::read_write_all();
        assert!(update_peer_grant(&conn, &grant).unwrap());
        assert_eq!(
            get_peer_grant(&conn, "grant-1").unwrap().unwrap().access,
            AccessMap::read_write_all()
        );

        // Clear token hash directly
        assert!(clear_peer_grant_token_hash(&conn, "grant-1").unwrap());
        assert_eq!(
            get_peer_grant(&conn, "grant-1")
                .unwrap()
                .unwrap()
                .token_hash,
            None
        );

        // Restore token hash, then revoke — revocation must clear token_hash and set revoked_at
        grant.token_hash = Some("sha256-grant-secret-digest-2".to_string());
        assert!(update_peer_grant(&conn, &grant).unwrap());
        assert!(revoke_peer_grant(&conn, "grant-1", "2026-11-23T05:30:00Z").unwrap());
        let revoked = get_peer_grant(&conn, "grant-1").unwrap().unwrap();
        assert_eq!(revoked.token_hash, None);
        assert_eq!(revoked.revoked_at.as_deref(), Some("2026-11-23T05:30:00Z"));
        assert_eq!(
            get_active_peer_grant_for_link(&conn, "link-1").unwrap(),
            None
        );

        // Second revoke is a no-op returning Ok(false) and preserves original revoked_at
        assert!(!revoke_peer_grant(&conn, "grant-1", "2026-11-23T06:00:00Z").unwrap());
        assert_eq!(
            get_peer_grant(&conn, "grant-1")
                .unwrap()
                .unwrap()
                .revoked_at
                .as_deref(),
            Some("2026-11-23T05:30:00Z")
        );

        // Corrupt access JSON in DB fails read cleanly instead of silently succeeding
        conn.execute(
            "UPDATE peer_grants SET access = '{bad-json' WHERE id = 'grant-1'",
            [],
        )
        .unwrap();
        assert!(get_peer_grant(&conn, "grant-1").is_err());

        assert!(delete_peer_grant(&conn, "grant-1").unwrap());
        assert!(!delete_peer_grant(&conn, "grant-1").unwrap());
    }

    #[test]
    fn pairing_window_and_attempt_crud_and_atomic_consumption() {
        let conn = open_migrated_in_memory_db();
        let window = PairingWindow {
            id: "win-1".to_string(),
            code_hash: "sha256-pairing-code-digest".to_string(),
            expires_at: 2_000_000_000,
            consumed_at: None,
        };
        insert_pairing_window(&conn, &window).unwrap();
        assert_eq!(
            get_pairing_window(&conn, "win-1").unwrap(),
            Some(window.clone())
        );
        assert_eq!(
            get_pairing_window_by_code_hash(&conn, "sha256-pairing-code-digest").unwrap(),
            Some(window.clone())
        );

        // Unique code_hash enforced
        let dup_code = PairingWindow {
            id: "win-2".to_string(),
            code_hash: "sha256-pairing-code-digest".to_string(),
            expires_at: 2_000_000_100,
            consumed_at: None,
        };
        assert!(insert_pairing_window(&conn, &dup_code).is_err());

        // Expired consumption fails
        assert!(!consume_pairing_window(&conn, "win-1", 2_000_000_000).unwrap());
        // Valid consumption succeeds once and rejects replay
        assert!(consume_pairing_window(&conn, "win-1", 1_999_999_900).unwrap());
        assert!(!consume_pairing_window(&conn, "win-1", 1_999_999_901).unwrap());
        assert_eq!(
            get_pairing_window(&conn, "win-1")
                .unwrap()
                .unwrap()
                .consumed_at,
            Some(1_999_999_900)
        );
        assert_eq!(list_pairing_windows(&conn).unwrap().len(), 1);
        let mut updated_window = get_pairing_window(&conn, "win-1").unwrap().unwrap();
        updated_window.expires_at += 60;
        assert!(update_pairing_window(&conn, &updated_window).unwrap());
        assert_eq!(
            get_pairing_window(&conn, "win-1").unwrap(),
            Some(updated_window)
        );

        let mut attempt = PairingAttempt {
            id: "att-1".to_string(),
            window_id: Some("win-1".to_string()),
            remote_name: Some("seedbox-1".to_string()),
            remote_pubkey: Some("pk-seedbox-1".to_string()),
            remote_tunnel_ip: Some("10.231.0.1".to_string()),
            remote_endpoint: Some("198.51.100.1".to_string()),
            source_ip: Some("198.51.100.1".to_string()),
            status: "pending".to_string(),
            error_code: None,
            expires_at: 2_000_000_000,
            created_at: "2026-11-23T05:00:00Z".to_string(),
        };
        insert_pairing_attempt(&conn, &attempt).unwrap();
        assert_eq!(
            get_pairing_attempt(&conn, "att-1").unwrap(),
            Some(attempt.clone())
        );
        assert_eq!(
            list_pairing_attempts_for_window(&conn, "win-1").unwrap(),
            vec![attempt.clone()]
        );

        attempt.status = "failed".to_string();
        attempt.error_code = Some("HANDSHAKE_TIMEOUT".to_string());
        assert!(update_pairing_attempt(&conn, &attempt).unwrap());
        assert_eq!(
            get_pairing_attempt(&conn, "att-1").unwrap(),
            Some(attempt.clone())
        );
        assert_eq!(list_pairing_attempts(&conn).unwrap().len(), 1);

        assert!(delete_pairing_attempt(&conn, "att-1").unwrap());
        assert_eq!(get_pairing_attempt(&conn, "att-1").unwrap(), None);
        assert!(delete_pairing_window(&conn, "win-1").unwrap());
        assert_eq!(get_pairing_window(&conn, "win-1").unwrap(), None);
    }

    #[test]
    fn peer_export_mount_worker_and_job_crud() {
        let conn = open_migrated_in_memory_db();
        let link = sample_link("link-1", "media-2", "pk-media-2", "10.231.0.2");
        insert_peer_link(&conn, &link).unwrap();

        // PeerExport
        let mut export = PeerExport {
            id: "exp-1".to_string(),
            link_id: "link-1".to_string(),
            path: "/srv/media/movies".to_string(),
            writable: false,
            squash_uid: Some(1000),
            squash_gid: Some(1000),
            created_at: "2026-11-23T05:00:00Z".to_string(),
        };
        insert_peer_export(&conn, &export).unwrap();
        assert_eq!(
            get_peer_export(&conn, "exp-1").unwrap(),
            Some(export.clone())
        );
        export.writable = true;
        export.squash_uid = Some(1001);
        assert!(update_peer_export(&conn, &export).unwrap());
        assert_eq!(
            list_peer_exports_for_link(&conn, "link-1").unwrap(),
            vec![export.clone()]
        );
        assert_eq!(list_peer_exports(&conn).unwrap().len(), 1);

        // PeerMount
        let mut mount = PeerMount {
            id: "mnt-1".to_string(),
            link_id: "link-1".to_string(),
            remote_path: "/srv/media/movies".to_string(),
            mount_path: "/mnt/af-peers/media-2/movies".to_string(),
            unit_name: "mnt-af\\x2dpeers-media\\x2d2-movies.mount".to_string(),
            writable: false,
            purpose: "media".to_string(),
            state: "mounted".to_string(),
            last_error: None,
        };
        insert_peer_mount(&conn, &mount).unwrap();
        let duplicate_mount = PeerMount {
            id: "mnt-duplicate".to_string(),
            ..mount.clone()
        };
        assert!(insert_peer_mount(&conn, &duplicate_mount).is_err());
        assert_eq!(
            get_peer_mount_by_mount_path(&conn, "/mnt/af-peers/media-2/movies").unwrap(),
            Some(mount.clone())
        );
        mount.state = "stopped".to_string();
        mount.last_error = Some("link down".to_string());
        assert!(update_peer_mount(&conn, &mount).unwrap());
        assert_eq!(get_peer_mount(&conn, "mnt-1").unwrap(), Some(mount.clone()));
        assert_eq!(
            list_peer_mounts_for_link(&conn, "link-1").unwrap(),
            vec![mount.clone()]
        );
        assert_eq!(list_peer_mounts(&conn).unwrap().len(), 1);

        // TranscodeWorker
        let mut worker = TranscodeWorker {
            link_id: "link-1".to_string(),
            enabled: true,
            weight: 2,
            max_jobs: 4,
            ffmpeg_version: Some("8.1.3-1-trixie".to_string()),
            encoders: Some(r#"["h264_vaapi","hevc_vaapi"]"#.to_string()),
            render_node: Some("/dev/dri/renderD128".to_string()),
            parity_ok: false,
            parity_error: Some("pending parity check".to_string()),
        };
        upsert_transcode_worker(&conn, &worker).unwrap();
        assert_eq!(
            get_transcode_worker(&conn, "link-1").unwrap(),
            Some(worker.clone())
        );
        worker.parity_ok = true;
        worker.parity_error = None;
        assert!(update_transcode_worker(&conn, &worker).unwrap());
        assert_eq!(list_transcode_workers(&conn).unwrap(), vec![worker.clone()]);

        // TranscodeJob (remote + local)
        let mut remote_job = TranscodeJob {
            id: "job-1".to_string(),
            link_id: Some("link-1".to_string()),
            started_at: "2026-11-23T05:00:00Z".to_string(),
            ended_at: None,
            exit_code: None,
            request_id: Some("req-1".to_string()),
            ran_locally: false,
        };
        let local_job = TranscodeJob {
            id: "job-2".to_string(),
            link_id: None,
            started_at: "2026-11-23T05:05:00Z".to_string(),
            ended_at: Some("2026-11-23T05:06:00Z".to_string()),
            exit_code: Some(0),
            request_id: Some("req-2".to_string()),
            ran_locally: true,
        };
        insert_transcode_job(&conn, &remote_job).unwrap();
        insert_transcode_job(&conn, &local_job).unwrap();

        remote_job.ended_at = Some("2026-11-23T05:02:00Z".to_string());
        remote_job.exit_code = Some(0);
        assert!(update_transcode_job(&conn, &remote_job).unwrap());
        assert_eq!(
            get_transcode_job(&conn, "job-1").unwrap(),
            Some(remote_job.clone())
        );
        assert_eq!(
            list_transcode_jobs(&conn, 10).unwrap(),
            vec![local_job.clone(), remote_job.clone()]
        );
        assert_eq!(
            list_transcode_jobs_for_link(&conn, "link-1", 10).unwrap(),
            vec![remote_job]
        );

        let pruned = prune_transcode_jobs_before(&conn, "2026-11-23T05:01:00Z").unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(get_transcode_job(&conn, "job-1").unwrap(), None);
        assert_eq!(get_transcode_job(&conn, "job-2").unwrap(), Some(local_job));

        assert!(delete_transcode_job(&conn, "job-2").unwrap());
        assert!(delete_transcode_worker(&conn, "link-1").unwrap());
        assert!(delete_peer_mount(&conn, "mnt-1").unwrap());
        assert!(delete_peer_export(&conn, "exp-1").unwrap());
    }

    #[test]
    fn foreign_key_enforcement_and_cascading_link_deletion() {
        let conn = open_migrated_in_memory_db();

        // Missing link_id must fail foreign-key check for all 4 dependent tables
        let orphan_grant = PeerGrant {
            id: "g-orphan".to_string(),
            link_id: "no-such-link".to_string(),
            run_as_user_id: 1,
            access: AccessMap::none(),
            token_hash: None,
            created_by: "admin".to_string(),
            created_at: "2026-11-23T05:00:00Z".to_string(),
            revoked_at: None,
        };
        assert!(insert_peer_grant(&conn, &orphan_grant).is_err());

        let orphan_export = PeerExport {
            id: "e-orphan".to_string(),
            link_id: "no-such-link".to_string(),
            path: "/srv/media".to_string(),
            writable: false,
            squash_uid: None,
            squash_gid: None,
            created_at: "2026-11-23T05:00:00Z".to_string(),
        };
        assert!(insert_peer_export(&conn, &orphan_export).is_err());

        let orphan_mount = PeerMount {
            id: "m-orphan".to_string(),
            link_id: "no-such-link".to_string(),
            remote_path: "/srv/media".to_string(),
            mount_path: "/mnt/af-peers/orphan/media".to_string(),
            unit_name: "mnt-af\\x2dpeers-orphan-media.mount".to_string(),
            writable: false,
            purpose: "media".to_string(),
            state: "stopped".to_string(),
            last_error: None,
        };
        assert!(insert_peer_mount(&conn, &orphan_mount).is_err());

        let orphan_worker = TranscodeWorker {
            link_id: "no-such-link".to_string(),
            enabled: false,
            weight: 1,
            max_jobs: 2,
            ffmpeg_version: None,
            encoders: None,
            render_node: None,
            parity_ok: false,
            parity_error: None,
        };
        assert!(upsert_transcode_worker(&conn, &orphan_worker).is_err());

        // Seed two links with dependent rows in all four child tables + a historical transcode job
        let link_a = sample_link("link-a", "peer-a", "pk-a", "10.231.0.2");
        let link_b = sample_link("link-b", "peer-b", "pk-b", "10.231.0.3");
        insert_peer_link(&conn, &link_a).unwrap();
        insert_peer_link(&conn, &link_b).unwrap();

        for (suffix, link_id) in [("a", "link-a"), ("b", "link-b")] {
            insert_peer_grant(
                &conn,
                &PeerGrant {
                    id: format!("grant-{suffix}"),
                    link_id: link_id.to_string(),
                    run_as_user_id: 10,
                    access: AccessMap::read_only_all(),
                    token_hash: Some(format!("hash-{suffix}")),
                    created_by: "admin".to_string(),
                    created_at: "2026-11-23T05:00:00Z".to_string(),
                    revoked_at: None,
                },
            )
            .unwrap();
            insert_peer_export(
                &conn,
                &PeerExport {
                    id: format!("export-{suffix}"),
                    link_id: link_id.to_string(),
                    path: format!("/srv/media/{suffix}"),
                    writable: false,
                    squash_uid: None,
                    squash_gid: None,
                    created_at: "2026-11-23T05:00:00Z".to_string(),
                },
            )
            .unwrap();
            insert_peer_mount(
                &conn,
                &PeerMount {
                    id: format!("mount-{suffix}"),
                    link_id: link_id.to_string(),
                    remote_path: format!("/srv/media/{suffix}"),
                    mount_path: format!("/mnt/af-peers/peer-{suffix}/media"),
                    unit_name: format!("mnt-af\\x2dpeers-peer\\x2d{suffix}-media.mount"),
                    writable: false,
                    purpose: "media".to_string(),
                    state: "mounted".to_string(),
                    last_error: None,
                },
            )
            .unwrap();
            upsert_transcode_worker(
                &conn,
                &TranscodeWorker {
                    link_id: link_id.to_string(),
                    enabled: true,
                    weight: 1,
                    max_jobs: 2,
                    ffmpeg_version: Some("8.1.3-1-trixie".to_string()),
                    encoders: None,
                    render_node: None,
                    parity_ok: true,
                    parity_error: None,
                },
            )
            .unwrap();
            insert_transcode_job(
                &conn,
                &TranscodeJob {
                    id: format!("job-{suffix}"),
                    link_id: Some(link_id.to_string()),
                    started_at: "2026-11-23T05:00:00Z".to_string(),
                    ended_at: Some("2026-11-23T05:01:00Z".to_string()),
                    exit_code: Some(0),
                    request_id: Some(format!("req-{suffix}")),
                    ran_locally: false,
                },
            )
            .unwrap();
        }

        // Deleting link-a cascades all dependent rows for link-a without affecting link-b or transcode_jobs
        assert!(delete_peer_link(&conn, "link-a").unwrap());

        assert_eq!(get_peer_grant(&conn, "grant-a").unwrap(), None);
        assert_eq!(get_peer_export(&conn, "export-a").unwrap(), None);
        assert_eq!(get_peer_mount(&conn, "mount-a").unwrap(), None);
        assert_eq!(get_transcode_worker(&conn, "link-a").unwrap(), None);

        // Historical job row survives link deletion
        assert!(get_transcode_job(&conn, "job-a").unwrap().is_some());

        // Peer B rows remain untouched
        assert!(get_peer_link(&conn, "link-b").unwrap().is_some());
        assert!(get_peer_grant(&conn, "grant-b").unwrap().is_some());
        assert!(get_peer_export(&conn, "export-b").unwrap().is_some());
        assert!(get_peer_mount(&conn, "mount-b").unwrap().is_some());
        assert!(get_transcode_worker(&conn, "link-b").unwrap().is_some());
        assert!(get_transcode_job(&conn, "job-b").unwrap().is_some());
    }

    #[test]
    fn digest_bearing_structs_redact_digests_in_debug_and_serde_output() {
        let link_digest = "deadbeef0123456789linkdigest";
        let grant_digest = "cafebabe9876543210grantdigest";
        let code_digest = "feedface5566778899codedigest";

        let mut link = sample_link("link-redacted", "media-2", "pk-redacted", "10.231.0.20");
        link.inbound_token_hash = Some(link_digest.to_string());
        let link_debug = format!("{link:?}");
        let link_json = serde_json::to_string(&link).unwrap();
        assert!(!link_debug.contains(link_digest));
        assert!(link_debug.contains(REDACTED_DIGEST));
        assert!(!link_json.contains(link_digest));
        assert!(!link_json.contains("inbound_token_hash"));

        link.inbound_token_hash = None;
        let cleared_link_debug = format!("{link:?}");
        assert!(cleared_link_debug.contains("inbound_token_hash: None"));

        let grant = PeerGrant {
            id: "grant-redacted".to_string(),
            link_id: "link-redacted".to_string(),
            run_as_user_id: 7,
            access: AccessMap::read_only_all(),
            token_hash: Some(grant_digest.to_string()),
            created_by: "alice".to_string(),
            created_at: "2026-11-23T05:00:00Z".to_string(),
            revoked_at: None,
        };
        let grant_debug = format!("{grant:?}");
        let grant_json = serde_json::to_string(&grant).unwrap();
        assert!(!grant_debug.contains(grant_digest));
        assert!(grant_debug.contains(REDACTED_DIGEST));
        assert!(!grant_json.contains(grant_digest));
        assert!(!grant_json.contains("token_hash"));

        let window = PairingWindow {
            id: "win-redacted".to_string(),
            code_hash: code_digest.to_string(),
            expires_at: 2_000_000_000,
            consumed_at: None,
        };
        let window_debug = format!("{window:?}");
        let window_json = serde_json::to_string(&window).unwrap();
        assert!(!window_debug.contains(code_digest));
        assert!(window_debug.contains(REDACTED_DIGEST));
        assert!(!window_json.contains(code_digest));
        assert!(!window_json.contains("code_hash"));
    }

    #[test]
    fn peer_received_grant_and_epoch_fencing_and_cascade() {
        let conn = open_migrated_in_memory_db();
        let link = sample_link("link-1", "media-2", "pk-media-2", "10.231.0.2");
        insert_peer_link(&conn, &link).unwrap();

        // Missing token_hash on peer_grants is not treated as an active grant
        let incomplete_grant = PeerGrant {
            id: "grant-incomplete".to_string(),
            link_id: "link-1".to_string(),
            run_as_user_id: 9,
            access: AccessMap::read_only_all(),
            token_hash: None,
            created_by: "alice".to_string(),
            created_at: "2026-11-23T05:00:00Z".to_string(),
            revoked_at: None,
        };
        insert_peer_grant(&conn, &incomplete_grant).unwrap();
        assert_eq!(
            get_active_peer_grant_for_link(&conn, "link-1").unwrap(),
            None
        );

        let complete_grant = PeerGrant {
            id: "grant-live".to_string(),
            link_id: "link-1".to_string(),
            run_as_user_id: 9,
            access: AccessMap::read_only_all(),
            token_hash: Some("sha256:live-digest".to_string()),
            created_by: "alice".to_string(),
            created_at: "2026-11-23T05:01:00Z".to_string(),
            revoked_at: None,
        };
        insert_peer_grant(&conn, &complete_grant).unwrap();
        assert_eq!(
            get_active_peer_grant_for_link(&conn, "link-1").unwrap(),
            Some(complete_grant.clone())
        );

        let revoked =
            revoke_active_peer_grants_for_link(&conn, "link-1", "2026-11-23T05:05:00Z").unwrap();
        assert_eq!(revoked.len(), 2);
        assert_eq!(
            get_active_peer_grant_for_link(&conn, "link-1").unwrap(),
            None
        );

        // Epoch fencing
        let gen1 = begin_peer_grant_op(&conn, "link-1", "op-1", "2026-11-23T05:10:00Z").unwrap();
        assert_eq!(gen1, 1);
        let gen2 = begin_peer_grant_op(&conn, "link-1", "op-2", "2026-11-23T05:10:01Z").unwrap();
        assert_eq!(gen2, 2);
        assert!(!clear_peer_grant_op_if_matches(
            &conn,
            "link-1",
            gen1,
            "op-1",
            "2026-11-23T05:10:02Z"
        )
        .unwrap());
        assert!(clear_peer_grant_op_if_matches(
            &conn,
            "link-1",
            gen2,
            "op-2",
            "2026-11-23T05:10:02Z"
        )
        .unwrap());
        let gen3 =
            bump_peer_grant_epoch_for_revoke(&conn, "link-1", "2026-11-23T05:10:03Z").unwrap();
        assert_eq!(gen3, 3);
        let epoch = get_peer_grant_epoch(&conn, "link-1").unwrap().unwrap();
        assert_eq!(epoch.issuer_generation, 3);
        assert_eq!(epoch.active_op_id, None);

        // Received grants, staged credential slots, durable cleanup queue, & monotonic tombstones
        let mut received = PeerReceivedGrant {
            link_id: "link-1".to_string(),
            grant_id: "remote-grant-1".to_string(),
            run_as_user_id: 21,
            access: AccessMap::read_write_all(),
            created_by: "remote-admin".to_string(),
            created_at: "2026-11-23T05:11:00Z".to_string(),
            generation: 2,
            revoked_at: None,
            credential_id: Some("grant-slot-gen2".to_string()),
            updated_at: "2026-11-23T05:11:00Z".to_string(),
        };
        assert_eq!(received.effective_credential_id(), "grant-slot-gen2");
        upsert_peer_received_grant(&conn, &received).unwrap();
        assert_eq!(
            get_active_peer_received_grant_for_link(&conn, "link-1").unwrap(),
            Some(received.clone())
        );
        assert_eq!(list_peer_received_grants(&conn).unwrap().len(), 1);
        assert!(list_peer_received_grant_cleanups(&conn).unwrap().is_empty());

        // Stale revocation (gen 1 < 2) must be rejected without queuing cleanup
        assert!(
            !mark_peer_received_grant_revoked(&conn, "link-1", 1, "2026-11-23T05:12:00Z").unwrap()
        );
        assert!(get_active_peer_received_grant_for_link(&conn, "link-1")
            .unwrap()
            .is_some());
        assert!(list_peer_received_grant_cleanups(&conn).unwrap().is_empty());

        // Fresh revocation (gen 3 >= 2) marks revoked, preserves generation fence, and queues
        // durable cleanup for the exact committed slot (`grant-slot-gen2`).
        assert!(
            mark_peer_received_grant_revoked(&conn, "link-1", 3, "2026-11-23T05:13:00Z").unwrap()
        );
        assert_eq!(
            get_active_peer_received_grant_for_link(&conn, "link-1").unwrap(),
            None
        );
        let tombstone = get_peer_received_grant(&conn, "link-1").unwrap().unwrap();
        assert_eq!(tombstone.generation, 3);
        assert_eq!(
            tombstone.revoked_at.as_deref(),
            Some("2026-11-23T05:13:00Z")
        );
        assert_eq!(tombstone.credential_id, None);
        let cleanups = list_peer_received_grant_cleanups_for_link(&conn, "link-1").unwrap();
        assert_eq!(cleanups.len(), 1);
        assert_eq!(cleanups[0].credential_id, "grant-slot-gen2");
        assert_eq!(cleanups[0].generation, 3);

        // Guarded cleanup deletion rejects mismatched generation or slot ID
        assert!(!delete_peer_received_grant_cleanup_if_matches(
            &conn,
            "link-1",
            "grant-slot-gen2",
            2
        )
        .unwrap());
        assert!(
            get_peer_received_grant_cleanup(&conn, "link-1", "grant-slot-gen2")
                .unwrap()
                .is_some()
        );

        // Matching `(link_id, credential_id, generation)` removes the cleanup row
        assert!(delete_peer_received_grant_cleanup_if_matches(
            &conn,
            "link-1",
            "grant-slot-gen2",
            3
        )
        .unwrap());
        assert!(list_peer_received_grant_cleanups(&conn).unwrap().is_empty());

        // Pre-staging cleanup intent can be promoted atomically out of cleanups while retiring old slot
        upsert_peer_received_grant_cleanup(
            &conn,
            "link-1",
            "grant-slot-gen4",
            4,
            "2026-11-23T05:14:00Z",
        )
        .unwrap();
        assert!(
            delete_peer_received_grant_cleanup_slot(&conn, "link-1", "grant-slot-gen4").unwrap()
        );
        received.grant_id = "remote-grant-2".to_string();
        received.generation = 4;
        received.revoked_at = None;
        received.credential_id = Some("grant-slot-gen4".to_string());
        upsert_peer_received_grant(&conn, &received).unwrap();
        let active_gen4 = get_active_peer_received_grant_for_link(&conn, "link-1")
            .unwrap()
            .unwrap();
        assert_eq!(active_gen4.grant_id, "remote-grant-2");
        assert_eq!(active_gen4.effective_credential_id(), "grant-slot-gen4");

        // Multiple pending cleanups on a link can be listed and cascaded on link deletion
        upsert_peer_received_grant_cleanup(
            &conn,
            "link-1",
            "grant-slot-orphan-a",
            5,
            "2026-11-23T05:15:00Z",
        )
        .unwrap();
        upsert_peer_received_grant_cleanup(
            &conn,
            "link-1",
            "grant-slot-orphan-b",
            6,
            "2026-11-23T05:15:01Z",
        )
        .unwrap();
        assert_eq!(
            list_peer_received_grant_cleanups_for_link(&conn, "link-1")
                .unwrap()
                .len(),
            2
        );

        // Deleting link cascades peer_received_grants, peer_received_grant_cleanups, and peer_grant_epochs
        assert!(delete_peer_link(&conn, "link-1").unwrap());
        assert_eq!(get_peer_received_grant(&conn, "link-1").unwrap(), None);
        assert!(list_peer_received_grant_cleanups_for_link(&conn, "link-1")
            .unwrap()
            .is_empty());
        assert_eq!(get_peer_grant_epoch(&conn, "link-1").unwrap(), None);
    }

    #[test]
    fn ensure_peer_grant_schema_invariants_upgrades_legacy_v27_table_idempotently() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE peer_links (
                 id TEXT PRIMARY KEY
             );
             CREATE TABLE peer_received_grants (
                 link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
                 grant_id TEXT NOT NULL,
                 run_as_user_id INTEGER NOT NULL,
                 access TEXT NOT NULL,
                 created_by TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 generation INTEGER NOT NULL DEFAULT 0,
                 revoked_at TEXT,
                 updated_at TEXT NOT NULL
             );
             INSERT INTO peer_links (id) VALUES ('link-legacy');
             INSERT INTO peer_received_grants (
                 link_id, grant_id, run_as_user_id, access, created_by, created_at, generation, revoked_at, updated_at
             ) VALUES (
                 'link-legacy', 'g-1', 5, '{\"services\":\"read\"}', 'alice', '2026-11-23T05:00:00Z', 1, NULL, '2026-11-23T05:00:00Z'
             );",
        )
        .unwrap();

        ensure_peer_grant_schema_invariants(&conn).unwrap();
        ensure_peer_grant_schema_invariants(&conn).unwrap();

        let loaded = get_peer_received_grant(&conn, "link-legacy")
            .unwrap()
            .expect("legacy received grant row preserved");
        assert_eq!(loaded.grant_id, "g-1");
        assert_eq!(loaded.generation, 1);
        assert_eq!(loaded.credential_id, None);
        assert_eq!(loaded.effective_credential_id(), "link-legacy");
        assert!(list_peer_received_grant_cleanups(&conn).unwrap().is_empty());
    }
}
