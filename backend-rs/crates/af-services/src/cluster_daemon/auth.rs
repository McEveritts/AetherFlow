use anyhow::Context;
use chrono::Utc;
use rand::RngCore;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::env;

// ─────────────────────────────────────────────────────────────────────────────
// Constant-Time PSK Verification & SQLite Schema Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Performs a constant-time byte slice equality check to prevent timing side-channels.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    af_models::constant_time_eq(a, b)
}

pub(super) fn hash_psk_sha256(psk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Verified transport identity of the caller on a cluster listener connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransportAuth {
    /// Direct in-process library call (e.g., unit tests).
    InternalCall,
    /// Opt-in `CLUSTER_ALLOW_INSECURE_LOOPBACK=true` plaintext loopback connection.
    InsecureLoopback,
    /// Verified TLS 1.3 mutual-TLS client certificate identity.
    Mtls {
        cert_sha256: String,
        subject_cn: Option<String>,
        is_admin_cert: bool,
    },
}

impl PeerTransportAuth {
    pub(super) fn mtls_cert_sha256(&self) -> Option<&str> {
        match self {
            Self::Mtls { cert_sha256, .. } => Some(cert_sha256.as_str()),
            _ => None,
        }
    }
}

pub(super) fn verify_master_control_plane_psk(candidate_psk: &str) -> bool {
    let candidate = candidate_psk.trim();
    if candidate.is_empty() {
        return false;
    }
    if let Ok(master_psk) = env::var("CLUSTER_PSK") {
        let master_trimmed = master_psk.trim();
        if !master_trimmed.is_empty() {
            return constant_time_eq(candidate.as_bytes(), master_trimmed.as_bytes());
        }
    }
    false
}

/// Verifies a worker's pre-shared key against `CLUSTER_PSK` (if configured on the master)
/// or against a previously enrolled node's stored `psk_hash` (`sha256:<hex>` or legacy Go
/// `$2a$`/`$2b$`/`$2y$` bcrypt hashes; Argon2id is reserved for user passwords in `af-auth`).
pub fn verify_cluster_psk(node_id: &str, candidate_psk: &str) -> Result<(), &'static str> {
    let candidate = candidate_psk.trim();
    if candidate.is_empty() {
        return Err("psk is required");
    }

    if verify_master_control_plane_psk(candidate) {
        return Ok(());
    }

    // Check if this node is already enrolled in `cluster_nodes` with a matching hash
    if !node_id.is_empty() {
        if let Ok(conn) = af_db::get_conn() {
            if let Ok(stored_hash) = conn.query_row(
                "SELECT COALESCE(psk_hash, '') FROM cluster_nodes WHERE id = ?1",
                params![node_id],
                |r| r.get::<_, String>(0),
            ) {
                return verify_enrolled_cluster_psk(candidate, &stored_hash);
            }
        }
    }

    Err("cluster PSK is not configured and node is not enrolled")
}

pub(super) fn verify_enrolled_cluster_psk(
    candidate: &str,
    stored_hash: &str,
) -> Result<(), &'static str> {
    if candidate.is_empty() || stored_hash.is_empty() {
        return Err("cluster PSK is not configured and node is not enrolled");
    }
    if stored_hash.starts_with("$2a$")
        || stored_hash.starts_with("$2b$")
        || stored_hash.starts_with("$2y$")
    {
        return if bcrypt::verify(candidate, stored_hash).unwrap_or(false) {
            Ok(())
        } else {
            Err("invalid cluster PSK for enrolled node")
        };
    }
    let candidate_hash = hash_psk_sha256(candidate);
    if constant_time_eq(candidate_hash.as_bytes(), stored_hash.as_bytes())
        || (!stored_hash.starts_with("sha256:")
            && constant_time_eq(candidate.as_bytes(), stored_hash.as_bytes()))
    {
        return Ok(());
    }
    Err("invalid cluster PSK for enrolled node")
}

/// Ensures `cluster_nodes` has `last_seen`, `cpu_usage`, `ram_usage`, `disk_usage`, and
/// `peer_cert_sha256` columns plus the single-use `cluster_enrollment_tokens` table.
pub fn ensure_cluster_schema() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let migrations = [
        "ALTER TABLE cluster_nodes ADD COLUMN last_seen DATETIME;",
        "ALTER TABLE cluster_nodes ADD COLUMN cpu_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN ram_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN disk_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN peer_cert_sha256 TEXT DEFAULT '';",
        "CREATE TABLE IF NOT EXISTS cluster_enrollment_tokens (
            token_hash TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_by TEXT
        );",
        "CREATE TABLE IF NOT EXISTS cluster_commands (
            id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            cmd_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            leased_until INTEGER,
            lease_generation INTEGER NOT NULL DEFAULT 0,
            result_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
        "ALTER TABLE cluster_commands ADD COLUMN lease_generation INTEGER DEFAULT 0;",
        "CREATE INDEX IF NOT EXISTS idx_cluster_commands_node_status ON cluster_commands(node_id, status, created_at);",
    ];
    for sql in migrations {
        let _ = conn.execute_batch(sql);
    }
}

/// Mints a 256-bit CSPRNG single-use worker enrollment token (24-hour TTL), persists its
/// SHA-256 digest in `cluster_enrollment_tokens`, and returns the 64-char hex token.
pub fn issue_cluster_enrollment_token() -> anyhow::Result<String> {
    ensure_cluster_schema();
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let token_hash = hash_psk_sha256(&token);
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let expires_at = now.timestamp() + 86_400;

    let conn = af_db::get_conn().context("failed opening database for cluster enrollment token")?;
    let _ = conn.execute(
        "DELETE FROM cluster_enrollment_tokens WHERE expires_at < ?1",
        params![now.timestamp()],
    );
    conn.execute(
        "INSERT INTO cluster_enrollment_tokens (token_hash, created_at, expires_at, consumed_by) \
         VALUES (?1, ?2, ?3, NULL)",
        params![token_hash, now_rfc3339, expires_at],
    )
    .context("failed persisting cluster enrollment token")?;
    Ok(token)
}

fn check_cert_not_enrolled_as_worker(cert_sha256: &str) -> Result<(), &'static str> {
    let fp = cert_sha256.trim();
    if fp.is_empty() {
        return Err("empty mTLS client certificate fingerprint");
    }
    ensure_cluster_schema();
    let conn = af_db::get_conn().map_err(|_| "cluster database unavailable")?;
    let cnt: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM cluster_nodes WHERE peer_cert_sha256 = ?1 AND COALESCE(role, 'worker') = 'worker'",
            params![fp],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|_| "cluster database query failed")?;
    if cnt > 0 {
        return Err("enrolled worker certificates are prohibited from cluster control-plane RPCs");
    }
    Ok(())
}

pub(super) fn authorize_cluster_control_plane(
    header_psk: &str,
    peer_auth: &PeerTransportAuth,
) -> Result<(), &'static str> {
    if let PeerTransportAuth::Mtls { cert_sha256, .. } = peer_auth {
        check_cert_not_enrolled_as_worker(cert_sha256)?;
    }
    match peer_auth {
        PeerTransportAuth::InternalCall => return Ok(()),
        PeerTransportAuth::Mtls {
            is_admin_cert: true,
            ..
        } => return Ok(()),
        _ => {}
    }
    if verify_master_control_plane_psk(header_psk) {
        return Ok(());
    }
    Err(
        "control-plane authentication required (master CLUSTER_PSK or control-plane client certificate)",
    )
}
