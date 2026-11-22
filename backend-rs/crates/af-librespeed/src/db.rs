mod bolt_migration;
mod fs_security;

pub use bolt_migration::parse_boltdb_telemetry_bytes;

use bolt_migration::discover_and_import_legacy_bolt_backups;
use fs_security::{
    check_not_symlink, ensure_parent_dirs, guard_and_backup_legacy_boltdb,
    verify_and_harden_sidecars, verify_no_symlinks_on_db_path,
    verify_parent_dir_not_world_writable,
};

use crate::ulid::{
    canonicalize_ulid, decode_legacy_go_obfuscated_ulid, decode_legacy_go_obfuscated_ulid_bytes,
    decode_ulid,
};
use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::task;

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryRecord {
    pub id: i64,
    pub uuid: String,
    pub timestamp: String,
    pub ip: String,
    pub ispinfo: String,
    pub extra: String,
    pub ua: String,
    pub lang: String,
    pub dl: String,
    pub ul: String,
    pub ping: String,
    pub jitter: String,
    pub log: String,
}

#[derive(Debug, Clone)]
pub struct NewTelemetryRecord {
    pub uuid: String,
    pub timestamp: String,
    pub ip: String,
    pub ispinfo: String,
    pub extra: String,
    pub ua: String,
    pub lang: String,
    pub dl: String,
    pub ul: String,
    pub ping: String,
    pub jitter: String,
    pub log: String,
}

#[derive(Clone)]
pub struct TelemetryVault {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
    obfuscation_key: [u8; 32],
    legacy_go_salt: Option<[u8; 4]>,
    max_rows: usize,
}

const TELEMETRY_SCHEMA_SQL: &str = "
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS telemetry_meta (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS telemetry_bolt_migrations (
        source_name TEXT PRIMARY KEY,
        imported_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS telemetry_legacy_raw_ids (
        uuid TEXT PRIMARY KEY,
        ulid_suffix BLOB
    );
    CREATE TABLE IF NOT EXISTS speedtest_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        ts_epoch_ms INTEGER,
        ip TEXT NOT NULL DEFAULT '',
        ispinfo TEXT NOT NULL DEFAULT '',
        extra TEXT NOT NULL DEFAULT '',
        ua TEXT NOT NULL DEFAULT '',
        lang TEXT NOT NULL DEFAULT '',
        dl TEXT NOT NULL DEFAULT '',
        ul TEXT NOT NULL DEFAULT '',
        ping TEXT NOT NULL DEFAULT '',
        jitter TEXT NOT NULL DEFAULT '',
        log TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_speedtest_users_ts_uuid
        ON speedtest_users (timestamp DESC, uuid DESC);
";

pub fn parse_timestamp_epoch_ms(ts: &str) -> i64 {
    let mut trimmed = ts.trim();
    if trimmed.is_empty() {
        return i64::MIN;
    }
    if let Some((before_mono, _)) = trimmed.split_once(" m=") {
        trimmed = before_mono.trim();
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return dt.timestamp_millis();
    }
    let candidate = {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4
            && (parts[2].starts_with('+') || parts[2].starts_with('-'))
            && parts[3].bytes().all(|b| b.is_ascii_alphabetic())
        {
            format!("{} {} {}", parts[0], parts[1], parts[2])
        } else {
            trimmed.to_string()
        }
    };
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ] {
        if let Ok(dt) = chrono::DateTime::parse_from_str(&candidate, fmt) {
            return dt.timestamp_millis();
        }
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(trimmed, fmt) {
            return ndt.and_utc().timestamp_millis();
        }
    }
    if let Ok(nd) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        if let Some(ndt) = nd.and_hms_opt(0, 0, 0) {
            return ndt.and_utc().timestamp_millis();
        }
    }
    if let Ok(num) = trimmed.parse::<i64>() {
        return if num.abs() >= 100_000_000_000 {
            num
        } else {
            num.saturating_mul(1000)
        };
    }
    i64::MIN
}

pub(super) fn ulid_suffix_blob(uuid: &str) -> Option<[u8; 12]> {
    let canon = canonicalize_ulid(uuid)?;
    let val = decode_ulid(&canon)?;
    let bytes = val.to_be_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&bytes[4..16]);
    Some(out)
}

fn table_has_column(conn: &Connection, table: &str, col_name: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in cols {
        if col? == col_name {
            return Ok(true);
        }
    }
    Ok(false)
}

fn init_telemetry_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(TELEMETRY_SCHEMA_SQL)?;

    if !table_has_column(conn, "speedtest_users", "ts_epoch_ms")? {
        conn.execute(
            "ALTER TABLE speedtest_users ADD COLUMN ts_epoch_ms INTEGER",
            [],
        )?;
    }
    {
        let mut stmt =
            conn.prepare("SELECT id, timestamp FROM speedtest_users WHERE ts_epoch_ms IS NULL")?;
        let pending: Vec<(i64, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !pending.is_empty() {
            let mut upd =
                conn.prepare("UPDATE speedtest_users SET ts_epoch_ms = ?1 WHERE id = ?2")?;
            for (id, ts) in pending {
                upd.execute(params![parse_timestamp_epoch_ms(&ts), id])?;
            }
        }
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_speedtest_users_retention
         ON speedtest_users (ts_epoch_ms DESC, timestamp DESC, id DESC);",
    )?;

    if !table_has_column(conn, "telemetry_legacy_raw_ids", "ulid_suffix")? {
        conn.execute(
            "ALTER TABLE telemetry_legacy_raw_ids ADD COLUMN ulid_suffix BLOB",
            [],
        )?;
    }
    backfill_legacy_ulid_suffixes(conn)?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_telemetry_legacy_ulid_suffix
         ON telemetry_legacy_raw_ids (ulid_suffix);",
    )?;
    Ok(())
}

pub(super) fn enforce_retention_on_conn(conn: &Connection, max_rows: usize) -> Result<()> {
    let keep = i64::try_from(max_rows).unwrap_or(100_000);
    conn.execute(
        "DELETE FROM speedtest_users
         WHERE id NOT IN (
             SELECT id FROM speedtest_users
             ORDER BY ts_epoch_ms DESC, timestamp DESC, id DESC
             LIMIT ?1
         )",
        params![keep],
    )
    .context("failed to enforce telemetry retention cap")?;
    conn.execute(
        "DELETE FROM telemetry_legacy_raw_ids
         WHERE uuid NOT IN (SELECT uuid FROM speedtest_users)",
        [],
    )
    .context("failed to prune telemetry_legacy_raw_ids")?;
    Ok(())
}

impl TelemetryVault {
    pub fn open(db_path: &Path) -> Result<Self> {
        Self::open_with_max_rows(db_path, crate::config::DEFAULT_MAX_TELEMETRY_ROWS)
    }

    pub fn open_in_memory(max_rows: usize) -> Result<Self> {
        if max_rows == 0 {
            bail!("max_telemetry_rows must be greater than 0");
        }
        let conn = Connection::open_in_memory()
            .context("failed to open in-memory SQLite telemetry database")?;
        init_telemetry_schema(&conn).context("failed to initialize in-memory telemetry schema")?;
        let obfuscation_key = init_or_load_obfuscation_key(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: PathBuf::from(":memory:"),
            obfuscation_key,
            legacy_go_salt: None,
            max_rows,
        })
    }

    pub fn open_with_max_rows(db_path: &Path, max_rows: usize) -> Result<Self> {
        if db_path.as_os_str().is_empty() {
            bail!("database_file path is empty");
        }
        if max_rows == 0 {
            bail!("max_telemetry_rows must be greater than 0");
        }

        verify_no_symlinks_on_db_path(db_path)?;
        ensure_parent_dirs(db_path)?;
        verify_parent_dir_not_world_writable(db_path)?;
        let legacy_backup = guard_and_backup_legacy_boltdb(db_path)?;
        let sibling_bolt_backup = if let Some(parent) = db_path.parent() {
            let sibling_bolt = parent.join("speedtest.bolt");
            if sibling_bolt != db_path {
                guard_and_backup_legacy_boltdb(&sibling_bolt)?
            } else {
                None
            }
        } else {
            None
        };
        verify_and_harden_sidecars(db_path)?;

        // Create/verify leaf file with O_NOFOLLOW and enforce 0600 permissions on the opened fd
        // so pre-existing database files with looser permissions are hardened atomically.
        let leaf = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(db_path)
            .with_context(|| {
                format!(
                    "failed secure O_NOFOLLOW open on telemetry database {}",
                    db_path.display()
                )
            })?;
        leaf.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to tighten permissions to 0600 on telemetry database {}",
                    db_path.display()
                )
            })?;
        drop(leaf);

        let mut conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("failed to open SQLite database {}", db_path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )
        .with_context(|| format!("failed to configure WAL pragmas at {}", db_path.display()))?;
        init_telemetry_schema(&conn)
            .with_context(|| format!("failed to initialize schema at {}", db_path.display()))?;

        verify_and_harden_sidecars(db_path)?;

        discover_and_import_legacy_bolt_backups(
            db_path,
            legacy_backup.as_deref(),
            sibling_bolt_backup.as_deref(),
            &mut conn,
            max_rows,
        )?;
        enforce_retention_on_conn(&conn, max_rows)?;

        let obfuscation_key = init_or_load_obfuscation_key(&conn)?;
        let legacy_go_salt = init_or_load_legacy_go_salt(db_path, &conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: db_path.to_path_buf(),
            obfuscation_key,
            legacy_go_salt,
            max_rows,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn obfuscation_key(&self) -> &[u8; 32] {
        &self.obfuscation_key
    }

    pub fn legacy_go_salt(&self) -> Option<[u8; 4]> {
        self.legacy_go_salt
    }

    /// Resolves a legacy 22-character `librespeed/speedtest-go` obfuscated share token
    /// (`base64.RawURLEncoding` over `ulid_bytes` with `bytes[0..4] ^= salt`) to a
    /// migrated canonical ULID in `telemetry_legacy_raw_ids`.
    ///
    /// Uses the imported `idObfuscation_salt.bin` 4-byte salt for exact O(1) lookup when
    /// available, and falls back to an O(1) indexed lookup on `ulid_suffix` (`bytes[4..16]`)
    /// across `telemetry_legacy_raw_ids` iff the match is globally unique.
    pub async fn resolve_legacy_go_share_id(&self, token: String) -> Result<Option<String>> {
        let Some(raw_bytes) = decode_legacy_go_obfuscated_ulid_bytes(&token) else {
            return Ok(None);
        };
        let salt_opt = self.legacy_go_salt;
        let conn_arc = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn_arc
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite vault mutex poisoned"))?;
            if let Some(salt) = salt_opt {
                if let Some(exact_uuid) = decode_legacy_go_obfuscated_ulid(&token, &salt) {
                    let found: Option<String> = conn
                        .query_row(
                            "SELECT u.uuid
                             FROM speedtest_users u
                             INNER JOIN telemetry_legacy_raw_ids l ON l.uuid = u.uuid
                             WHERE u.uuid = ?1
                             LIMIT 1",
                            params![exact_uuid],
                            |row| row.get(0),
                        )
                        .optional()
                        .context("failed exact legacy Go share ID lookup")?;
                    if found.is_some() {
                        return Ok(found);
                    }
                }
            }

            let suffix = &raw_bytes[4..16];
            let mut stmt = conn
                .prepare(
                    "SELECT u.uuid
                     FROM telemetry_legacy_raw_ids l
                     INNER JOIN speedtest_users u ON u.uuid = l.uuid
                     WHERE l.ulid_suffix = ?1
                     LIMIT 2",
                )
                .context("failed preparing indexed legacy Go suffix lookup")?;
            let rows = stmt
                .query_map(params![suffix], |row| row.get::<_, String>(0))
                .context("failed executing indexed legacy Go suffix lookup")?;
            let mut matched: Vec<String> = Vec::with_capacity(2);
            for row in rows {
                matched.push(row.context("failed decoding legacy Go candidate UUID")?);
            }
            if matched.len() == 1 {
                Ok(matched.pop())
            } else {
                Ok(None)
            }
        })
        .await
        .context("legacy Go share ID lookup panicked")?
    }

    pub async fn is_legacy_raw_id(&self, uuid: String) -> Result<bool> {
        let conn_arc = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn_arc
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite vault mutex poisoned"))?;
            let found: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM telemetry_legacy_raw_ids WHERE uuid = ?1 LIMIT 1",
                    params![uuid],
                    |row| row.get(0),
                )
                .optional()
                .context("failed querying telemetry_legacy_raw_ids")?;
            Ok(found.is_some())
        })
        .await
        .context("legacy raw id lookup panicked")?
    }

    pub async fn insert(&self, record: NewTelemetryRecord) -> Result<()> {
        self.insert_with_mode(record, false).await
    }

    pub async fn insert_with_mode(
        &self,
        record: NewTelemetryRecord,
        issued_raw_id: bool,
    ) -> Result<()> {
        let conn_arc = Arc::clone(&self.conn);
        let max_rows = self.max_rows;
        task::spawn_blocking(move || {
            let conn = conn_arc
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite vault mutex poisoned"))?;
            let uuid_copy = record.uuid.clone();
            let ts_epoch_ms = parse_timestamp_epoch_ms(&record.timestamp);
            conn.execute(
                "INSERT INTO speedtest_users
                 (uuid, timestamp, ts_epoch_ms, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    record.uuid,
                    record.timestamp,
                    ts_epoch_ms,
                    record.ip,
                    record.ispinfo,
                    record.extra,
                    record.ua,
                    record.lang,
                    record.dl,
                    record.ul,
                    record.ping,
                    record.jitter,
                    record.log,
                ],
            )
            .context("failed to insert telemetry record")?;

            if issued_raw_id {
                let suffix_opt = ulid_suffix_blob(&uuid_copy);
                conn.execute(
                    "INSERT OR IGNORE INTO telemetry_legacy_raw_ids (uuid, ulid_suffix) VALUES (?1, ?2)",
                    params![uuid_copy, suffix_opt.as_ref().map(|b| b.as_slice())],
                )
                .context("failed to record unobfuscated share ID")?;
            }

            enforce_retention_on_conn(&conn, max_rows)?;
            Ok(())
        })
        .await
        .context("telemetry insert task panicked")?
    }

    pub async fn get_by_uuid(&self, uuid: String) -> Result<Option<TelemetryRecord>> {
        let conn_arc = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn_arc
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite vault mutex poisoned"))?;
            conn.query_row(
                "SELECT id, uuid, timestamp, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log
                 FROM speedtest_users
                 WHERE uuid = ?1
                 LIMIT 1",
                params![uuid],
                row_to_record,
            )
            .optional()
            .context("failed to query telemetry record by uuid")
        })
        .await
        .context("telemetry query task panicked")?
    }

    pub async fn list_recent(&self, limit: usize) -> Result<Vec<TelemetryRecord>> {
        let conn_arc = Arc::clone(&self.conn);
        let bounded = i64::try_from(limit.min(500)).unwrap_or(100);
        task::spawn_blocking(move || {
            let conn = conn_arc
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite vault mutex poisoned"))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, uuid, timestamp, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log
                     FROM speedtest_users
                     ORDER BY ts_epoch_ms DESC, timestamp DESC, id DESC
                     LIMIT ?1",
                )
                .context("failed to prepare recent telemetry query")?;
            let rows = stmt
                .query_map(params![bounded], row_to_record)
                .context("failed to execute recent telemetry query")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("failed to decode telemetry row")?);
            }
            Ok(out)
        })
        .await
        .context("telemetry list task panicked")?
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TelemetryRecord> {
    let opt_str = |idx: usize| -> rusqlite::Result<String> {
        Ok(row.get::<_, Option<String>>(idx)?.unwrap_or_default())
    };
    Ok(TelemetryRecord {
        id: row.get(0)?,
        uuid: opt_str(1)?,
        timestamp: opt_str(2)?,
        ip: opt_str(3)?,
        ispinfo: opt_str(4)?,
        extra: opt_str(5)?,
        ua: opt_str(6)?,
        lang: opt_str(7)?,
        dl: opt_str(8)?,
        ul: opt_str(9)?,
        ping: opt_str(10)?,
        jitter: opt_str(11)?,
        log: opt_str(12)?,
    })
}

fn backfill_legacy_ulid_suffixes(conn: &Connection) -> Result<()> {
    let mut stmt =
        conn.prepare("SELECT uuid FROM telemetry_legacy_raw_ids WHERE ulid_suffix IS NULL")?;
    let pending: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !pending.is_empty() {
        let mut upd =
            conn.prepare("UPDATE telemetry_legacy_raw_ids SET ulid_suffix = ?1 WHERE uuid = ?2")?;
        for uuid in pending {
            if let Some(sfx) = ulid_suffix_blob(&uuid) {
                upd.execute(params![sfx.as_slice(), uuid])?;
            }
        }
    }
    Ok(())
}

fn init_or_load_obfuscation_key(conn: &Connection) -> Result<[u8; 32]> {
    let had_obfuscation_key: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM telemetry_meta WHERE key = 'obfuscation_key' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("failed probing telemetry obfuscation_key")?;
    if had_obfuscation_key.is_none() {
        conn.execute(
            "INSERT OR IGNORE INTO telemetry_legacy_raw_ids (uuid) SELECT uuid FROM speedtest_users",
            [],
        )
        .context("failed preserving pre-obfuscation SQLite share IDs")?;
        backfill_legacy_ulid_suffixes(conn)
            .context("failed backfilling ULID suffixes for pre-obfuscation SQLite share IDs")?;
    }

    let mut candidate_key = [0u8; 32];
    OsRng.fill_bytes(&mut candidate_key);
    conn.execute(
        "INSERT OR IGNORE INTO telemetry_meta (key, value) VALUES ('obfuscation_key', ?1)",
        params![candidate_key.as_slice()],
    )
    .context("failed to seed telemetry obfuscation_key")?;

    let stored_blob: Vec<u8> = conn
        .query_row(
            "SELECT value FROM telemetry_meta WHERE key = 'obfuscation_key'",
            [],
            |row| row.get(0),
        )
        .context("failed to load telemetry obfuscation_key")?;

    if stored_blob.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&stored_blob);
        Ok(arr)
    } else {
        conn.execute(
            "UPDATE telemetry_meta SET value = ?1 WHERE key = 'obfuscation_key'",
            params![candidate_key.as_slice()],
        )
        .context("failed to repair telemetry obfuscation_key")?;
        Ok(candidate_key)
    }
}

fn init_or_load_legacy_go_salt(db_path: &Path, conn: &Connection) -> Result<Option<[u8; 4]>> {
    let stored_salt: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM telemetry_meta WHERE key = 'legacy_go_obfuscation_salt' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("failed probing legacy_go_obfuscation_salt")?;

    let mut disk_candidates = Vec::new();
    if let Some(parent) = db_path.parent() {
        disk_candidates.push(parent.join("idObfuscation_salt.bin"));
        if let Some(grandparent) = parent.parent() {
            if grandparent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == "librespeed")
            {
                disk_candidates.push(grandparent.join("idObfuscation_salt.bin"));
            }
        }
    }

    let mut imported_from_disk: Option<[u8; 4]> = None;
    for salt_path in disk_candidates {
        let mut safe_ancestors = true;
        for anc in salt_path.ancestors().skip(1) {
            if anc.as_os_str().is_empty() {
                break;
            }
            if check_not_symlink(anc, "legacy salt ancestor").is_err() {
                safe_ancestors = false;
                break;
            }
        }
        if !safe_ancestors || check_not_symlink(&salt_path, "idObfuscation_salt.bin").is_err() {
            continue;
        }
        let Ok(mut salt_file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&salt_path)
        else {
            continue;
        };
        let Ok(meta) = salt_file.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let _ = salt_file.set_permissions(fs::Permissions::from_mode(0o600));
        if meta.len() == 4 && imported_from_disk.is_none() {
            let mut salt = [0u8; 4];
            if salt_file.read_exact(&mut salt).is_ok() {
                imported_from_disk = Some(salt);
            }
        }
    }

    if let Some(blob) = stored_salt {
        if blob.len() == 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&blob);
            return Ok(Some(arr));
        }
    }

    if let Some(salt) = imported_from_disk {
        conn.execute(
            "INSERT OR REPLACE INTO telemetry_meta (key, value) VALUES ('legacy_go_obfuscation_salt', ?1)",
            params![salt.as_slice()],
        )
        .context("failed storing legacy_go_obfuscation_salt")?;
        return Ok(Some(salt));
    }

    Ok(None)
}

#[cfg(test)]
mod tests;
