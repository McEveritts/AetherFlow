use crate::ulid::{
    canonicalize_ulid, decode_legacy_go_obfuscated_ulid, decode_legacy_go_obfuscated_ulid_bytes,
    decode_ulid,
};
use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task;
use tracing::{info, warn};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const BBOLT_MAGIC: u32 = 0xED0C_DAED;
const BBOLT_VERSION: u32 = 2;
const BBOLT_PAGE_HEADER_BYTES: usize = 16;
const BBOLT_BRANCH_FLAG: u16 = 0x01;
const BBOLT_LEAF_FLAG: u16 = 0x02;
const BBOLT_META_FLAG: u16 = 0x04;
const BBOLT_BUCKET_LEAF_FLAG: u32 = 0x01;
const MAX_BOLTDB_PAGE_SPAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_BOLTDB_CUMULATIVE_READ_BYTES: usize = 256 * 1024 * 1024;
const MAX_BOLTDB_TREE_DEPTH: usize = 16;
const MAX_BOLTDB_VISITED_PAGES: usize = 65_536;
const SQLITE_SIDECAR_SUFFIXES: [(&str, &str); 3] = [
    ("-wal", "SQLite WAL sidecar"),
    ("-shm", "SQLite SHM sidecar"),
    ("-journal", "SQLite rollback journal sidecar"),
];

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

fn ulid_suffix_blob(uuid: &str) -> Option<[u8; 12]> {
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
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
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

fn enforce_retention_on_conn(conn: &Connection, max_rows: usize) -> Result<()> {
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
                guard_and_backup_legacy_boltdb(&sibling_bolt).ok().flatten()
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
        );
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
    Ok(TelemetryRecord {
        id: row.get(0)?,
        uuid: row.get(1)?,
        timestamp: row.get(2)?,
        ip: row.get(3)?,
        ispinfo: row.get(4)?,
        extra: row.get(5)?,
        ua: row.get(6)?,
        lang: row.get(7)?,
        dl: row.get(8)?,
        ul: row.get(9)?,
        ping: row.get(10)?,
        jitter: row.get(11)?,
        log: row.get(12)?,
    })
}

fn check_not_symlink(path: &Path, label: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!("refusing symlink for {label}: {}", path.display());
            }
            Ok(Some(meta))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to stat {label}: {}", path.display())),
    }
}

fn verify_no_symlinks_on_db_path(db_path: &Path) -> Result<()> {
    if let Some(meta) = check_not_symlink(db_path, "database_file")? {
        if meta.is_dir() {
            bail!(
                "database_file points to a directory, expected regular file: {}",
                db_path.display()
            );
        }
    }

    for ancestor in db_path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if let Some(meta) = check_not_symlink(ancestor, "database ancestor directory")? {
            if !meta.is_dir() {
                bail!(
                    "database ancestor path is not a directory: {}",
                    ancestor.display()
                );
            }
        }
    }

    verify_sidecar_symlinks(db_path)
}

fn verify_sidecar_symlinks(db_path: &Path) -> Result<()> {
    for (suffix, label) in SQLITE_SIDECAR_SUFFIXES {
        let sc_path = sidecar_path(db_path, suffix);
        if let Some(meta) = check_not_symlink(&sc_path, label)? {
            if !meta.is_file() {
                bail!("{label} is not a regular file: {}", sc_path.display());
            }
        }
    }
    Ok(())
}

fn verify_and_harden_sidecars(db_path: &Path) -> Result<()> {
    verify_sidecar_symlinks(db_path)?;
    for (suffix, _label) in SQLITE_SIDECAR_SUFFIXES {
        let sc_path = sidecar_path(db_path, suffix);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&sc_path)
        {
            Ok(sc_file) => {
                let meta = sc_file.metadata().with_context(|| {
                    format!("failed to fstat SQLite sidecar {}", sc_path.display())
                })?;
                if !meta.is_file() {
                    bail!(
                        "SQLite sidecar is not a regular file: {}",
                        sc_path.display()
                    );
                }
                sc_file
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .with_context(|| {
                        format!(
                            "failed to tighten permissions to 0600 on SQLite sidecar {}",
                            sc_path.display()
                        )
                    })?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed secure O_NOFOLLOW open on SQLite sidecar {}",
                        sc_path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

fn verify_parent_dir_not_world_writable(db_path: &Path) -> Result<()> {
    let parent = match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let meta = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "failed to inspect telemetry database directory {}",
            parent.display()
        )
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!(
            "telemetry database parent is not a regular directory: {}",
            parent.display()
        );
    }
    let mode = meta.permissions().mode();
    if (mode & 0o002) != 0 {
        bail!(
            "refusing world-writable parent directory (mode {:04o}) for telemetry database: {}",
            mode & 0o7777,
            parent.display()
        );
    }
    Ok(())
}

fn sidecar_path(base: &Path, suffix: &str) -> PathBuf {
    let mut os = base.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

fn ensure_parent_dirs(db_path: &Path) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create telemetry database directory {}",
                    parent.display()
                )
            })?;
        }
    }
    Ok(())
}

fn move_file_noreplace(src: &Path, dst: &Path) -> Result<bool> {
    check_not_symlink(dst, "BoltDB backup path")?;
    let src_c = CString::new(src.as_os_str().as_bytes())
        .with_context(|| format!("invalid NUL in source path {}", src.display()))?;
    let dst_c = CString::new(dst.as_os_str().as_bytes())
        .with_context(|| format!("invalid NUL in backup path {}", dst.display()))?;

    // SAFETY: src_c and dst_c are valid NUL-terminated C strings; AT_FDCWD resolves relative paths safely.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EEXIST) | Some(libc::ENOTEMPTY) => Ok(false),
        Some(libc::ENOSYS) | Some(libc::EINVAL) => match fs::hard_link(src, dst) {
            Ok(()) => {
                fs::remove_file(src).with_context(|| {
                    format!(
                        "failed to unlink migrated database source {} after hard_link",
                        src.display()
                    )
                })?;
                Ok(true)
            }
            Err(link_err) if link_err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(link_err) => Err(link_err).with_context(|| {
                format!(
                    "failed non-overwriting hard_link backup {} -> {}",
                    src.display(),
                    dst.display()
                )
            }),
        },
        _ => Err(err).with_context(|| {
            format!(
                "failed atomic RENAME_NOREPLACE backup {} -> {}",
                src.display(),
                dst.display()
            )
        }),
    }
}

fn guard_and_backup_legacy_boltdb(db_path: &Path) -> Result<Option<PathBuf>> {
    let Some(meta) = check_not_symlink(db_path, "database_file")? else {
        return Ok(None);
    };
    if !meta.is_file() {
        bail!("database_file is not a regular file: {}", db_path.display());
    }
    if meta.len() == 0 {
        return Ok(None);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(db_path)
        .with_context(|| format!("failed to inspect existing database {}", db_path.display()))?;

    let mut header = [0u8; 16];
    let n = file.read(&mut header)?;
    drop(file);

    if n == 16 && &header == SQLITE_MAGIC {
        return Ok(None);
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let already_bolt_ext = db_path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("bolt"));
    let bak_ext = if already_bolt_ext {
        ".bak"
    } else {
        ".bolt.bak"
    };

    let mut candidates = Vec::with_capacity(66);
    candidates.push(sidecar_path(db_path, bak_ext));
    candidates.push(sidecar_path(db_path, &format!("{bak_ext}.{ts}")));
    for seq in 1..=64u32 {
        candidates.push(sidecar_path(db_path, &format!("{bak_ext}.{ts}.{seq}")));
    }

    let mut chosen_backup = None;
    for candidate in candidates {
        if move_file_noreplace(db_path, &candidate)? {
            chosen_backup = Some(candidate);
            break;
        }
    }
    let Some(backup_path) = chosen_backup else {
        bail!(
            "exhausted non-overwriting BoltDB backup slots for {}",
            db_path.display()
        );
    };
    let bak_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&backup_path)
        .with_context(|| {
            format!(
                "failed secure O_NOFOLLOW open on BoltDB backup {}",
                backup_path.display()
            )
        })?;
    bak_file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!(
                "failed to tighten permissions to 0600 on BoltDB backup {}",
                backup_path.display()
            )
        })?;
    drop(bak_file);
    warn!(
        old_path = %db_path.display(),
        backup_path = %backup_path.display(),
        "Detected non-SQLite/legacy BoltDB database file; moved aside (0600) before initializing SQLite WAL telemetry"
    );
    info!("SQLite telemetry initialized cleanly after legacy backup");
    Ok(Some(backup_path))
}

#[derive(Debug, Clone, Copy)]
struct BoltMeta {
    page_size: usize,
    root_pgid: u64,
    txid: u64,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn parse_bbolt_meta(page: &[u8]) -> Option<BoltMeta> {
    if page.len() < 80 {
        return None;
    }
    let flags = u16::from_le_bytes(page[8..10].try_into().ok()?);
    if flags != BBOLT_META_FLAG {
        return None;
    }
    let magic = u32::from_le_bytes(page[16..20].try_into().ok()?);
    let version = u32::from_le_bytes(page[20..24].try_into().ok()?);
    if magic != BBOLT_MAGIC || version != BBOLT_VERSION {
        return None;
    }
    let page_size = u32::from_le_bytes(page[24..28].try_into().ok()?) as usize;
    if !page_size.is_power_of_two() || !(1024..=65_536).contains(&page_size) {
        return None;
    }
    let root_pgid = u64::from_le_bytes(page[32..40].try_into().ok()?);
    let txid = u64::from_le_bytes(page[64..72].try_into().ok()?);
    let checksum = u64::from_le_bytes(page[72..80].try_into().ok()?);
    if fnv1a_64(&page[16..72]) != checksum {
        return None;
    }
    Some(BoltMeta {
        page_size,
        root_pgid,
        txid,
    })
}

fn select_best_bbolt_meta(data: &[u8]) -> Option<BoltMeta> {
    let meta0 = parse_bbolt_meta(data);
    let mut meta1: Option<BoltMeta> = None;
    if let Some(m0) = meta0 {
        if data.len() >= m0.page_size.saturating_add(80) {
            meta1 = parse_bbolt_meta(&data[m0.page_size..]);
        }
    } else {
        for cand_ps in [4096usize, 8192, 16_384, 32_768, 65_536, 1024, 2048] {
            if data.len() >= cand_ps.saturating_add(80) {
                if let Some(m1) = parse_bbolt_meta(&data[cand_ps..]) {
                    if m1.page_size == cand_ps {
                        meta1 = Some(m1);
                        break;
                    }
                }
            }
        }
    }

    match (meta0, meta1) {
        (Some(m0), Some(m1)) => {
            if m1.txid > m0.txid {
                Some(m1)
            } else {
                Some(m0)
            }
        }
        (Some(m0), None) => Some(m0),
        (None, Some(m1)) => Some(m1),
        (None, None) => None,
    }
}

fn clamp_imported_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

fn extract_json_field_ci(
    map: &serde_json::Map<String, serde_json::Value>,
    aliases: &[&str],
) -> String {
    for &alias in aliases {
        if let Some(v) = map.get(alias) {
            match v {
                serde_json::Value::String(s) => return s.clone(),
                serde_json::Value::Number(n) => return n.to_string(),
                _ => {}
            }
        }
    }
    for (k, v) in map {
        if aliases.iter().any(|a| k.eq_ignore_ascii_case(a)) {
            match v {
                serde_json::Value::String(s) => return s.clone(),
                serde_json::Value::Number(n) => return n.to_string(),
                _ => {}
            }
        }
    }
    String::new()
}

fn decode_bolt_telemetry_leaf(key_bytes: &[u8], val_bytes: &[u8]) -> Option<NewTelemetryRecord> {
    let serde_json::Value::Object(map) = serde_json::from_slice(val_bytes).ok()? else {
        return None;
    };
    let mut raw_uuid = extract_json_field_ci(&map, &["uuid", "id"]);
    if raw_uuid.trim().is_empty() {
        if let Ok(key_str) = std::str::from_utf8(key_bytes) {
            raw_uuid = key_str.trim().to_string();
        }
    }
    let trimmed_uuid = raw_uuid.trim();
    let uuid = if let Some(canon) = canonicalize_ulid(trimmed_uuid) {
        canon
    } else if (8..=64).contains(&trimmed_uuid.len())
        && trimmed_uuid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        trimmed_uuid.to_string()
    } else {
        return None;
    };

    let dl = clamp_imported_utf8(extract_json_field_ci(&map, &["dl", "download"]).trim(), 24);
    let ul = clamp_imported_utf8(extract_json_field_ci(&map, &["ul", "upload"]).trim(), 24);
    let ping = clamp_imported_utf8(extract_json_field_ci(&map, &["ping"]).trim(), 24);
    let jitter = clamp_imported_utf8(extract_json_field_ci(&map, &["jitter"]).trim(), 24);
    if dl.is_empty() && ul.is_empty() && ping.is_empty() && jitter.is_empty() {
        return None;
    }

    let raw_ts = extract_json_field_ci(&map, &["timestamp", "created_at"]);
    let timestamp = if raw_ts.trim().is_empty() {
        "1970-01-01T00:00:00.000Z".to_string()
    } else {
        clamp_imported_utf8(raw_ts.trim(), 64)
    };

    Some(NewTelemetryRecord {
        uuid,
        timestamp,
        ip: clamp_imported_utf8(
            extract_json_field_ci(&map, &["ip", "ip_address", "ipaddress"]).trim(),
            128,
        ),
        ispinfo: clamp_imported_utf8(&extract_json_field_ci(&map, &["ispinfo", "isp_info"]), 8192),
        extra: clamp_imported_utf8(&extract_json_field_ci(&map, &["extra"]), 8192),
        ua: clamp_imported_utf8(
            &extract_json_field_ci(&map, &["ua", "user_agent", "useragent"]),
            512,
        ),
        lang: clamp_imported_utf8(&extract_json_field_ci(&map, &["lang", "language"]), 64),
        dl,
        ul,
        ping,
        jitter,
        log: clamp_imported_utf8(&extract_json_field_ci(&map, &["log", "logs"]), 65_536),
    })
}

trait BoltByteSource {
    fn byte_len(&self) -> u64;
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

impl BoltByteSource for &[u8] {
    fn byte_len(&self) -> u64 {
        self.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).context("bbolt slice offset overflow")?;
        let end = start
            .checked_add(buf.len())
            .context("bbolt slice end overflow")?;
        if end > self.len() {
            bail!("bbolt read past slice end ({end} > {})", self.len());
        }
        buf.copy_from_slice(&self[start..end]);
        Ok(())
    }
}

struct FileBoltSource {
    file: fs::File,
    len: u64,
}

impl BoltByteSource for FileBoltSource {
    fn byte_len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .context("bbolt file offset overflow")?;
        if end > self.len {
            bail!("bbolt read past file end ({end} > {})", self.len);
        }
        self.file
            .read_exact_at(buf, offset)
            .with_context(|| format!("bbolt positional pread failed at offset {offset}"))
    }
}

fn select_best_bbolt_meta_from_source<S: BoltByteSource>(src: &S) -> Option<BoltMeta> {
    let head_len = usize::try_from(src.byte_len().min(131_072)).ok()?;
    if head_len < 80 {
        return None;
    }
    let mut head = vec![0u8; head_len];
    src.read_exact_at(0, &mut head).ok()?;
    select_best_bbolt_meta(&head)
}

fn walk_bbolt_page_id<S: BoltByteSource>(
    src: &S,
    page_size: usize,
    pgid: u64,
    depth: usize,
    visited: &mut HashSet<u64>,
    cumulative_bytes: &mut usize,
    out: &mut Vec<NewTelemetryRecord>,
) -> Result<()> {
    if depth > MAX_BOLTDB_TREE_DEPTH || pgid < 2 || visited.len() >= MAX_BOLTDB_VISITED_PAGES {
        bail!("bbolt tree depth or page bound exceeded at pgid={pgid}");
    }
    if !visited.insert(pgid) {
        bail!("cyclic bbolt page reference detected at pgid={pgid}");
    }
    let start = pgid
        .checked_mul(page_size as u64)
        .context("bbolt page start overflow")?;
    if start
        .checked_add(BBOLT_PAGE_HEADER_BYTES as u64)
        .is_none_or(|hdr_end| hdr_end > src.byte_len())
    {
        bail!("bbolt page {pgid} header out of file bounds");
    }
    let mut hdr = [0u8; BBOLT_PAGE_HEADER_BYTES];
    src.read_exact_at(start, &mut hdr)?;
    let overflow =
        u32::from_le_bytes(hdr[12..16].try_into().expect("4-byte overflow slice")) as usize;
    let span_pages = 1usize
        .checked_add(overflow)
        .context("bbolt page overflow count")?;
    let span_bytes = span_pages
        .checked_mul(page_size)
        .context("bbolt page span byte overflow")?;
    if span_bytes > MAX_BOLTDB_PAGE_SPAN_BYTES {
        bail!("bbolt page {pgid} span ({span_bytes} bytes) exceeds 16 MiB bound");
    }
    *cumulative_bytes = cumulative_bytes
        .checked_add(span_bytes)
        .context("bbolt cumulative read byte overflow")?;
    if *cumulative_bytes > MAX_BOLTDB_CUMULATIVE_READ_BYTES {
        bail!("bbolt cumulative page reads exceed 256 MiB bound");
    }
    let end = start
        .checked_add(span_bytes as u64)
        .context("bbolt page end overflow")?;
    if end > src.byte_len() {
        bail!("bbolt page {pgid} span exceeds file length");
    }
    let mut page_buf = vec![0u8; span_bytes];
    src.read_exact_at(start, &mut page_buf)?;
    walk_bbolt_page_slice(
        src,
        page_size,
        &page_buf,
        depth,
        visited,
        cumulative_bytes,
        out,
    )
}

fn walk_bbolt_page_slice<S: BoltByteSource>(
    src: &S,
    page_size: usize,
    page_span: &[u8],
    depth: usize,
    visited: &mut HashSet<u64>,
    cumulative_bytes: &mut usize,
    out: &mut Vec<NewTelemetryRecord>,
) -> Result<()> {
    if depth > MAX_BOLTDB_TREE_DEPTH || page_span.len() < BBOLT_PAGE_HEADER_BYTES {
        bail!("invalid bbolt page slice");
    }
    let flags = u16::from_le_bytes(page_span[8..10].try_into().expect("2-byte flags"));
    let count = u16::from_le_bytes(page_span[10..12].try_into().expect("2-byte count")) as usize;
    let elems_end = count
        .checked_mul(16)
        .and_then(|n| BBOLT_PAGE_HEADER_BYTES.checked_add(n))
        .context("bbolt element table overflow")?;
    if elems_end > page_span.len() {
        bail!("bbolt element headers exceed page span");
    }

    if flags == BBOLT_BRANCH_FLAG {
        for idx in 0..count {
            let elem_off = BBOLT_PAGE_HEADER_BYTES + idx * 16;
            let child_pgid = u64::from_le_bytes(
                page_span[elem_off + 8..elem_off + 16]
                    .try_into()
                    .expect("8-byte child pgid"),
            );
            walk_bbolt_page_id(
                src,
                page_size,
                child_pgid,
                depth + 1,
                visited,
                cumulative_bytes,
                out,
            )?;
        }
        Ok(())
    } else if flags == BBOLT_LEAF_FLAG {
        for idx in 0..count {
            let elem_off = BBOLT_PAGE_HEADER_BYTES + idx * 16;
            let eflags = u32::from_le_bytes(
                page_span[elem_off..elem_off + 4]
                    .try_into()
                    .expect("eflags"),
            );
            let pos = u32::from_le_bytes(
                page_span[elem_off + 4..elem_off + 8]
                    .try_into()
                    .expect("pos"),
            ) as usize;
            let ksize = u32::from_le_bytes(
                page_span[elem_off + 8..elem_off + 12]
                    .try_into()
                    .expect("ksize"),
            ) as usize;
            let vsize = u32::from_le_bytes(
                page_span[elem_off + 12..elem_off + 16]
                    .try_into()
                    .expect("vsize"),
            ) as usize;
            let k_start = elem_off
                .checked_add(pos)
                .context("bbolt leaf key start overflow")?;
            let v_start = k_start
                .checked_add(ksize)
                .context("bbolt leaf val start overflow")?;
            let v_end = v_start
                .checked_add(vsize)
                .context("bbolt leaf val end overflow")?;
            if v_end > page_span.len() {
                bail!("bbolt leaf key/value exceeds page span");
            }
            let key_bytes = &page_span[k_start..v_start];
            let val_bytes = &page_span[v_start..v_end];
            if (eflags & BBOLT_BUCKET_LEAF_FLAG) != 0 {
                if val_bytes.len() < 16 {
                    bail!("truncated bbolt sub-bucket header");
                }
                let sub_root =
                    u64::from_le_bytes(val_bytes[0..8].try_into().expect("8-byte sub_root"));
                if sub_root == 0 {
                    if val_bytes.len() > 16 {
                        walk_bbolt_page_slice(
                            src,
                            page_size,
                            &val_bytes[16..],
                            depth + 1,
                            visited,
                            cumulative_bytes,
                            out,
                        )?;
                    }
                } else {
                    walk_bbolt_page_id(
                        src,
                        page_size,
                        sub_root,
                        depth + 1,
                        visited,
                        cumulative_bytes,
                        out,
                    )?;
                }
            } else if let Some(record) = decode_bolt_telemetry_leaf(key_bytes, val_bytes) {
                out.push(record);
            }
        }
        Ok(())
    } else {
        bail!("unsupported bbolt tree page flags 0x{flags:04x}");
    }
}

fn parse_boltdb_telemetry_from_source<S: BoltByteSource>(
    src: &S,
) -> Result<Vec<NewTelemetryRecord>> {
    let Some(meta) = select_best_bbolt_meta_from_source(src) else {
        bail!("no valid bbolt v2 meta page with matching FNV-1a checksum");
    };
    if meta.root_pgid < 2 {
        return Ok(Vec::new());
    }
    let mut visited = HashSet::new();
    let mut cumulative_bytes = 0usize;
    let mut records = Vec::new();
    walk_bbolt_page_id(
        src,
        meta.page_size,
        meta.root_pgid,
        0,
        &mut visited,
        &mut cumulative_bytes,
        &mut records,
    )?;
    records.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.uuid.cmp(&b.uuid))
    });
    records.dedup_by(|a, b| a.uuid == b.uuid);
    Ok(records)
}

pub fn parse_boltdb_telemetry_bytes(data: &[u8]) -> Result<Vec<NewTelemetryRecord>> {
    parse_boltdb_telemetry_from_source(&data)
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

fn discover_and_import_legacy_bolt_backups(
    db_path: &Path,
    primary_backup: Option<&Path>,
    sibling_backup: Option<&Path>,
    conn: &mut Connection,
    max_rows: usize,
) {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = primary_backup {
        candidates.push(p.to_path_buf());
    }
    if let Some(s) = sibling_backup {
        if !candidates.iter().any(|c| c == s) {
            candidates.push(s.to_path_buf());
        }
    }
    if let (Some(parent), Some(db_fname)) = (
        db_path.parent(),
        db_path.file_name().and_then(|s| s.to_str()),
    ) {
        if let Ok(entries) = fs::read_dir(parent) {
            let bak_exact = format!("{db_fname}.bak");
            let bak_prefix = format!("{db_fname}.bak.");
            let bolt_bak_exact = format!("{db_fname}.bolt.bak");
            let bolt_bak_prefix = format!("{db_fname}.bolt.bak.");
            let pre_migrate_prefix = format!("{db_fname}.pre-migrate.");
            let mut extra: Vec<PathBuf> = Vec::new();
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if !ft.is_file() {
                    continue;
                }
                let fname_os = entry.file_name();
                let Some(fname) = fname_os.to_str() else {
                    continue;
                };
                let is_bolt_backup = fname == bak_exact
                    || fname.starts_with(&bak_prefix)
                    || fname == bolt_bak_exact
                    || fname.starts_with(&bolt_bak_prefix)
                    || fname == "speedtest.bolt.bak"
                    || fname.starts_with("speedtest.bolt.bak.")
                    || fname == "speedtest.bolt.bolt.bak"
                    || fname.starts_with("speedtest.bolt.bolt.bak.")
                    || ((fname.starts_with(&pre_migrate_prefix)
                        || fname.starts_with("speedtest.bolt.pre-migrate."))
                        && fname.ends_with(".bak"));
                if is_bolt_backup {
                    let path = entry.path();
                    if !candidates.iter().any(|c| c == &path) {
                        extra.push(path);
                    }
                }
            }
            extra.sort();
            candidates.extend(extra);
        }
    }

    for cand in candidates {
        let Some(source_name) = cand.file_name().and_then(|s| s.to_str()).map(str::to_owned) else {
            continue;
        };
        let already_migrated: bool = conn
            .query_row(
                "SELECT 1 FROM telemetry_bolt_migrations WHERE source_name = ?1 LIMIT 1",
                params![&source_name],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false);
        if already_migrated {
            continue;
        }
        import_legacy_boltdb_if_valid(&cand, &source_name, conn, max_rows);
    }
}

fn import_legacy_boltdb_if_valid(
    backup_path: &Path,
    source_name: &str,
    conn: &mut Connection,
    max_rows: usize,
) {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(backup_path)
    {
        Ok(f) => f,
        Err(err) => {
            warn!(
                backup = %backup_path.display(),
                error = %err,
                "Skipping legacy BoltDB telemetry import: failed opening backup"
            );
            return;
        }
    };
    let Ok(meta) = file.metadata() else {
        return;
    };
    if !meta.is_file() {
        warn!(
            backup = %backup_path.display(),
            "Skipping legacy BoltDB telemetry import: backup is not a regular file"
        );
        return;
    }
    if meta.len() < 80 {
        warn!(
            backup = %backup_path.display(),
            size_bytes = meta.len(),
            "Legacy non-SQLite backup is smaller than bbolt header; leaving eligible for repair"
        );
        return;
    }

    let src = FileBoltSource {
        file,
        len: meta.len(),
    };
    let mut records = match parse_boltdb_telemetry_from_source(&src) {
        Ok(r) => r,
        Err(err) => {
            warn!(
                backup = %backup_path.display(),
                reason = %err,
                "Legacy non-SQLite backup is not an importable BoltDB v2 archive; leaving unrecorded for retry after repair"
            );
            return;
        }
    };
    if records.is_empty() {
        return;
    }
    records.sort_by(|a, b| {
        let a_ms = parse_timestamp_epoch_ms(&a.timestamp);
        let b_ms = parse_timestamp_epoch_ms(&b.timestamp);
        b_ms.cmp(&a_ms)
            .then_with(|| b.timestamp.cmp(&a.timestamp))
            .then_with(|| b.uuid.cmp(&a.uuid))
    });
    if records.len() > max_rows {
        records.truncate(max_rows);
    }
    // Insert oldest-to-newest among retained BoltDB rows so `id` increases chronologically too.
    records.reverse();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let imported = (|| -> Result<usize> {
        let tx = conn.transaction()?;
        let mut inserted = 0usize;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO speedtest_users
                 (uuid, timestamp, ts_epoch_ms, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?;
            let mut legacy_id_stmt = tx.prepare(
                "INSERT OR IGNORE INTO telemetry_legacy_raw_ids (uuid, ulid_suffix) VALUES (?1, ?2)",
            )?;
            for rec in &records {
                let ts_epoch_ms = parse_timestamp_epoch_ms(&rec.timestamp);
                inserted += stmt.execute(params![
                    rec.uuid,
                    rec.timestamp,
                    ts_epoch_ms,
                    rec.ip,
                    rec.ispinfo,
                    rec.extra,
                    rec.ua,
                    rec.lang,
                    rec.dl,
                    rec.ul,
                    rec.ping,
                    rec.jitter,
                    rec.log,
                ])?;
                let suffix_opt = ulid_suffix_blob(&rec.uuid);
                legacy_id_stmt
                    .execute(params![rec.uuid, suffix_opt.as_ref().map(|b| b.as_slice())])?;
            }
        }
        enforce_retention_on_conn(&tx, max_rows)?;
        tx.execute(
            "INSERT OR IGNORE INTO telemetry_bolt_migrations (source_name, imported_at) VALUES (?1, ?2)",
            params![source_name, now_ts],
        )?;
        tx.commit()?;
        Ok(inserted)
    })();

    match imported {
        Ok(n) => {
            info!(
                backup_path = %backup_path.display(),
                imported_rows = n,
                "Migrated legacy BoltDB speedtest history into SQLite WAL telemetry vault"
            );
        }
        Err(err) => {
            warn!(
                backup_path = %backup_path.display(),
                error = %err,
                "Failed inserting migrated BoltDB rows into SQLite vault"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let unique = format!(
                "af-librespeed-db-{}-{}-{}",
                label,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            let dir = std::env::temp_dir().join(unique);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn opens_wal_vault_with_0600_perms_and_roundtrips_records() {
        let tmp = TempDirGuard::new("roundtrip");
        let db_path = tmp.0.join("nested").join("speedtest.db");

        let vault = TelemetryVault::open(&db_path).expect("open vault");
        let mode = fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        vault
            .insert(NewTelemetryRecord {
                uuid: "01JABCDEFGHJKMNPQRSTVWXYZ0".to_string(),
                timestamp: "2026-11-15T01:02:03.004Z".to_string(),
                ip: "198.51.100.1".to_string(),
                ispinfo: r#"{"processedString":"198.51.100.1"}"#.to_string(),
                extra: "tag=alpha".to_string(),
                ua: "Mozilla/5.0".to_string(),
                lang: "en-US".to_string(),
                dl: "912.34".to_string(),
                ul: "456.78".to_string(),
                ping: "4.25".to_string(),
                jitter: "0.75".to_string(),
                log: "ok".to_string(),
            })
            .await
            .unwrap();

        let fetched = vault
            .get_by_uuid("01JABCDEFGHJKMNPQRSTVWXYZ0".to_string())
            .await
            .unwrap()
            .expect("record exists");
        assert_eq!(fetched.dl, "912.34");
        assert_eq!(fetched.extra, "tag=alpha");

        let recent = vault.list_recent(10).await.unwrap();
        assert_eq!(recent.len(), 1);

        // Verify obfuscation_key persists across reopen and pre-existing 0644 perms tighten to 0600
        let first_key = *vault.obfuscation_key();
        drop(vault);
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o644)).unwrap();
        let reopened = TelemetryVault::open(&db_path).expect("reopen vault");
        assert_eq!(reopened.obfuscation_key(), &first_key);
        let tightened = fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(tightened, 0o600);
    }

    #[test]
    fn backs_up_legacy_boltdb_header_before_sqlite_init() {
        let tmp = TempDirGuard::new("bolt");
        let db_path = tmp.0.join("speedtest.db");
        let mut fake_bolt = vec![0u8; 64];
        fake_bolt[12..16].copy_from_slice(&[0xED, 0xDA, 0x0C, 0xED]);
        fs::write(&db_path, &fake_bolt).unwrap();
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o644)).unwrap();

        let _vault = TelemetryVault::open(&db_path).expect("open migrated vault");
        let bak_path = tmp.0.join("speedtest.db.bolt.bak");
        assert!(bak_path.exists());
        assert_eq!(fs::read(&bak_path).unwrap(), fake_bolt);
        let bak_mode = fs::metadata(&bak_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(bak_mode, 0o600);

        let header = &fs::read(&db_path).unwrap()[..16];
        assert_eq!(header, SQLITE_MAGIC);

        // Second non-SQLite migration never overwrites existing .bolt.bak (nor a pre-existing .bolt.bak.<ts>)
        let mut second_bolt = vec![0xA5u8; 64];
        second_bolt[12..16].copy_from_slice(&[0xED, 0xDA, 0x0C, 0xED]);
        fs::write(&db_path, &second_bolt).unwrap();
        let _vault2 = TelemetryVault::open(&db_path).expect("open second migrated vault");
        assert_eq!(fs::read(&bak_path).unwrap(), fake_bolt);
        let extra_baks: Vec<_> = fs::read_dir(&tmp.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p != &bak_path
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("speedtest.db.bolt.bak."))
            })
            .collect();
        assert_eq!(extra_baks.len(), 1);
        assert_eq!(fs::read(&extra_baks[0]).unwrap(), second_bolt);
    }

    #[test]
    fn rejects_world_writable_parent_dir_including_sticky() {
        let tmp = TempDirGuard::new("world-writable");
        for mode in [0o777, 0o1777] {
            let insecure_dir = tmp.0.join(format!("insecure-{mode:o}"));
            fs::create_dir_all(&insecure_dir).unwrap();
            fs::set_permissions(&insecure_dir, fs::Permissions::from_mode(mode)).unwrap();
            let res = TelemetryVault::open(&insecure_dir.join("speedtest.db"));
            fs::set_permissions(&insecure_dir, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                res.is_err(),
                "expected world-writable mode {mode:o} to fail"
            );
        }
    }

    #[test]
    fn rejects_symlinked_db_sidecar_and_parent() {
        let tmp = TempDirGuard::new("symlink");
        let target = tmp.0.join("real.db");
        fs::write(&target, b"").unwrap();

        let sym_db = tmp.0.join("sym.db");
        symlink(&target, &sym_db).unwrap();
        assert!(TelemetryVault::open(&sym_db).is_err());

        let normal_db = tmp.0.join("normal.db");
        let wal_link = tmp.0.join("normal.db-wal");
        symlink(&target, &wal_link).unwrap();
        assert!(TelemetryVault::open(&normal_db).is_err());

        let journal_db = tmp.0.join("journal.db");
        let journal_link = tmp.0.join("journal.db-journal");
        symlink(&target, &journal_link).unwrap();
        assert!(TelemetryVault::open(&journal_db).is_err());

        let real_dir = tmp.0.join("real_dir");
        fs::create_dir_all(&real_dir).unwrap();
        let sym_dir = tmp.0.join("sym_dir");
        symlink(&real_dir, &sym_dir).unwrap();
        assert!(TelemetryVault::open(&sym_dir.join("sub.db")).is_err());
    }

    fn write_test_bbolt_meta_page(
        buf: &mut [u8],
        pgid: u64,
        page_size: u32,
        root_pgid: u64,
        txid: u64,
    ) {
        buf.fill(0);
        buf[0..8].copy_from_slice(&pgid.to_le_bytes());
        buf[8..10].copy_from_slice(&BBOLT_META_FLAG.to_le_bytes());
        buf[16..20].copy_from_slice(&BBOLT_MAGIC.to_le_bytes());
        buf[20..24].copy_from_slice(&BBOLT_VERSION.to_le_bytes());
        buf[24..28].copy_from_slice(&page_size.to_le_bytes());
        buf[32..40].copy_from_slice(&root_pgid.to_le_bytes());
        buf[56..64].copy_from_slice(&(pgid + 5).to_le_bytes());
        buf[64..72].copy_from_slice(&txid.to_le_bytes());
        let checksum = fnv1a_64(&buf[16..72]);
        buf[72..80].copy_from_slice(&checksum.to_le_bytes());
    }

    fn build_leaf_page_bytes(pgid: u64, page_len: usize, items: &[(u32, &[u8], &[u8])]) -> Vec<u8> {
        let mut page = vec![0u8; page_len];
        page[0..8].copy_from_slice(&pgid.to_le_bytes());
        page[8..10].copy_from_slice(&BBOLT_LEAF_FLAG.to_le_bytes());
        page[10..12].copy_from_slice(&(items.len() as u16).to_le_bytes());
        let mut data_cursor = BBOLT_PAGE_HEADER_BYTES + items.len() * 16;
        for (idx, (eflags, k, v)) in items.iter().enumerate() {
            let elem_off = BBOLT_PAGE_HEADER_BYTES + idx * 16;
            let pos = (data_cursor - elem_off) as u32;
            page[elem_off..elem_off + 4].copy_from_slice(&eflags.to_le_bytes());
            page[elem_off + 4..elem_off + 8].copy_from_slice(&pos.to_le_bytes());
            page[elem_off + 8..elem_off + 12].copy_from_slice(&(k.len() as u32).to_le_bytes());
            page[elem_off + 12..elem_off + 16].copy_from_slice(&(v.len() as u32).to_le_bytes());
            page[data_cursor..data_cursor + k.len()].copy_from_slice(k);
            data_cursor += k.len();
            page[data_cursor..data_cursor + v.len()].copy_from_slice(v);
            data_cursor += v.len();
        }
        page
    }

    #[tokio::test]
    async fn migrates_legacy_bbolt_v2_records_both_paged_and_inline_buckets_and_preserves_backup() {
        let page_size = 4096usize;
        let mut archive = vec![0u8; page_size * 5];

        // Page 0: older meta (txid=1, bogus root 99); Page 1: newer committed meta (txid=2, root=2)
        write_test_bbolt_meta_page(&mut archive[0..page_size], 0, page_size as u32, 99, 1);
        write_test_bbolt_meta_page(
            &mut archive[page_size..page_size * 2],
            1,
            page_size as u32,
            2,
            2,
        );

        // Inline sub-bucket value (16-byte bucket header with root=0 + embedded leaf page)
        let inline_json = br#"{"uuid":"01JABCDEFGHJKMNPQRSTVWXYZ2","timestamp":"2026-11-15T10:02:00.000Z","ip":"198.51.100.8","dl":"888.88","ul":"444.44","ping":"2.50","jitter":"0.25","extra":"inline-bucket"}"#;
        let inline_leaf = build_leaf_page_bytes(
            0,
            320,
            &[(0, b"01JABCDEFGHJKMNPQRSTVWXYZ2", inline_json.as_slice())],
        );
        let mut inline_bucket_val = vec![0u8; 16 + inline_leaf.len()];
        inline_bucket_val[16..].copy_from_slice(&inline_leaf);

        // Normal sub-bucket value pointing to branch page 3
        let mut paged_bucket_val = [0u8; 16];
        paged_bucket_val[0..8].copy_from_slice(&3u64.to_le_bytes());

        // Page 2: root leaf page containing both buckets
        let root_page = build_leaf_page_bytes(
            2,
            page_size,
            &[
                (
                    BBOLT_BUCKET_LEAF_FLAG,
                    b"inline_speedtest",
                    &inline_bucket_val,
                ),
                (BBOLT_BUCKET_LEAF_FLAG, b"speedtest", &paged_bucket_val),
            ],
        );
        archive[page_size * 2..page_size * 3].copy_from_slice(&root_page);

        // Page 3: branch page pointing to leaf page 4
        {
            let branch = &mut archive[page_size * 3..page_size * 4];
            branch[0..8].copy_from_slice(&3u64.to_le_bytes());
            branch[8..10].copy_from_slice(&BBOLT_BRANCH_FLAG.to_le_bytes());
            branch[10..12].copy_from_slice(&1u16.to_le_bytes());
            let elem_off = BBOLT_PAGE_HEADER_BYTES;
            let key = b"01JABCDEFGHJKMNPQRSTVWXYZ1";
            branch[elem_off..elem_off + 4].copy_from_slice(&16u32.to_le_bytes());
            branch[elem_off + 4..elem_off + 8].copy_from_slice(&(key.len() as u32).to_le_bytes());
            branch[elem_off + 8..elem_off + 16].copy_from_slice(&4u64.to_le_bytes());
            branch[elem_off + 16..elem_off + 16 + key.len()].copy_from_slice(key);
        }

        // Page 4: leaf page with Go speedtest-go PascalCase TelemetryData record
        let go_json = br#"{"UUID":"01JABCDEFGHJKMNPQRSTVWXYZ1","Timestamp":"2026-11-15T10:01:00.000Z","IPAddress":"198.51.100.7","ISPInfo":"{\"processedString\":\"198.51.100.7 - ExampleISP\"}","Extra":"paged-bucket","UserAgent":"GoSpeedtest/1.1","Language":"en-US","Download":"777.77","Upload":"333.33","Ping":"3.10","Jitter":"0.40","Log":"ok"}"#;
        let leaf_page = build_leaf_page_bytes(
            4,
            page_size,
            &[(0, b"01JABCDEFGHJKMNPQRSTVWXYZ1", go_json.as_slice())],
        );
        archive[page_size * 4..page_size * 5].copy_from_slice(&leaf_page);

        let tmp = TempDirGuard::new("bolt-v2-import");
        let db_path = tmp.0.join("speedtest.db");
        fs::write(&db_path, &archive).unwrap();

        let vault = TelemetryVault::open(&db_path).expect("open & migrate bbolt v2");
        let bak_path = tmp.0.join("speedtest.db.bolt.bak");
        assert_eq!(fs::read(&bak_path).unwrap(), archive);
        assert_eq!(
            fs::metadata(&bak_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let recent = vault.list_recent(10).await.unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ2");
        assert_eq!(recent[0].dl, "888.88");
        assert_eq!(recent[0].extra, "inline-bucket");
        assert_eq!(recent[1].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ1");
        assert_eq!(recent[1].dl, "777.77");
        assert_eq!(recent[1].extra, "paged-bucket");

        let by_id = vault
            .get_by_uuid("01JABCDEFGHJKMNPQRSTVWXYZ1".to_string())
            .await
            .unwrap()
            .expect("migrated record retrievable by ULID");
        assert_eq!(by_id.ul, "333.33");
        assert_eq!(by_id.ip, "198.51.100.7");

        // Cyclic branch page self-reference must be rejected cleanly
        let mut cyclic = archive.clone();
        let self_off = page_size * 3 + BBOLT_PAGE_HEADER_BYTES + 8;
        cyclic[self_off..self_off + 8].copy_from_slice(&3u64.to_le_bytes());
        assert!(parse_boltdb_telemetry_bytes(&cyclic).is_err());

        // Crash-resumable migration: simulate process crash right after BoltDB was renamed to
        // `speedtest.db.bolt.bak` (before SQLite imported rows), and confirm next startup
        // discovers `.bolt.bak`, imports records once, and records legacy raw IDs.
        let crash_tmp = TempDirGuard::new("bolt-crash-resume");
        let crash_db = crash_tmp.0.join("speedtest.db");
        let crash_bak = crash_tmp.0.join("speedtest.db.bolt.bak");
        fs::write(&crash_bak, &archive).unwrap();
        let resumed = TelemetryVault::open(&crash_db).expect("resume interrupted bolt migration");
        assert_eq!(resumed.list_recent(10).await.unwrap().len(), 2);
        assert!(resumed
            .is_legacy_raw_id("01JABCDEFGHJKMNPQRSTVWXYZ1".to_string())
            .await
            .unwrap());

        // In-memory vault supports full telemetry lifecycle without touching disk
        let mem_vault = TelemetryVault::open_in_memory(10).expect("in-memory vault");
        assert_eq!(mem_vault.path(), Path::new(":memory:"));
    }

    fn build_single_record_bbolt_archive(uuid: &str, timestamp: &str, dl: &str) -> Vec<u8> {
        let page_size = 4096usize;
        let mut archive = vec![0u8; page_size * 4];
        write_test_bbolt_meta_page(&mut archive[0..page_size], 0, page_size as u32, 2, 1);
        write_test_bbolt_meta_page(
            &mut archive[page_size..page_size * 2],
            1,
            page_size as u32,
            2,
            2,
        );
        let mut bucket_val = [0u8; 16];
        bucket_val[0..8].copy_from_slice(&3u64.to_le_bytes());
        let root_page = build_leaf_page_bytes(
            2,
            page_size,
            &[(BBOLT_BUCKET_LEAF_FLAG, b"speedtest", &bucket_val)],
        );
        archive[page_size * 2..page_size * 3].copy_from_slice(&root_page);

        let payload = format!(
            r#"{{"uuid":"{uuid}","timestamp":"{timestamp}","ip":"198.51.100.9","dl":"{dl}","ul":"100.0","ping":"1.5","jitter":"0.2"}}"#
        );
        let leaf_page =
            build_leaf_page_bytes(3, page_size, &[(0, uuid.as_bytes(), payload.as_bytes())]);
        archive[page_size * 3..page_size * 4].copy_from_slice(&leaf_page);
        archive
    }

    #[tokio::test]
    async fn migrates_sparse_128mib_bbolt_via_pread_and_retries_after_repair() {
        let tmp = TempDirGuard::new("sparse-128m-and-retry");
        let db_path = tmp.0.join("speedtest.db");
        let sparse_bak = tmp.0.join("speedtest.bolt.bak");

        // 1. Truncated/unreadable backup must NOT be permanently marked migrated
        fs::write(&sparse_bak, b"truncated-partial-copy").unwrap();
        {
            let v1 = TelemetryVault::open(&db_path).expect("open with truncated backup");
            assert!(v1.list_recent(10).await.unwrap().is_empty());
        }

        // 2. Repair the backup into a sparse 128 MiB BoltDB v2 file (> old 64 MiB limit)
        //    with leaf page placed at 96 MiB (pgid = 24_576 * 4096)
        let page_size = 4096usize;
        let high_leaf_pgid: u64 = 24_576;
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&sparse_bak)
            .unwrap();
        f.set_len(128 * 1024 * 1024).unwrap();
        let mut meta0 = vec![0u8; page_size];
        let mut meta1 = vec![0u8; page_size];
        write_test_bbolt_meta_page(&mut meta0, 0, page_size as u32, 2, 1);
        write_test_bbolt_meta_page(&mut meta1, 1, page_size as u32, 2, 2);
        f.write_all_at(&meta0, 0).unwrap();
        f.write_all_at(&meta1, page_size as u64).unwrap();

        let mut bucket_val = [0u8; 16];
        bucket_val[0..8].copy_from_slice(&high_leaf_pgid.to_le_bytes());
        let root_page = build_leaf_page_bytes(
            2,
            page_size,
            &[(BBOLT_BUCKET_LEAF_FLAG, b"speedtest", &bucket_val)],
        );
        f.write_all_at(&root_page, (page_size * 2) as u64).unwrap();

        let rec_json = br#"{"uuid":"01JABCDEFGHJKMNPQRSTVWXYZ9","timestamp":"2026-11-15T12:00:00.000Z","dl":"950.5","ul":"450.2","ping":"1.9","jitter":"0.1"}"#;
        let high_leaf = build_leaf_page_bytes(
            high_leaf_pgid,
            page_size,
            &[(0, b"01JABCDEFGHJKMNPQRSTVWXYZ9", rec_json.as_slice())],
        );
        f.write_all_at(&high_leaf, high_leaf_pgid * page_size as u64)
            .unwrap();
        drop(f);

        let v2 = TelemetryVault::open(&db_path).expect("reopen after repairing 128 MiB boltdb");
        let rows = v2.list_recent(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ9");
        assert_eq!(rows[0].dl, "950.5");
    }

    #[tokio::test]
    async fn bolt_extension_backup_naming_multi_backup_retention_and_legacy_go_share_ids() {
        use crate::ulid::encode_legacy_go_obfuscated_ulid;

        // 1. Direct `.bolt` database_file backs up to `speedtest.bolt.bak` (not `.bolt.bolt.bak`)
        let tmp_bolt = TempDirGuard::new("dot-bolt-naming");
        let dot_bolt_db = tmp_bolt.0.join("speedtest.bolt");
        let arch1 = build_single_record_bbolt_archive(
            "01JABCDEFGHJKMNPQRSTVWXYZ3",
            "2026-11-15T09:00:00.000Z",
            "500.0",
        );
        fs::write(&dot_bolt_db, &arch1).unwrap();
        let salt = [0x12, 0x34, 0x56, 0x78];
        let salt_path = tmp_bolt.0.join("idObfuscation_salt.bin");
        fs::write(&salt_path, salt).unwrap();
        fs::set_permissions(&salt_path, fs::Permissions::from_mode(0o644)).unwrap();

        let v_bolt = TelemetryVault::open(&dot_bolt_db).expect("migrate speedtest.bolt");
        assert!(tmp_bolt.0.join("speedtest.bolt.bak").is_file());
        assert!(!tmp_bolt.0.join("speedtest.bolt.bolt.bak").exists());
        assert_eq!(
            fs::metadata(&salt_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(v_bolt.legacy_go_salt(), Some(salt));

        let go_tok = encode_legacy_go_obfuscated_ulid("01JABCDEFGHJKMNPQRSTVWXYZ3", &salt).unwrap();
        assert_eq!(
            v_bolt
                .resolve_legacy_go_share_id(go_tok.clone())
                .await
                .unwrap()
                .as_deref(),
            Some("01JABCDEFGHJKMNPQRSTVWXYZ3")
        );

        // 2. Multi-backup global `max_rows = 1` cap + crash-resume of `.bolt.bolt.bak` + saltless 96-bit fallback
        let tmp_cap = TempDirGuard::new("multi-backup-cap");
        let cap_db = tmp_cap.0.join("speedtest.db");
        let older = build_single_record_bbolt_archive(
            "01JABCDEFGHJKMNPQRSTVWXYZ4",
            "2026-11-15T08:00:00.000Z",
            "300.0",
        );
        let newer = build_single_record_bbolt_archive(
            "01JABCDEFGHJKMNPQRSTVWXYZ5",
            "2026-11-15T11:00:00.000Z",
            "999.0",
        );
        fs::write(tmp_cap.0.join("speedtest.bolt.bolt.bak"), &older).unwrap();
        fs::write(tmp_cap.0.join("speedtest.db.bolt.bak"), &newer).unwrap();

        let v_cap = TelemetryVault::open_with_max_rows(&cap_db, 1).expect("open with max_rows=1");
        let kept = v_cap.list_recent(10).await.unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ5");
        assert!(!v_cap
            .is_legacy_raw_id("01JABCDEFGHJKMNPQRSTVWXYZ4".to_string())
            .await
            .unwrap());

        // Saltless 96-bit suffix fallback resolves unique migrated ULID even without idObfuscation_salt.bin
        let unknown_salt_tok = encode_legacy_go_obfuscated_ulid(
            "01JABCDEFGHJKMNPQRSTVWXYZ5",
            &[0xAA, 0xBB, 0xCC, 0xDD],
        )
        .unwrap();
        assert_eq!(v_cap.legacy_go_salt(), None);
        assert_eq!(
            v_cap
                .resolve_legacy_go_share_id(unknown_salt_tok)
                .await
                .unwrap()
                .as_deref(),
            Some("01JABCDEFGHJKMNPQRSTVWXYZ5")
        );
    }

    #[tokio::test]
    async fn reopen_enforces_lowered_max_rows_and_mixed_offset_timestamp_ordering() {
        let tmp = TempDirGuard::new("reopen-retention-offsets");
        let db_path = tmp.0.join("speedtest.db");

        // 1. Insert 3 records with mixed timezone offsets where row insertion order != UTC chronological order:
        // - r1: 2026-11-15T18:00:00+02:00 == 16:00:00Z (middle)
        // - r2: 2026-11-15T15:30:00Z       == 15:30:00Z (oldest, inserted 2nd!)
        // - r3: 2026-11-15 16:45:00.250 +0000 UTC m=+12.34 == 16:45:00.250Z (newest, Go time.Time.String())
        {
            let v = TelemetryVault::open_with_max_rows(&db_path, 10).unwrap();
            for (uuid, ts, dl) in [
                (
                    "01JABCDEFGHJKMNPQRSTVWXYA1",
                    "2026-11-15T18:00:00+02:00",
                    "200.0",
                ),
                (
                    "01JABCDEFGHJKMNPQRSTVWXYA2",
                    "2026-11-15T15:30:00Z",
                    "100.0",
                ),
                (
                    "01JABCDEFGHJKMNPQRSTVWXYA3",
                    "2026-11-15 16:45:00.250 +0000 UTC m=+12.345",
                    "300.0",
                ),
            ] {
                v.insert_with_mode(
                    NewTelemetryRecord {
                        uuid: uuid.to_string(),
                        timestamp: ts.to_string(),
                        ip: "0.0.0.0".to_string(),
                        ispinfo: String::new(),
                        extra: String::new(),
                        ua: String::new(),
                        lang: String::new(),
                        dl: dl.to_string(),
                        ul: "50.0".to_string(),
                        ping: "4.0".to_string(),
                        jitter: "0.5".to_string(),
                        log: String::new(),
                    },
                    true,
                )
                .await
                .unwrap();
            }

            let ordered = v.list_recent(10).await.unwrap();
            let uuids: Vec<&str> = ordered.iter().map(|r| r.uuid.as_str()).collect();
            assert_eq!(
                uuids,
                vec![
                    "01JABCDEFGHJKMNPQRSTVWXYA3",
                    "01JABCDEFGHJKMNPQRSTVWXYA1",
                    "01JABCDEFGHJKMNPQRSTVWXYA2",
                ],
                "list_recent must order by parsed UTC epoch ms, not string or rowid order"
            );
        }

        // 2. Reopen the existing SQLite DB with lowered `max_rows = 2` (with NO BoltDB import);
        // the oldest UTC record (`A2`, 15:30Z) must be pruned immediately on reopen even though it had higher `id` than `A1`!
        let v_reopened = TelemetryVault::open_with_max_rows(&db_path, 2).unwrap();
        let after_reopen = v_reopened.list_recent(10).await.unwrap();
        let kept_uuids: Vec<&str> = after_reopen.iter().map(|r| r.uuid.as_str()).collect();
        assert_eq!(
            kept_uuids,
            vec!["01JABCDEFGHJKMNPQRSTVWXYA3", "01JABCDEFGHJKMNPQRSTVWXYA1"]
        );
        assert!(!v_reopened
            .is_legacy_raw_id("01JABCDEFGHJKMNPQRSTVWXYA2".to_string())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn first_open_of_pre_obfuscation_sqlite_db_backfills_ulid_suffix_without_salt() {
        use crate::ulid::{encode_legacy_go_obfuscated_ulid, generate_ulid};

        let tmp = TempDirGuard::new("first-open-legacy-suffix");
        let db_path = tmp.0.join("legacy_go.sql");

        let legacy_uuid = generate_ulid();
        let unknown_salt = [0xDE, 0xAD, 0xBE, 0xEF];
        let legacy_share_token =
            encode_legacy_go_obfuscated_ulid(&legacy_uuid, &unknown_salt).unwrap();

        // Simulate pre-existing Go SQLite database (`speedtest_users` only, no `telemetry_meta` or salt file)
        {
            let raw_conn = Connection::open(&db_path).unwrap();
            raw_conn
                .execute_batch(
                    "CREATE TABLE speedtest_users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        ispinfo TEXT,
                        extra TEXT,
                        ua TEXT NOT NULL,
                        lang TEXT NOT NULL,
                        dl TEXT,
                        ul TEXT,
                        ping TEXT,
                        jitter TEXT,
                        log TEXT,
                        uuid TEXT UNIQUE
                    );",
                )
                .unwrap();
            raw_conn
                .execute(
                    "INSERT INTO speedtest_users (timestamp, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log, uuid)
                     VALUES ('2026-11-15T10:00:00Z', '198.51.100.12', '', '', 'TestUA', 'en', '777.0', '333.0', '3.1', '0.2', '', ?1)",
                    params![&legacy_uuid],
                )
                .unwrap();
        }

        // Very FIRST open of TelemetryVault (no restart, no `idObfuscation_salt.bin` on disk)
        let vault = TelemetryVault::open(&db_path).unwrap();
        assert!(vault.legacy_go_salt.is_none());

        let resolved = vault
            .resolve_legacy_go_share_id(legacy_share_token)
            .await
            .unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some(legacy_uuid.as_str()),
            "first startup must backfill ulid_suffix so saltless Go XOR share tokens resolve immediately"
        );
    }
}
