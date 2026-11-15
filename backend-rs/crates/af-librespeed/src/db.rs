use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task;
use tracing::{info, warn};

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
}

impl TelemetryVault {
    pub fn open(db_path: &Path) -> Result<Self> {
        if db_path.as_os_str().is_empty() {
            bail!("database_file path is empty");
        }

        verify_no_symlinks_on_db_path(db_path)?;
        ensure_parent_dirs(db_path)?;
        guard_and_backup_legacy_boltdb(db_path)?;
        verify_sidecar_symlinks(db_path)?;

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

        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to open SQLite database {}", db_path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS telemetry_meta (
                 key TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS speedtest_users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 uuid TEXT NOT NULL UNIQUE,
                 timestamp TEXT NOT NULL,
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
                 ON speedtest_users (timestamp DESC, uuid DESC);",
        )
        .with_context(|| format!("failed to initialize schema at {}", db_path.display()))?;

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

        let obfuscation_key = if stored_blob.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&stored_blob);
            arr
        } else {
            conn.execute(
                "UPDATE telemetry_meta SET value = ?1 WHERE key = 'obfuscation_key'",
                params![candidate_key.as_slice()],
            )
            .context("failed to repair telemetry obfuscation_key")?;
            candidate_key
        };

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: db_path.to_path_buf(),
            obfuscation_key,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn obfuscation_key(&self) -> &[u8; 32] {
        &self.obfuscation_key
    }

    pub async fn insert(&self, record: NewTelemetryRecord) -> Result<()> {
        let conn_arc = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn_arc
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite vault mutex poisoned"))?;
            conn.execute(
                "INSERT INTO speedtest_users
                 (uuid, timestamp, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    record.uuid,
                    record.timestamp,
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
                     ORDER BY timestamp DESC, uuid DESC
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
    let wal_path = sidecar_path(db_path, "-wal");
    let shm_path = sidecar_path(db_path, "-shm");
    if let Some(meta) = check_not_symlink(&wal_path, "SQLite WAL sidecar")? {
        if meta.is_dir() {
            bail!("SQLite WAL sidecar is a directory: {}", wal_path.display());
        }
    }
    if let Some(meta) = check_not_symlink(&shm_path, "SQLite SHM sidecar")? {
        if meta.is_dir() {
            bail!("SQLite SHM sidecar is a directory: {}", shm_path.display());
        }
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

fn guard_and_backup_legacy_boltdb(db_path: &Path) -> Result<()> {
    let Some(meta) = check_not_symlink(db_path, "database_file")? else {
        return Ok(());
    };
    if !meta.is_file() {
        bail!("database_file is not a regular file: {}", db_path.display());
    }
    if meta.len() == 0 {
        return Ok(());
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
        return Ok(());
    }

    let mut backup_path = sidecar_path(db_path, ".bolt.bak");
    if check_not_symlink(&backup_path, "BoltDB backup path")?.is_some() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        backup_path = sidecar_path(db_path, &format!(".bolt.bak.{ts}"));
        check_not_symlink(&backup_path, "timestamped BoltDB backup path")?;
    }

    fs::rename(db_path, &backup_path).with_context(|| {
        format!(
            "failed to back up non-SQLite database {} to {}",
            db_path.display(),
            backup_path.display()
        )
    })?;
    warn!(
        old_path = %db_path.display(),
        backup_path = %backup_path.display(),
        "Detected non-SQLite/legacy BoltDB database file; moved aside before initializing SQLite WAL telemetry"
    );
    info!("SQLite telemetry initialized cleanly after legacy backup");
    Ok(())
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

        let _vault = TelemetryVault::open(&db_path).expect("open migrated vault");
        let bak_path = tmp.0.join("speedtest.db.bolt.bak");
        assert!(bak_path.exists());
        assert_eq!(fs::read(&bak_path).unwrap(), fake_bolt);

        let header = &fs::read(&db_path).unwrap()[..16];
        assert_eq!(header, SQLITE_MAGIC);
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

        let real_dir = tmp.0.join("real_dir");
        fs::create_dir_all(&real_dir).unwrap();
        let sym_dir = tmp.0.join("sym_dir");
        symlink(&real_dir, &sym_dir).unwrap();
        assert!(TelemetryVault::open(&sym_dir.join("sub.db")).is_err());
    }
}
