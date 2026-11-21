use super::{get_backup_dir, is_valid_backup_filename, MAX_BACKUP_UPLOAD_CHUNKS};
use anyhow::{ensure, Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

const STAGING_DIRECTORY: &str = ".upload-staging";
const STAGING_LOCK: &str = ".upload-staging.lock";
pub(super) const SESSION_METADATA: &str = "meta.json";

static SESSION_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^u-?[0-9]+-[a-zA-Z0-9_-]{1,48}-[a-zA-Z0-9_-]{1,64}$").unwrap());

#[derive(Clone, Copy)]
pub(super) struct StagingLimits {
    pub(super) part_bytes: u64,
    pub(super) sessions: usize,
    pub(super) idle_for: Duration,
}

impl StagingLimits {
    pub(super) const DEFAULT: Self = Self {
        // Keep enough room within a second 16 GiB for one assembled backup or chunk replacement.
        part_bytes: 16 * 1024 * 1024 * 1024,
        sessions: 32,
        idle_for: Duration::from_secs(24 * 60 * 60),
    };
}

#[derive(Default)]
pub(super) struct StagingUsage {
    pub(super) part_bytes: u64,
    pub(super) sessions: usize,
    pub(super) current: Option<SessionParts>,
}

#[derive(Default)]
pub(super) struct SessionParts {
    pub(super) bytes: u64,
    pub(super) received: usize,
}

pub(super) struct BackupStaging {
    root: PathBuf,
    // Keep this stable inode for all requests and sweeps on this backup directory.
    _lock: File,
}

impl BackupStaging {
    pub(super) fn acquire(backup_dir: &Path, wait: bool) -> Result<Option<Self>> {
        ensure_private_backup_dir(backup_dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(backup_dir.join(STAGING_LOCK))?;
        ensure_single_link_regular(&lock.metadata()?)?;
        if wait {
            lock.lock()?;
        } else {
            match lock.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => return Ok(None),
                Err(TryLockError::Error(err)) => return Err(err.into()),
            }
        }

        let root = backup_dir.join(STAGING_DIRECTORY);
        create_directory(&root)?;
        Ok(Some(Self { root, _lock: lock }))
    }

    pub(super) fn session_path(&self, filename: &str, session_key: &str) -> PathBuf {
        self.root.join(filename).join(session_key)
    }

    pub(super) fn scan(
        &self,
        now: SystemTime,
        idle_for: Duration,
        current: Option<(&Path, usize)>,
    ) -> Result<StagingUsage> {
        let mut usage = StagingUsage::default();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(filename) = name.to_str().filter(|name| is_valid_backup_filename(name)) else {
                continue;
            };
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let directory = entry.path();
            for session in fs::read_dir(&directory)? {
                let session = session?;
                if !session.file_type()?.is_dir()
                    || !session
                        .file_name()
                        .to_str()
                        .is_some_and(|name| SESSION_NAME.is_match(name))
                {
                    continue;
                }
                let path = session.path();
                let is_current = current.filter(|(target, _)| path == *target);
                let (parts, activity) =
                    inspect_session(&path, filename, is_current.map_or(0, |(_, total)| total))?;
                if activity.is_none() && remove_empty_directory(&path)? {
                    continue;
                }
                let last_activity = match activity {
                    Some(time) => time,
                    None => session.metadata()?.modified()?,
                };
                if now
                    .duration_since(last_activity)
                    .is_ok_and(|age| age >= idle_for)
                {
                    fs::remove_dir_all(&path)
                        .with_context(|| format!("expiring upload {}", path.display()))?;
                    continue;
                }
                usage.part_bytes = usage.part_bytes.saturating_add(parts.bytes);
                usage.sessions += 1;
                if is_current.is_some() {
                    usage.current = Some(parts);
                }
            }
            remove_empty_directory(&directory)?;
        }
        Ok(usage)
    }
}

pub(crate) fn maintain_backup_upload_staging() {
    if let Err(error) = sweep(&get_backup_dir(), StagingLimits::DEFAULT.idle_for) {
        tracing::warn!(%error, "backup upload staging cleanup failed");
    }
}

fn sweep(backup_dir: &Path, idle_for: Duration) -> Result<()> {
    // Avoid creating a staging tree on installations that never used chunk uploads.
    match fs::symlink_metadata(backup_dir.join(STAGING_DIRECTORY)) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        result => {
            ensure!(
                result?.is_dir(),
                "backup upload staging must be a directory"
            );
        }
    }
    if let Some(staging) = BackupStaging::acquire(backup_dir, false)? {
        staging.scan(SystemTime::now(), idle_for, None)?;
    }
    Ok(())
}

fn inspect_session(
    path: &Path,
    filename: &str,
    total_chunks: usize,
) -> Result<(SessionParts, Option<SystemTime>)> {
    let mut parts = SessionParts::default();
    let mut activity = None;
    let mut interrupted_writes = Vec::new();
    let assembly = format!("{filename}.uploading");
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let index = part_index(name);
        if index.is_some() || name == SESSION_METADATA {
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                activity = activity.max(Some(metadata.modified()?));
                if let Some(index) = index {
                    parts.bytes = parts.bytes.saturating_add(metadata.len());
                    if index < total_chunks && metadata.nlink() == 1 && metadata.len() != 0 {
                        parts.received += 1;
                    }
                }
            }
            continue;
        }
        let is_interrupted_write = name
            .strip_suffix(".tmp")
            .is_some_and(|name| name == SESSION_METADATA || part_index(name).is_some())
            || name == assembly
            || name
                .strip_prefix(&assembly)
                .is_some_and(|suffix| matches!(suffix, "-wal" | "-shm" | "-journal"));
        if is_interrupted_write && !entry.file_type()?.is_dir() {
            interrupted_writes.push(entry.path());
        }
    }

    // Only one request can write, replace or assemble parts while holding the staging lock.
    for interrupted in interrupted_writes {
        fs::remove_file(interrupted)?;
    }
    Ok((parts, activity))
}

fn part_index(name: &str) -> Option<usize> {
    let digits = name.strip_suffix(".part")?;
    if digits.len() != 6 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits
        .parse()
        .ok()
        .filter(|index| *index < MAX_BACKUP_UPLOAD_CHUNKS)
}

fn ensure_private_backup_dir(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!("parent traversal in backup directory {}", path.display())
            }
            Component::Normal(name) => {
                current.push(name);
                match fs::symlink_metadata(&current) {
                    Ok(meta) => ensure!(meta.is_dir(), "not a directory: {}", current.display()),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        create_directory(&current)?
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }
    }

    let directory = open_directory(path)?;
    let metadata = directory.metadata()?;
    let uid = unsafe { libc::geteuid() };
    ensure!(
        uid == 0 || metadata.uid() == uid,
        "backup directory is not owned by the service user: {}",
        path.display()
    );
    if metadata.mode() & 0o777 != 0o700 {
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(super) fn create_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if let Err(error) = sync_directory(parent) {
                let _ = fs::remove_dir(path);
                return Err(error.into());
            }
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            ensure!(
                fs::symlink_metadata(path)?.is_dir(),
                "not a directory: {}",
                path.display()
            );
        }
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

fn remove_empty_directory(path: &Path) -> io::Result<bool> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(false),
        Err(err) => Err(err),
    }
}

pub(super) fn remove_session(path: &Path) {
    if let Err(error) = fs::remove_dir_all(path)
        .and_then(|_| remove_empty_directory(path.parent().expect("session has a parent")))
    {
        tracing::warn!(%error, path = %path.display(), "could not remove backup upload session");
    }
}

pub(super) fn open_staged_file(path: &Path) -> Result<Option<File>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    ensure_single_link_regular(&file.metadata()?)?;
    Ok(Some(file))
}

fn ensure_single_link_regular(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "expected a single-link regular staging file"
    );
    Ok(())
}

pub(super) fn create_staged_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub(super) fn write_staged_file(path: &Path, temporary: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_staged_file(temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        sync_directory(path.parent().expect("staged file has a parent"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    open_directory(path)?.sync_all()
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        process_backup_chunk_upload, read_verified_backup_checksum, BackupUploadResult,
        BackupUploadSessionMeta,
    };
    use axum::http::StatusCode;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::symlink;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("af-backup-staging-{}", uuid::Uuid::new_v4()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn session(&self, filename: &str, id: &str) -> PathBuf {
            self.0
                .join(STAGING_DIRECTORY)
                .join(filename)
                .join(format!("u0-anon-{id}"))
        }

        fn legacy_part(&self, filename: &str, id: &str, bytes: &[u8]) -> PathBuf {
            let session = self.session(filename, id);
            fs::create_dir_all(&session).unwrap();
            let metadata = BackupUploadSessionMeta {
                total_chunks: 2,
                expected_sha256: None,
                user_id: 0,
                session_jti: "anon".into(),
                upload_id: id.into(),
            };
            fs::write(
                session.join(SESSION_METADATA),
                serde_json::to_vec(&metadata).unwrap(),
            )
            .unwrap();
            fs::write(session.join("000000.part"), bytes).unwrap();
            session
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn expire(session: &Path) {
        let old = SystemTime::now() - Duration::from_secs(25 * 60 * 60);
        for name in [SESSION_METADATA, "000000.part"] {
            File::open(session.join(name))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
    }

    fn upload(
        root: &Scratch,
        filename: &str,
        id: &str,
        index: usize,
        bytes: &[u8],
        limits: StagingLimits,
    ) -> BackupUploadResult {
        process_backup_chunk_upload(
            &root.0,
            filename,
            index,
            2,
            None,
            Some(id),
            None,
            bytes,
            limits,
        )
    }

    #[test]
    fn restart_sweep_reclaims_expired_sessions_and_interrupted_writes() {
        let root = Scratch::new();
        let abandoned = root.legacy_part("abandoned.sqlite", "old", b"old payload");
        expire(&abandoned);
        // A crash during assembly or a replacement must not extend the committed upload's lifetime.
        fs::write(
            abandoned.join("abandoned.sqlite.uploading"),
            b"partial assembly",
        )
        .unwrap();
        let recent = root.legacy_part("recent.sqlite", "live", b"committed");
        fs::write(recent.join("000000.part.tmp"), b"partial replacement").unwrap();
        fs::write(recent.join("meta.json.tmp"), b"incomplete metadata").unwrap();
        fs::write(recent.join("recent.sqlite.uploading"), b"partial assembly").unwrap();
        let orphan = root.session("orphan.sqlite", "interrupted");
        fs::create_dir_all(&orphan).unwrap();
        fs::write(orphan.join("meta.json.tmp"), b"incomplete metadata").unwrap();

        let sidecars = [
            root.0.join("abandoned.sqlite"),
            root.0.join("abandoned.sqlite.sha256"),
            root.0.join("abandoned.sqlite.manifest.json"),
            root.0.join("abandoned.sqlite.manifest.json.sha256"),
            root.0.join("abandoned.sqlite.part.00000"),
            root.0.join(STAGING_DIRECTORY).join("unrelated"),
        ];
        for path in &sidecars {
            fs::write(path, b"keep").unwrap();
        }

        let guard = BackupStaging::acquire(&root.0, true).unwrap().unwrap();
        sweep(&root.0, StagingLimits::DEFAULT.idle_for).unwrap();
        assert!(abandoned.exists(), "maintenance must skip an active writer");
        drop(guard);

        sweep(&root.0, StagingLimits::DEFAULT.idle_for).unwrap();
        assert!(!abandoned.parent().unwrap().exists());
        assert!(!orphan.parent().unwrap().exists());
        assert_eq!(fs::read(recent.join("000000.part")).unwrap(), b"committed");
        assert_eq!(fs::read_dir(&recent).unwrap().count(), 2);
        for path in sidecars {
            assert_eq!(fs::read(path).unwrap(), b"keep");
        }
    }

    #[test]
    fn admission_counts_legacy_parts_and_rejects_new_sessions_before_writing() {
        let root = Scratch::new();
        let limits = StagingLimits {
            part_bytes: 8,
            sessions: 2,
            ..StagingLimits::DEFAULT
        };
        let old = root.legacy_part("archive.sqlite", "legacy", b"123456789");
        let refused = upload(&root, "other.sqlite", "second", 0, b"x", limits).unwrap_err();
        assert_eq!(
            (refused.0, refused.1),
            (StatusCode::INSUFFICIENT_STORAGE, "BACKUP_STAGING_FULL")
        );
        assert!(!root
            .session("other.sqlite", "second")
            .parent()
            .unwrap()
            .exists());

        let retry = upload(&root, "archive.sqlite", "legacy", 0, b"123456789", limits).unwrap();
        assert_eq!(retry["received"], 1);
        upload(&root, "archive.sqlite", "legacy", 0, b"1234", limits).unwrap();
        upload(&root, "other.sqlite", "second", 0, b"567", limits).unwrap();
        let refused = upload(&root, "other.sqlite", "third", 0, b"x", limits).unwrap_err();
        assert_eq!(refused.0, StatusCode::INSUFFICIENT_STORAGE);
        assert!(!root.session("other.sqlite", "third").exists());

        expire(&old);
        upload(&root, "other.sqlite", "third", 0, b"xxxx", limits).unwrap();
        assert!(!old.exists());
        assert!(root.session("other.sqlite", "second").exists());
    }

    #[test]
    fn concurrent_admission_cannot_overcommit_the_part_budget() {
        let root = Scratch::new();
        let limits = StagingLimits {
            part_bytes: 4,
            ..StagingLimits::DEFAULT
        };
        let start = std::sync::Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let write = |id| {
                start.wait();
                upload(&root, "same.sqlite", id, 0, b"abc", limits)
            };
            let left = scope.spawn(move || write("left"));
            let right = scope.spawn(move || write("right"));
            [left.join().unwrap(), right.join().unwrap()]
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .into_iter()
                .find_map(|result| result.err())
                .unwrap()
                .0,
            StatusCode::INSUFFICIENT_STORAGE
        );
    }

    #[test]
    fn multipart_retry_recovers_committed_parts_and_frees_capacity() {
        let root = Scratch::new();
        let source = Scratch::new();
        let db_path = source.0.join("source.sqlite");
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE records (label TEXT); INSERT INTO records VALUES ('uploaded');",
            )
            .unwrap();
        let bytes = fs::read(db_path).unwrap();
        let (first, last) = bytes.split_at(bytes.len() / 2);
        let checksum = hex::encode(Sha256::digest(&bytes));
        let filename = "valid.sqlite";
        let limits = StagingLimits {
            part_bytes: bytes.len() as u64,
            sessions: 1,
            ..StagingLimits::DEFAULT
        };
        let send = |index, bytes| {
            process_backup_chunk_upload(
                &root.0,
                filename,
                index,
                2,
                Some(&checksum),
                None,
                None,
                bytes,
                limits,
            )
        };

        assert_eq!(send(0, first).unwrap()["complete"], false);
        assert_eq!(send(0, first).unwrap()["received"], 1);
        let session = root.session(filename, "default");
        let obstacle = root.0.join("valid.sqlite.manifest.json");
        fs::create_dir(&obstacle).unwrap();
        assert_eq!(
            send(1, last).unwrap_err().0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!root.0.join(filename).exists());
        assert_eq!(fs::read(session.join("000000.part")).unwrap(), first);
        assert_eq!(fs::read(session.join("000001.part")).unwrap(), last);
        assert!(!session.join("valid.sqlite.uploading").exists());

        fs::remove_dir(obstacle).unwrap();
        sweep(&root.0, limits.idle_for).unwrap();
        let complete = send(1, last).unwrap();
        assert_eq!(complete["complete"], true);
        assert_eq!(complete["checksum"], checksum);
        assert!(!session.parent().unwrap().exists());
        assert_eq!(
            read_verified_backup_checksum(&root.0, filename)
                .unwrap()
                .0
                .actual_sha256,
            checksum
        );

        upload(&root, "other.sqlite", "second", 0, first, limits).unwrap();
        assert_eq!(fs::read(root.0.join(filename)).unwrap(), bytes);
    }

    #[test]
    fn staging_never_follows_directory_or_part_symlinks() {
        let root = Scratch::new();
        let outside = Scratch::new();
        let limits = StagingLimits::DEFAULT;
        let victim = outside.0.join("target");
        fs::write(&victim, b"safe").unwrap();

        fs::create_dir(root.0.join(STAGING_DIRECTORY)).unwrap();
        let linked_dir = root.0.join(STAGING_DIRECTORY).join("linked.sqlite");
        symlink(&outside.0, &linked_dir).unwrap();
        assert_eq!(
            upload(&root, "linked.sqlite", "link", 0, b"unsafe", limits)
                .unwrap_err()
                .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 1);

        let session = root.legacy_part("archive.sqlite", "link", b"part");
        fs::remove_file(session.join("000000.part")).unwrap();
        symlink(&victim, session.join("000000.part")).unwrap();
        symlink(&victim, session.join("000001.part.tmp")).unwrap();
        assert_eq!(
            upload(&root, "archive.sqlite", "link", 0, b"overwrite", limits)
                .unwrap_err()
                .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(fs::read(&victim).unwrap(), b"safe");
        assert!(session.join("000000.part").is_symlink());
        assert!(!session.join("000001.part.tmp").is_symlink());
        assert!(linked_dir.is_symlink());
    }

    #[tokio::test]
    async fn mounted_upload_resumes_after_an_interrupted_body() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use axum::body::{to_bytes, Body};
        use axum::http::{header, HeaderMap, Request};
        use tower::ServiceExt;

        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let root = Scratch::new();
        let backup_dir = root.0.join("data/backups");
        std::env::set_var("AETHERFLOW_BACKUP_DIR", &backup_dir);
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users(id, username, role) VALUES(679, 'backup-upload', 'admin')",
            [],
        )
        .unwrap();
        drop(conn);
        let (token, _) = crate::auth::create_standard_jwt(679, &HeaderMap::new()).unwrap();
        let source = Scratch::new();
        let db_path = source.0.join("source.sqlite");
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY);")
            .unwrap();
        let bytes = fs::read(db_path).unwrap();
        let (first, last) = bytes.split_at(bytes.len() / 2);
        let app = crate::routes::build_router();
        let send = |index, body| {
            let request = Request::post(format!(
                "/api/v1/admin/backup/upload/staged.sqlite?chunk={index}&total=2&session_id=legacy"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header("X-Requested-With", "XMLHttpRequest")
            .body(body)
            .unwrap();
            app.clone().oneshot(request)
        };
        let first = send(0, Body::from(first.to_vec())).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let disconnected = Body::from_stream(futures::stream::iter([
            Ok(last[..4].to_vec()),
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "disconnected",
            )),
        ]));
        let rejected = send(1, disconnected).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert!(!backup_dir.join("staged.sqlite").exists());
        sweep(&backup_dir, StagingLimits::DEFAULT.idle_for).unwrap();

        let response = send(1, Body::from(last.to_vec())).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["complete"], true);
        assert_eq!(result["upload_id"], "legacy");
        assert_eq!(fs::read(backup_dir.join("staged.sqlite")).unwrap(), bytes);
    }
}
