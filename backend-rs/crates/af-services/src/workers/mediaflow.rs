use super::*;
use std::collections::VecDeque;

// ─────────────────────────────────────────────────────────────────────────────
// 5. MediaFlow Worker Poller
// ─────────────────────────────────────────────────────────────────────────────

pub(super) static MEDIAFLOW_POLLER_ACTIVE: AtomicBool = AtomicBool::new(false);
pub(super) static MEDIAFLOW_PROCESSING: AtomicBool = AtomicBool::new(false);
pub(super) static MEDIAFLOW_PROGRESS_TX: Lazy<tokio::sync::broadcast::Sender<String>> =
    Lazy::new(|| tokio::sync::broadcast::channel(256).0);

/// Subscribes to structured JSON MediaFlow progress events.
pub fn subscribe_mediaflow_progress() -> tokio::sync::broadcast::Receiver<String> {
    MEDIAFLOW_PROGRESS_TX.subscribe()
}

/// Broadcasts a structured JSON MediaFlow progress event to active subscribers.
pub fn publish_mediaflow_progress(event: &serde_json::Value) {
    let _ = MEDIAFLOW_PROGRESS_TX.send(event.to_string());
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct MediaflowTrashMeta {
    pub job_id: i64,
    pub trashed_at_unix: i64,
    pub original_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct MediaflowPublishIntent {
    pub job_id: i64,
    pub published_path: String,
    pub trash_entry_name: String,
    pub new_size: i64,
    #[serde(default)]
    pub source_fingerprint: String,
}

pub(super) fn publish_intent_filename(job_id: i64) -> String {
    format!(".publish_intent_{job_id}.json")
}

pub(super) fn trash_meta_filename(trash_entry_name: &str) -> String {
    format!("{trash_entry_name}.meta.json")
}

#[cfg(unix)]
pub(super) fn compute_published_media_mode(src_mode: u32) -> libc::mode_t {
    (((src_mode & 0o666) | 0o644) & 0o666) as libc::mode_t
}

/// Drains `reader` continuously until EOF so child processes (e.g. `ffmpeg`) never receive
/// `SIGPIPE` after 64 KiB of stderr output, retaining at most `head_cap + tail_cap` bytes
/// in memory for diagnostic reporting.
pub(super) async fn drain_stderr_bounded<R>(
    mut reader: R,
    head_cap: usize,
    tail_cap: usize,
) -> String
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut head: Vec<u8> = Vec::with_capacity(head_cap.min(16 * 1024));
    let mut tail: VecDeque<u8> = VecDeque::with_capacity(tail_cap.min(48 * 1024));
    let mut omitted_bytes: usize = 0;
    let mut chunk = [0u8; 8192];

    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let mut slice = &chunk[..n];
                if head.len() < head_cap {
                    let take = (head_cap - head.len()).min(slice.len());
                    head.extend_from_slice(&slice[..take]);
                    slice = &slice[take..];
                }
                if !slice.is_empty() {
                    if tail_cap == 0 {
                        omitted_bytes = omitted_bytes.saturating_add(slice.len());
                    } else if slice.len() >= tail_cap {
                        omitted_bytes = omitted_bytes
                            .saturating_add(tail.len())
                            .saturating_add(slice.len() - tail_cap);
                        tail.clear();
                        tail.extend(slice[slice.len() - tail_cap..].iter().copied());
                    } else {
                        let overflow = (tail.len() + slice.len()).saturating_sub(tail_cap);
                        if overflow > 0 {
                            omitted_bytes = omitted_bytes.saturating_add(overflow);
                            for _ in 0..overflow {
                                tail.pop_front();
                            }
                        }
                        tail.extend(slice.iter().copied());
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    if tail.is_empty() {
        return String::from_utf8_lossy(&head).into_owned();
    }

    let head_str = String::from_utf8_lossy(&head);
    let tail_vec: Vec<u8> = tail.into_iter().collect();
    let tail_str = String::from_utf8_lossy(&tail_vec);
    if omitted_bytes > 0 {
        format!("{head_str}\n...[omitted {omitted_bytes} bytes]...\n{tail_str}")
    } else {
        let mut combined = head;
        combined.extend_from_slice(&tail_vec);
        String::from_utf8_lossy(&combined).into_owned()
    }
}

pub(super) async fn probe_mediaflow_duration_secs(
    input_uri: &str,
    #[cfg(unix)] pinned_fd: Option<std::os::unix::io::RawFd>,
) -> Option<f64> {
    let mut cmd = Command::new("ffprobe");
    cmd.args([
        "-v",
        "error",
        "-show_entries",
        "format=duration",
        "-of",
        "default=noprint_wrappers=1:nokey=1",
        input_uri,
    ])
    .kill_on_drop(true);
    #[cfg(unix)]
    if let Some(raw_fd) = pinned_fd {
        unsafe {
            cmd.pre_exec(move || {
                let flags = libc::fcntl(raw_fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(raw_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let out = tokio::time::timeout(Duration::from_secs(5), cmd.output())
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|&d| d.is_finite() && d > 0.0)
}

pub(super) fn mediaflow_transcode_timeout() -> Duration {
    let secs = env::var("AETHERFLOW_MEDIAFLOW_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(4 * 3600);
    Duration::from_secs(secs)
}

pub(super) const DEFAULT_MEDIAFLOW_TRASH_RETENTION_SECS: u64 = 7 * 24 * 3600;

pub(super) fn mediaflow_trash_retention() -> Duration {
    let secs = env::var("MEDIAFLOW_TRASH_RETENTION_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MEDIAFLOW_TRASH_RETENTION_SECS);
    Duration::from_secs(secs)
}

pub const DEFAULT_MEDIAFLOW_ROOTS: &[&str] = &["/mnt", "/media", "/srv", "/data"];

/// Resolves MediaFlow's allowed candidate roots from an optional raw `AF_ALLOWED_FS_ROOTS`
/// string. When unset or empty, defaults align with the systemd writable roots
/// (`/mnt`, `/media`, `/srv`, `/data`) while preserving `ProtectHome=read-only`.
/// When explicitly configured, retains only valid existing absolute directories and
/// fails closed rather than silently falling back to defaults.
pub fn mediaflow_allowed_roots_from_raw(raw_env: Option<&str>) -> Vec<PathBuf> {
    let raw_roots: Vec<PathBuf> = match raw_env {
        Some(raw) if !raw.trim().is_empty() => raw
            .split([',', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .collect(),
        _ => DEFAULT_MEDIAFLOW_ROOTS.iter().map(PathBuf::from).collect(),
    };
    let mut resolved = Vec::new();
    for root in raw_roots {
        if let Ok(canon) = fs::canonicalize(&root) {
            if canon.is_dir() && !resolved.contains(&canon) {
                resolved.push(canon);
            }
        }
    }
    resolved
}

pub fn mediaflow_allowed_roots() -> Vec<PathBuf> {
    let env_val = env::var("AF_ALLOWED_FS_ROOTS").ok();
    mediaflow_allowed_roots_from_raw(env_val.as_deref())
}

pub fn is_path_within_allowed_mediaflow_roots(candidate: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| {
        if let Ok(canon_root) = fs::canonicalize(root) {
            canon_root.is_dir() && candidate.starts_with(&canon_root)
        } else {
            false
        }
    })
}

pub const MEDIAFLOW_MISSING_IDENTITY_MSG: &str =
    "Legacy queue entry is missing scanned source identity; re-scan and re-approve before transcoding";

pub const MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG: &str =
    "Source media file changed since scan/approval; re-scan and re-approve required before transcoding";

pub const MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG: &str =
    "Source media file changed during transcode; aborting publication to preserve replacement file";

pub const MEDIAFLOW_CANCELLED_MSG: &str = "Cancelled by administrator";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaflowSourceIdentity {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub fingerprint: String,
}

pub fn parse_stored_mediaflow_identity(
    source_dev: Option<i64>,
    source_ino: Option<i64>,
    source_size: Option<i64>,
    source_mtime_sec: Option<i64>,
    source_mtime_nsec: Option<i64>,
    source_fingerprint: Option<&str>,
) -> Option<MediaflowSourceIdentity> {
    let dev = source_dev? as u64;
    let ino = source_ino? as u64;
    let size_i64 = source_size?;
    if size_i64 < 0 {
        return None;
    }
    let mtime_sec = source_mtime_sec?;
    let mtime_nsec = source_mtime_nsec?;
    let fingerprint = source_fingerprint?.trim();
    if fingerprint.is_empty() {
        return None;
    }
    Some(MediaflowSourceIdentity {
        dev,
        ino,
        size: size_i64 as u64,
        mtime_sec,
        mtime_nsec,
        fingerprint: fingerprint.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelInflightOutcome {
    CancelSignalled,
    AlreadyPublishing,
    NotRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InflightPhase {
    Running,
    Cancelled,
    Publishing,
}

struct ActiveMediaflowJob {
    job_id: i64,
    phase: InflightPhase,
    cancel_tx: tokio::sync::watch::Sender<bool>,
}

static MEDIAFLOW_ACTIVE_JOB: Lazy<Mutex<Option<ActiveMediaflowJob>>> =
    Lazy::new(|| Mutex::new(None));

struct ActiveMediaflowJobGuard {
    job_id: i64,
}

impl Drop for ActiveMediaflowJobGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = MEDIAFLOW_ACTIVE_JOB.lock() {
            if guard.as_ref().is_some_and(|job| job.job_id == self.job_id) {
                *guard = None;
            }
        }
    }
}

fn register_active_mediaflow_job(
    job_id: i64,
) -> (ActiveMediaflowJobGuard, tokio::sync::watch::Receiver<bool>) {
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    if let Ok(mut guard) = MEDIAFLOW_ACTIVE_JOB.lock() {
        *guard = Some(ActiveMediaflowJob {
            job_id,
            phase: InflightPhase::Running,
            cancel_tx,
        });
    }
    (ActiveMediaflowJobGuard { job_id }, cancel_rx)
}

/// Signals an in-flight MediaFlow job to cancel before publication.
/// Returns `AlreadyPublishing` if the worker has already entered the atomic
/// publication critical section, or `NotRunning` if `job_id` is not currently active.
pub fn cancel_inflight_mediaflow_job(job_id: i64) -> CancelInflightOutcome {
    let Ok(mut guard) = MEDIAFLOW_ACTIVE_JOB.lock() else {
        return CancelInflightOutcome::NotRunning;
    };
    let Some(active) = guard.as_mut() else {
        return CancelInflightOutcome::NotRunning;
    };
    if active.job_id != job_id {
        return CancelInflightOutcome::NotRunning;
    }
    match active.phase {
        InflightPhase::Publishing => CancelInflightOutcome::AlreadyPublishing,
        InflightPhase::Cancelled => {
            let _ = active.cancel_tx.send(true);
            CancelInflightOutcome::CancelSignalled
        }
        InflightPhase::Running => {
            active.phase = InflightPhase::Cancelled;
            let _ = active.cancel_tx.send(true);
            CancelInflightOutcome::CancelSignalled
        }
    }
}

fn try_begin_mediaflow_publication(job_id: i64) -> bool {
    let Ok(mut guard) = MEDIAFLOW_ACTIVE_JOB.lock() else {
        return false;
    };
    let Some(active) = guard.as_mut() else {
        return false;
    };
    if active.job_id != job_id {
        return false;
    }
    if active.phase == InflightPhase::Running {
        active.phase = InflightPhase::Publishing;
        true
    } else {
        false
    }
}

async fn wait_for_mediaflow_cancel(rx: &mut tokio::sync::watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    loop {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
        if *rx.borrow() {
            return;
        }
    }
}

const MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES: usize = 64 * 1024;

#[cfg(unix)]
fn read_exact_at_file(file: &fs::File, offset: u64, buf: &mut [u8]) -> Result<(), String> {
    use std::os::unix::fs::FileExt;
    let mut read_total = 0usize;
    while read_total < buf.len() {
        match file.read_at(&mut buf[read_total..], offset + read_total as u64) {
            Ok(0) => {
                return Err("Source file truncated concurrently during fingerprinting".to_string());
            }
            Ok(n) => read_total += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(format!("Failed reading source file for fingerprint: {err}"));
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_exact_at_file(file: &fs::File, offset: u64, buf: &mut [u8]) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut cloned = file
        .try_clone()
        .map_err(|e| format!("Failed cloning source file for fingerprint: {e}"))?;
    cloned
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed seeking source file for fingerprint: {e}"))?;
    cloned
        .read_exact(buf)
        .map_err(|e| format!("Failed reading source file for fingerprint: {e}"))?;
    let _ = cloned.seek(SeekFrom::Start(0));
    Ok(())
}

fn compute_pinned_file_fingerprint(file: &fs::File, size: u64) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"af-mediaflow-source-v1\0");
    hasher.update(size.to_le_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|err| format!("Failed to stat source file for fingerprint: {err}"))?;
        hasher.update(metadata.ctime().to_le_bytes());
        hasher.update(metadata.ctime_nsec().to_le_bytes());
    }

    let sample = MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES as u64;
    if size <= sample * 3 {
        let mut offset = 0u64;
        let mut buf = vec![0u8; (size as usize).min(MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES)];
        while offset < size {
            let chunk_len = ((size - offset) as usize).min(buf.len());
            read_exact_at_file(file, offset, &mut buf[..chunk_len])?;
            hasher.update(offset.to_le_bytes());
            hasher.update((chunk_len as u64).to_le_bytes());
            hasher.update(&buf[..chunk_len]);
            offset += chunk_len as u64;
        }
    } else {
        let mid_offset = (size / 2).saturating_sub(sample / 2);
        let tail_offset = size.saturating_sub(sample);
        let mut buf = vec![0u8; MEDIAFLOW_FINGERPRINT_SAMPLE_BYTES];
        for offset in [0u64, mid_offset, tail_offset] {
            read_exact_at_file(file, offset, &mut buf)?;
            hasher.update(offset.to_le_bytes());
            hasher.update(sample.to_le_bytes());
            hasher.update(&buf);
        }
    }

    Ok(format!("v1:sha256:{}", hex::encode(hasher.finalize())))
}

pub struct PinnedMediaflowSource {
    #[cfg(unix)]
    pub(super) parent_dir: fs::File,
    pub(super) source_file: fs::File,
    pub canon_parent: PathBuf,
    pub canon_src: PathBuf,
    pub source_fname: String,
    pub identity: MediaflowSourceIdentity,
    #[cfg(unix)]
    pub(super) src_mode: u32,
    #[cfg(unix)]
    change_time: (i64, i64),
}

impl PinnedMediaflowSource {
    #[cfg(unix)]
    pub fn source_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.source_file.as_raw_fd()
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_cast)] // libc::stat field widths vary across Linux targets.
    pub(super) fn matches_live_stat(&self, st: &libc::stat) -> bool {
        (st.st_mode & libc::S_IFMT) == libc::S_IFREG
            && st.st_nlink == 1
            && (st.st_dev as u64) == self.identity.dev
            && (st.st_ino as u64) == self.identity.ino
            && st.st_size >= 0
            && (st.st_size as u64) == self.identity.size
            && (st.st_mtime as i64) == self.identity.mtime_sec
            && (st.st_mtime_nsec as i64) == self.identity.mtime_nsec
            && (st.st_ctime as i64, st.st_ctime_nsec as i64) == self.change_time
    }

    /// Re-verifies that the pinned source file descriptor, its live directory entry,
    /// and its bounded SHA-256 content fingerprint still match the identity captured at pin time.
    pub fn verify_still_matches_live(&self) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::io::AsRawFd;

            let fmeta = self
                .source_file
                .metadata()
                .map_err(|e| format!("Failed to stat pinned source file: {e}"))?;
            if !fmeta.is_file()
                || fmeta.nlink() != 1
                || fmeta.dev() != self.identity.dev
                || fmeta.ino() != self.identity.ino
                || fmeta.len() != self.identity.size
                || fmeta.mtime() != self.identity.mtime_sec
                || fmeta.mtime_nsec() != self.identity.mtime_nsec
                || (fmeta.ctime(), fmeta.ctime_nsec()) != self.change_time
            {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }

            let live_fp = compute_pinned_file_fingerprint(&self.source_file, self.identity.size)?;
            let live_st = fstatat_nofollow(self.parent_dir.as_raw_fd(), &self.source_fname)
                .map_err(|_| MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string())?;
            if live_fp != self.identity.fingerprint || !self.matches_live_stat(&live_st) {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let fmeta = self
                .source_file
                .metadata()
                .map_err(|e| format!("Failed to stat pinned source file: {e}"))?;
            if !fmeta.is_file() || fmeta.len() != self.identity.size {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }
            let live_fp = compute_pinned_file_fingerprint(&self.source_file, self.identity.size)?;
            if live_fp != self.identity.fingerprint {
                return Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string());
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
pub(super) fn cstring_from_os_name(name: &str, label: &str) -> Result<std::ffi::CString, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(format!("Invalid {label} entry name"));
    }
    std::ffi::CString::new(name.as_bytes()).map_err(|_| format!("{label} contains interior NUL"))
}

#[cfg(unix)]
pub(super) fn fstatat_nofollow(
    dirfd: std::os::unix::io::RawFd,
    entry_name: &str,
) -> std::io::Result<libc::stat> {
    use std::os::unix::ffi::OsStrExt;
    let c_name = std::ffi::CString::new(std::ffi::OsStr::new(entry_name).as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dirfd, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(st)
    }
}

#[cfg(unix)]
pub(super) fn unlinkat_entry(dirfd: std::os::unix::io::RawFd, entry_name: &str) {
    if let Ok(c_name) = std::ffi::CString::new(entry_name.as_bytes()) {
        unsafe {
            let _ = libc::unlinkat(dirfd, c_name.as_ptr(), 0);
        }
    }
}

#[cfg(unix)]
pub(super) fn write_dirfd_json_atomic(
    dirfd: std::os::unix::io::RawFd,
    target_name: &str,
    payload: &[u8],
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    let target_c = cstring_from_os_name(target_name, "metadata filename")?;
    let tmp_name = format!(
        ".tmp_meta_{}_{}",
        uuid::Uuid::new_v4().simple(),
        target_name.trim_start_matches('.')
    );
    let tmp_c = cstring_from_os_name(&tmp_name, "temporary metadata filename")?;

    let fd = unsafe {
        libc::openat(
            dirfd,
            tmp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Failed to open temporary metadata file {tmp_name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    unsafe {
        let _ = libc::fchmod(fd, 0o600);
    }
    let mut tmp_file = unsafe { fs::File::from_raw_fd(fd) };
    if let Err(err) = tmp_file
        .write_all(payload)
        .and_then(|()| tmp_file.sync_all())
    {
        drop(tmp_file);
        unlinkat_entry(dirfd, &tmp_name);
        return Err(format!("Failed writing metadata file {target_name}: {err}"));
    }
    drop(tmp_file);

    if let Ok(existing_st) = fstatat_nofollow(dirfd, target_name) {
        if (existing_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            unlinkat_entry(dirfd, &tmp_name);
            return Err(format!("Refusing symlink metadata target {target_name}"));
        }
    }

    let rc = unsafe { libc::renameat(dirfd, tmp_c.as_ptr(), dirfd, target_c.as_ptr()) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unlinkat_entry(dirfd, &tmp_name);
        return Err(format!(
            "Failed activating metadata file {target_name}: {err}"
        ));
    }
    unsafe {
        let _ = libc::fsync(dirfd);
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn touch_dirfd_entry_mtime_nofollow(
    dirfd: std::os::unix::io::RawFd,
    entry_name: &str,
    now_unix: i64,
) -> Result<(), String> {
    let entry_c = cstring_from_os_name(entry_name, "trash entry filename")?;
    let ts = libc::timespec {
        tv_sec: now_unix as libc::time_t,
        tv_nsec: 0,
    };
    let times = [ts, ts];
    let rc = unsafe {
        libc::utimensat(
            dirfd,
            entry_c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        return Err(format!(
            "Failed updating mtime on trashed media {entry_name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn persist_trash_entry_metadata_dirfd(
    trash_fd: std::os::unix::io::RawFd,
    trash_entry_name: &str,
    job_id: i64,
    original_name: &str,
    now_unix: i64,
) -> Result<(), String> {
    let _ = touch_dirfd_entry_mtime_nofollow(trash_fd, trash_entry_name, now_unix);
    let meta = MediaflowTrashMeta {
        job_id,
        trashed_at_unix: now_unix,
        original_name: original_name.to_string(),
    };
    let bytes =
        serde_json::to_vec(&meta).map_err(|e| format!("Failed serializing trash metadata: {e}"))?;
    let meta_name = trash_meta_filename(trash_entry_name);
    write_dirfd_json_atomic(trash_fd, &meta_name, &bytes)
}

fn read_regular_json_bounded<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    use std::io::Read;

    #[cfg(unix)]
    let file = {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return None;
        }
        let f = unsafe { fs::File::from_raw_fd(fd) };
        if !f.metadata().ok()?.is_file() {
            return None;
        }
        f
    };
    #[cfg(not(unix))]
    let file = {
        let meta = fs::symlink_metadata(path).ok()?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return None;
        }
        fs::File::open(path).ok()?
    };

    let mut buf = Vec::new();
    file.take(64 * 1024).read_to_end(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

pub fn open_and_pin_mediaflow_source(raw_path: &str) -> Result<PinnedMediaflowSource, String> {
    let roots = mediaflow_allowed_roots();
    open_and_pin_mediaflow_source_in_roots(raw_path, &roots)
}

pub fn open_and_pin_mediaflow_source_in_roots(
    raw_path: &str,
    roots: &[PathBuf],
) -> Result<PinnedMediaflowSource, String> {
    let src_path = Path::new(raw_path);
    if raw_path.trim().is_empty() || !src_path.is_absolute() {
        return Err("Source path must be an absolute path".to_string());
    }
    let Some(fname_os) = src_path.file_name() else {
        return Err("Source path has no filename".to_string());
    };
    let Some(fname_str) = fname_os.to_str() else {
        return Err("Source filename must be valid UTF-8".to_string());
    };
    if fname_str.starts_with(".tmp_mediaflow_")
        || fname_str.ends_with(".tmp.mkv")
        || src_path
            .components()
            .any(|c| c.as_os_str() == ".mediaflow_trash")
    {
        return Err("Refusing temporary or trash path in MediaFlow queue".to_string());
    }
    let Some(parent) = src_path.parent() else {
        return Err("Source path has no parent directory".to_string());
    };

    let parent_lmeta =
        fs::symlink_metadata(parent).map_err(|_| "Parent directory does not exist".to_string())?;
    if parent_lmeta.file_type().is_symlink() || !parent_lmeta.is_dir() {
        return Err("Source parent directory must not be a symlink".to_string());
    }

    let lmeta =
        fs::symlink_metadata(src_path).map_err(|_| "Source file does not exist".to_string())?;
    if lmeta.file_type().is_symlink() {
        return Err("Refusing symlink source file".to_string());
    }
    if !lmeta.file_type().is_file() {
        return Err("Source path is not a regular file".to_string());
    }

    let canon_parent = fs::canonicalize(parent)
        .map_err(|e| format!("Failed to canonicalize parent directory: {e}"))?;
    let canon_src = fs::canonicalize(src_path)
        .map_err(|e| format!("Failed to canonicalize source file: {e}"))?;
    if canon_src != canon_parent.join(fname_os) {
        return Err("Source path resolved through an unexpected link".to_string());
    }

    if !is_path_within_allowed_mediaflow_roots(&canon_src, roots) {
        return Err("Source file is outside allowed MediaFlow library roots".to_string());
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        if lmeta.nlink() != 1 {
            return Err("Refusing hard-linked source file (st_nlink != 1)".to_string());
        }

        let parent_cstr = std::ffi::CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| "Parent directory path contains interior NUL".to_string())?;
        let dir_fd = unsafe {
            libc::open(
                parent_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dir_fd < 0 {
            return Err(format!(
                "Failed to open pinned parent directory safely: {}",
                std::io::Error::last_os_error()
            ));
        }
        let parent_dir = unsafe { fs::File::from_raw_fd(dir_fd) };
        let dir_meta = parent_dir
            .metadata()
            .map_err(|e| format!("Failed to stat pinned parent directory: {e}"))?;
        let canon_parent_meta = fs::symlink_metadata(&canon_parent)
            .map_err(|e| format!("Failed to verify canonical parent directory: {e}"))?;
        if dir_meta.dev() != canon_parent_meta.dev() || dir_meta.ino() != canon_parent_meta.ino() {
            return Err("Parent directory changed concurrently during pinning".to_string());
        }

        let fname_cstr = cstring_from_os_name(fname_str, "source filename")?;
        let src_fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                fname_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if src_fd < 0 {
            return Err(format!(
                "Failed to open pinned source file safely: {}",
                std::io::Error::last_os_error()
            ));
        }
        let source_file = unsafe { fs::File::from_raw_fd(src_fd) };
        let fmeta = source_file
            .metadata()
            .map_err(|e| format!("Failed to stat opened source file: {e}"))?;
        if !fmeta.is_file() {
            return Err("Opened source descriptor is not a regular file".to_string());
        }
        if fmeta.nlink() != 1 {
            return Err("Refusing hard-linked source descriptor (st_nlink != 1)".to_string());
        }
        if fmeta.dev() != lmeta.dev() || fmeta.ino() != lmeta.ino() {
            return Err("Source file inode changed concurrently during validation".to_string());
        }

        let fingerprint = compute_pinned_file_fingerprint(&source_file, fmeta.len())?;
        let fmeta_after = source_file
            .metadata()
            .map_err(|e| format!("Failed to re-stat pinned source file: {e}"))?;
        if !fmeta_after.is_file()
            || fmeta_after.nlink() != 1
            || fmeta_after.dev() != fmeta.dev()
            || fmeta_after.ino() != fmeta.ino()
            || fmeta_after.len() != fmeta.len()
            || fmeta_after.mtime() != fmeta.mtime()
            || fmeta_after.mtime_nsec() != fmeta.mtime_nsec()
            || fmeta_after.ctime() != fmeta.ctime()
            || fmeta_after.ctime_nsec() != fmeta.ctime_nsec()
        {
            return Err("Source file changed concurrently during fingerprinting".to_string());
        }

        let identity = MediaflowSourceIdentity {
            dev: fmeta.dev(),
            ino: fmeta.ino(),
            size: fmeta.len(),
            mtime_sec: fmeta.mtime(),
            mtime_nsec: fmeta.mtime_nsec(),
            fingerprint,
        };
        let pinned = PinnedMediaflowSource {
            parent_dir,
            source_file,
            canon_parent,
            canon_src,
            source_fname: fname_str.to_string(),
            identity,
            src_mode: fmeta.mode(),
            change_time: (fmeta.ctime(), fmeta.ctime_nsec()),
        };
        let live_st = fstatat_nofollow(pinned.parent_dir.as_raw_fd(), &pinned.source_fname)
            .map_err(|_| "Source directory entry vanished during pinning".to_string())?;
        if !pinned.matches_live_stat(&live_st) {
            return Err("Source file changed concurrently during pinning".to_string());
        }
        Ok(pinned)
    }

    #[cfg(not(unix))]
    {
        let source_file = fs::OpenOptions::new()
            .read(true)
            .open(&canon_src)
            .map_err(|e| format!("Failed to open source file safely: {e}"))?;
        let fmeta = source_file
            .metadata()
            .map_err(|e| format!("Failed to stat opened source file: {e}"))?;
        if !fmeta.is_file() {
            return Err("Opened source descriptor is not a regular file".to_string());
        }
        let fingerprint = compute_pinned_file_fingerprint(&source_file, fmeta.len())?;
        let modified_secs = fmeta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| (d.as_secs() as i64, d.subsec_nanos() as i64))
            .unwrap_or((0, 0));
        Ok(PinnedMediaflowSource {
            source_file,
            canon_parent,
            canon_src,
            source_fname: fname_str.to_string(),
            identity: MediaflowSourceIdentity {
                dev: 0,
                ino: 0,
                size: fmeta.len(),
                mtime_sec: modified_secs.0,
                mtime_nsec: modified_secs.1,
                fingerprint,
            },
        })
    }
}

pub(super) fn is_stale_mediaflow_temp_name(name: &str) -> bool {
    (name.starts_with(".tmp_mediaflow_") && name.ends_with(".mkv"))
        || (name.starts_with('.') && name.ends_with(".tmp.mkv"))
}

pub(super) fn cleanup_stale_mediaflow_temps_in_dir(dir: &Path) {
    let Ok(dmeta) = fs::symlink_metadata(dir) else {
        return;
    };
    if dmeta.file_type().is_symlink() || !dmeta.is_dir() {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !is_stale_mediaflow_temp_name(name) {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.file_type().is_symlink() && meta.file_type().is_file() {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

pub(super) fn prune_mediaflow_trash_dir(trash_dir: &Path, retention: Duration) {
    let Ok(tmeta) = fs::symlink_metadata(trash_dir) else {
        return;
    };
    if tmeta.file_type().is_symlink() || !tmeta.is_dir() {
        return;
    }
    let now_unix = Utc::now().timestamp();
    let retention_secs = retention.as_secs();
    let Ok(entries) = fs::read_dir(trash_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if fname.starts_with(".publish_intent_") || fname.starts_with(".tmp_meta_") {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            continue;
        }
        if let Some(base_entry) = fname.strip_suffix(".meta.json") {
            let companion_media = trash_dir.join(base_entry);
            if fs::symlink_metadata(&companion_media).is_err() {
                let _ = fs::remove_file(&path);
            }
            continue;
        }

        let meta_path = trash_dir.join(trash_meta_filename(fname));
        let Some(meta_rec) = read_regular_json_bounded::<MediaflowTrashMeta>(&meta_path) else {
            // Never prune a trashed media original without a verified trashed_at_unix record!
            continue;
        };
        if meta_rec.trashed_at_unix <= 0 || now_unix < meta_rec.trashed_at_unix {
            continue;
        }
        let age_secs = (now_unix - meta_rec.trashed_at_unix) as u64;
        if age_secs >= retention_secs {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(&meta_path);
        }
    }
}

async fn persist_mediaflow_completion_with_retry(
    job_id: i64,
    out_str: &str,
    new_size: i64,
) -> Result<(), String> {
    let mut backoff_ms = 20u64;
    let mut last_err = String::new();
    for attempt in 0..5 {
        match af_db::get_conn() {
            Ok(conn) => {
                match conn.execute(
                    "UPDATE mediaflow_queue SET status = 'COMPLETED', file_path = ?1, new_codec = 'hevc', new_size = ?2, error_log = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?3 AND status = 'PROCESSING'",
                    params![out_str, new_size, job_id],
                ) {
                    Ok(1) => return Ok(()),
                    Ok(0) => {
                        return Err(
                            "Job row was no longer in PROCESSING state during completion commit"
                                .to_string(),
                        )
                    }
                    Ok(_) => return Ok(()),
                    Err(err) => last_err = err.to_string(),
                }
            }
            Err(err) => last_err = err.to_string(),
        }
        if attempt < 4 {
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = backoff_ms.saturating_mul(2);
        }
    }
    Err(last_err)
}

/// Reconciles any `PROCESSING` MediaFlow jobs stranded by a prior crash/restart:
/// - If a durable `.publish_intent_<job_id>.json` exists and both the published output and
///   trashed original exist on disk, finalizes the SQLite row to `COMPLETED` and removes the intent.
/// - Otherwise marks stranded `PROCESSING` rows as `FAILED`.
/// - Marks legacy `PENDING_APPROVAL` / `APPROVED` rows missing persisted source identity as
///   `NEEDS_RESCAN` so operators re-scan and re-approve safely.
/// - Sweeps stale `.tmp_mediaflow_*` temp files and genuinely expired `.mediaflow_trash` entries.
pub fn reconcile_mediaflow_startup() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let mut candidate_dirs: HashSet<PathBuf> = HashSet::new();
    if let Ok(mut stmt) = conn.prepare("SELECT file_path FROM mediaflow_queue") {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            for path_str in rows.flatten() {
                if let Some(parent) = Path::new(&path_str).parent() {
                    if parent.is_absolute() {
                        candidate_dirs.insert(parent.to_path_buf());
                    }
                }
            }
        }
    }

    let roots = mediaflow_allowed_roots();
    let mut processing_rows: Vec<(i64, String)> = Vec::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT id, file_path FROM mediaflow_queue WHERE status = 'PROCESSING'")
    {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        {
            for pair in rows.flatten() {
                processing_rows.push(pair);
            }
        }
    }

    let now_unix = Utc::now().timestamp();
    for (job_id, raw_path) in processing_rows {
        let Some(parent) = Path::new(&raw_path).parent() else {
            continue;
        };
        let Ok(canon_dir) = fs::canonicalize(parent) else {
            continue;
        };
        if !is_path_within_allowed_mediaflow_roots(&canon_dir, &roots) {
            continue;
        }
        let trash_dir = canon_dir.join(".mediaflow_trash");
        let intent_path = trash_dir.join(publish_intent_filename(job_id));
        let Some(intent) = read_regular_json_bounded::<MediaflowPublishIntent>(&intent_path) else {
            continue;
        };
        if intent.job_id != job_id
            || intent.trash_entry_name.contains('/')
            || intent.trash_entry_name.is_empty()
        {
            let _ = fs::remove_file(&intent_path);
            continue;
        }

        let pub_path = Path::new(&intent.published_path);
        let pub_valid = pub_path.parent() == Some(canon_dir.as_path())
            && fs::symlink_metadata(pub_path)
                .ok()
                .is_some_and(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0);
        let trashed_path = trash_dir.join(&intent.trash_entry_name);
        let trash_valid = fs::symlink_metadata(&trashed_path)
            .ok()
            .is_some_and(|m| !m.file_type().is_symlink() && m.is_file());

        if pub_valid && trash_valid {
            let actual_size = fs::symlink_metadata(pub_path)
                .map(|m| m.len() as i64)
                .unwrap_or(intent.new_size)
                .max(intent.new_size);
            if conn
                .execute(
                    "UPDATE mediaflow_queue SET status = 'COMPLETED', file_path = ?1, new_codec = 'hevc', new_size = ?2, error_log = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?3 AND status = 'PROCESSING'",
                    params![intent.published_path, actual_size, job_id],
                )
                .is_ok_and(|affected| affected == 1)
            {
                let meta_path = trash_dir.join(trash_meta_filename(&intent.trash_entry_name));
                if read_regular_json_bounded::<MediaflowTrashMeta>(&meta_path).is_none() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::ffi::OsStrExt;
                        use std::os::unix::io::{AsRawFd, FromRawFd};
                        if let Ok(c_trash) =
                            std::ffi::CString::new(trash_dir.as_os_str().as_bytes())
                        {
                            let raw_fd = unsafe {
                                libc::open(
                                    c_trash.as_ptr(),
                                    libc::O_RDONLY
                                        | libc::O_DIRECTORY
                                        | libc::O_NOFOLLOW
                                        | libc::O_CLOEXEC,
                                )
                            };
                            if raw_fd >= 0 {
                                let tf = unsafe { fs::File::from_raw_fd(raw_fd) };
                                let orig_name = Path::new(&raw_path)
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("");
                                let _ = persist_trash_entry_metadata_dirfd(
                                    tf.as_raw_fd(),
                                    &intent.trash_entry_name,
                                    job_id,
                                    orig_name,
                                    now_unix,
                                );
                            }
                        }
                    }
                }
                let _ = fs::remove_file(&intent_path);
                tracing::info!(
                    job_id = job_id,
                    published_path = %intent.published_path,
                    "mediaflow: reconciled completed transcode from durable publish intent on startup"
                );
            }
        } else {
            let _ = fs::remove_file(&intent_path);
        }
    }

    let stranded = conn
        .execute(
            "UPDATE mediaflow_queue SET status = 'FAILED', error_log = 'Interrupted by service restart', updated_at = CURRENT_TIMESTAMP WHERE status = 'PROCESSING'",
            [],
        )
        .unwrap_or(0);
    if stranded > 0 {
        tracing::warn!(
            stranded_jobs = stranded,
            "mediaflow: marked stranded PROCESSING job(s) as FAILED after service restart"
        );
    }

    let legacy_invalidated = conn
        .execute(
            "UPDATE mediaflow_queue
             SET status = 'NEEDS_RESCAN',
                 error_log = ?1,
                 updated_at = CURRENT_TIMESTAMP
             WHERE status IN ('PENDING_APPROVAL', 'APPROVED')
               AND (
                   source_dev IS NULL
                   OR source_ino IS NULL
                   OR source_size IS NULL
                   OR source_mtime_sec IS NULL
                   OR source_mtime_nsec IS NULL
                   OR COALESCE(source_fingerprint, '') = ''
               )",
            params![MEDIAFLOW_MISSING_IDENTITY_MSG],
        )
        .unwrap_or(0);
    if legacy_invalidated > 0 {
        tracing::warn!(
            legacy_jobs = legacy_invalidated,
            "mediaflow: transitioned legacy identity-less queue job(s) to NEEDS_RESCAN on startup"
        );
    }

    let retention = mediaflow_trash_retention();
    for dir in candidate_dirs {
        let Ok(canon_dir) = fs::canonicalize(&dir) else {
            continue;
        };
        if !is_path_within_allowed_mediaflow_roots(&canon_dir, &roots) {
            continue;
        }
        cleanup_stale_mediaflow_temps_in_dir(&canon_dir);
        prune_mediaflow_trash_dir(&canon_dir.join(".mediaflow_trash"), retention);
    }
}

/// Spawns the background MediaFlow worker poller (10-second interval) that picks up
/// `APPROVED` items in `mediaflow_queue`, transitions them to `PROCESSING`, invokes
/// `ffmpeg` with hardware transcode flags from [`af_hardware::get_gpu_transcode_flags()`],
/// and updates the row to `COMPLETED`, `FAILED`, `CANCELLED`, or `NEEDS_RESCAN`.
pub fn start_mediaflow_poller() {
    if MEDIAFLOW_POLLER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    tokio::spawn(async move {
        reconcile_mediaflow_startup();
        tracing::info!(
            interval_secs = 10,
            "mediaflow autonomous transcode poller initialized"
        );

        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let _ = process_next_mediaflow_job().await;
        }
    });
}

struct ClaimedMediaflowJob {
    id: i64,
    file_path: String,
    expected_identity: Option<MediaflowSourceIdentity>,
}

struct AbortOnDrop(Option<tokio::task::AbortHandle>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

struct TempOutputGuard<'a> {
    #[cfg(unix)]
    dirfd: std::os::unix::io::RawFd,
    #[cfg(unix)]
    temp_fname: &'a str,
    #[cfg(not(unix))]
    temp_output: &'a Path,
    active: bool,
}

impl<'a> TempOutputGuard<'a> {
    fn cleanup_now(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        #[cfg(unix)]
        unlinkat_entry(self.dirfd, self.temp_fname);
        #[cfg(not(unix))]
        let _ = fs::remove_file(self.temp_output);
    }
}

impl Drop for TempOutputGuard<'_> {
    fn drop(&mut self) {
        self.cleanup_now();
    }
}

fn is_job_still_processing(job_id: i64) -> bool {
    af_db::get_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row(
                "SELECT status FROM mediaflow_queue WHERE id = ?1",
                params![job_id],
                |r| r.get::<_, String>(0),
            )
            .ok()
        })
        .is_some_and(|status| status == "PROCESSING")
}

/// Processes a single `APPROVED` job from `mediaflow_queue` if one exists and no job
/// is currently running. Returns `true` if a job was picked up and processed.
pub async fn process_next_mediaflow_job() -> bool {
    use tokio::io::{AsyncBufReadExt, BufReader};

    if MEDIAFLOW_PROCESSING.swap(true, Ordering::SeqCst) {
        return false;
    }

    struct ProcessingGuard;
    impl Drop for ProcessingGuard {
        fn drop(&mut self) {
            MEDIAFLOW_PROCESSING.store(false, Ordering::SeqCst);
        }
    }
    let _guard = ProcessingGuard;

    let job_opt: Option<ClaimedMediaflowJob> = {
        let Ok(conn) = af_db::get_conn() else {
            return false;
        };
        let Ok(row) = conn.query_row(
            "SELECT id, file_path, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, COALESCE(source_fingerprint, '')
             FROM mediaflow_queue
             WHERE status = 'APPROVED'
             ORDER BY created_at ASC, id ASC
             LIMIT 1",
            [],
            |r| {
                let id = r.get::<_, i64>(0)?;
                let file_path = r.get::<_, String>(1)?;
                let expected_identity = parse_stored_mediaflow_identity(
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, Option<String>>(7)?.as_deref(),
                );
                Ok(ClaimedMediaflowJob {
                    id,
                    file_path,
                    expected_identity,
                })
            },
        ) else {
            return false;
        };
        match conn.execute(
            "UPDATE mediaflow_queue SET status = 'PROCESSING', updated_at = CURRENT_TIMESTAMP WHERE id = ?1 AND status = 'APPROVED'",
            params![row.id],
        ) {
            Ok(1) => Some(row),
            _ => None,
        }
    };

    let Some(job) = job_opt else {
        return false;
    };
    let job_id = job.id;
    let file_path = job.file_path;

    let (_active_job_guard, mut cancel_rx) = register_active_mediaflow_job(job_id);

    let Some(expected_identity) = job.expected_identity else {
        record_mediaflow_needs_rescan(job_id, MEDIAFLOW_MISSING_IDENTITY_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "needs_rescan",
            "file": file_path,
            "progress": 0,
            "message": MEDIAFLOW_MISSING_IDENTITY_MSG,
        }));
        return true;
    };

    let pinned = match open_and_pin_mediaflow_source(&file_path) {
        Ok(valid) => valid,
        Err(reason) => {
            let needs_rescan = reason.contains("does not exist")
                || reason.contains("symlink")
                || reason.contains("hard-linked")
                || reason.contains("regular file")
                || reason.contains("changed concurrently");
            if needs_rescan {
                let msg = format!("{reason}; re-scan and re-approve before transcoding");
                record_mediaflow_needs_rescan(job_id, &msg);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "needs_rescan",
                    "file": file_path,
                    "progress": 0,
                    "message": msg,
                }));
            } else {
                record_mediaflow_failure(job_id, &reason);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "failed",
                    "file": file_path,
                    "progress": 0,
                    "message": reason,
                }));
            }
            return true;
        }
    };

    if pinned.identity != expected_identity {
        record_mediaflow_needs_rescan(job_id, MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "needs_rescan",
            "file": file_path,
            "progress": 0,
            "message": MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG,
        }));
        return true;
    }

    if *cancel_rx.borrow() || !is_job_still_processing(job_id) {
        record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "cancelled",
            "file": file_path,
            "progress": 0,
            "message": "Transcode cancelled",
        }));
        return true;
    }

    let src_path = &pinned.canon_src;
    let parent_dir = &pinned.canon_parent;

    let flags = af_hardware::get_gpu_transcode_flags();
    let stem = src_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let out_fname = format!("{}_hevc.mkv", stem);
    let out_path = parent_dir.join(&out_fname);
    if out_path != *src_path && fs::symlink_metadata(&out_path).is_ok() {
        let msg = format!(
            "Refusing to clobber existing output file: {}",
            out_path.display()
        );
        record_mediaflow_failure(job_id, &msg);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "failed",
            "file": file_path,
            "progress": 0,
            "message": msg,
        }));
        return true;
    }

    let temp_fname = format!(
        ".tmp_mediaflow_{}_{}.mkv",
        job_id,
        uuid::Uuid::new_v4().simple()
    );
    let temp_output = parent_dir.join(&temp_fname);

    #[cfg(unix)]
    let (temp_dev, temp_ino) = {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let temp_cstr = match cstring_from_os_name(&temp_fname, "temporary output filename") {
            Ok(c) => c,
            Err(msg) => {
                record_mediaflow_failure(job_id, &msg);
                return true;
            }
        };
        let tfd = unsafe {
            libc::openat(
                pinned.parent_dir.as_raw_fd(),
                temp_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if tfd < 0 {
            let msg = format!(
                "Failed to create exclusive temporary output file: {}",
                std::io::Error::last_os_error()
            );
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
            return true;
        }
        let temp_file = unsafe { fs::File::from_raw_fd(tfd) };
        match temp_file.metadata() {
            Ok(meta) => (meta.dev(), meta.ino()),
            Err(err) => {
                drop(temp_file);
                unlinkat_entry(pinned.parent_dir.as_raw_fd(), &temp_fname);
                let msg = format!("Failed to inspect temporary output file: {err}");
                record_mediaflow_failure(job_id, &msg);
                return true;
            }
        }
    };

    #[cfg(not(unix))]
    if let Err(err) = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_output)
    {
        let msg = format!("Failed to create exclusive temporary output file: {err}");
        record_mediaflow_failure(job_id, &msg);
        return true;
    }

    #[cfg(unix)]
    let mut temp_guard = {
        use std::os::unix::io::AsRawFd;
        TempOutputGuard {
            dirfd: pinned.parent_dir.as_raw_fd(),
            temp_fname: &temp_fname,
            active: true,
        }
    };
    #[cfg(not(unix))]
    let mut temp_guard = TempOutputGuard {
        temp_output: &temp_output,
        active: true,
    };

    let mut args: Vec<String> = vec!["-nostdin".to_string(), "-y".to_string()];
    if !flags.hw_accel.is_empty() && flags.hw_accel != "none" {
        args.push("-hwaccel".to_string());
        args.push(flags.hw_accel.clone());
        if !flags.hw_accel_device.is_empty() {
            args.push("-hwaccel_device".to_string());
            args.push(flags.hw_accel_device.clone());
        }
        if !flags.output_format.is_empty() {
            args.push("-hwaccel_output_format".to_string());
            args.push(flags.output_format.clone());
        }
    }

    let video_codec = if flags.video_codec.trim().is_empty() {
        "libx265"
    } else {
        flags.video_codec.trim()
    };

    #[cfg(unix)]
    let (input_uri, child_pinned_fd) = {
        use std::os::unix::io::AsRawFd;
        let raw_fd = pinned.source_file.as_raw_fd();
        if cfg!(target_os = "linux") && Path::new("/proc/self/fd").is_dir() {
            (format!("file:/proc/self/fd/{raw_fd}"), Some(raw_fd))
        } else {
            (format!("file:{}", src_path.to_string_lossy()), None)
        }
    };
    #[cfg(not(unix))]
    let input_uri = format!("file:{}", src_path.to_string_lossy());

    args.extend([
        "-i".to_string(),
        input_uri.clone(),
        "-map".to_string(),
        "0".to_string(),
        "-c:v".to_string(),
        video_codec.to_string(),
        "-b:v".to_string(),
        "5M".to_string(),
        "-c:a".to_string(),
        "copy".to_string(),
        "-c:s".to_string(),
        "copy".to_string(),
        "-nostats".to_string(),
        "-progress".to_string(),
        "pipe:1".to_string(),
        format!("file:{}", temp_output.to_string_lossy()),
    ]);

    tracing::info!(
        job_id = job_id,
        file_path = %file_path,
        codec = %video_codec,
        fingerprint = %pinned.identity.fingerprint,
        "mediaflow: starting transcode job"
    );
    publish_mediaflow_progress(&serde_json::json!({
        "status": "running",
        "file": file_path,
        "progress": 0,
        "message": "Starting transcode",
    }));

    #[cfg(unix)]
    let duration_secs = probe_mediaflow_duration_secs(&input_uri, child_pinned_fd).await;
    #[cfg(not(unix))]
    let duration_secs = probe_mediaflow_duration_secs(&input_uri).await;

    if *cancel_rx.borrow() || !is_job_still_processing(job_id) {
        temp_guard.cleanup_now();
        record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
        publish_mediaflow_progress(&serde_json::json!({
            "status": "cancelled",
            "file": file_path,
            "progress": 0,
            "message": "Transcode cancelled",
        }));
        return true;
    }

    let timeout = mediaflow_transcode_timeout();

    let mut cmd = Command::new("ffmpeg");
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    if let Some(raw_fd) = child_pinned_fd {
        unsafe {
            cmd.pre_exec(move || {
                let flags = libc::fcntl(raw_fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(raw_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            temp_guard.cleanup_now();
            let msg = format!("FFmpeg execution error: {}", err);
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
            return true;
        }
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let progress_file = file_path.clone();

    let stdout_task = tokio::spawn(async move {
        let Some(stdout) = stdout_pipe else {
            return;
        };
        let mut lines = BufReader::new(stdout).lines();
        let mut out_time_secs: f64 = 0.0;
        let mut last_pct: i32 = -1;
        let mut last_emit = Instant::now() - Duration::from_secs(10);
        while let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim();
            if let Some(val) = trimmed
                .strip_prefix("out_time_us=")
                .or_else(|| trimmed.strip_prefix("out_time_ms="))
            {
                if let Ok(us) = val.parse::<i64>() {
                    out_time_secs = (us.max(0) as f64) / 1_000_000.0;
                }
            } else if trimmed == "progress=continue" || trimmed == "progress=end" {
                let pct = duration_secs
                    .filter(|&d| d > 0.0)
                    .map(|d| ((out_time_secs / d) * 100.0).clamp(0.0, 99.0) as i32)
                    .unwrap_or(0);
                if pct != last_pct || last_emit.elapsed() >= Duration::from_secs(2) {
                    last_pct = pct;
                    last_emit = Instant::now();
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "running",
                        "file": progress_file,
                        "progress": pct,
                        "message": if duration_secs.is_some() {
                            format!("Transcoding ({pct}%)")
                        } else {
                            format!("Transcoding ({out_time_secs:.1}s)")
                        },
                    }));
                }
            }
        }
    });

    let stderr_task = tokio::spawn(async move {
        let Some(stderr) = stderr_pipe else {
            return String::new();
        };
        drain_stderr_bounded(stderr, 16 * 1024, 48 * 1024).await
    });

    let mut stdout_abort = AbortOnDrop(Some(stdout_task.abort_handle()));
    let mut stderr_abort = AbortOnDrop(Some(stderr_task.abort_handle()));

    enum WaitSignal {
        Exited(std::io::Result<std::process::ExitStatus>),
        Cancelled,
        TimedOut,
    }

    enum FfmpegOutcome {
        Exited(std::io::Result<std::process::ExitStatus>, String),
        Cancelled,
        TimedOut,
    }

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    let wait_signal = tokio::select! {
        biased;
        _ = wait_for_mediaflow_cancel(&mut cancel_rx) => WaitSignal::Cancelled,
        status = child.wait() => WaitSignal::Exited(status),
        _ = &mut deadline => WaitSignal::TimedOut,
    };

    let outcome = match wait_signal {
        WaitSignal::Exited(status) => {
            let _ = stdout_task.await;
            let stderr_text = stderr_task.await.unwrap_or_default();
            stdout_abort.0 = None;
            stderr_abort.0 = None;
            FfmpegOutcome::Exited(status, stderr_text)
        }
        WaitSignal::Cancelled => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            drop(stdout_abort);
            drop(stderr_abort);
            FfmpegOutcome::Cancelled
        }
        WaitSignal::TimedOut => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            drop(stdout_abort);
            drop(stderr_abort);
            FfmpegOutcome::TimedOut
        }
    };

    match outcome {
        FfmpegOutcome::Exited(Ok(status), _stderr_text) if status.success() => {
            #[cfg(unix)]
            let temp_size = {
                use std::os::unix::io::AsRawFd;
                let dirfd = pinned.parent_dir.as_raw_fd();
                match fstatat_nofollow(dirfd, &temp_fname) {
                    Ok(st)
                        if (st.st_mode & libc::S_IFMT) == libc::S_IFREG
                            && st.st_dev == temp_dev
                            && st.st_ino == temp_ino =>
                    {
                        st.st_size.max(0) as u64
                    }
                    _ => 0,
                }
            };
            #[cfg(not(unix))]
            let temp_size = fs::symlink_metadata(&temp_output)
                .ok()
                .filter(|m| !m.file_type().is_symlink() && m.file_type().is_file())
                .map(|m| m.len())
                .unwrap_or(0);

            if temp_size == 0 {
                temp_guard.cleanup_now();
                let msg = "FFmpeg exited cleanly but produced an empty or missing output file";
                record_mediaflow_failure(job_id, msg);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "failed",
                    "file": file_path,
                    "progress": 0,
                    "message": msg,
                }));
                return true;
            }

            if !try_begin_mediaflow_publication(job_id) || !is_job_still_processing(job_id) {
                temp_guard.cleanup_now();
                record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "cancelled",
                    "file": file_path,
                    "progress": 0,
                    "message": "Transcode cancelled",
                }));
                return true;
            }

            let new_size = temp_size as i64;
            let out_str = out_path.to_string_lossy().to_string();
            let intent_fname = publish_intent_filename(job_id);

            if let Err(conflict_msg) = pinned.verify_still_matches_live() {
                temp_guard.cleanup_now();
                record_mediaflow_failure(job_id, &conflict_msg);
                publish_mediaflow_progress(&serde_json::json!({
                    "status": "failed",
                    "file": file_path,
                    "progress": 0,
                    "message": conflict_msg,
                }));
                return true;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                use std::os::unix::io::{AsRawFd, FromRawFd};

                let dirfd = pinned.parent_dir.as_raw_fd();

                // Set published permissions (e.g. 0644 / 0664, never suid/sgid/exec) on the
                // verified temporary output inode before hard-linking it into the media library.
                let temp_c = std::ffi::CString::new(temp_fname.as_bytes()).unwrap();
                {
                    let chmod_fd = unsafe {
                        libc::openat(
                            dirfd,
                            temp_c.as_ptr(),
                            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if chmod_fd < 0 {
                        temp_guard.cleanup_now();
                        let msg = format!(
                            "Failed opening temporary output for chmod: {}",
                            std::io::Error::last_os_error()
                        );
                        record_mediaflow_failure(job_id, &msg);
                        publish_mediaflow_progress(&serde_json::json!({
                            "status": "failed",
                            "file": file_path,
                            "progress": 0,
                            "message": msg,
                        }));
                        return true;
                    }
                    let chmod_file = unsafe { fs::File::from_raw_fd(chmod_fd) };
                    let meta_ok = chmod_file
                        .metadata()
                        .is_ok_and(|m| m.is_file() && m.dev() == temp_dev && m.ino() == temp_ino);
                    if !meta_ok {
                        drop(chmod_file);
                        temp_guard.cleanup_now();
                        let msg = "Temporary output inode changed unexpectedly before publication";
                        record_mediaflow_failure(job_id, msg);
                        publish_mediaflow_progress(&serde_json::json!({
                            "status": "failed",
                            "file": file_path,
                            "progress": 0,
                            "message": msg,
                        }));
                        return true;
                    }
                    let pub_mode = compute_published_media_mode(pinned.src_mode);
                    if unsafe { libc::fchmod(chmod_file.as_raw_fd(), pub_mode) } < 0 {
                        let err = std::io::Error::last_os_error();
                        drop(chmod_file);
                        temp_guard.cleanup_now();
                        let msg = format!("Failed applying permissions to output file: {err}");
                        record_mediaflow_failure(job_id, &msg);
                        publish_mediaflow_progress(&serde_json::json!({
                            "status": "failed",
                            "file": file_path,
                            "progress": 0,
                            "message": msg,
                        }));
                        return true;
                    }
                    let _ = chmod_file.sync_all();
                }

                let trash_cstr = std::ffi::CString::new(".mediaflow_trash").unwrap();
                unsafe {
                    if libc::mkdirat(dirfd, trash_cstr.as_ptr(), 0o755) < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() != std::io::ErrorKind::AlreadyExists {
                            temp_guard.cleanup_now();
                            let msg = format!("Failed to create .mediaflow_trash directory: {err}");
                            record_mediaflow_failure(job_id, &msg);
                            publish_mediaflow_progress(&serde_json::json!({
                                "status": "failed",
                                "file": file_path,
                                "progress": 0,
                                "message": msg,
                            }));
                            return true;
                        }
                    }
                }
                let raw_trash_fd = unsafe {
                    libc::openat(
                        dirfd,
                        trash_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw_trash_fd < 0 {
                    temp_guard.cleanup_now();
                    let msg = "Refusing symlink or non-directory .mediaflow_trash";
                    record_mediaflow_failure(job_id, msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }
                let trash_dir_file = unsafe { fs::File::from_raw_fd(raw_trash_fd) };
                let trash_fd = trash_dir_file.as_raw_fd();

                let mut trash_entry_name = format!("{job_id}_{}", pinned.source_fname);
                if fstatat_nofollow(trash_fd, &trash_entry_name).is_ok() {
                    trash_entry_name = format!(
                        "{job_id}_{}_{}",
                        uuid::Uuid::new_v4().simple(),
                        pinned.source_fname
                    );
                }
                if fstatat_nofollow(trash_fd, &trash_entry_name).is_ok() {
                    temp_guard.cleanup_now();
                    let msg = "Refusing to clobber existing .mediaflow_trash entry";
                    record_mediaflow_failure(job_id, msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }

                // Persist durable publication intent BEFORE executing linkat/renameat swap
                let intent = MediaflowPublishIntent {
                    job_id,
                    published_path: out_str.clone(),
                    trash_entry_name: trash_entry_name.clone(),
                    new_size,
                    source_fingerprint: pinned.identity.fingerprint.clone(),
                };
                let intent_bytes = match serde_json::to_vec(&intent) {
                    Ok(b) => b,
                    Err(err) => {
                        temp_guard.cleanup_now();
                        let msg = format!("Failed serializing publish intent: {err}");
                        record_mediaflow_failure(job_id, &msg);
                        return true;
                    }
                };
                if let Err(msg) = write_dirfd_json_atomic(trash_fd, &intent_fname, &intent_bytes) {
                    temp_guard.cleanup_now();
                    record_mediaflow_failure(job_id, &msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }

                let out_c = std::ffi::CString::new(out_fname.as_bytes()).unwrap();
                let src_c = std::ffi::CString::new(pinned.source_fname.as_bytes()).unwrap();
                let trash_entry_c = std::ffi::CString::new(trash_entry_name.as_bytes()).unwrap();

                let publish_res: Result<(), String> = if out_fname != pinned.source_fname {
                    let link_rc =
                        unsafe { libc::linkat(dirfd, temp_c.as_ptr(), dirfd, out_c.as_ptr(), 0) };
                    if link_rc < 0 {
                        let err = std::io::Error::last_os_error();
                        temp_guard.cleanup_now();
                        Err(format!(
                            "Failed to publish transcoded output without clobbering target: {err}"
                        ))
                    } else {
                        let still_same = fstatat_nofollow(dirfd, &pinned.source_fname)
                            .map(|st| pinned.matches_live_stat(&st))
                            .unwrap_or(false);
                        if !still_same {
                            unlinkat_entry(dirfd, &out_fname);
                            temp_guard.cleanup_now();
                            Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string())
                        } else if unsafe {
                            libc::renameat(dirfd, src_c.as_ptr(), trash_fd, trash_entry_c.as_ptr())
                        } < 0
                        {
                            let err = std::io::Error::last_os_error();
                            unlinkat_entry(dirfd, &out_fname);
                            temp_guard.cleanup_now();
                            Err(format!(
                                "Failed to move original media into .mediaflow_trash: {err}"
                            ))
                        } else {
                            temp_guard.cleanup_now();
                            Ok(())
                        }
                    }
                } else {
                    let still_same = fstatat_nofollow(dirfd, &pinned.source_fname)
                        .map(|st| pinned.matches_live_stat(&st))
                        .unwrap_or(false);
                    if !still_same {
                        temp_guard.cleanup_now();
                        Err(MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG.to_string())
                    } else if unsafe {
                        libc::renameat(dirfd, src_c.as_ptr(), trash_fd, trash_entry_c.as_ptr())
                    } < 0
                    {
                        let err = std::io::Error::last_os_error();
                        temp_guard.cleanup_now();
                        Err(format!(
                            "Failed to move original media into .mediaflow_trash: {err}"
                        ))
                    } else if unsafe {
                        libc::linkat(dirfd, temp_c.as_ptr(), dirfd, out_c.as_ptr(), 0)
                    } < 0
                    {
                        let err = std::io::Error::last_os_error();
                        unsafe {
                            let _ = libc::renameat(
                                trash_fd,
                                trash_entry_c.as_ptr(),
                                dirfd,
                                src_c.as_ptr(),
                            );
                        }
                        temp_guard.cleanup_now();
                        Err(format!("Failed to publish transcoded output: {err}"))
                    } else {
                        temp_guard.cleanup_now();
                        Ok(())
                    }
                };

                if let Err(msg) = publish_res {
                    unlinkat_entry(trash_fd, &intent_fname);
                    drop(trash_dir_file);
                    record_mediaflow_failure(job_id, &msg);
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "failed",
                        "file": file_path,
                        "progress": 0,
                        "message": msg,
                    }));
                    return true;
                }

                let now_unix = Utc::now().timestamp();
                if let Err(err) = persist_trash_entry_metadata_dirfd(
                    trash_fd,
                    &trash_entry_name,
                    job_id,
                    &pinned.source_fname,
                    now_unix,
                ) {
                    tracing::warn!(
                        job_id = job_id,
                        trash_entry = %trash_entry_name,
                        error = %err,
                        "mediaflow: failed writing trash metadata sidecar; trashed original will be preserved from pruning"
                    );
                }
                unsafe {
                    let _ = libc::fsync(dirfd);
                }
                drop(trash_dir_file);
            }

            let trash_dir = parent_dir.join(".mediaflow_trash");
            prune_mediaflow_trash_dir(&trash_dir, mediaflow_trash_retention());

            match persist_mediaflow_completion_with_retry(job_id, &out_str, new_size).await {
                Ok(()) => {
                    let _ = fs::remove_file(trash_dir.join(&intent_fname));
                    tracing::info!(
                        job_id = job_id,
                        output = %out_str,
                        new_size = new_size,
                        "mediaflow: transcode completed"
                    );
                    publish_mediaflow_progress(&serde_json::json!({
                        "status": "completed",
                        "file": out_str,
                        "progress": 100,
                        "message": "Transcode completed",
                    }));
                }
                Err(db_err) => {
                    tracing::error!(
                        job_id = job_id,
                        output = %out_str,
                        error = %db_err,
                        "mediaflow: filesystem publication succeeded but SQLite completion update failed after retries; retaining publish intent for startup reconciliation"
                    );
                }
            }
        }
        FfmpegOutcome::Exited(Ok(status), stderr_text) => {
            temp_guard.cleanup_now();
            let err_log = tail_error_log(&stderr_text, 1000);
            let msg = format!("FFmpeg error ({}): {}", status, err_log);
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
        }
        FfmpegOutcome::Exited(Err(err), _) => {
            temp_guard.cleanup_now();
            let msg = format!("FFmpeg execution error: {}", err);
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
        }
        FfmpegOutcome::Cancelled => {
            temp_guard.cleanup_now();
            record_mediaflow_cancelled(job_id, MEDIAFLOW_CANCELLED_MSG);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "cancelled",
                "file": file_path,
                "progress": 0,
                "message": "Transcode cancelled",
            }));
        }
        FfmpegOutcome::TimedOut => {
            temp_guard.cleanup_now();
            let msg = format!("FFmpeg timed out after {}s", timeout.as_secs());
            record_mediaflow_failure(job_id, &msg);
            publish_mediaflow_progress(&serde_json::json!({
                "status": "failed",
                "file": file_path,
                "progress": 0,
                "message": msg,
            }));
        }
    }

    drop(temp_guard);
    drop(pinned);
    true
}

pub(super) fn tail_error_log(text: &str, max_len: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }
    let mut start = trimmed.len() - max_len;
    while start < trimmed.len() && !trimmed.is_char_boundary(start) {
        start += 1;
    }
    trimmed[start..].to_string()
}

pub(super) fn record_mediaflow_failure(job_id: i64, reason: &str) {
    tracing::error!(job_id = job_id, error = %reason, "mediaflow: transcode job failed");
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'FAILED', error_log = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2 AND status = 'PROCESSING'",
            params![reason, job_id],
        );
    }
}

pub(super) fn record_mediaflow_needs_rescan(job_id: i64, reason: &str) {
    tracing::warn!(job_id = job_id, reason = %reason, "mediaflow: transcode job requires re-scan/re-review");
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'NEEDS_RESCAN', error_log = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2 AND status = 'PROCESSING'",
            params![reason, job_id],
        );
    }
}

pub(super) fn record_mediaflow_cancelled(job_id: i64, reason: &str) {
    tracing::info!(job_id = job_id, reason = %reason, "mediaflow: transcode job cancelled");
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'CANCELLED', error_log = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2 AND status = 'PROCESSING'",
            params![reason, job_id],
        );
    }
}
