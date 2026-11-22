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
    #[serde(default)]
    pub output: Option<MediaflowPublishedOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct MediaflowPublishedOutput {
    temp_name: String,
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    fingerprint: String,
}

#[cfg(unix)]
impl MediaflowPublishedOutput {
    pub(super) fn capture(file: &fs::File, temp_name: String) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(|err| err.to_string())?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err("MediaFlow publish output is missing or empty".to_string());
        }
        let fingerprint = compute_mediaflow_fingerprint(file, metadata.len(), false)?;
        let after = file.metadata().map_err(|err| err.to_string())?;
        if (metadata.ctime(), metadata.ctime_nsec()) != (after.ctime(), after.ctime_nsec()) {
            return Err("MediaFlow publish output changed during fingerprinting".to_string());
        }
        Ok(Self {
            temp_name,
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            fingerprint,
        })
    }

    #[allow(clippy::unnecessary_cast)] // libc::stat field widths vary across Linux targets.
    fn matches_entry(&self, stat: &libc::stat) -> bool {
        stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_uid == unsafe { libc::geteuid() }
            && stat.st_dev as u64 == self.dev
            && stat.st_ino as u64 == self.ino
            && stat.st_size as u64 == self.size
            && stat.st_mtime as i64 == self.mtime_sec
            && stat.st_mtime_nsec as i64 == self.mtime_nsec
    }
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

mod executor;
mod recovery;
mod source;

pub use executor::process_next_mediaflow_job;
pub(super) use recovery::prune_mediaflow_trash_dir;
use recovery::{mediaflow_output_name, persist_mediaflow_completion_with_retry};
pub use recovery::{reconcile_mediaflow_startup, start_mediaflow_poller};
use source::{compute_mediaflow_fingerprint, read_regular_json_bounded};
pub(super) use source::{
    cstring_from_os_name, fstatat_nofollow, persist_trash_entry_metadata_dirfd, unlinkat_entry,
    write_dirfd_json_atomic,
};
pub use source::{
    open_and_pin_mediaflow_source, open_and_pin_mediaflow_source_in_roots, PinnedMediaflowSource,
};
