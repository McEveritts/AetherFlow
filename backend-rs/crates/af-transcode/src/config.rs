//! Runtime configuration, environment allowlist, and safety validation for `af-transcode`.

use crate::protocol::{
    StartRequest, MAX_FRAME_BYTES, MAX_START_ARGS, MAX_START_ARG_BYTES, MAX_START_CWD_BYTES,
    MAX_START_ENV_ENTRIES, MAX_START_ENV_VALUE_BYTES,
};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// Default real `jellyfin-ffmpeg` binary path on Debian 13.
pub const DEFAULT_REAL_FFMPEG_PATH: &str = "/usr/lib/jellyfin-ffmpeg/ffmpeg";

/// Dedicated secret-free transcode environment file read as fallback by `af-transcode`.
///
/// Transcode workers run as `User=jellyfin` and must NEVER read `/etc/aetherflow/aetherflow.env`.
pub const DEFAULT_TRANSCODE_ENV_FILE: &str = "/etc/aetherflow/transcode.env";

/// Default Jellyfin cache root permitted as a worker child working-directory subtree.
pub const DEFAULT_JELLYFIN_CACHE_DIR: &str = "/var/cache/jellyfin";

/// Maximum size in bytes accepted when reading `DEFAULT_TRANSCODE_ENV_FILE`.
pub const MAX_TRANSCODE_ENV_FILE_BYTES: usize = 16 * 1024;

/// Default Unix socket where the Jellyfin-side `af-api` dispatcher listens (P9).
pub const DEFAULT_DISPATCHER_SOCKET_PATH: &str = "/run/aetherflow-transcode/transcode.sock";

/// Default Unix socket where `af-transcode worker` listens.
pub const DEFAULT_WORKER_SOCKET_PATH: &str = "/run/aetherflow-transcode-worker/worker.sock";

/// Environment variable overriding the real `ffmpeg` executable path.
pub const ENV_REAL_FFMPEG: &str = "AF_TRANSCODE_REAL_FFMPEG";

/// Environment variable overriding the dispatcher Unix socket path (for fixtures/testing).
pub const ENV_DISPATCHER_SOCKET: &str = "AF_TRANSCODE_DISPATCHER_SOCK";

/// Environment variable overriding the worker Unix socket path (for fixtures/testing).
pub const ENV_WORKER_SOCKET: &str = "AF_TRANSCODE_WORKER_SOCK";

/// Environment variable overriding maximum concurrent worker jobs (`1..=64`).
pub const ENV_WORKER_MAX_JOBS: &str = "AF_TRANSCODE_WORKER_MAX_JOBS";

/// Environment variable overriding the worker Unix socket permissions in octal (e.g. `0660`).
pub const ENV_WORKER_SOCKET_MODE: &str = "AF_TRANSCODE_WORKER_SOCKET_MODE";

/// Environment variable overriding the shim handshake timeout in milliseconds.
pub const ENV_HANDSHAKE_TIMEOUT_MS: &str = "AF_TRANSCODE_HANDSHAKE_TIMEOUT_MS";

/// Internal recursion-guard environment variable set when the shim `exec`s the real `ffmpeg`.
pub const ENV_SHIM_RECURSION_GUARD: &str = "AF_TRANSCODE_SHIM_ACTIVE";

/// End-to-end handshake budget enforced by the shim from connect start until `RunLocal` or `Started`.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Recommended remote-start budget for the P9 dispatcher so it always replies within the shim's 2 s window.
pub const RECOMMENDED_DISPATCHER_REMOTE_START_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Maximum time the worker waits for the initial `Frame::Start` after accepting a socket connection.
pub const DEFAULT_WORKER_START_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time a single frame write to the peer Unix socket may stall before aborting the connection.
pub const DEFAULT_FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time capability probe subprocesses (`ffmpeg`, `dpkg-query`) are permitted to run.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default maximum concurrent jobs handled by a single worker instance.
pub const DEFAULT_WORKER_MAX_JOBS: usize = 8;

/// Hard upper bound for `max_concurrent_jobs`.
pub const MAX_WORKER_MAX_JOBS: usize = 64;

/// Default restricted Unix socket mode (`rw-rw----`, no world access).
pub const DEFAULT_WORKER_SOCKET_MODE: u32 = 0o660;

/// Maximum safe Unix domain socket path length (`sun_path` minus NUL terminator on Linux).
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;

/// Narrow environment variable allowlist permitted to cross from the Jellyfin shim to a remote worker.
///
/// Loader variables (`LD_*`), execution overrides (`PATH`, `BASH_ENV`, `SHELL`, ...), GPU driver
/// overrides (`LIBVA_*`, `VK_*`, `OCL_*`, ...), and `FFREPORT` are deliberately excluded.
pub const ALLOWED_ENV_KEYS: &[&str] = &[
    "TMPDIR",
    "TZ",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "FONTCONFIG_FILE",
    "FONTCONFIG_PATH",
];

/// Baseline environment keys preserved from the worker's own process environment (never from remote `Start`).
pub const WORKER_BASELINE_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "XDG_RUNTIME_DIR",
    "LIBVA_DRIVER_NAME",
    "LIBVA_DRIVERS_PATH",
    "MESA_SHADER_CACHE_DIR",
];

/// Configuration and validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("refusing to invoke real ffmpeg at '{0}': path resolves to the active af-transcode binary (recursion guard)")]
    RecursiveFfmpegPath(PathBuf),

    #[error("shim recursion guard triggered ({ENV_SHIM_RECURSION_GUARD} is already set)")]
    ShimRecursionDetected,

    #[error("invalid worker socket mode {mode:#o}: {reason}")]
    InvalidSocketMode { mode: u32, reason: String },

    #[error("invalid Start request: {0}")]
    InvalidStartRequest(String),

    #[error("I/O error for '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Validates a `KEY` identifier in a `transcode.env` file (`[A-Za-z_][A-Za-z0-9_]*`).
fn is_valid_env_file_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Parses one `VALUE` from a `KEY=VALUE` line, stripping comments and matching quotes.
fn parse_env_file_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let parsed = if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        trimmed[1..trimmed.len() - 1].to_string()
    } else if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        // Strip inline comments preceded by ASCII whitespace (so unquoted `#` inside paths is kept).
        let bytes = trimmed.as_bytes();
        let mut end = bytes.len();
        for idx in 1..bytes.len() {
            if bytes[idx] == b'#' && bytes[idx - 1].is_ascii_whitespace() {
                end = idx;
                break;
            }
        }
        if trimmed.starts_with('#') {
            String::new()
        } else {
            trimmed[..end].trim_end().to_string()
        }
    };

    if parsed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    Some(parsed)
}

fn parse_transcode_env_contents(contents: &str) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    for raw_line in contents.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let body = trimmed
            .strip_prefix("export")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .map(str::trim_start)
            .unwrap_or(trimmed);
        let Some((raw_key, raw_val)) = body.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        if !is_valid_env_file_key(key) {
            continue;
        }
        if let Some(val) = parse_env_file_value(raw_val) {
            entries.insert(key.to_string(), val);
        }
    }
    entries
}

/// Safely reads a dedicated transcode `KEY=VALUE` environment file (e.g. `/etc/aetherflow/transcode.env`).
///
/// Security invariants:
/// - Explicitly refuses any file named `aetherflow.env` (workers must NEVER read main API secrets).
/// - Opens with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` to prevent symlink races and FIFO blocking.
/// - Verifies on the open descriptor (`fstat`) that the target is a regular file, not world-writable,
///   and bounded to `MAX_TRANSCODE_ENV_FILE_BYTES`.
pub fn read_transcode_env_file(path: &Path) -> Result<BTreeMap<String, String>, ConfigError> {
    validate_absolute_clean_path(path)?;
    if path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("aetherflow.env"))
    {
        return Err(ConfigError::InvalidPath {
            path: path.display().to_string(),
            reason: "refusing to read main aetherflow.env from transcode config".to_string(),
        });
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;

    let meta = file.metadata().map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !meta.is_file() {
        return Err(ConfigError::InvalidPath {
            path: path.display().to_string(),
            reason: "transcode env path must be a regular file".to_string(),
        });
    }
    if meta.permissions().mode() & 0o002 != 0 {
        return Err(ConfigError::InvalidPath {
            path: path.display().to_string(),
            reason: "transcode env file must not be world-writable".to_string(),
        });
    }
    if meta.len() > MAX_TRANSCODE_ENV_FILE_BYTES as u64 {
        return Err(ConfigError::InvalidPath {
            path: path.display().to_string(),
            reason: format!("transcode env file exceeds {MAX_TRANSCODE_ENV_FILE_BYTES} byte limit"),
        });
    }

    let mut raw = Vec::new();
    file.take((MAX_TRANSCODE_ENV_FILE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
    if raw.len() > MAX_TRANSCODE_ENV_FILE_BYTES {
        return Err(ConfigError::InvalidPath {
            path: path.display().to_string(),
            reason: format!("transcode env file exceeds {MAX_TRANSCODE_ENV_FILE_BYTES} byte limit"),
        });
    }

    let contents = String::from_utf8(raw).map_err(|_| ConfigError::InvalidPath {
        path: path.display().to_string(),
        reason: "transcode env file must be valid UTF-8".to_string(),
    })?;
    Ok(parse_transcode_env_contents(&contents))
}

fn read_transcode_env_var_from_path(path: &Path, key: &str) -> Option<String> {
    match read_transcode_env_file(path) {
        Ok(entries) => entries.get(key).cloned(),
        Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "ignoring unreadable or unsafe transcode env file"
            );
            None
        }
    }
}

fn resolve_real_ffmpeg_path(env_override: Option<&OsStr>, env_file: &Path) -> PathBuf {
    if let Some(val) = env_override.filter(|v| !v.is_empty()) {
        return PathBuf::from(val);
    }
    if let Some(val) =
        read_transcode_env_var_from_path(env_file, ENV_REAL_FFMPEG).filter(|v| !v.is_empty())
    {
        return PathBuf::from(val);
    }
    PathBuf::from(DEFAULT_REAL_FFMPEG_PATH)
}

/// Resolves the configured real `ffmpeg` path from `AF_TRANSCODE_REAL_FFMPEG`, falling back
/// to the given dedicated transcode env file and finally `DEFAULT_REAL_FFMPEG_PATH`.
pub fn configured_real_ffmpeg_path_with_env_file(env_file: &Path) -> PathBuf {
    let env_val: Option<OsString> = env::var_os(ENV_REAL_FFMPEG);
    resolve_real_ffmpeg_path(env_val.as_deref(), env_file)
}

/// Resolves the configured real `ffmpeg` path from `AF_TRANSCODE_REAL_FFMPEG`, falling back
/// to `/etc/aetherflow/transcode.env` and finally `DEFAULT_REAL_FFMPEG_PATH`.
pub fn configured_real_ffmpeg_path() -> PathBuf {
    configured_real_ffmpeg_path_with_env_file(Path::new(DEFAULT_TRANSCODE_ENV_FILE))
}

/// Resolves the configured dispatcher Unix socket path from `AF_TRANSCODE_DISPATCHER_SOCK` or the default.
pub fn configured_dispatcher_socket_path() -> PathBuf {
    env::var_os(ENV_DISPATCHER_SOCKET)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DISPATCHER_SOCKET_PATH))
}

/// Resolves the configured worker Unix socket path from `AF_TRANSCODE_WORKER_SOCK` or the default.
pub fn configured_worker_socket_path() -> PathBuf {
    env::var_os(ENV_WORKER_SOCKET)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WORKER_SOCKET_PATH))
}

/// Resolves the configured shim handshake timeout (default 2 s).
pub fn configured_handshake_timeout() -> Duration {
    env::var(ENV_HANDSHAKE_TIMEOUT_MS)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|&ms| (50..=30_000).contains(&ms))
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT)
}

fn resolve_worker_max_jobs(env_override: Option<&str>, env_file: &Path) -> usize {
    let raw = env_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            read_transcode_env_var_from_path(env_file, ENV_WORKER_MAX_JOBS)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });
    raw.and_then(|value| value.parse::<usize>().ok())
        .map(|n| n.clamp(1, MAX_WORKER_MAX_JOBS))
        .unwrap_or(DEFAULT_WORKER_MAX_JOBS)
}

/// Resolves the configured worker max concurrent jobs from `AF_TRANSCODE_WORKER_MAX_JOBS`,
/// falling back to the given dedicated transcode env file and finally `DEFAULT_WORKER_MAX_JOBS`
/// (clamped `1..=64`).
pub fn configured_worker_max_jobs_with_env_file(env_file: &Path) -> usize {
    let env_val = env::var(ENV_WORKER_MAX_JOBS).ok();
    resolve_worker_max_jobs(env_val.as_deref(), env_file)
}

/// Resolves the configured worker max concurrent jobs from `AF_TRANSCODE_WORKER_MAX_JOBS`,
/// falling back to `/etc/aetherflow/transcode.env` and finally `DEFAULT_WORKER_MAX_JOBS`
/// (clamped `1..=64`).
pub fn configured_worker_max_jobs() -> usize {
    configured_worker_max_jobs_with_env_file(Path::new(DEFAULT_TRANSCODE_ENV_FILE))
}

/// Resolves the configured worker socket mode (octal, default `0o660`).
pub fn configured_worker_socket_mode() -> Result<u32, ConfigError> {
    let Some(raw) = env::var(ENV_WORKER_SOCKET_MODE).ok() else {
        return Ok(DEFAULT_WORKER_SOCKET_MODE);
    };
    let trimmed = raw.trim().trim_start_matches("0o").trim_start_matches("0O");
    let mode = u32::from_str_radix(trimmed, 8).map_err(|_| ConfigError::InvalidSocketMode {
        mode: 0,
        reason: format!("expected octal mode, got '{raw}'"),
    })?;
    validate_socket_mode(mode)?;
    Ok(mode)
}

/// Validates that a Unix socket mode forbids world access and retains owner read/write.
pub fn validate_socket_mode(mode: u32) -> Result<(), ConfigError> {
    if mode > 0o777 {
        return Err(ConfigError::InvalidSocketMode {
            mode,
            reason: "mode bits above 0o777 are not permitted".to_string(),
        });
    }
    if mode & 0o007 != 0 {
        return Err(ConfigError::InvalidSocketMode {
            mode,
            reason: "world permissions must be 0".to_string(),
        });
    }
    if mode & 0o600 != 0o600 {
        return Err(ConfigError::InvalidSocketMode {
            mode,
            reason: "owner read/write bits (0o600) are required".to_string(),
        });
    }
    Ok(())
}

/// Validates that `path` is a safe absolute path with no `..` traversal or NUL bytes.
pub fn validate_absolute_clean_path(path: &Path) -> Result<(), ConfigError> {
    let raw = path.to_string_lossy();
    if raw.is_empty() {
        return Err(ConfigError::InvalidPath {
            path: raw.into_owned(),
            reason: "path must not be empty".to_string(),
        });
    }
    if raw.contains('\0') || raw.contains('\n') || raw.contains('\r') {
        return Err(ConfigError::InvalidPath {
            path: raw.into_owned(),
            reason: "path contains forbidden control characters".to_string(),
        });
    }
    if !path.is_absolute() {
        return Err(ConfigError::InvalidPath {
            path: raw.into_owned(),
            reason: "path must be absolute".to_string(),
        });
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ConfigError::InvalidPath {
            path: raw.into_owned(),
            reason: "path must not contain '..' components".to_string(),
        });
    }
    Ok(())
}

/// Validates the configured real `ffmpeg` executable and guards against executing `af-transcode` itself.
pub fn validate_real_ffmpeg_path(path: &Path) -> Result<PathBuf, ConfigError> {
    validate_absolute_clean_path(path)?;

    let target_meta = fs::metadata(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !target_meta.is_file() {
        return Err(ConfigError::InvalidPath {
            path: path.display().to_string(),
            reason: "real ffmpeg path must resolve to a regular file".to_string(),
        });
    }
    if target_meta.permissions().mode() & 0o111 == 0 {
        return Err(ConfigError::InvalidPath {
            path: path.display().to_string(),
            reason: "real ffmpeg path is not executable".to_string(),
        });
    }

    let canonical_target = fs::canonicalize(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;

    if let Ok(current_exe) = env::current_exe() {
        if let Ok(current_meta) = fs::metadata(&current_exe) {
            if current_meta.dev() == target_meta.dev() && current_meta.ino() == target_meta.ino() {
                return Err(ConfigError::RecursiveFfmpegPath(path.to_path_buf()));
            }
        }
        if let Ok(canonical_self) = fs::canonicalize(&current_exe) {
            if canonical_self == canonical_target {
                return Err(ConfigError::RecursiveFfmpegPath(path.to_path_buf()));
            }
        }
    }

    Ok(canonical_target)
}

/// Returns `true` if `key` is on the narrow cross-node environment allowlist.
pub fn is_allowed_env_key(key: &str) -> bool {
    ALLOWED_ENV_KEYS.contains(&key)
}

/// Validates one `(key, value)` environment entry against the narrow allowlist and value rules.
pub fn validate_env_entry(key: &str, value: &str) -> Result<(), ConfigError> {
    if !is_allowed_env_key(key) {
        return Err(ConfigError::InvalidStartRequest(format!(
            "environment variable '{key}' is not on the transcode allowlist"
        )));
    }
    if value.is_empty() {
        return Err(ConfigError::InvalidStartRequest(format!(
            "environment variable '{key}' must not be empty"
        )));
    }
    if value.len() > MAX_START_ENV_VALUE_BYTES {
        return Err(ConfigError::InvalidStartRequest(format!(
            "environment variable '{key}' exceeds {MAX_START_ENV_VALUE_BYTES} bytes"
        )));
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ConfigError::InvalidStartRequest(format!(
            "environment variable '{key}' contains control characters"
        )));
    }

    match key {
        "TMPDIR" | "FONTCONFIG_FILE" => {
            validate_absolute_clean_path(Path::new(value))
                .map_err(|err| ConfigError::InvalidStartRequest(format!("invalid {key}: {err}")))?;
        }
        "FONTCONFIG_PATH" => {
            for segment in value.split(':') {
                validate_absolute_clean_path(Path::new(segment)).map_err(|err| {
                    ConfigError::InvalidStartRequest(format!(
                        "invalid FONTCONFIG_PATH entry: {err}"
                    ))
                })?;
            }
        }
        "LANG" | "LC_ALL" | "LC_CTYPE" => {
            if value.len() > 128
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'))
            {
                return Err(ConfigError::InvalidStartRequest(format!(
                    "invalid locale syntax for {key}"
                )));
            }
        }
        "TZ" => {
            if value.len() > 128
                || value.contains("..")
                || !value.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'/' | b'_' | b'+' | b'-' | b':' | b'.')
                })
            {
                return Err(ConfigError::InvalidStartRequest(
                    "invalid TZ value".to_string(),
                ));
            }
        }
        _ => unreachable!("key verified against ALLOWED_ENV_KEYS"),
    }

    Ok(())
}

/// Validates a complete `env_subset` list received in `Frame::Start`.
pub fn validate_env_subset(entries: &[(String, String)]) -> Result<(), ConfigError> {
    if entries.len() > MAX_START_ENV_ENTRIES {
        return Err(ConfigError::InvalidStartRequest(format!(
            "env_subset has {} entries, exceeding limit {MAX_START_ENV_ENTRIES}",
            entries.len()
        )));
    }
    let mut seen = HashSet::with_capacity(entries.len());
    for (key, value) in entries {
        if !seen.insert(key.as_str()) {
            return Err(ConfigError::InvalidStartRequest(format!(
                "duplicate environment variable '{key}'"
            )));
        }
        validate_env_entry(key, value)?;
    }
    Ok(())
}

/// Collects only validated allowlisted environment variables from the current process.
pub fn collect_allowed_env_subset() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for &key in ALLOWED_ENV_KEYS {
        if let Ok(value) = env::var(key) {
            if validate_env_entry(key, &value).is_ok() {
                out.push((key.to_string(), value));
            }
        }
    }
    out
}

/// Validates `cwd` from a `StartRequest` and verifies it exists as a directory on the worker.
pub fn validate_cwd(cwd: &str) -> Result<PathBuf, ConfigError> {
    if cwd.is_empty() {
        return Err(ConfigError::InvalidStartRequest(
            "cwd must not be empty".to_string(),
        ));
    }
    if cwd.len() > MAX_START_CWD_BYTES {
        return Err(ConfigError::InvalidStartRequest(format!(
            "cwd exceeds {MAX_START_CWD_BYTES} bytes"
        )));
    }
    let path = Path::new(cwd);
    validate_absolute_clean_path(path)
        .map_err(|err| ConfigError::InvalidStartRequest(format!("invalid cwd: {err}")))?;

    let meta = fs::metadata(path).map_err(|err| {
        ConfigError::InvalidStartRequest(format!("cwd '{cwd}' is not accessible: {err}"))
    })?;
    if !meta.is_dir() {
        return Err(ConfigError::InvalidStartRequest(format!(
            "cwd '{cwd}' is not a directory"
        )));
    }
    Ok(path.to_path_buf())
}

/// Validates that `path` is an absolute, clean, non-symlink existing directory and returns its
/// canonical path.
pub fn validate_safe_dir(path: &Path) -> Result<PathBuf, ConfigError> {
    validate_absolute_clean_path(path)?;
    let _dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
    fs::canonicalize(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Resolves and clamps the worker child `ffmpeg` working directory to a safe restricted root.
///
/// - Validates `fallback_safe_cwd` as a clean non-symlink existing directory.
/// - Canonicalizes `requested_cwd` (resolving any intermediate symlinks so symlink escapes
///   such as `<allowed>/escape -> /etc` are detected).
/// - Keeps `canonical_requested` only when it is inside one of the canonicalized `allowed_roots`
///   (which always includes `fallback_safe_cwd`); otherwise clamps to `fallback_safe_cwd`.
pub fn resolve_worker_child_cwd(
    requested_cwd: &Path,
    fallback_safe_cwd: &Path,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, ConfigError> {
    let canonical_fallback = validate_safe_dir(fallback_safe_cwd)?;

    let canonical_requested = match fs::canonicalize(requested_cwd) {
        Ok(dir) if dir.is_dir() => dir,
        _ => return Ok(canonical_fallback),
    };

    if canonical_requested.starts_with(&canonical_fallback) {
        return Ok(canonical_requested);
    }

    for root in allowed_roots {
        if validate_absolute_clean_path(root).is_err() {
            continue;
        }
        if let Ok(canonical_root) = fs::canonicalize(root) {
            if canonical_root.is_dir() && canonical_requested.starts_with(&canonical_root) {
                return Ok(canonical_requested);
            }
        }
    }

    Ok(canonical_fallback)
}

/// Validates an incoming `StartRequest` (`args`, `cwd`, and narrow `env_subset` allowlist).
pub fn validate_start_request(req: &StartRequest) -> Result<PathBuf, ConfigError> {
    if req.args.is_empty() {
        return Err(ConfigError::InvalidStartRequest(
            "args must not be empty".to_string(),
        ));
    }
    if req.args.len() > MAX_START_ARGS {
        return Err(ConfigError::InvalidStartRequest(format!(
            "args count {} exceeds limit {MAX_START_ARGS}",
            req.args.len()
        )));
    }

    let mut total_arg_bytes: usize = 0;
    for (idx, arg) in req.args.iter().enumerate() {
        if arg.len() > MAX_START_ARG_BYTES {
            return Err(ConfigError::InvalidStartRequest(format!(
                "arg[{idx}] length {} exceeds limit {MAX_START_ARG_BYTES}",
                arg.len()
            )));
        }
        if arg.contains('\0') {
            return Err(ConfigError::InvalidStartRequest(format!(
                "arg[{idx}] contains NUL byte"
            )));
        }
        total_arg_bytes = total_arg_bytes.saturating_add(arg.len());
        if total_arg_bytes > MAX_FRAME_BYTES {
            return Err(ConfigError::InvalidStartRequest(format!(
                "total argument bytes exceed {MAX_FRAME_BYTES}"
            )));
        }
    }

    let validated_cwd = validate_cwd(&req.cwd)?;
    validate_env_subset(&req.env_subset)?;
    Ok(validated_cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_allowlist_rejects_loader_and_arbitrary_vars() {
        for forbidden in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "PATH",
            "BASH_ENV",
            "LIBVA_DRIVERS_PATH",
            "LIBVA_DRIVER_NAME",
            "VK_ICD_FILENAMES",
            "FFREPORT",
            "AF_TRANSCODE_REAL_FFMPEG",
            "JELLYFIN_FFMPEG",
            "RANDOM_VAR",
        ] {
            assert!(
                validate_env_entry(forbidden, "/tmp/safe").is_err(),
                "{forbidden} must be rejected"
            );
        }

        assert!(validate_env_entry("TMPDIR", "/var/cache/jellyfin/af-tmp").is_ok());
        assert!(validate_env_entry("TMPDIR", "relative/tmp").is_err());
        assert!(validate_env_entry("TMPDIR", "/var/cache/../etc").is_err());
        assert!(validate_env_entry("TMPDIR", "/var/cache\0/tmp").is_err());
        assert!(validate_env_entry("TZ", "UTC").is_ok());
        assert!(validate_env_entry("TZ", "America/New_York").is_ok());
        assert!(validate_env_entry("TZ", "../etc/passwd").is_err());
        assert!(validate_env_entry("LANG", "C.UTF-8").is_ok());
        assert!(validate_env_entry("LANG", "en_US.UTF-8;id").is_err());
        assert!(
            validate_env_entry("FONTCONFIG_PATH", "/etc/fonts:/var/cache/jellyfin/fonts").is_ok()
        );
        assert!(validate_env_entry("FONTCONFIG_PATH", "/etc/fonts:relative").is_err());
    }

    #[test]
    fn duplicate_env_keys_are_rejected() {
        let dup = vec![
            ("TZ".to_string(), "UTC".to_string()),
            ("TZ".to_string(), "Europe/Berlin".to_string()),
        ];
        assert!(validate_env_subset(&dup).is_err());
    }

    #[test]
    fn socket_mode_forbids_world_bits() {
        assert!(validate_socket_mode(0o600).is_ok());
        assert!(validate_socket_mode(0o660).is_ok());
        assert!(validate_socket_mode(0o666).is_err());
        assert!(validate_socket_mode(0o664).is_err());
        assert!(validate_socket_mode(0o641).is_err());
        assert!(validate_socket_mode(0o400).is_err());
        assert!(validate_socket_mode(0o1660).is_err());
    }

    #[test]
    fn validate_real_ffmpeg_blocks_self_recursion() {
        let exe = env::current_exe().expect("current_exe");
        let err = validate_real_ffmpeg_path(&exe).expect_err("must reject self");
        assert!(matches!(err, ConfigError::RecursiveFfmpegPath(_)));
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!("/tmp/af-cfg-{tag}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn transcode_env_file_parses_quotes_comments_and_precedence() {
        let dir = unique_temp_dir("envparse");
        let env_path = dir.join("transcode.env");
        fs::write(
            &env_path,
            r#"
# Full-line comment
; Systemd semicolon comment
AF_TRANSCODE_REAL_FFMPEG="/opt/custom/bin/ffmpeg"
export AF_TRANSCODE_WORKER_MAX_JOBS=12 # inline comment
SINGLE_QUOTED='hello # not a comment'
UNQUOTED_HASH=/opt/dir#1/ffmpeg
"#,
        )
        .expect("write env file");
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o640)).unwrap();

        let parsed = read_transcode_env_file(&env_path).expect("parse transcode.env");
        assert_eq!(
            parsed.get(ENV_REAL_FFMPEG).map(String::as_str),
            Some("/opt/custom/bin/ffmpeg")
        );
        assert_eq!(
            parsed.get(ENV_WORKER_MAX_JOBS).map(String::as_str),
            Some("12")
        );
        assert_eq!(
            parsed.get("SINGLE_QUOTED").map(String::as_str),
            Some("hello # not a comment")
        );
        assert_eq!(
            parsed.get("UNQUOTED_HASH").map(String::as_str),
            Some("/opt/dir#1/ffmpeg")
        );

        // Fallback reads transcode.env when process env is unset; process env wins when set.
        assert_eq!(
            resolve_real_ffmpeg_path(None, &env_path),
            PathBuf::from("/opt/custom/bin/ffmpeg")
        );
        assert_eq!(
            resolve_real_ffmpeg_path(Some(OsStr::new("/usr/bin/override-ffmpeg")), &env_path),
            PathBuf::from("/usr/bin/override-ffmpeg")
        );
        assert_eq!(resolve_worker_max_jobs(None, &env_path), 12);
        assert_eq!(resolve_worker_max_jobs(Some("24"), &env_path), 24);
        assert_eq!(
            resolve_worker_max_jobs(Some("999"), &env_path),
            MAX_WORKER_MAX_JOBS
        );
        assert_eq!(resolve_worker_max_jobs(Some("0"), &env_path), 1);

        // Missing env file falls back cleanly to built-in defaults.
        let missing = dir.join("absent.env");
        assert_eq!(
            resolve_real_ffmpeg_path(None, &missing),
            PathBuf::from(DEFAULT_REAL_FFMPEG_PATH)
        );
        assert_eq!(
            resolve_worker_max_jobs(None, &missing),
            DEFAULT_WORKER_MAX_JOBS
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn transcode_env_file_rejects_symlinks_aetherflow_env_world_writable_and_oversized() {
        use std::os::unix::fs::symlink;

        let dir = unique_temp_dir("envsec");

        // 1. Refuse main aetherflow.env by filename guard.
        let main_env = dir.join("aetherflow.env");
        fs::write(&main_env, "AF_TRANSCODE_WORKER_MAX_JOBS=32\n").unwrap();
        assert!(read_transcode_env_file(&main_env).is_err());

        // 2. Refuse symlink (O_NOFOLLOW).
        let real_file = dir.join("real.env");
        fs::write(&real_file, "AF_TRANSCODE_WORKER_MAX_JOBS=16\n").unwrap();
        let sym_file = dir.join("transcode.env");
        symlink(&real_file, &sym_file).unwrap();
        assert!(read_transcode_env_file(&sym_file).is_err());
        // Fallback helper safely ignores unsafe symlink and uses default.
        assert_eq!(
            resolve_worker_max_jobs(None, &sym_file),
            DEFAULT_WORKER_MAX_JOBS
        );

        // 3. Refuse directory (non-regular file).
        assert!(read_transcode_env_file(&dir).is_err());

        // 4. Refuse world-writable file.
        let ww_file = dir.join("ww.env");
        fs::write(&ww_file, "AF_TRANSCODE_WORKER_MAX_JOBS=16\n").unwrap();
        fs::set_permissions(&ww_file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_transcode_env_file(&ww_file).is_err());

        // 5. Refuse oversized file (> MAX_TRANSCODE_ENV_FILE_BYTES).
        let big_file = dir.join("big.env");
        fs::write(&big_file, "A".repeat(MAX_TRANSCODE_ENV_FILE_BYTES + 1)).unwrap();
        assert!(read_transcode_env_file(&big_file).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_worker_child_cwd_clamps_out_of_root_and_symlink_escapes() {
        use std::os::unix::fs::symlink;

        let dir = unique_temp_dir("safecwd");
        let safe_root = dir.join("safe");
        let allowed_sub = safe_root.join("sub");
        let extra_root = dir.join("extra");
        let outside = dir.join("outside");
        fs::create_dir_all(&allowed_sub).unwrap();
        fs::create_dir_all(&extra_root).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let escape_link = safe_root.join("escape");
        symlink(&outside, &escape_link).unwrap();

        let canonical_safe = fs::canonicalize(&safe_root).unwrap();
        let canonical_sub = fs::canonicalize(&allowed_sub).unwrap();
        let canonical_extra = fs::canonicalize(&extra_root).unwrap();

        // Inside safe_root -> preserved.
        assert_eq!(
            resolve_worker_child_cwd(&allowed_sub, &safe_root, &[]).unwrap(),
            canonical_sub
        );

        // Inside explicit allowed_roots -> preserved.
        assert_eq!(
            resolve_worker_child_cwd(&extra_root, &safe_root, std::slice::from_ref(&extra_root))
                .unwrap(),
            canonical_extra
        );

        // Outside allowed_roots (e.g. /etc or sibling dir) -> clamped to safe_root.
        assert_eq!(
            resolve_worker_child_cwd(&outside, &safe_root, &[]).unwrap(),
            canonical_safe
        );
        assert_eq!(
            resolve_worker_child_cwd(Path::new("/"), &safe_root, &[]).unwrap(),
            canonical_safe
        );

        // Symlink inside safe_root pointing outside -> canonicalized and clamped to safe_root!
        assert_eq!(
            resolve_worker_child_cwd(&escape_link, &safe_root, &[]).unwrap(),
            canonical_safe
        );

        // Symlinked fallback safe_cwd itself is rejected.
        assert!(resolve_worker_child_cwd(&allowed_sub, &escape_link, &[]).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
