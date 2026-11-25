//! Stage 3 & Stage 6: Bare-metal systemd unit installation (`install_packaged_unit`),
//! daemon reload & service restart (`aetherflow-runner.service`, `aetherflow-api.service`),
//! and deep readiness health probing (`/health/ready`).
//!
//! All systemd and HTTP readiness operations are abstracted behind [`LifecycleController`]
//! and [`HealthProber`] so tests can verify exact call sequences without touching host services.

use crate::config::ReleaseConfig;
use crate::error::{ReleaseError, ReleaseResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Parses the top-level `"status"` string from a `/health/ready` JSON body,
/// matching `parse_health_status` in `deploy/release-manager.sh`.
/// Key order and whitespace do not matter.
/// v4 Rust returns `{"database":"ok","redis":"disabled","status":"ready","uptime":"0.0s"}`.
pub fn parse_health_status(response_body: &str) -> Option<String> {
    let trimmed = response_body.trim();
    if trimmed.is_empty() {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let obj = val.as_object()?;
    let status = obj.get("status")?.as_str()?.trim();
    if status.is_empty() {
        None
    } else {
        Some(status.to_string())
    }
}

/// Returns `true` if `status` is considered healthy by `release-manager.sh` (`"ready"` or `"ok"`).
pub fn is_healthy_status(status: &str) -> bool {
    matches!(status, "ready" | "ok")
}

const TRANSCODE_SHIM_RELATIVE_PATH: &str = "usr/lib/aetherflow/transcode/ffmpeg";
pub const TRANSCODE_WORKER_UNIT: &str = "af-transcode-worker.service";

fn active_release_directory(config: &ReleaseConfig) -> ReleaseResult<Option<PathBuf>> {
    let parent = config
        .current_link
        .parent()
        .ok_or_else(|| ReleaseError::PathValidation {
            path: config.current_link.clone(),
            reason: "current release link has no parent".to_string(),
        })?;
    crate::fs_security::ensure_no_symlink_ancestors(parent)?;
    let target = match fs::read_link(&config.current_link) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ReleaseError::io("reading current release link", error)),
    };
    let release_dir = if target.is_absolute() {
        target
    } else {
        parent.join(target)
    };
    if release_dir.parent() != Some(config.releases_dir.as_path()) {
        return Err(ReleaseError::PathValidation {
            path: release_dir,
            reason: "current release must be a direct child of the releases directory".to_string(),
        });
    }
    crate::fs_security::ensure_no_symlink_ancestors(&release_dir)?;
    Ok(Some(release_dir))
}

pub(crate) fn packaged_systemd_directory(config: &ReleaseConfig) -> ReleaseResult<PathBuf> {
    match active_release_directory(config)? {
        Some(release_dir) => Ok(release_dir.join("deploy/systemd")),
        None => Ok(config.current_link.join("deploy/systemd")),
    }
}

/// Resolves the installed transcode shim path (`/usr/lib/aetherflow/transcode/ffmpeg`),
/// rebased under `config.isolated_root` when isolated so tests never touch host `/usr/lib`.
pub fn resolve_transcode_shim_path(config: &ReleaseConfig) -> PathBuf {
    match config.isolated_root {
        Some(ref root) => root.join(TRANSCODE_SHIM_RELATIVE_PATH),
        None => PathBuf::from("/").join(TRANSCODE_SHIM_RELATIVE_PATH),
    }
}

/// Atomically refreshes an already-installed transcode shim (`.../usr/lib/aetherflow/transcode/ffmpeg`)
/// from the active release's `bin/af-transcode` binary.
///
/// - Stays dormant (`Ok(false)`) when the shim file does not exist or when the active release
///   does not include `bin/af-transcode` (legacy bundle compatibility).
/// - Fails closed (`Err(ReleaseError::PathValidation)`) if the shim path, any existing ancestor,
///   or the source `bin/af-transcode` path is a symlink or non-regular file.
/// - Copies via an exclusive sibling temp file (`0755`, `O_NOFOLLOW`), fsyncs, closes the write
///   descriptor, and atomically `rename`s over `ffmpeg` to prevent `ETXTBSY` and partial binaries.
pub fn refresh_installed_transcode_shim(config: &ReleaseConfig) -> ReleaseResult<bool> {
    let shim_path = resolve_transcode_shim_path(config);
    crate::fs_security::ensure_no_symlink_ancestors(&shim_path)?;

    match fs::symlink_metadata(&shim_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(ReleaseError::PathValidation {
                    path: shim_path,
                    reason: "refusing symlinked transcode shim path".to_string(),
                });
            }
            if !meta.file_type().is_file() {
                return Err(ReleaseError::PathValidation {
                    path: shim_path,
                    reason: "refusing non-regular transcode shim path".to_string(),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting transcode shim {}", shim_path.display()),
                err,
            ));
        }
    }

    let Some(release_dir) = active_release_directory(config)? else {
        return Ok(false);
    };
    let src_bin = release_dir.join("bin/af-transcode");
    crate::fs_security::ensure_no_symlink_ancestors(&src_bin)?;

    let mut src_opts = fs::OpenOptions::new();
    src_opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        src_opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut src_file = match src_opts.open(&src_bin) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(ReleaseError::io(
                format!("opening release transcode binary {}", src_bin.display()),
                err,
            ));
        }
    };
    let src_meta = src_file.metadata().map_err(|err| {
        ReleaseError::io(
            format!("inspecting release transcode binary {}", src_bin.display()),
            err,
        )
    })?;
    if !src_meta.is_file() {
        return Err(ReleaseError::PathValidation {
            path: src_bin,
            reason: "release bin/af-transcode must be a regular non-symlink file".to_string(),
        });
    }

    let shim_dir = shim_path
        .parent()
        .ok_or_else(|| ReleaseError::PathValidation {
            path: shim_path.clone(),
            reason: "transcode shim path has no parent directory".to_string(),
        })?;
    let tmp_path = shim_dir.join(format!(
        ".ffmpeg.tmp.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let mut tmp_opts = fs::OpenOptions::new();
    tmp_opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        tmp_opts
            .mode(0o755)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut tmp_file = tmp_opts.open(&tmp_path).map_err(|err| {
        ReleaseError::io(
            format!(
                "creating temporary transcode shim file {}",
                tmp_path.display()
            ),
            err,
        )
    })?;

    let write_res: ReleaseResult<()> = (|| {
        std::io::copy(&mut src_file, &mut tmp_file).map_err(|err| {
            ReleaseError::io(
                format!(
                    "copying transcode binary {} -> {}",
                    src_bin.display(),
                    tmp_path.display()
                ),
                err,
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use std::os::unix::io::AsRawFd;
            tmp_file
                .set_permissions(fs::Permissions::from_mode(0o755))
                .map_err(|err| {
                    ReleaseError::io(
                        format!(
                            "setting mode 0755 on temporary transcode shim {}",
                            tmp_path.display()
                        ),
                        err,
                    )
                })?;
            if unsafe { libc::geteuid() } == 0 {
                let rc = unsafe { libc::fchown(tmp_file.as_raw_fd(), 0, 0) };
                if rc != 0 {
                    return Err(ReleaseError::io(
                        format!(
                            "setting root:root ownership on temporary transcode shim {}",
                            tmp_path.display()
                        ),
                        std::io::Error::last_os_error(),
                    ));
                }
            }
        }
        tmp_file.sync_all().map_err(|err| {
            ReleaseError::io(
                format!("fsync temporary transcode shim {}", tmp_path.display()),
                err,
            )
        })?;
        Ok(())
    })();

    // Close write descriptor before rename so concurrent execve never observes ETXTBSY.
    drop(tmp_file);
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = crate::fs_security::ensure_no_symlink_ancestors(&shim_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    match fs::symlink_metadata(&shim_path) {
        Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_file() => {}
        Ok(_) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(ReleaseError::PathValidation {
                path: shim_path,
                reason: "transcode shim changed to symlink or non-regular file before rename"
                    .to_string(),
            });
        }
        Err(err) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(ReleaseError::io(
                format!("re-verifying transcode shim {}", shim_path.display()),
                err,
            ));
        }
    }

    fs::rename(&tmp_path, &shim_path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        ReleaseError::io(
            format!(
                "atomically renaming {} -> {}",
                tmp_path.display(),
                shim_path.display()
            ),
            err,
        )
    })?;
    crate::fs_security::sync_parent_dir_best_effort(shim_dir);
    Ok(true)
}

/// Installs a packaged systemd unit file (`aetherflow-runner.service` or `aetherflow-api.service`)
/// into `systemd_units_dst` ONLY if the destination unit does not already exist.
///
/// Preserves the critical invariant from `install_packaged_unit` in `deploy/release-manager.sh`:
/// replacing an already-installed unit would drop host `ReadWritePaths` customizations when
/// the live SQLite database resides outside `/var/lib/aetherflow`.
///
/// Returns `Ok(true)` if the unit was newly installed, or `Ok(false)` if skipped/kept.
pub fn install_packaged_unit_if_missing(
    src_unit: &Path,
    systemd_units_dst: &Path,
) -> ReleaseResult<bool> {
    if !src_unit.is_file() {
        return Ok(false);
    }
    let Some(file_name) = src_unit.file_name() else {
        return Ok(false);
    };
    crate::fs_security::create_dir_all_no_symlinks(systemd_units_dst, 0o755)?;
    let dest = systemd_units_dst.join(file_name);
    if fs::symlink_metadata(&dest).is_ok() {
        // Keep installed unit untouched so custom ReadWritePaths are preserved
        return Ok(false);
    }
    crate::fs_security::atomic_copy_file_with_mode(src_unit, &dest, 0o644, None)?;
    Ok(true)
}

const RUNNER_HARDENING_DROPIN: &[u8] = b"[Service]\nUMask=0077\nRuntimeDirectory=aetherflow\nRuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=yes\nLogsDirectory=aetherflow\nLogsDirectoryMode=0750\nPrivateTmp=yes\nProtectClock=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nLockPersonality=yes\nRestrictRealtime=yes\nSystemCallArchitectures=native\nSystemCallFilter=~@clock @cpu-emulation @debug @module @obsolete @raw-io @reboot @swap\n";
const API_HARDENING_DROPIN: &[u8] = b"[Service]\nUMask=0027\nLogsDirectory=\nProtectClock=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nLockPersonality=yes\nRestrictNamespaces=yes\nRestrictRealtime=yes\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n";

/// Atomically installs vendor-managed systemd hardening drop-ins matching `deploy/release-manager.sh`
/// without modifying existing base `.service` files (preserving custom operator `ReadWritePaths`/`BindPaths`
/// and allowing higher-numbered operator drop-ins such as `override.conf` to win).
///
/// Removes stale `05-aetherflow-unit-defaults.conf` (canonical units own `RestartSec`/`TimeoutStopSec`)
/// and removes stale `aetherflow-log-retention.service.d/10-aetherflow-hardening.conf` (canonical unit
/// sets `UMask=0027`).
pub fn install_systemd_hardening_dropins(
    systemd_units_dst: &Path,
    include_log_retention: bool,
) -> ReleaseResult<()> {
    crate::fs_security::create_dir_all_no_symlinks(systemd_units_dst, 0o755)?;
    let mut entries: Vec<(&str, Option<&[u8]>)> = vec![
        ("aetherflow-runner.service.d", Some(RUNNER_HARDENING_DROPIN)),
        ("aetherflow-api.service.d", Some(API_HARDENING_DROPIN)),
    ];
    if include_log_retention {
        entries.push(("aetherflow-log-retention.service.d", None));
    }
    for (dropin_dir_name, content_opt) in entries {
        let dropin_dir = systemd_units_dst.join(dropin_dir_name);
        let defaults_path = dropin_dir.join("05-aetherflow-unit-defaults.conf");
        let conf_path = dropin_dir.join("10-aetherflow-hardening.conf");
        crate::fs_security::ensure_no_symlink_ancestors(&defaults_path)?;
        crate::fs_security::ensure_no_symlink_ancestors(&conf_path)?;

        if fs::symlink_metadata(&defaults_path).is_ok() {
            fs::remove_file(&defaults_path).map_err(|e| {
                ReleaseError::io(
                    format!(
                        "removing stale unit defaults drop-in {}",
                        defaults_path.display()
                    ),
                    e,
                )
            })?;
        }

        let Some(content) = content_opt else {
            if fs::symlink_metadata(&conf_path).is_ok() {
                fs::remove_file(&conf_path).map_err(|e| {
                    ReleaseError::io(
                        format!(
                            "removing stale log-retention hardening drop-in {}",
                            conf_path.display()
                        ),
                        e,
                    )
                })?;
            }
            let _ = fs::remove_dir(&dropin_dir);
            continue;
        };

        crate::fs_security::create_dir_all_no_symlinks(&dropin_dir, 0o755)?;
        crate::fs_security::atomic_write_bytes_with_mode(&conf_path, content, 0o644)?;
    }
    Ok(())
}

/// Verifies that live systemd or PM2 lifecycle mutations are explicitly authorized
/// when running under an isolated release root (`--root` / `AETHERFLOW_RELEASE_ROOT`).
pub fn verify_isolated_systemd_lifecycle_authorized(config: &ReleaseConfig) -> ReleaseResult<()> {
    let Some(ref isolated_root) = config.isolated_root else {
        return Ok(());
    };
    let normalized_root = af_models::normalize_lexical_path(isolated_root, "isolated_root")
        .map_err(|reason| ReleaseError::PathValidation {
            path: isolated_root.clone(),
            reason,
        })?;
    if normalized_root == Path::new("/") {
        return Ok(());
    }

    let allow_flag = std::env::var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE")
        .ok()
        .map(|val| val.trim().to_string())
        .unwrap_or_default();
    if allow_flag != "1" {
        return Err(ReleaseError::Systemd {
            action: "isolated_systemd_guard".to_string(),
            reason: format!(
                "refusing live host systemd/PM2 lifecycle mutation under isolated root '{}' without AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1 and /etc/aetherflow-disposable-guest; pass --dry-run on non-disposable hosts",
                normalized_root.display()
            ),
        });
    }

    let marker_path = Path::new("/etc/aetherflow-disposable-guest");
    let marker_meta = fs::symlink_metadata(marker_path).map_err(|_| ReleaseError::Systemd {
        action: "isolated_systemd_guard".to_string(),
        reason: format!(
            "refusing live systemd/PM2 lifecycle mutation under isolated root '{}': missing disposable-guest marker file {}",
            normalized_root.display(),
            marker_path.display()
        ),
    })?;
    if !marker_meta.file_type().is_file() {
        return Err(ReleaseError::Systemd {
            action: "isolated_systemd_guard".to_string(),
            reason: format!(
                "refusing live systemd/PM2 lifecycle mutation under isolated root '{}': {} must be a regular non-symlink file",
                normalized_root.display(),
                marker_path.display()
            ),
        });
    }

    Ok(())
}

fn validate_cli_bin_dir(config: &ReleaseConfig) -> ReleaseResult<()> {
    if let Some(ref isolated_root) = config.isolated_root {
        af_models::validate_path_within_isolated_root(
            &config.cli_bin_dir,
            isolated_root,
            "CLI_BIN_DIR",
        )
        .map_err(|reason| ReleaseError::PathValidation {
            path: config.cli_bin_dir.clone(),
            reason,
        })?;
    }
    Ok(())
}

/// Preflights `config.cli_bin_dir` parent directory and write permissions BEFORE swapping `current`
/// when `release_dir` contains a CLI binary (`af` or `bin/af`), so permission/containment errors
/// fail cleanly pre-swap rather than stranding `current` on an unvalidated candidate.
pub fn preflight_cli_entrypoints(config: &ReleaseConfig, release_dir: &Path) -> ReleaseResult<()> {
    let has_af = release_dir.join("af").is_file() || release_dir.join("bin/af").is_file();
    if !has_af {
        return Ok(());
    }
    validate_cli_bin_dir(config)?;
    crate::fs_security::create_dir_all_no_symlinks(&config.cli_bin_dir, 0o755)?;

    let dest_af = config.cli_bin_dir.join("af");
    match fs::symlink_metadata(&dest_af) {
        Ok(meta) if !meta.file_type().is_symlink() => {
            // Existing regular wrapper (e.g. packages/system/af) is left untouched by sync_cli_entrypoints
            return Ok(());
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting CLI entrypoint {}", dest_af.display()),
                err,
            ));
        }
    }

    let probe_path = config.cli_bin_dir.join(format!(
        ".af-cli-preflight-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let probe_file = opts.open(&probe_path).map_err(|err| {
        ReleaseError::io(
            format!(
                "preflighting writable CLI_BIN_DIR {}",
                config.cli_bin_dir.display()
            ),
            err,
        )
    })?;
    drop(probe_file);
    let _ = fs::remove_file(&probe_path);
    Ok(())
}

/// Synchronizes `<cli_bin_dir>/af` symlink when the release contains `af` or `bin/af`,
/// matching `sync_cli_entrypoints` in `deploy/release-manager.sh` while staying strictly
/// contained within `config.cli_bin_dir`.
pub fn sync_cli_entrypoints(config: &ReleaseConfig, epoch_id: &str) -> ReleaseResult<()> {
    validate_cli_bin_dir(config)?;

    let candidate_af = if config.current_link.join("bin/af").is_file() {
        Some(config.current_link.join("bin/af"))
    } else if config.current_link.join("af").is_file() {
        Some(config.current_link.join("af"))
    } else {
        None
    };

    let Some(target_af) = candidate_af else {
        return Ok(());
    };

    crate::fs_security::create_dir_all_no_symlinks(&config.cli_bin_dir, 0o755)?;

    let dest_af = config.cli_bin_dir.join("af");
    let replace_allowed = match fs::symlink_metadata(&dest_af) {
        Ok(meta) => meta.file_type().is_symlink(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting CLI entrypoint {}", dest_af.display()),
                err,
            ));
        }
    };
    if replace_allowed {
        crate::symlink::atomic_replace_file_symlink(
            &dest_af,
            &target_af,
            &format!("af.{}", epoch_id),
        )?;
    }
    Ok(())
}

/// Trait abstracting host service lifecycle operations (`systemctl` and legacy `pm2` cleanup).
/// Tests MUST use a mock implementation so real host services are never touched.
pub trait LifecycleController: Send + Sync {
    /// Returns `true` if this controller mutates real host systemd/PM2 state and therefore
    /// requires explicit disposable-guest authorization when `config.isolated_root` is active.
    fn requires_isolated_systemd_authorization(&self) -> bool {
        false
    }

    /// Queries `systemctl show -p Environment aetherflow-api` for Stage 0 database path resolution.
    fn query_unit_environment(&self, unit: &str) -> Option<String>;

    /// Installs packaged units if missing, reloads systemd, stops legacy `aetherflow-frontend.service` / PM2,
    /// and enables + restarts `aetherflow-runner.service` and `aetherflow-api.service`.
    fn restart_systemd_units(&self, config: &ReleaseConfig) -> ReleaseResult<()>;

    fn verify_running_release(&self, _config: &ReleaseConfig) -> ReleaseResult<()> {
        Ok(())
    }

    /// Stops `aetherflow-api.service` and `aetherflow-runner.service` prior to restoring a corrupted SQLite DB.
    fn stop_database_services(&self, db_path: &Path) -> ReleaseResult<()>;

    /// One-shot PM2 teardown (`pm2 kill`, `pm2 unstartup`) used by `migrate-systemd`.
    fn terminate_legacy_pm2(&self) -> ReleaseResult<()>;
}

/// Result of a single HTTP readiness check attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckAttempt {
    pub http_status: u16,
    pub body: String,
}

/// Trait abstracting the HTTP readiness probe (`GET /health/ready`).
pub trait HealthProber: Send + Sync {
    /// Performs a single HTTP GET against `endpoint`.
    fn check_once(&self, endpoint: &str) -> ReleaseResult<HealthCheckAttempt>;
}

/// Polls `prober` up to `retries` times with `interval` delay between attempts until HTTP 200
/// with JSON `"status": "ready"` or `"status": "ok"` is observed.
pub fn poll_readiness_probe(
    prober: &dyn HealthProber,
    endpoint: &str,
    retries: u32,
    interval: Duration,
) -> ReleaseResult<String> {
    let max_attempts = retries.max(1);
    let mut last_error = String::from("no attempts executed");

    for attempt in 1..=max_attempts {
        match prober.check_once(endpoint) {
            Ok(res) => {
                if res.http_status == 200 {
                    if let Some(status) = parse_health_status(&res.body) {
                        if is_healthy_status(&status) {
                            return Ok(status);
                        }
                        last_error = format!("HTTP 200 but status={}", status);
                    } else {
                        last_error = "HTTP 200 but missing/invalid JSON status field".to_string();
                    }
                } else {
                    last_error = format!("HTTP {}", res.http_status);
                }
            }
            Err(err) => {
                last_error = err.to_string();
            }
        }

        if attempt < max_attempts && !interval.is_zero() {
            std::thread::sleep(interval);
        }
    }

    Err(ReleaseError::HealthProbeFailed {
        endpoint: endpoint.to_string(),
        attempts: max_attempts,
        last_error,
    })
}

/// Bounded check that waits until no local listener accepts TCP connections on `addr`
/// (used during PM2 -> systemd migration so the old listener releases the port before
/// `aetherflow-api.service` binds it).
pub fn wait_for_listener_stopped(
    addr: std::net::SocketAddr,
    timeout: Duration,
) -> ReleaseResult<()> {
    let start = std::time::Instant::now();
    loop {
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            Err(_) => return Ok(()),
            Ok(stream) => {
                drop(stream);
                if start.elapsed() >= timeout {
                    return Err(ReleaseError::Systemd {
                        action: "terminate_legacy_pm2".to_string(),
                        reason: format!(
                            "legacy listener on {} is still accepting connections after {:?}",
                            addr, timeout
                        ),
                    });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Extracts a local `SocketAddr` from an HTTP endpoint URL (e.g., `http://127.0.0.1:8080/health/ready`).
pub fn parse_endpoint_socket_addr(endpoint: &str) -> Option<std::net::SocketAddr> {
    let parsed = url::Url::parse(endpoint).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    format!("{}:{}", host, port).parse().ok()
}

/// Validates deployed frontend assets (`web/dist/index.html` and at least one non-empty `.wasm`)
/// when `web/dist` (or `web`) is present in `release_dir`.
///
/// Synthetic binary-only test fixtures that omit `web/dist` altogether pass cleanly.
pub fn verify_deployed_frontend_assets(release_dir: &Path) -> ReleaseResult<()> {
    let web_dir = release_dir.join("web");
    match fs::symlink_metadata(&web_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(ReleaseError::ArtifactVerification(format!(
                    "Deployed release web directory {} is a symlink or non-directory.",
                    web_dir.display()
                )));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting deployed web directory {}", web_dir.display()),
                err,
            ));
        }
    }

    let dist_dir = web_dir.join("dist");
    match fs::symlink_metadata(&dist_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(ReleaseError::ArtifactVerification(format!(
                    "Deployed release web/dist path {} is a symlink or non-directory.",
                    dist_dir.display()
                )));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(ReleaseError::io(
                format!(
                    "inspecting deployed web/dist directory {}",
                    dist_dir.display()
                ),
                err,
            ));
        }
    }

    let index_path = dist_dir.join("index.html");
    let has_index = fs::symlink_metadata(&index_path)
        .map(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0)
        .unwrap_or(false);
    if !has_index {
        return Err(ReleaseError::ArtifactVerification(format!(
            "Deployed release is missing a non-empty regular {}.",
            index_path.display()
        )));
    }

    let entries = fs::read_dir(&dist_dir).map_err(|err| {
        ReleaseError::ArtifactVerification(format!(
            "Failed to inspect deployed frontend directory {}: {}",
            dist_dir.display(),
            err
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            ReleaseError::ArtifactVerification(format!(
                "Failed to read deployed frontend entry in {}: {}",
                dist_dir.display(),
                err
            ))
        })?;
        if !entry.file_name().to_string_lossy().ends_with(".wasm") {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|err| {
            ReleaseError::ArtifactVerification(format!(
                "Failed to inspect deployed frontend asset {}: {}",
                path.display(),
                err
            ))
        })?;
        if !meta.file_type().is_symlink() && meta.is_file() && meta.len() > 0 {
            return Ok(());
        }
    }

    Err(ReleaseError::ArtifactVerification(format!(
        "Deployed release is missing a non-empty regular {}/*.wasm module.",
        dist_dir.display()
    )))
}

/// Production bare-metal Linux `LifecycleController` invoking `systemctl`.
#[derive(Debug, Clone, Default)]
pub struct SystemdLifecycleController;

impl LifecycleController for SystemdLifecycleController {
    fn verify_running_release(&self, config: &ReleaseConfig) -> ReleaseResult<()> {
        let expected = fs::canonicalize(config.current_link.join("aetherflow-api"))
            .map_err(|error| ReleaseError::io("resolving candidate executable", error))?;
        if let Some(release_dir) = expected.parent() {
            verify_deployed_frontend_assets(release_dir)?;
        }
        for unit in ["aetherflow-api.service", "aetherflow-runner.service"] {
            let output = Command::new("systemctl")
                .args(["show", "--property=MainPID", "--value", unit])
                .output()
                .map_err(|error| ReleaseError::io("querying service runtime identity", error))?;
            let pid = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .ok();
            let actual = if output.status.success() {
                pid.filter(|pid| *pid > 0)
                    .and_then(|pid| fs::read_link(format!("/proc/{pid}/exe")).ok())
            } else {
                None
            };
            verify_executable_identity(unit, &expected, actual.as_deref())?;
        }
        Ok(())
    }

    fn requires_isolated_systemd_authorization(&self) -> bool {
        true
    }

    fn query_unit_environment(&self, unit: &str) -> Option<String> {
        let out = Command::new("systemctl")
            .args(["show", "-p", "Environment", unit])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).into_owned();
        if s.trim().is_empty() {
            None
        } else {
            Some(s)
        }
    }

    fn restart_systemd_units(&self, config: &ReleaseConfig) -> ReleaseResult<()> {
        verify_isolated_systemd_lifecycle_authorized(config)?;
        let packaged_systemd_dir = packaged_systemd_directory(config)?;
        let has_log_retention = packaged_systemd_dir
            .parent()
            .map(|deploy_dir| deploy_dir.join("log-retention.py").is_file())
            .unwrap_or(false);
        if packaged_systemd_dir.is_dir() {
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-runner.service"),
                &config.systemd_units_dst,
            )?;
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-api.service"),
                &config.systemd_units_dst,
            )?;
            if has_log_retention {
                let _ = install_packaged_unit_if_missing(
                    &packaged_systemd_dir.join("aetherflow-log-retention.service"),
                    &config.systemd_units_dst,
                )?;
                let _ = install_packaged_unit_if_missing(
                    &packaged_systemd_dir.join("aetherflow-log-retention.timer"),
                    &config.systemd_units_dst,
                )?;
            }
            install_systemd_hardening_dropins(&config.systemd_units_dst, has_log_retention)?;
        }

        if config.isolated_root.is_none() {
            crate::fs_security::apply_root_aetherflow_dir_ownership_and_mode(Path::new(
                "/run/aetherflow",
            ))?;
        }

        let _ = refresh_installed_transcode_shim(config)?;

        run_systemctl(&config.log_file, &["daemon-reload"], true)?;

        let _ = run_systemctl(
            &config.log_file,
            &["stop", "aetherflow-frontend.service"],
            false,
        );
        let _ = run_systemctl(
            &config.log_file,
            &["disable", "aetherflow-frontend.service"],
            false,
        );
        let _ = Command::new("pm2")
            .args(["delete", "aetherflow-frontend", "aetherflow-api"])
            .output();

        run_systemctl(
            &config.log_file,
            &[
                "enable",
                "aetherflow-runner.service",
                "aetherflow-api.service",
            ],
            true,
        )?;
        run_systemctl(
            &config.log_file,
            &["restart", "aetherflow-runner.service"],
            true,
        )?;
        run_systemctl(
            &config.log_file,
            &["restart", "aetherflow-api.service"],
            true,
        )?;
        let _ = restart_transcode_worker_if_active_with_bin(Path::new("systemctl"))?;

        run_post_restart_log_retention_with_bin(Path::new("systemctl"), config, has_log_retention);
        Ok(())
    }

    fn stop_database_services(&self, _db_path: &Path) -> ReleaseResult<()> {
        // When `systemctl` is absent on a stripped container/test host (`ErrorKind::NotFound`),
        // match `release-manager.sh` (`if ! command -v systemctl ... return 0`).
        // When `systemctl` IS present, propagate any non-zero exit status so `restore_state_if_corrupted`
        // refuses to overwrite a database while live services are still running.
        run_systemctl_if_present(&[
            "stop",
            "aetherflow-api.service",
            "aetherflow-runner.service",
        ])
    }

    fn terminate_legacy_pm2(&self) -> ReleaseResult<()> {
        match Command::new("pm2").arg("kill").output() {
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    let detail = if !stderr.is_empty() { stderr } else { stdout };
                    return Err(ReleaseError::Systemd {
                        action: "pm2 kill".to_string(),
                        reason: format!("exit {}: {}", out.status, detail),
                    });
                }
                let _ = Command::new("pm2").arg("unstartup").output();
                // Bounded check that the legacy listener on 127.0.0.1:8080 has terminated
                let default_addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
                wait_for_listener_stopped(default_addr, Duration::from_secs(5))?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ReleaseError::Systemd {
                action: "pm2 kill".to_string(),
                reason: e.to_string(),
            }),
        }
    }
}

fn run_systemctl_if_present(args: &[&str]) -> ReleaseResult<()> {
    let action_desc = format!("systemctl {}", args.join(" "));
    match Command::new("systemctl").args(args).output() {
        Ok(out) => {
            if out.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let detail = if !stderr.is_empty() { stderr } else { stdout };
                Err(ReleaseError::Systemd {
                    action: action_desc,
                    reason: format!("exit {}: {}", out.status, detail),
                })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ReleaseError::Systemd {
            action: action_desc,
            reason: e.to_string(),
        }),
    }
}

pub fn run_post_restart_log_retention_with_bin(
    systemctl_bin: &Path,
    config: &ReleaseConfig,
    has_log_retention: bool,
) {
    if config.isolated_root.is_none() {
        if let Err(err) = crate::fs_security::apply_root_aetherflow_dir_ownership_and_mode(
            Path::new("/var/log/aetherflow"),
        ) {
            crate::engine::append_jsonl_log(
                &config.log_file,
                "WARN",
                &format!(
                    "Best-effort /var/log/aetherflow ownership setup failed (continuing): {err}"
                ),
            );
        }
    }
    if has_log_retention {
        let _ = run_systemctl_with_bin(
            systemctl_bin,
            Some(&config.log_file),
            &["enable", "--now", "aetherflow-log-retention.timer"],
            false,
        );
        let _ = run_systemctl_with_bin(
            systemctl_bin,
            Some(&config.log_file),
            &["start", "aetherflow-log-retention.service"],
            false,
        );
    }
}

fn run_systemctl(log_file: &Path, args: &[&str], required: bool) -> ReleaseResult<()> {
    run_systemctl_with_bin(Path::new("systemctl"), Some(log_file), args, required)
}

fn run_systemctl_with_bin(
    systemctl_bin: &Path,
    log_file: Option<&Path>,
    args: &[&str],
    required: bool,
) -> ReleaseResult<()> {
    let action_desc = format!("systemctl {}", args.join(" "));
    match Command::new(systemctl_bin).args(args).output() {
        Ok(out) => {
            if out.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let detail = if !stderr.is_empty() { stderr } else { stdout };
                if !required {
                    if let Some(log_file) = log_file {
                        crate::engine::append_jsonl_log(
                            log_file,
                            "WARN",
                            &format!(
                                "Best-effort {action_desc} failed (exit {}): {detail}",
                                out.status
                            ),
                        );
                    }
                    Ok(())
                } else {
                    Err(ReleaseError::Systemd {
                        action: action_desc,
                        reason: format!("exit {}: {}", out.status, detail),
                    })
                }
            }
        }
        Err(e) => {
            if !required {
                if let Some(log_file) = log_file {
                    crate::engine::append_jsonl_log(
                        log_file,
                        "WARN",
                        &format!("Best-effort {action_desc} failed to execute: {e}"),
                    );
                }
                Ok(())
            } else {
                Err(ReleaseError::Systemd {
                    action: action_desc,
                    reason: e.to_string(),
                })
            }
        }
    }
}

fn systemctl_unit_is_active(systemctl_bin: &Path, unit: &str) -> ReleaseResult<bool> {
    let action_desc = format!("systemctl is-active --quiet {unit}");
    match Command::new(systemctl_bin)
        .args(["is-active", "--quiet", unit])
        .output()
    {
        Ok(out) => Ok(out.status.success()),
        Err(e) => Err(ReleaseError::Systemd {
            action: action_desc,
            reason: e.to_string(),
        }),
    }
}

/// Restarts `af-transcode-worker.service` ONLY if `systemctl is-active --quiet` reports it active.
pub(crate) fn restart_transcode_worker_if_active_with_bin(
    systemctl_bin: &Path,
) -> ReleaseResult<bool> {
    if systemctl_unit_is_active(systemctl_bin, TRANSCODE_WORKER_UNIT)? {
        run_systemctl_with_bin(
            systemctl_bin,
            None,
            &["restart", TRANSCODE_WORKER_UNIT],
            true,
        )?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn verify_executable_identity(
    unit: &str,
    expected: &Path,
    actual: Option<&Path>,
) -> ReleaseResult<()> {
    if actual == Some(expected) {
        return Ok(());
    }
    Err(ReleaseError::Systemd {
        action: format!("verify runtime identity of {unit}"),
        reason: format!("expected {}, running {:?}", expected.display(), actual),
    })
}

#[cfg(test)]
mod runtime_identity_tests {
    use super::*;

    #[test]
    fn healthy_old_service_is_not_a_successful_deployment() {
        let expected = Path::new("/opt/AetherFlow/releases/new/aetherflow-api");
        let old = Path::new("/opt/AetherFlow/releases/old/aetherflow-api");
        assert!(verify_executable_identity("api", expected, Some(old)).is_err());
        assert!(verify_executable_identity("runner", expected, None).is_err());
        assert!(verify_executable_identity("api", expected, Some(expected)).is_ok());
    }

    #[test]
    fn hardening_dropins_remove_stale_defaults_and_log_retention_hardening() {
        let tmp = std::env::temp_dir().join(format!(
            "af-dropin-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        for unit in [
            "aetherflow-runner.service.d",
            "aetherflow-api.service.d",
            "aetherflow-log-retention.service.d",
        ] {
            let dir = tmp.join(unit);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("05-aetherflow-unit-defaults.conf"),
                b"[Service]\nTimeoutStopSec=30s\n",
            )
            .unwrap();
        }
        std::fs::write(
            tmp.join("aetherflow-log-retention.service.d/10-aetherflow-hardening.conf"),
            b"[Service]\nUMask=0077\n",
        )
        .unwrap();

        std::fs::write(
            tmp.join("aetherflow-runner.service.d/10-aetherflow-hardening.conf"),
            b"[Service]\nLogsDirectoryPreserve=yes\n",
        )
        .unwrap();

        install_systemd_hardening_dropins(&tmp, true).expect("install dropins");

        for unit in [
            "aetherflow-runner.service.d",
            "aetherflow-api.service.d",
            "aetherflow-log-retention.service.d",
        ] {
            assert!(
                !tmp.join(unit)
                    .join("05-aetherflow-unit-defaults.conf")
                    .exists(),
                "stale 05-aetherflow-unit-defaults.conf must be removed in {unit}"
            );
        }
        assert!(
            !tmp.join("aetherflow-log-retention.service.d/10-aetherflow-hardening.conf")
                .exists(),
            "stale log-retention 10-aetherflow-hardening.conf must be removed"
        );
        assert!(
            !tmp.join("aetherflow-log-retention.service.d").exists(),
            "empty log-retention drop-in dir should be pruned"
        );
        let runner_hardening = std::fs::read_to_string(
            tmp.join("aetherflow-runner.service.d/10-aetherflow-hardening.conf"),
        )
        .expect("runner hardening");
        assert!(runner_hardening.contains("UMask=0077"));
        assert!(runner_hardening.contains("LogsDirectory=aetherflow\n"));
        assert!(!runner_hardening.contains("LogsDirectoryPreserve="));
        let api_hardening = std::fs::read_to_string(
            tmp.join("aetherflow-api.service.d/10-aetherflow-hardening.conf"),
        )
        .expect("api hardening");
        assert!(api_hardening.contains("UMask=0027"));
        assert!(api_hardening.contains("LogsDirectory="));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

/// Production HTTP `HealthProber` using `reqwest` with a 5-second per-attempt timeout.
#[derive(Debug, Clone, Default)]
pub struct ReqwestHealthProber;

impl HealthProber for ReqwestHealthProber {
    fn check_once(&self, endpoint: &str) -> ReleaseResult<HealthCheckAttempt> {
        let endpoint_owned = endpoint.to_string();
        std::thread::spawn(move || -> ReleaseResult<HealthCheckAttempt> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| ReleaseError::Systemd {
                    action: "health_probe_runtime".to_string(),
                    reason: e.to_string(),
                })?;
            rt.block_on(async move {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .no_proxy()
                    .build()
                    .map_err(|e| ReleaseError::Systemd {
                        action: "health_probe_client".to_string(),
                        reason: e.to_string(),
                    })?;
                let resp = client.get(&endpoint_owned).send().await.map_err(|e| {
                    ReleaseError::Systemd {
                        action: "health_probe_request".to_string(),
                        reason: e.to_string(),
                    }
                })?;
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                Ok(HealthCheckAttempt {
                    http_status: status,
                    body,
                })
            })
        })
        .join()
        .map_err(|_| ReleaseError::Systemd {
            action: "health_probe_join".to_string(),
            reason: "health probe worker thread panicked".to_string(),
        })?
    }
}

/// Helper for tests that records all lifecycle calls in memory and never invokes `systemctl` or `pm2`.
#[derive(Debug, Default)]
pub struct NoopLifecycleController {
    pub unit_env: Option<String>,
}

impl LifecycleController for NoopLifecycleController {
    fn query_unit_environment(&self, _unit: &str) -> Option<String> {
        self.unit_env.clone()
    }

    fn restart_systemd_units(&self, config: &ReleaseConfig) -> ReleaseResult<()> {
        let packaged_systemd_dir = packaged_systemd_directory(config)?;
        let has_log_retention = packaged_systemd_dir
            .parent()
            .map(|deploy_dir| deploy_dir.join("log-retention.py").is_file())
            .unwrap_or(false);
        if packaged_systemd_dir.is_dir() {
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-runner.service"),
                &config.systemd_units_dst,
            )?;
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-api.service"),
                &config.systemd_units_dst,
            )?;
            if has_log_retention {
                let _ = install_packaged_unit_if_missing(
                    &packaged_systemd_dir.join("aetherflow-log-retention.service"),
                    &config.systemd_units_dst,
                )?;
                let _ = install_packaged_unit_if_missing(
                    &packaged_systemd_dir.join("aetherflow-log-retention.timer"),
                    &config.systemd_units_dst,
                )?;
            }
            install_systemd_hardening_dropins(&config.systemd_units_dst, has_log_retention)?;
        }
        let _ = refresh_installed_transcode_shim(config)?;
        Ok(())
    }

    fn stop_database_services(&self, _db_path: &Path) -> ReleaseResult<()> {
        Ok(())
    }

    fn terminate_legacy_pm2(&self) -> ReleaseResult<()> {
        Ok(())
    }
}
