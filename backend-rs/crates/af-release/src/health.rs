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

pub(crate) fn packaged_systemd_directory(config: &ReleaseConfig) -> ReleaseResult<PathBuf> {
    let parent = config.current_link.parent().ok_or_else(|| ReleaseError::PathValidation {
        path: config.current_link.clone(),
        reason: "current release link has no parent".to_string(),
    })?;
    crate::fs_security::ensure_no_symlink_ancestors(parent)?;
    let target = match fs::read_link(&config.current_link) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(config.current_link.join("deploy/systemd"));
        }
        Err(error) => return Err(ReleaseError::io("reading current release link", error)),
    };
    let release_dir = if target.is_absolute() { target } else { parent.join(target) };
    if release_dir.parent() != Some(config.releases_dir.as_path()) {
        return Err(ReleaseError::PathValidation {
            path: release_dir,
            reason: "current release must be a direct child of the releases directory".to_string(),
        });
    }
    crate::fs_security::ensure_no_symlink_ancestors(&release_dir)?;
    Ok(release_dir.join("deploy/systemd"))
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

/// Trait abstracting host service lifecycle operations (`systemctl` and legacy `pm2` cleanup).
/// Tests MUST use a mock implementation so real host services are never touched.
pub trait LifecycleController: Send + Sync {
    /// Queries `systemctl show -p Environment aetherflow-api` for Stage 0 database path resolution.
    fn query_unit_environment(&self, unit: &str) -> Option<String>;

    /// Installs packaged units if missing, reloads systemd, stops legacy `aetherflow-frontend.service` / PM2,
    /// and enables + restarts `aetherflow-runner.service` and `aetherflow-api.service`.
    fn restart_systemd_units(&self, config: &ReleaseConfig) -> ReleaseResult<()>;

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
pub fn wait_for_listener_stopped(addr: std::net::SocketAddr, timeout: Duration) -> ReleaseResult<()> {
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

/// Production bare-metal Linux `LifecycleController` invoking `systemctl`.
#[derive(Debug, Clone, Default)]
pub struct SystemdLifecycleController;

impl LifecycleController for SystemdLifecycleController {
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
        let packaged_systemd_dir = packaged_systemd_directory(config)?;
        if packaged_systemd_dir.is_dir() {
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-runner.service"),
                &config.systemd_units_dst,
            )?;
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-api.service"),
                &config.systemd_units_dst,
            )?;
        }

        run_systemctl(&["daemon-reload"], true)?;

        // Stop legacy separate frontend service or PM2 if still present (best-effort)
        let _ = run_systemctl(&["stop", "aetherflow-frontend.service"], false);
        let _ = run_systemctl(&["disable", "aetherflow-frontend.service"], false);
        let _ = Command::new("pm2")
            .args(["delete", "aetherflow-frontend", "aetherflow-api"])
            .output();

        // Propagate `systemctl enable` failure when `systemctl` is present
        run_systemctl(
            &[
                "enable",
                "aetherflow-runner.service",
                "aetherflow-api.service",
            ],
            true,
        )?;
        run_systemctl(&["restart", "aetherflow-runner.service"], true)?;
        run_systemctl(&["restart", "aetherflow-api.service"], true)?;
        Ok(())
    }

    fn stop_database_services(&self, _db_path: &Path) -> ReleaseResult<()> {
        // When `systemctl` is absent on a stripped container/test host (`ErrorKind::NotFound`),
        // match `release-manager.sh` (`if ! command -v systemctl ... return 0`).
        // When `systemctl` IS present, propagate any non-zero exit status so `restore_state_if_corrupted`
        // refuses to overwrite a database while live services are still running.
        run_systemctl_if_present(&["stop", "aetherflow-api.service", "aetherflow-runner.service"])
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

fn run_systemctl(args: &[&str], required: bool) -> ReleaseResult<()> {
    let action_desc = format!("systemctl {}", args.join(" "));
    match Command::new("systemctl").args(args).output() {
        Ok(out) => {
            if out.status.success() || !required {
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
        Err(e) => {
            if !required {
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
        if packaged_systemd_dir.is_dir() {
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-runner.service"),
                &config.systemd_units_dst,
            )?;
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-api.service"),
                &config.systemd_units_dst,
            )?;
        }
        Ok(())
    }

    fn stop_database_services(&self, _db_path: &Path) -> ReleaseResult<()> {
        Ok(())
    }

    fn terminate_legacy_pm2(&self) -> ReleaseResult<()> {
        Ok(())
    }
}
