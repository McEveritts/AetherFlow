use super::policy::DEFAULT_MANDATORY_QUIESCE_SERVICES;
use crate::error::{HostBackupError, HostBackupResult};
use std::path::{Path, PathBuf};

/// Controller interface for stopping writer services before restore replacement and
/// restarting + verifying service health after replacement (or after rollback).
pub trait ServiceQuiescenceController {
    /// Stops the requested service units before any live destination file is replaced.
    fn stop_services(&self, units: &[String]) -> HostBackupResult<()>;

    /// Starts the requested service units and verifies their post-restore health.
    fn start_and_verify_services(&self, units: &[String]) -> HostBackupResult<()>;
}

/// No-op service quiescence controller for isolated staging roots and offline tests.
#[derive(Debug, Clone, Default)]
pub struct NoopQuiescenceController;

impl ServiceQuiescenceController for NoopQuiescenceController {
    fn stop_services(&self, _units: &[String]) -> HostBackupResult<()> {
        Ok(())
    }

    fn start_and_verify_services(&self, _units: &[String]) -> HostBackupResult<()> {
        Ok(())
    }
}

/// Systemd service quiescence controller that invokes `systemctl stop`, `systemctl start`,
/// and `systemctl is-active --quiet` on the configured units, with automatic compensation
/// if a multi-unit stop fails partway through.
#[derive(Debug, Clone)]
pub struct CommandQuiescenceController {
    pub systemctl_bin: PathBuf,
}

impl Default for CommandQuiescenceController {
    fn default() -> Self {
        Self {
            systemctl_bin: PathBuf::from("/bin/systemctl"),
        }
    }
}

impl CommandQuiescenceController {
    fn is_uninstalled_mandatory_writer_in_staging(&self, unit: &str) -> bool {
        if self.systemctl_bin != Path::new("/bin/systemctl") {
            return false;
        }
        if !DEFAULT_MANDATORY_QUIESCE_SERVICES.contains(&unit) {
            return false;
        }
        let staging_active = std::env::var("AETHERFLOW_RESTORE_STAGING_ROOT")
            .map(|val| !val.trim().is_empty())
            .unwrap_or(false);
        if !staging_active {
            return false;
        }
        let unit_dirs = [
            "/etc/systemd/system",
            "/run/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
        ];
        !unit_dirs
            .iter()
            .any(|dir| Path::new(dir).join(unit).exists())
    }
}

impl ServiceQuiescenceController for CommandQuiescenceController {
    fn stop_services(&self, units: &[String]) -> HostBackupResult<()> {
        let mut stopped_so_far: Vec<String> = Vec::new();
        for unit in units {
            let trimmed = unit.trim();
            if trimmed.is_empty() || self.is_uninstalled_mandatory_writer_in_staging(trimmed) {
                continue;
            }
            let output = std::process::Command::new(&self.systemctl_bin)
                .arg("stop")
                .arg(trimmed)
                .output();
            let stop_err = match output {
                Ok(out) if out.status.success() => None,
                Ok(out) => {
                    let stderr_msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    Some(if stderr_msg.is_empty() {
                        format!("systemctl stop exited with status {}", out.status)
                    } else {
                        stderr_msg
                    })
                }
                Err(err) => Some(err.to_string()),
            };

            if let Some(reason) = stop_err {
                let mut comp_errors = Vec::new();
                for prev in stopped_so_far.iter().rev() {
                    if let Err(comp_err) =
                        self.start_and_verify_services(std::slice::from_ref(prev))
                    {
                        comp_errors.push(format!("{}: {}", prev, comp_err));
                    }
                }
                let full_reason = if comp_errors.is_empty() {
                    reason
                } else {
                    format!(
                        "{} (compensation restart errors: {})",
                        reason,
                        comp_errors.join(", ")
                    )
                };
                return Err(HostBackupError::ServiceQuiescenceFailed {
                    unit: trimmed.to_string(),
                    phase: "stop".to_string(),
                    reason: full_reason,
                });
            }
            stopped_so_far.push(trimmed.to_string());
        }
        Ok(())
    }

    fn start_and_verify_services(&self, units: &[String]) -> HostBackupResult<()> {
        for unit in units {
            let trimmed = unit.trim();
            if trimmed.is_empty() || self.is_uninstalled_mandatory_writer_in_staging(trimmed) {
                continue;
            }
            let start_out = std::process::Command::new(&self.systemctl_bin)
                .arg("start")
                .arg(trimmed)
                .output()
                .map_err(|err| HostBackupError::ServiceQuiescenceFailed {
                    unit: trimmed.to_string(),
                    phase: "start".to_string(),
                    reason: err.to_string(),
                })?;
            if !start_out.status.success() {
                let stderr_msg = String::from_utf8_lossy(&start_out.stderr)
                    .trim()
                    .to_string();
                return Err(HostBackupError::ServiceQuiescenceFailed {
                    unit: trimmed.to_string(),
                    phase: "start".to_string(),
                    reason: if stderr_msg.is_empty() {
                        format!("systemctl start exited with status {}", start_out.status)
                    } else {
                        stderr_msg
                    },
                });
            }

            let active_out = std::process::Command::new(&self.systemctl_bin)
                .arg("is-active")
                .arg("--quiet")
                .arg(trimmed)
                .output()
                .map_err(|err| HostBackupError::ServiceQuiescenceFailed {
                    unit: trimmed.to_string(),
                    phase: "is-active".to_string(),
                    reason: err.to_string(),
                })?;
            if !active_out.status.success() {
                return Err(HostBackupError::ServiceQuiescenceFailed {
                    unit: trimmed.to_string(),
                    phase: "is-active".to_string(),
                    reason: format!("unit '{}' is not active after start", trimmed),
                });
            }
        }
        Ok(())
    }
}

pub(super) fn stop_services_with_compensation<Q: ServiceQuiescenceController>(
    quiescence: &Q,
    units: &[String],
) -> Result<(), (HostBackupError, bool)> {
    if let Err(stop_err) = quiescence.stop_services(units) {
        let reversed_units: Vec<String> = units.iter().rev().cloned().collect();
        let mut comp_errors: Vec<String> = Vec::new();
        for comp_unit in &reversed_units {
            if let Err(comp_err) =
                quiescence.start_and_verify_services(std::slice::from_ref(comp_unit))
            {
                comp_errors.push(format!("{}: {}", comp_unit, comp_err));
            }
        }
        if comp_errors.is_empty() {
            return Err((stop_err, false));
        }
        let combined = match stop_err {
            HostBackupError::ServiceQuiescenceFailed {
                unit: failed_unit,
                phase,
                reason,
            } => HostBackupError::ServiceQuiescenceFailed {
                unit: failed_unit,
                phase,
                reason: format!(
                    "{} (compensation restart errors: {})",
                    reason,
                    comp_errors.join(", ")
                ),
            },
            other => HostBackupError::ServiceQuiescenceFailed {
                unit: units.last().cloned().unwrap_or_default(),
                phase: "stop".to_string(),
                reason: format!(
                    "{} (compensation restart errors: {})",
                    other,
                    comp_errors.join(", ")
                ),
            },
        };
        return Err((combined, true));
    }
    Ok(())
}

pub(super) fn stop_services_for_recovery<Q: ServiceQuiescenceController>(
    quiescence: &Q,
    units: &[String],
) -> HostBackupResult<()> {
    for unit in units {
        quiescence.stop_services(std::slice::from_ref(unit))?;
    }
    Ok(())
}
