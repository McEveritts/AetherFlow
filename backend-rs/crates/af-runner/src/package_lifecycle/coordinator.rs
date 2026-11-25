use super::admitted_snapshots::LifecycleReceipt;
use super::backend::{is_incomplete_rollback_error, LifecycleBackend};
#[cfg(test)]
use super::receipt_snapshots::TEST_CERTIFY_FAIL_HOOK;
use super::receipt_snapshots::{
    rollback_operation_state_with_runtime, snapshot_blueprint_targets,
    snapshot_candidate_receipts_with_env, FileSnapshot,
};
use super::redaction::sanitize_lifecycle_field;
use super::runtime_snapshot::PackageRuntimeSnapshot;
use super::version_probe::resolve_verified_installed_version;
use af_models::{Package, PackageRunnerRequest};
use af_release::lifecycle::{self, OwnerLease};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::mpsc;

pub(super) struct CoordinatedOperation {
    pub(super) conn: Connection,
    pub(super) request: PackageRunnerRequest,
    package: Package,
    units: Vec<String>,
    started_at: String,
    _owner: OwnerLease,
}

fn effective_fs_root_for_conn(conn: &Connection) -> Option<std::path::PathBuf> {
    if let Some(root) = crate::PackageExecutionEnv::default().fs_root {
        return Some(root);
    }
    conn.path().map(Path::new).and_then(|p| {
        p.ancestors().find_map(|anc| {
            let rel = p.strip_prefix(anc).ok()?;
            if anc != Path::new("/")
                && (rel == Path::new("var/lib/aetherflow/aetherflow.sqlite")
                    || rel == Path::new("var/lib/aetherflow/aetherflow.db")
                    || rel == Path::new("etc/aetherflow/aetherflow.db"))
            {
                Some(anc.to_path_buf())
            } else {
                None
            }
        })
    })
}

impl CoordinatedOperation {
    pub(super) fn admit(
        mut conn: Connection,
        mut request: PackageRunnerRequest,
        package: Package,
        mut units: Vec<String>,
    ) -> Result<Self> {
        anyhow::ensure!(
            request.lifecycle_job_id.is_empty(),
            "Direct lifecycle cannot adopt a foreign identity"
        );
        anyhow::ensure!(
            !request.delete_data || request.action == "remove",
            "Purge requires removal"
        );
        if request.secondary_port != 0 {
            anyhow::ensure!(
                (1..=65535).contains(&request.secondary_port),
                "Requested secondary port is invalid"
            );
            anyhow::ensure!(
                request.package_id == "rclone" && request.action != "remove",
                "Secondary port is only valid for rclone install, reinstall, or update"
            );
            anyhow::ensure!(
                request.app_port == 0 || request.secondary_port != request.app_port,
                "Rclone RC API port {} must differ from GUI port {}",
                request.secondary_port,
                request.app_port
            );
        }
        conn.busy_timeout(Duration::from_secs(5))?;
        lifecycle::initialize_schema(&conn)?;
        if matches!(request.action.as_str(), "install" | "reinstall") {
            let conflicting_dns = match request.package_id.as_str() {
                "pihole" => Some(("adguardhome", "AdGuard Home", "/install/.adguardhome.lock")),
                "adguardhome" => Some(("pihole", "Pi-hole", "/install/.pihole.lock")),
                _ => None,
            };
            if let Some((other_id, other_label, other_lock)) = conflicting_dns {
                let env_cfg = crate::PackageExecutionEnv::default();
                if af_models::inspect_canonical_package_receipt(
                    other_id,
                    Some(other_lock),
                    env_cfg.fs_root.as_deref(),
                )
                .unwrap_or(false)
                {
                    anyhow::bail!(
                        "Cannot {} {} while {} ({}) is already installed ({}): both bind DNS TCP/UDP :53. Remove {} first before installing {}.",
                        request.action,
                        package.label,
                        other_label,
                        other_id,
                        other_lock,
                        other_id,
                        request.package_id
                    );
                }
            }
        }
        if request.action != "remove" {
            let fs_root = effective_fs_root_for_conn(&conn);
            let mut reserved = af_db::list_reserved_ports_excluding(&conn, &request.package_id)?;
            reserved.extend(crate::rclone_extra_reserved_ports(
                &request.package_id,
                fs_root.as_deref(),
            ));
            let candidate_port = if request.app_port > 0 {
                Some(request.app_port)
            } else {
                af_db::load_lifecycle_ingress(&conn, &request.package_id)?
                    .map(|cfg| cfg.listen_port)
                    .filter(|p| *p > 0)
            };
            if let Some(port) = candidate_port {
                anyhow::ensure!(
                    !reserved.contains(&port),
                    "Listen port {} is already reserved by another application",
                    port
                );
                if let Some(res) = lifecycle::port_resource(port) {
                    if !units.contains(&res) {
                        units.push(res);
                    }
                }
            }
            if request.package_id == "rclone" {
                let candidate_secondary = if request.secondary_port > 0 {
                    anyhow::ensure!(
                        candidate_port.is_none_or(|p| p != request.secondary_port),
                        "Rclone RC API port {} must differ from GUI port {}",
                        request.secondary_port,
                        candidate_port.unwrap_or_default()
                    );
                    anyhow::ensure!(
                        !reserved.contains(&request.secondary_port),
                        "Rclone RC API port {} is already reserved by another application",
                        request.secondary_port
                    );
                    Some(request.secondary_port)
                } else {
                    af_db::load_lifecycle_secondary_port(
                        &conn,
                        "rclone",
                        af_models::RCLONE_RC_API_PORT_ROLE,
                    )?
                    .or_else(|| {
                        crate::extract_rclone_runtime_api_port_for_root(fs_root.as_deref())
                            .map(i32::from)
                    })
                    .filter(|&p| {
                        (1..=65535).contains(&p)
                            && candidate_port.is_none_or(|gui| gui != p)
                            && !reserved.contains(&p)
                    })
                };
                if let Some(sec_port) = candidate_secondary {
                    if let Some(res) = lifecycle::port_resource(sec_port) {
                        if !units.contains(&res) {
                            units.push(res);
                        }
                    }
                }
            }
        }
        request.lifecycle_job_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now().to_rfc3339();
        if request.action == "update" {
            let valid = request
                .expected_target_version
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && af_release::lifecycle::validate_target_version(s))
                .is_some();
            if !valid {
                anyhow::bail!(
                    "Cannot start update: expected_target_version is missing, empty, or invalid"
                );
            }
        }
        if let Some(ref target) = request.expected_target_version {
            let trimmed = target.trim();
            if trimmed.is_empty() || !af_release::lifecycle::validate_target_version(trimmed) {
                anyhow::bail!(
                    "Cannot start {}: expected_target_version '{}' is invalid",
                    request.action,
                    target
                );
            }
        }
        if let Err(reason) = crate::validate_package_target_policy(
            &request.package_id,
            &package.update_source,
            &package.update_package,
            &request.action,
            request.expected_target_version.as_deref(),
        ) {
            anyhow::bail!("Cannot start {}: {}", request.action, reason);
        }
        let owner = lifecycle::admit_job_with_target(
            &mut conn,
            &request.package_id,
            &request.lifecycle_job_id,
            &request.action,
            &started_at,
            &units,
            request.expected_target_version.as_deref(),
        )?;
        Ok(Self {
            conn,
            request,
            package,
            units,
            started_at,
            _owner: owner,
        })
    }

    fn is_installed_on_disk_in(&self, fs_root: Option<&Path>) -> bool {
        af_models::inspect_canonical_package_receipt(
            &self.package.name,
            Some(&self.package.lock_file),
            fs_root,
        )
        .unwrap_or(false)
    }

    fn is_installed_on_disk(&self) -> bool {
        let env_cfg = crate::PackageExecutionEnv::default();
        self.is_installed_on_disk_in(env_cfg.fs_root.as_deref())
    }

    fn has_legacy_upgrade_receipt(&self) -> bool {
        let env_cfg = crate::PackageExecutionEnv::default();
        af_models::inspect_package_receipts(
            &self.package.name,
            Some(&self.package.lock_file),
            env_cfg.fs_root.as_deref(),
        )
        .map(|status| status.has_legacy_upgrade_receipt())
        .unwrap_or(false)
    }

    fn resolve_port_in_tx(
        request: &PackageRunnerRequest,
        package: &Package,
        fs_root: Option<&Path>,
        installed_or_legacy: bool,
        conn: &Connection,
        base_reserved: &std::collections::BTreeSet<i32>,
        backend: &impl LifecycleBackend,
    ) -> Result<i32> {
        if request.action == "remove" {
            return Ok(0);
        }
        let mut reserved = base_reserved.clone();
        reserved.extend(crate::rclone_extra_reserved_ports(
            &request.package_id,
            fs_root,
        ));
        let ingress = af_db::load_lifecycle_ingress(conn, &request.package_id)?;
        let saved = ingress
            .as_ref()
            .map(|config| config.listen_port)
            .unwrap_or(0);
        if request.action == "update" {
            let runtime = backend.runtime_port(&request.package_id);
            if runtime > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&runtime),
                    "Native application listen port is invalid"
                );
                anyhow::ensure!(
                    !reserved.contains(&runtime),
                    "Listen port {} is already reserved by another application",
                    runtime
                );
                return Ok(runtime);
            }
            if saved > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&saved),
                    "Persisted listen port is invalid"
                );
                anyhow::ensure!(
                    !reserved.contains(&saved),
                    "Listen port {} is already reserved by another application",
                    saved
                );
                return Ok(saved);
            }
            anyhow::ensure!(
                package.default_port <= 0,
                "Existing application listen port is unavailable"
            );
            return Ok(0);
        }
        if request.app_port > 0 {
            anyhow::ensure!(
                (1024..=65535).contains(&request.app_port),
                "Requested listen port is invalid"
            );
            anyhow::ensure!(
                !reserved.contains(&request.app_port),
                "Listen port {} is already reserved by another application",
                request.app_port
            );
            return Ok(request.app_port);
        }
        if saved > 0 {
            anyhow::ensure!(
                (1024..=65535).contains(&saved),
                "Persisted listen port is invalid"
            );
            anyhow::ensure!(
                !reserved.contains(&saved),
                "Listen port {} is already reserved by another application",
                saved
            );
            return Ok(saved);
        }
        if installed_or_legacy {
            let runtime = backend.runtime_port(&request.package_id);
            if runtime > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&runtime),
                    "Native application listen port is invalid"
                );
                if !reserved.contains(&runtime) {
                    return Ok(runtime);
                }
            }
            let env_cfg = crate::PackageExecutionEnv::default();
            if let Ok(Some(receipt_port)) = af_models::read_package_receipt_port(
                &package.name,
                Some(&package.lock_file),
                env_cfg.fs_root.as_deref(),
            ) {
                if (1024..=65535).contains(&receipt_port)
                    && !reserved.contains(&receipt_port)
                    && (request.action == "reinstall" || backend.available_port(receipt_port))
                {
                    return Ok(receipt_port);
                }
            }
        }
        let default = package.default_port;
        if default <= 0 {
            return Ok(0);
        }
        if request.package_id == "rclone" {
            if request.secondary_port > 0 {
                reserved.insert(request.secondary_port);
            } else if let Some(sec) = af_db::load_lifecycle_secondary_port(
                conn,
                "rclone",
                af_models::RCLONE_RC_API_PORT_ROLE,
            )? {
                reserved.insert(sec);
            }
        }
        if !reserved.contains(&default) && backend.available_port(default) {
            return Ok(default);
        }
        anyhow::ensure!(
            !matches!(request.package_id.as_str(), "plex" | "calibreweb"),
            "Fixed application port is unavailable"
        );
        let [start, end] = af_models::MARKETPLACE_FALLBACK_PORT_RANGE;
        (start..=end)
            .find(|port| !reserved.contains(port) && backend.available_port(*port))
            .context("No application listen port is available")
    }

    fn resolve_and_reserve_port(&mut self, backend: &impl LifecycleBackend) -> Result<i32> {
        if self.request.action == "remove" {
            return Ok(0);
        }
        let fs_root = self.effective_fs_root();
        let installed_or_legacy = self.is_installed_on_disk() || self.has_legacy_upgrade_receipt();
        let request = &self.request;
        let package = &self.package;
        let chosen = af_db::reserve_lifecycle_port_in_tx(
            &mut self.conn,
            &request.package_id,
            &request.lifecycle_job_id,
            Some(&request.action),
            |tx, reserved| {
                let port = Self::resolve_port_in_tx(
                    request,
                    package,
                    fs_root.as_deref(),
                    installed_or_legacy,
                    tx,
                    reserved,
                    backend,
                )?;
                Ok((port > 0).then_some(port))
            },
        )?
        .unwrap_or(0);
        if let Some(res) = lifecycle::port_resource(chosen) {
            if !self.units.contains(&res) {
                self.units.push(res);
            }
        }
        Ok(chosen)
    }

    fn update_units(&self) -> Vec<String> {
        let is_in_place_reinstall = self.request.action == "reinstall"
            || (self.request.action == "install" && self.is_installed_on_disk());
        if (self.request.action != "update" && !is_in_place_reinstall)
            || self.package.service_type == "pm2"
            || matches!(
                self.package.name.as_str(),
                "nextcloud" | "rutorrent" | "organizr" | "maintainerr"
            )
        {
            return Vec::new();
        }
        let root = crate::PackageExecutionEnv::default().fs_root;
        let rclone = root
            .as_deref()
            .unwrap_or(Path::new("/"))
            .join("etc/rclone/rclone.conf");
        let configured = self.units.iter().any(|unit| unit == "rclone-vfs")
            && std::fs::read_to_string(rclone).is_ok_and(|text| {
                text.lines()
                    .any(|line| line.trim().eq_ignore_ascii_case("[remote]"))
            });
        let mut units: Vec<_> = self
            .units
            .iter()
            .filter(|unit| {
                !unit.starts_with("port:")
                    && !matches!(unit.as_str(), "recyclarr" | "scrutiny-collector")
                    && (unit.as_str() != "rclone-vfs" || configured)
            })
            .cloned()
            .collect();
        lifecycle::sort_units_for_stop(&mut units);
        units
    }

    fn rollback_quiesce_units(&self) -> Vec<String> {
        if !matches!(
            self.request.action.as_str(),
            "install" | "update" | "reinstall"
        ) || self.package.service_type == "pm2"
            || matches!(
                self.package.name.as_str(),
                "nextcloud" | "rutorrent" | "organizr" | "maintainerr"
            )
        {
            return Vec::new();
        }
        let mut units: Vec<_> = self
            .units
            .iter()
            .filter(|unit| !unit.starts_with("port:"))
            .cloned()
            .collect();
        lifecycle::sort_units_for_stop(&mut units);
        units
    }
}

impl CoordinatedOperation {
    fn effective_fs_root(&self) -> Option<std::path::PathBuf> {
        effective_fs_root_for_conn(&self.conn)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn restore_and_restart_units(
        backend: &impl LifecycleBackend,
        lifecycle_job_id: &str,
        package_id: &str,
        quiesce_units: &[String],
        restart_units: &[String],
        receipt_snapshots: &[FileSnapshot],
        blueprint_snapshots: &[FileSnapshot],
        receipt_restore_error: &mut Option<String>,
        restart_failures: &mut Vec<String>,
        incomplete_rollback: bool,
        quiesce_first: bool,
    ) {
        Self::restore_and_restart_units_with_runtime(
            backend,
            lifecycle_job_id,
            package_id,
            quiesce_units,
            restart_units,
            receipt_snapshots,
            blueprint_snapshots,
            receipt_restore_error,
            restart_failures,
            incomplete_rollback,
            quiesce_first,
            None,
        )
        .await
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn restore_and_restart_units_with_runtime(
        backend: &impl LifecycleBackend,
        lifecycle_job_id: &str,
        package_id: &str,
        quiesce_units: &[String],
        restart_units: &[String],
        receipt_snapshots: &[FileSnapshot],
        blueprint_snapshots: &[FileSnapshot],
        receipt_restore_error: &mut Option<String>,
        restart_failures: &mut Vec<String>,
        incomplete_rollback: bool,
        quiesce_first: bool,
        runtime_snapshot: Option<PackageRuntimeSnapshot>,
    ) {
        Self::restore_and_restart_units_with_runtime_and_vhosts(
            backend,
            lifecycle_job_id,
            package_id,
            quiesce_units,
            restart_units,
            receipt_snapshots,
            blueprint_snapshots,
            receipt_restore_error,
            restart_failures,
            incomplete_rollback,
            quiesce_first,
            runtime_snapshot,
            Vec::new(),
            None,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn restore_and_restart_units_with_runtime_and_vhosts(
        backend: &impl LifecycleBackend,
        lifecycle_job_id: &str,
        package_id: &str,
        quiesce_units: &[String],
        restart_units: &[String],
        receipt_snapshots: &[FileSnapshot],
        blueprint_snapshots: &[FileSnapshot],
        receipt_restore_error: &mut Option<String>,
        restart_failures: &mut Vec<String>,
        incomplete_rollback: bool,
        quiesce_first: bool,
        mut runtime_snapshot: Option<PackageRuntimeSnapshot>,
        vhost_backups: Vec<crate::VhostBackup>,
        fs_root: Option<PathBuf>,
    ) {
        if incomplete_rollback {
            if let Some(snapshot) = runtime_snapshot.as_mut() {
                snapshot.preserve_on_drop = true;
            }
        }
        let mut quiesce_failed = false;
        if quiesce_first {
            let mut seen = std::collections::HashSet::new();
            let mut ordered_quiesce: Vec<String> = quiesce_units
                .iter()
                .chain(restart_units.iter())
                .filter(|unit| seen.insert((*unit).clone()))
                .cloned()
                .collect();
            lifecycle::sort_units_for_stop(&mut ordered_quiesce);
            for unit in &ordered_quiesce {
                match backend.control(unit, "stop", lifecycle_job_id).await {
                    Ok(()) => {
                        match backend.quiescent(unit).await {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::error!(
                                    unit,
                                    "Unit is still active after stop before restoration"
                                );
                                quiesce_failed = true;
                                restart_failures.push(format!(
                                    "{unit}: still active after stop before restoration"
                                ));
                            }
                            Err(error) => {
                                tracing::error!(unit, error = %error, "Failed to verify quiescence before restoration");
                                quiesce_failed = true;
                                restart_failures.push(format!("{unit}: failed to verify quiescence before restoration: {error}"));
                            }
                        }
                    }
                    Err(error) => {
                        let err_str = error.to_string();
                        let err_lower = err_str.to_ascii_lowercase();
                        let is_absent_err = err_lower.contains("not loaded")
                            || err_lower.contains("not-found")
                            || err_lower.contains("no such file")
                            || err_lower.contains("exit status: 5")
                            || err_lower.contains("exit code 5");
                        if is_absent_err && matches!(backend.quiescent(unit).await, Ok(true)) {
                            tracing::info!(unit, "Absent unit not loaded during stop before restoration, confirmed quiescent");
                        } else {
                            tracing::error!(unit, error = %error, "Failed to quiesce unit before state restoration");
                            quiesce_failed = true;
                            restart_failures
                                .push(format!("{unit}: stop before restoration failed: {error}"));
                        }
                    }
                }
            }
        }

        if quiesce_failed {
            let preserved_path = runtime_snapshot.as_mut().map(|snapshot| {
                snapshot.preserve_on_drop = true;
                snapshot.backup_root.display().to_string()
            });
            let msg = match preserved_path {
                Some(path) => format!(
                    "Skipped snapshot restoration because service quiescence failed (incomplete-rollback); recovery backup preserved at {path}"
                ),
                None => "Skipped snapshot restoration because service quiescence failed (incomplete-rollback)".to_string(),
            };
            if let Some(ref mut existing) = receipt_restore_error {
                existing.push_str(&format!("; {}", msg));
            } else {
                *receipt_restore_error = Some(msg);
            }
            let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
            return;
        }

        let receipt_snapshots = receipt_snapshots.to_vec();
        let blueprint_snapshots = blueprint_snapshots.to_vec();
        let restoration = tokio::task::spawn_blocking(move || {
            rollback_operation_state_with_runtime(
                &receipt_snapshots,
                &blueprint_snapshots,
                if incomplete_rollback {
                    None
                } else {
                    runtime_snapshot.as_mut()
                },
            )?;
            let vhosts_changed = if incomplete_rollback || vhost_backups.is_empty() {
                false
            } else {
                crate::restore_app_vhost_backups(&vhost_backups).map_err(|e| e.to_string())?
            };
            Ok::<bool, String>(vhosts_changed)
        })
        .await
        .map_err(|err| format!("Snapshot restore worker failed: {err}"))
        .and_then(|result| result);
        let mut snapshot_restore_failed = false;
        match restoration {
            Ok(vhosts_changed) => {
                if vhosts_changed {
                    crate::reload_apache_after_rollback_if_live(fs_root.as_deref()).await;
                }
            }
            Err(restore_err) => {
                tracing::error!(
                    package = %package_id,
                    error = %restore_err,
                    "Failed to restore candidate receipts, blueprints, and package runtime"
                );
                snapshot_restore_failed = true;
                if let Some(ref mut existing) = receipt_restore_error {
                    existing.push_str(&format!("; {}", restore_err));
                } else {
                    *receipt_restore_error = Some(restore_err);
                }
            }
        }

        if incomplete_rollback || snapshot_restore_failed {
            if !restart_units.is_empty() {
                if incomplete_rollback {
                    tracing::error!(
                        package = %package_id,
                        "Refusing to restart pre-stopped service after incomplete rollback"
                    );
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after incomplete rollback"
                            .to_string(),
                    );
                }
                if snapshot_restore_failed {
                    tracing::error!(
                        package = %package_id,
                        "Refusing to restart pre-stopped service after snapshot restoration failure"
                    );
                    restart_failures.push("Refusing to restart pre-stopped service after snapshot restoration failure".to_string());
                }
            }
        } else {
            restart_failures.clear();
            for unit in lifecycle::ordered_units_for_start(restart_units) {
                if let Err(error) = backend.control(&unit, "start", lifecycle_job_id).await {
                    tracing::error!(unit, error = %error, "Application service restoration failed");
                    restart_failures.push(format!(
                        "Application service start for unit '{unit}' failed: {error}"
                    ));
                } else {
                    match backend.active(&unit).await {
                        Ok(true) => {}
                        Ok(false) => {
                            let msg = format!(
                                "Application service unit '{unit}' is not active after start"
                            );
                            tracing::error!(unit, "{}", msg);
                            restart_failures.push(msg);
                        }
                        Err(error) => {
                            let msg = format!("Cannot confirm application service state for unit '{unit}' after start: {error}");
                            tracing::error!(unit, error = %error, "Cannot confirm application service state");
                            restart_failures.push(msg);
                        }
                    }
                }
            }
        }
    }

    pub(super) async fn execute(
        &mut self,
        backend: &impl LifecycleBackend,
        sender: &mpsc::Sender<String>,
    ) -> Result<LifecycleReceipt> {
        let rollback_quiesce_units = self.rollback_quiesce_units();
        let mut pre_op_env = crate::PackageExecutionEnv::default();
        if pre_op_env.fs_root.is_none() {
            pre_op_env.fs_root = self.effective_fs_root();
        }
        let receipt_snapshots = match snapshot_candidate_receipts_with_env(
            &self.request.package_id,
            &pre_op_env,
        ) {
            Ok(snaps) => snaps,
            Err(snap_err) => {
                let err_msg = format!(
                    "Failed to snapshot candidate receipts before execution: {}",
                    snap_err
                );
                tracing::error!(package = %self.request.package_id, error = %err_msg, "Preflight candidate receipt snapshot failed");
                let sanitized_err = sanitize_lifecycle_field(&err_msg);
                let sanitized_expected = self
                    .request
                    .expected_target_version
                    .as_deref()
                    .map(sanitize_lifecycle_field);
                let mut finish_res = Ok(());
                for _ in 0..3 {
                    finish_res = lifecycle::finish_job_with_diagnostics(
                        &self.conn,
                        &self.request.package_id,
                        &self.request.lifecycle_job_id,
                        &self.request.action,
                        false,
                        lifecycle::LifecycleJobDiagnostics {
                            failure_category: "preflight",
                            failed_stage: Some("preflight_receipt_snapshot"),
                            exit_code: Some(1),
                            sanitized_summary: Some(&sanitized_err),
                            expected_target_version: sanitized_expected.as_deref(),
                            ..Default::default()
                        },
                    );
                    if finish_res.is_ok() {
                        break;
                    }
                }
                if let Err(ref finish_err) = finish_res {
                    anyhow::bail!("{err_msg}; completion error: {finish_err}");
                }
                anyhow::bail!("{err_msg}");
            }
        };
        let blueprint_snapshots = match snapshot_blueprint_targets(
            &self.request.package_id,
            &pre_op_env,
        ) {
            Ok(snaps) => snaps,
            Err(snap_err) => {
                let err_msg = format!(
                    "Failed to snapshot blueprint targets before execution: {}",
                    snap_err
                );
                tracing::error!(package = %self.request.package_id, error = %err_msg, "Preflight blueprint target snapshot failed");
                let sanitized_err = sanitize_lifecycle_field(&err_msg);
                let sanitized_expected = self
                    .request
                    .expected_target_version
                    .as_deref()
                    .map(sanitize_lifecycle_field);
                let mut finish_res = Ok(());
                for _ in 0..3 {
                    finish_res = lifecycle::finish_job_with_diagnostics(
                        &self.conn,
                        &self.request.package_id,
                        &self.request.lifecycle_job_id,
                        &self.request.action,
                        false,
                        lifecycle::LifecycleJobDiagnostics {
                            failure_category: "preflight",
                            failed_stage: Some("preflight_receipt_snapshot"),
                            exit_code: Some(1),
                            sanitized_summary: Some(&sanitized_err),
                            expected_target_version: sanitized_expected.as_deref(),
                            ..Default::default()
                        },
                    );
                    if finish_res.is_ok() {
                        break;
                    }
                }
                if let Err(ref finish_err) = finish_res {
                    anyhow::bail!("{err_msg}; completion error: {finish_err}");
                }
                anyhow::bail!("{err_msg}");
            }
        };

        let prior_installed = self.is_installed_on_disk_in(pre_op_env.fs_root.as_deref());
        let mut stopped = Vec::new();
        let mut failure = "preparation";
        let mut runtime_snapshot: Option<PackageRuntimeSnapshot> = None;
        let mut vhost_backups: Vec<crate::VhostBackup> = Vec::new();
        let mut prep_services_verified = false;
        let mut snapshot_captured = false;
        let mut script_attempted = false;
        let all_controllable_units = self.update_units();
        let should_quiesce_oneshots_pre_op =
            prior_installed || matches!(self.request.action.as_str(), "update" | "reinstall");
        let pre_remove_rclone_api_port = if self.request.package_id == "rclone"
            && self.request.action == "remove"
            && !self.request.delete_data
        {
            crate::extract_rclone_runtime_api_port_for_root(pre_op_env.fs_root.as_deref())
                .map(i32::from)
        } else {
            None
        };
        let mut execution: Result<()> = async {
            self.request.app_port = self.resolve_and_reserve_port(backend)?;
            for unit in &all_controllable_units {
                if !backend.quiescent(unit).await? {
                    stopped.push(unit.clone());
                    backend
                        .control(unit, "stop", &self.request.lifecycle_job_id)
                        .await?;
                }
            }
            if should_quiesce_oneshots_pre_op {
                for unit in &rollback_quiesce_units {
                    if matches!(unit.as_str(), "recyclarr" | "scrutiny-collector")
                        && !backend.quiescent(unit).await?
                    {
                        backend
                            .control(unit, "stop", &self.request.lifecycle_job_id)
                            .await?;
                    }
                }
            }
            prep_services_verified = true;
            if matches!(
                self.request.action.as_str(),
                "install" | "reinstall" | "update"
            ) {
                vhost_backups = crate::snapshot_app_vhost_backups(
                    &self.request.package_id,
                    pre_op_env.fs_root.as_deref(),
                )
                .map_err(|e| {
                    anyhow::anyhow!("Failed to snapshot Apache vhosts before execution: {e}")
                })?;
                runtime_snapshot = Some(
                    PackageRuntimeSnapshot::capture_blocking(
                        self.request.package_id.clone(),
                        rollback_quiesce_units.clone(),
                        pre_op_env.clone(),
                    )
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to snapshot package runtime before execution: {e}")
                    })?,
                );
                snapshot_captured = true;
            }
            failure = "installer";
            script_attempted = true;
            backend.script(&self.request, sender).await?;
            Ok(())
        }
        .await;
        let incomplete_rollback = execution
            .as_ref()
            .err()
            .is_some_and(|err| is_incomplete_rollback_error(&err.to_string()));
        let mut restart_failures: Vec<String> = Vec::new();
        let mut rollback_restart_failures: Vec<String> = Vec::new();
        let mut rollback_ran = false;
        let mut restore_failed;
        let mut receipt_restore_error: Option<String> = None;
        let lifecycle_job_id = self.request.lifecycle_job_id.clone();
        let package_id = self.request.package_id.clone();

        if execution.is_err() {
            let quiesce_units = if failure == "preparation" {
                &stopped
            } else {
                &rollback_quiesce_units
            };
            Self::restore_and_restart_units_with_runtime_and_vhosts(
                backend,
                &lifecycle_job_id,
                &package_id,
                quiesce_units,
                &stopped,
                &receipt_snapshots,
                &blueprint_snapshots,
                &mut receipt_restore_error,
                &mut restart_failures,
                incomplete_rollback,
                true,
                runtime_snapshot.take(),
                std::mem::take(&mut vhost_backups),
                pre_op_env.fs_root.clone(),
            )
            .await;
            rollback_ran = true;
            rollback_restart_failures = restart_failures.clone();
            restore_failed = !restart_failures.is_empty();
        } else {
            if incomplete_rollback {
                if !stopped.is_empty() {
                    tracing::error!(
                        package = %self.request.package_id,
                        "Refusing to restart pre-stopped service after incomplete rollback"
                    );
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after incomplete rollback"
                            .to_string(),
                    );
                }
            } else {
                for unit in lifecycle::ordered_units_for_start(&stopped) {
                    if let Err(error) = backend
                        .control(&unit, "start", &self.request.lifecycle_job_id)
                        .await
                    {
                        tracing::error!(unit, error = %error, "Application service restoration failed");
                        restart_failures.push(format!(
                            "Application service start for unit '{unit}' failed: {error}"
                        ));
                    } else {
                        match backend.active(&unit).await {
                            Ok(true) => {}
                            Ok(false) => {
                                let msg = format!(
                                    "Application service unit '{unit}' is not active after start"
                                );
                                tracing::error!(unit, "{}", msg);
                                restart_failures.push(msg);
                            }
                            Err(error) => {
                                let msg = format!("Cannot confirm application service state for unit '{unit}' after start: {error}");
                                tracing::error!(unit, error = %error, "Cannot confirm application service state");
                                restart_failures.push(msg);
                            }
                        }
                    }
                }
            }
            restore_failed = !restart_failures.is_empty();
            if restore_failed {
                let initial_failures = restart_failures.clone();
                let mut restore_restart_failures = Vec::new();
                Self::restore_and_restart_units_with_runtime_and_vhosts(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restore_restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restore_restart_failures.clone();
                restart_failures = initial_failures;
                restart_failures.extend(restore_restart_failures);
                restore_failed = true;
            }
        }

        // Target certification BEFORE post-install ingress synchronization & configuration commit
        let mut target_match_failed = false;
        let mut achieved_ver: Option<String> = None;
        if execution.is_ok()
            && !restore_failed
            && self.request.expected_target_version.is_some()
            && self.request.action != "remove"
        {
            let target = self.request.expected_target_version.as_deref().unwrap();
            let mut env_cfg = crate::PackageExecutionEnv::default();
            if env_cfg.fs_root.is_none() {
                env_cfg.fs_root = self.effective_fs_root();
            }
            achieved_ver = resolve_verified_installed_version(&self.request.package_id, &env_cfg);
            let matches = achieved_ver
                .as_deref()
                .map(|ach| af_release::lifecycle::versions_match_target(ach, target))
                .unwrap_or(false);
            if !matches {
                target_match_failed = true;
                failure = "target_verification";
                #[cfg(test)]
                {
                    if let Some(hook) = TEST_CERTIFY_FAIL_HOOK.lock().unwrap().as_ref() {
                        hook(&package_id);
                    }
                }
                // Rollback / restore previous candidate receipts and blueprints while quiesced so uncertified version is not retained
                Self::restore_and_restart_units_with_runtime_and_vhosts(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restart_failures.clone();
                if !restart_failures.is_empty() {
                    restore_failed = true;
                }
            }
        }

        // Re-check service units right after target certification to ensure none exited during certification
        if execution.is_ok() && !restore_failed && !target_match_failed && !incomplete_rollback {
            for unit in &stopped {
                match backend.active(unit).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let msg = format!("Application service unit '{unit}' exited or became inactive during certification");
                        tracing::error!(unit, "{}", msg);
                        restart_failures.push(msg);
                    }
                    Err(error) => {
                        let msg = format!("Cannot confirm application service state for unit '{unit}' after certification: {error}");
                        tracing::error!(unit, error = %error, "Cannot confirm application service state");
                        restart_failures.push(msg);
                    }
                }
            }
            if !restart_failures.is_empty() {
                restore_failed = true;
                let primary_failures = restart_failures.clone();
                let mut restore_restart_failures = Vec::new();
                Self::restore_and_restart_units_with_runtime_and_vhosts(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restore_restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restore_restart_failures.clone();
                restart_failures = primary_failures;
                restart_failures.extend(restore_restart_failures);
            }
        }

        // Post-install ingress synchronization & blueprint app config only AFTER certification succeeds
        let mut post_commit_ingress: Option<af_models::AppIngressConfig> = None;
        if execution.is_ok() && !restore_failed && !target_match_failed {
            let post_commit: Result<()> = async {
                failure = if self.request.action == "remove" {
                    "retention"
                } else {
                    "configuration"
                };
                let base: Option<String> = self
                    .conn
                    .query_row(
                        "SELECT COALESCE(base_domain,'') FROM settings WHERE id=1",
                        [],
                        |row| row.get(0),
                    )
                    .optional()?;
                let base_domain = base.as_deref().unwrap_or("");
                let planned_ingress = if self.request.action != "remove"
                    && (1024..=65535).contains(&self.request.app_port)
                {
                    let existing =
                        af_db::load_lifecycle_ingress(&self.conn, &self.request.package_id)?;
                    af_db::plan_lifecycle_ingress(
                        &self.request.package_id,
                        self.request.app_port,
                        base_domain,
                        existing.as_ref(),
                    )?
                } else {
                    None
                };
                if self.request.action != "remove"
                    && (1024..=65535).contains(&self.request.app_port)
                {
                    let fs_root = self.effective_fs_root();
                    crate::package_executor::apply_runner_blueprint_in_background_with_ingress(
                        fs_root.clone(),
                        self.request.package_id.clone(),
                        self.request.app_port,
                        planned_ingress.clone(),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                    if let Some(cfg) = planned_ingress.as_ref() {
                        let apache_dir = match fs_root.as_deref() {
                            Some(root) => root.join("etc/apache2"),
                            None => {
                                crate::resolve_provider_dir("AETHERFLOW_APACHE_DIR", "/etc/apache2")
                            }
                        };
                        let clean_app =
                            af_models::resolve_package_lock_name(&self.request.package_id);
                        if (apache_dir.join("sites-available").is_dir()
                            || apache_dir.join("sites-enabled").is_dir())
                            && crate::get_runner_package_definition(clean_app).is_some()
                        {
                            let vhost_req = af_models::RunnerApacheVhostRequest {
                                app_name: clean_app.to_string(),
                                listen_port: cfg.listen_port,
                                internal_domain: Some(format!("{clean_app}.aether.local")),
                                public_domain: (!cfg.public_domain.trim().is_empty())
                                    .then(|| cfg.public_domain.trim().to_string()),
                                external_access_enabled: cfg.external_access_enabled,
                                tls_enabled: cfg.tls_enabled,
                                reload_apache: fs_root.is_none(),
                                ..Default::default()
                            };
                            crate::sync_apache_vhost_local(&vhost_req, &apache_dir).await?;
                        }
                    }
                }
                let secondary_update = if self.request.package_id == "rclone" {
                    if self.request.action == "remove" {
                        pre_remove_rclone_api_port
                            .map(|p| (af_models::RCLONE_RC_API_PORT_ROLE, Some(p)))
                    } else {
                        crate::rclone_secondary_port_update_for_root(
                            self.effective_fs_root().as_deref(),
                            self.request.app_port,
                            (self.request.secondary_port > 0)
                                .then_some(self.request.secondary_port),
                        )
                    }
                } else {
                    None
                };
                af_db::synchronize_lifecycle_ingress_with_secondary_port(
                    &mut self.conn,
                    &self.request.package_id,
                    &self.request.action,
                    &self.request.lifecycle_job_id,
                    self.request.app_port,
                    secondary_update,
                    self.request.delete_data,
                    base_domain,
                )?;
                post_commit_ingress = planned_ingress;
                Ok(())
            }
            .await;
            if let Err(error) = post_commit {
                execution = Err(error);
                Self::restore_and_restart_units_with_runtime_and_vhosts(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restart_failures.clone();
                if !restart_failures.is_empty() {
                    restore_failed = true;
                }
            } else if self.effective_fs_root().is_none()
                && post_commit_ingress.as_ref().is_some_and(|cfg| {
                    cfg.external_access_enabled
                        && cfg.tls_enabled
                        && !cfg.public_domain.trim().is_empty()
                })
            {
                if let Err(err) = crate::sync_certbot_and_managed_ingress().await {
                    tracing::warn!(
                        package = %self.request.package_id,
                        error = %err,
                        "post-install certbot and managed ingress sync failed"
                    );
                }
            }
        }

        if runtime_snapshot.is_some() {
            let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
        }
        let success = execution.is_ok() && !restore_failed && !target_match_failed;
        let prior_state_recovered = !success
            && matches!(
                self.request.action.as_str(),
                "reinstall" | "update" | "install"
            )
            && prior_installed
            && prep_services_verified
            && !incomplete_rollback
            && rollback_ran
            && (!script_attempted || snapshot_captured)
            && receipt_restore_error.is_none()
            && rollback_restart_failures.is_empty()
            && self.is_installed_on_disk_in(pre_op_env.fs_root.as_deref());
        if let Err(error) = &execution {
            tracing::error!(package = %self.request.package_id, error = %error, "Required lifecycle phase failed");
        }
        if restore_failed {
            failure = if execution.is_err() && failure == "configuration" {
                "configuration_and_service_restore"
            } else if incomplete_rollback || execution.is_ok() {
                "service_restore"
            } else {
                failure
            };
        } else if target_match_failed {
            failure = "target_verification";
        }
        let diag_summary = if target_match_failed {
            let mut msg = format!(
                "Target certification failed after installer execution (runtime state may be partially committed): expected {}, achieved {}",
                self.request.expected_target_version.as_deref().unwrap_or(""),
                achieved_ver.as_deref().unwrap_or("none")
            );
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            Some(msg)
        } else if !restart_failures.is_empty() {
            let mut msg = format!(
                "Application service restoration failed: {}",
                restart_failures.join("; ")
            );
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            Some(msg)
        } else if let Err(ref exec_err) = execution {
            let mut msg = format!("Execution failed in {} phase: {}", failure, exec_err);
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            Some(msg)
        } else {
            receipt_restore_error
                .as_ref()
                .map(|r_err| format!("Receipt restoration error: {}", r_err))
        };
        let sanitized_diag_summary = diag_summary.as_deref().map(sanitize_lifecycle_field);
        let sanitized_expected = self
            .request
            .expected_target_version
            .as_deref()
            .map(sanitize_lifecycle_field);
        let sanitized_achieved = achieved_ver.as_deref().map(sanitize_lifecycle_field);
        lifecycle::finish_job_with_diagnostics(
            &self.conn,
            &self.request.package_id,
            &self.request.lifecycle_job_id,
            &self.request.action,
            success,
            lifecycle::LifecycleJobDiagnostics {
                failure_category: failure,
                failed_stage: if target_match_failed {
                    Some("target_certification_after_install_commit")
                } else if restore_failed {
                    Some("service_restoration")
                } else if execution.is_err() {
                    Some(failure)
                } else if receipt_restore_error.is_some() {
                    Some("rollback")
                } else {
                    None
                },
                exit_code: if target_match_failed
                    || restore_failed
                    || execution.is_err()
                    || receipt_restore_error.is_some()
                {
                    Some(1)
                } else {
                    None
                },
                sanitized_summary: sanitized_diag_summary
                    .as_deref()
                    .or(if target_match_failed {
                        Some("Post-execution installed version did not match expected target")
                    } else if restore_failed {
                        Some("Service restart verification failed")
                    } else if execution.is_err() {
                        Some("Lifecycle execution failed")
                    } else if receipt_restore_error.is_some() {
                        Some("Receipt restoration failed")
                    } else {
                        None
                    }),
                expected_target_version: sanitized_expected.as_deref(),
                achieved_version: sanitized_achieved.as_deref(),
                recovery_state: prior_state_recovered
                    .then_some(lifecycle::RECOVERY_STATE_PRIOR_VERIFIED),
                retention_state: (success && self.request.action == "remove").then_some(
                    if self.request.delete_data {
                        lifecycle::RETENTION_STATE_PURGED
                    } else {
                        lifecycle::RETENTION_STATE_RETAINED
                    },
                ),
                ..Default::default()
            },
        )?;
        let finished_at = self.conn.query_row(
            "SELECT finished_at FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
            rusqlite::params![self.request.package_id, self.request.lifecycle_job_id],
            |row| row.get(0),
        )?;
        Ok(LifecycleReceipt {
            job_id: self.request.lifecycle_job_id.clone(),
            package_id: self.request.package_id.clone(),
            action: self.request.action.clone(),
            status: if success { "completed" } else { "failed" }.into(),
            started_at: self.started_at.clone(),
            finished_at,
            app_port: self.request.app_port,
        })
    }
}
