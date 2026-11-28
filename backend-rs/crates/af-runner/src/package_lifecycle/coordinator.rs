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

/// Scoped SQLite handle that executes synchronous DB operations and `sqlite3_close()`
/// (including `-wal`/`-shm`/`-journal` sidecar checkpoint/unlink) under the immutable open-time
/// DB parent directory owner's Linux per-thread `fsuid`/`fsgid` when running as `root`.
pub(super) struct OwnerScopedConnection {
    conn: Option<Connection>,
    db_path: Option<PathBuf>,
    owner_creds: Option<(u32, u32)>,
}

impl OwnerScopedConnection {
    pub(super) fn open_hardened(path: &Path, read_write: bool) -> Result<Self> {
        let owner_creds = af_release::fs_security::resolve_path_owner_fsuid(path)?;
        let conn = match owner_creds {
            Some((uid, gid)) => af_release::fs_security::with_uid_gid_fsuid(uid, gid, || {
                af_release::fs_security::open_sqlite_nofollow_hardened(path, read_write)
            })?,
            None => af_release::fs_security::open_sqlite_nofollow_hardened(path, read_write)?,
        };
        Ok(Self {
            conn: Some(conn),
            db_path: Some(path.to_path_buf()),
            owner_creds,
        })
    }

    fn new(conn: Connection) -> Result<Self> {
        let db_path = conn
            .path()
            .filter(|p| !p.is_empty() && *p != ":memory:")
            .map(PathBuf::from);
        let owner_creds = match db_path.as_deref() {
            Some(path) => match af_release::fs_security::resolve_path_owner_fsuid(path) {
                Ok(creds) => creds,
                Err(err) => {
                    #[cfg(unix)]
                    if unsafe { libc::geteuid() } == 0 {
                        tracing::error!(
                            path = %path.display(),
                            "refusing to close SQLite handle as root after path owner validation failure"
                        );
                        std::mem::forget(conn);
                    }
                    return Err(err.into());
                }
            },
            None => None,
        };
        Ok(Self {
            conn: Some(conn),
            db_path,
            owner_creds,
        })
    }

    fn run_scoped<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        match (self.owner_creds, self.db_path.as_deref()) {
            (Some((uid, gid)), _) => {
                let mut outcome: Option<Result<T>> = None;
                af_release::fs_security::with_uid_gid_fsuid(uid, gid, || {
                    outcome = Some(f());
                    Ok(())
                })?;
                outcome.expect("closure executed")
            }
            (None, Some(path)) => {
                let mut outcome: Option<Result<T>> = None;
                af_release::fs_security::with_path_owner_fsuid(path, || {
                    outcome = Some(f());
                    Ok(())
                })?;
                outcome.expect("closure executed")
            }
            (None, None) => f(),
        }
    }

    fn with_db<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let conn = self.conn.as_ref().expect("connection active until Drop");
        self.run_scoped(|| f(conn))
    }

    fn with_db_mut<T, F>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T>,
    {
        let owner_creds = self.owner_creds;
        let db_path = self.db_path.clone();
        let conn = self.conn.as_mut().expect("connection active until Drop");
        match (owner_creds, db_path.as_deref()) {
            (Some((uid, gid)), _) => {
                let mut outcome: Option<Result<T>> = None;
                af_release::fs_security::with_uid_gid_fsuid(uid, gid, || {
                    outcome = Some(f(conn));
                    Ok(())
                })?;
                outcome.expect("closure executed")
            }
            (None, Some(path)) => {
                let mut outcome: Option<Result<T>> = None;
                af_release::fs_security::with_path_owner_fsuid(path, || {
                    outcome = Some(f(conn));
                    Ok(())
                })?;
                outcome.expect("closure executed")
            }
            (None, None) => f(conn),
        }
    }

    fn db_path_str(&self) -> Option<&str> {
        self.db_path.as_deref().and_then(|p| p.to_str())
    }
}

#[cfg(test)]
impl std::ops::Deref for OwnerScopedConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("connection active until Drop")
    }
}

impl Drop for OwnerScopedConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut held = Some(conn);
            match (self.owner_creds, self.db_path.as_deref()) {
                (Some((uid, gid)), _) => {
                    let _ = af_release::fs_security::with_uid_gid_fsuid(uid, gid, || {
                        drop(held.take());
                        Ok(())
                    });
                    if let Some(unclosed) = held {
                        // Never invoke `sqlite3_close()` at fsuid=0 if credential drop failed.
                        tracing::error!(
                            uid,
                            gid,
                            "refusing to close unprivileged SQLite handle as root after fsuid failure"
                        );
                        std::mem::forget(unclosed);
                    }
                }
                (None, Some(path)) => {
                    let _ = af_release::fs_security::with_path_owner_fsuid(path, || {
                        drop(held.take());
                        Ok(())
                    });
                    if let Some(unclosed) = held {
                        tracing::error!(
                            path = %path.display(),
                            "refusing to close SQLite handle as root after path owner validation failure"
                        );
                        std::mem::forget(unclosed);
                    }
                }
                (None, None) => {
                    drop(held);
                }
            }
        }
    }
}

pub(super) struct CoordinatedOperation {
    pub(super) conn: OwnerScopedConnection,
    pub(super) request: PackageRunnerRequest,
    package: Package,
    units: Vec<String>,
    started_at: String,
    _owner: OwnerLease,
}

impl Drop for CoordinatedOperation {
    fn drop(&mut self) {
        let owner = &mut self._owner;
        let _ = self.conn.with_db(|conn| owner.retire_with_conn(conn));
    }
}

fn effective_fs_root_for_db_path(db_path: Option<&str>) -> Option<std::path::PathBuf> {
    if let Some(root) = crate::PackageExecutionEnv::default().fs_root {
        return Some(root);
    }
    db_path.map(Path::new).and_then(|p| {
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
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn admit(
        conn: Connection,
        request: PackageRunnerRequest,
        package: Package,
        units: Vec<String>,
    ) -> Result<Self> {
        let conn = OwnerScopedConnection::new(conn)?;
        Self::admit_scoped(conn, request, package, units)
    }

    pub(super) fn admit_scoped(
        mut conn: OwnerScopedConnection,
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
        conn.with_db(|c| {
            c.busy_timeout(Duration::from_secs(5))?;
            lifecycle::initialize_schema(c)?;
            Ok(())
        })?;
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
            let fs_root = effective_fs_root_for_db_path(conn.db_path_str());
            let mut reserved =
                conn.with_db(|c| af_db::list_reserved_ports_excluding(c, &request.package_id))?;
            reserved.extend(crate::rclone_extra_reserved_ports(
                &request.package_id,
                fs_root.as_deref(),
            ));
            let candidate_port = if request.app_port > 0 {
                Some(request.app_port)
            } else {
                conn.with_db(|c| af_db::load_lifecycle_ingress(c, &request.package_id))?
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
                    conn.with_db(|c| {
                        af_db::load_lifecycle_secondary_port(
                            c,
                            "rclone",
                            af_models::RCLONE_RC_API_PORT_ROLE,
                        )
                    })?
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
        let owner = conn.with_db_mut(|c| {
            lifecycle::admit_job_with_target(
                c,
                &request.package_id,
                &request.lifecycle_job_id,
                &request.action,
                &started_at,
                &units,
                request.expected_target_version.as_deref(),
            )
        })?;
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

    #[allow(clippy::too_many_arguments)]
    fn resolve_port_in_tx(
        request: &PackageRunnerRequest,
        package: &Package,
        installed_or_legacy: bool,
        extra_reserved: &std::collections::BTreeSet<i32>,
        pre_runtime_port: i32,
        pre_receipt_port: Option<i32>,
        conn: &Connection,
        base_reserved: &std::collections::BTreeSet<i32>,
        backend: &impl LifecycleBackend,
    ) -> Result<i32> {
        if request.action == "remove" {
            return Ok(0);
        }
        let mut reserved = base_reserved.clone();
        reserved.extend(extra_reserved.iter().copied());
        let ingress = af_db::load_lifecycle_ingress(conn, &request.package_id)?;
        let saved = ingress
            .as_ref()
            .map(|config| config.listen_port)
            .unwrap_or(0);
        if request.action == "update" {
            let runtime = pre_runtime_port;
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
            let runtime = pre_runtime_port;
            if runtime > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&runtime),
                    "Native application listen port is invalid"
                );
                if !reserved.contains(&runtime) {
                    return Ok(runtime);
                }
            }
            if let Some(receipt_port) = pre_receipt_port {
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
        // Pre-resolve all host filesystem config/receipt reads at effective credentials BEFORE
        // dropping thread fsuid for SQLite writes so private service-owned configs (0600/0750)
        // remain readable by root runner.
        let extra_reserved =
            crate::rclone_extra_reserved_ports(&self.request.package_id, fs_root.as_deref());
        let pre_runtime_port = if self.request.action == "update" || installed_or_legacy {
            backend.runtime_port(&self.request.package_id)
        } else {
            0
        };
        let pre_receipt_port = if installed_or_legacy {
            let env_cfg = crate::PackageExecutionEnv::default();
            af_models::read_package_receipt_port(
                &self.package.name,
                Some(&self.package.lock_file),
                env_cfg.fs_root.as_deref(),
            )
            .ok()
            .flatten()
        } else {
            None
        };
        let request = &self.request;
        let package = &self.package;
        let chosen = self
            .conn
            .with_db_mut(|conn| {
                af_db::reserve_lifecycle_port_in_tx(
                    conn,
                    &request.package_id,
                    &request.lifecycle_job_id,
                    Some(&request.action),
                    |tx, reserved| {
                        let port = Self::resolve_port_in_tx(
                            request,
                            package,
                            installed_or_legacy,
                            &extra_reserved,
                            pre_runtime_port,
                            pre_receipt_port,
                            tx,
                            reserved,
                            backend,
                        )?;
                        Ok((port > 0).then_some(port))
                    },
                )
            })?
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
        effective_fs_root_for_db_path(self.conn.db_path_str())
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
        let (restoration, vhosts_changed) = match tokio::task::spawn_blocking(move || {
            let mut vhosts_changed = false;
            let res = (|| -> Result<(), String> {
                // Restore vhost backups before runtime and blueprint snapshots because
                // PackageRuntimeSnapshot::capture also includes Apache vhosts; restoring
                // vhost_backups first ensures sites-available/sites-enabled drift is
                // detected for reload_apache_after_rollback_if_live.
                if !incomplete_rollback && !vhost_backups.is_empty() {
                    vhosts_changed = crate::restore_app_vhost_backups(&vhost_backups)
                        .map_err(|e| e.to_string())?;
                }
                rollback_operation_state_with_runtime(
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    if incomplete_rollback {
                        None
                    } else {
                        runtime_snapshot.as_mut()
                    },
                )?;
                Ok(())
            })();
            (res, vhosts_changed)
        })
        .await
        {
            Ok(pair) => pair,
            Err(err) => (Err(format!("Snapshot restore worker failed: {err}")), false),
        };
        if vhosts_changed {
            crate::reload_apache_after_rollback_if_live(fs_root.as_deref()).await;
        }
        let mut snapshot_restore_failed = false;
        if let Err(restore_err) = restoration {
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
                    finish_res = self.conn.with_db(|conn| {
                        lifecycle::finish_job_with_diagnostics(
                            conn,
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
                        )
                    });
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
                    finish_res = self.conn.with_db(|conn| {
                        lifecycle::finish_job_with_diagnostics(
                            conn,
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
                        )
                    });
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
                let (base, planned_ingress) = self.conn.with_db(|conn| {
                    let base: Option<String> = conn
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
                            af_db::load_lifecycle_ingress(conn, &self.request.package_id)?;
                        af_db::plan_lifecycle_ingress(
                            &self.request.package_id,
                            self.request.app_port,
                            base_domain,
                            existing.as_ref(),
                        )?
                    } else {
                        None
                    };
                    Ok((base, planned_ingress))
                })?;
                let base_domain = base.as_deref().unwrap_or("");
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
                let package_id_for_sync = self.request.package_id.clone();
                let action_for_sync = self.request.action.clone();
                let job_id_for_sync = self.request.lifecycle_job_id.clone();
                let app_port_for_sync = self.request.app_port;
                let delete_data_for_sync = self.request.delete_data;
                self.conn.with_db_mut(|conn| {
                    af_db::synchronize_lifecycle_ingress_with_secondary_port(
                        conn,
                        &package_id_for_sync,
                        &action_for_sync,
                        &job_id_for_sync,
                        app_port_for_sync,
                        secondary_update,
                        delete_data_for_sync,
                        base_domain,
                    )
                })?;
                if self.request.action == "remove" {
                    let fs_root = self.effective_fs_root();
                    let apache_dir = match fs_root.as_deref() {
                        Some(root) => root.join("etc/apache2"),
                        None => {
                            crate::resolve_provider_dir("AETHERFLOW_APACHE_DIR", "/etc/apache2")
                        }
                    };
                    let clean_app =
                        af_models::resolve_package_lock_name(&self.request.package_id).to_string();
                    let probe_apache_dir = apache_dir.clone();
                    let probe_clean_app = clean_app.clone();
                    let has_managed_vhost = tokio::task::spawn_blocking(move || {
                        let has_apache_dirs =
                            ["sites-available", "sites-enabled"]
                                .into_iter()
                                .any(|subdir| {
                                    !matches!(
                                        std::fs::symlink_metadata(probe_apache_dir.join(subdir)),
                                        Err(err) if err.kind() == std::io::ErrorKind::NotFound
                                    )
                                });
                        if !has_apache_dirs
                            || crate::get_runner_package_definition(&probe_clean_app).is_none()
                        {
                            return false;
                        }
                        let managed_vhosts = [
                            format!("aetherflow-app-{probe_clean_app}.conf"),
                            format!("aetherflow-ext-{probe_clean_app}.conf"),
                            format!("aetherflow-ext-{probe_clean_app}-le-ssl.conf"),
                        ];
                        ["sites-available", "sites-enabled"]
                            .into_iter()
                            .any(|subdir| {
                                let dir = probe_apache_dir.join(subdir);
                                managed_vhosts.iter().any(|name| {
                                    !matches!(
                                        std::fs::symlink_metadata(dir.join(name)),
                                        Err(err) if err.kind() == std::io::ErrorKind::NotFound
                                    )
                                })
                            })
                    })
                    .await
                    .map_err(|err| anyhow::anyhow!("vhost removal probe worker failed: {err}"))?;
                    if has_managed_vhost {
                        failure = "configuration";
                        let vhost_req = af_models::RunnerApacheVhostRequest {
                            app_name: clean_app,
                            remove_only: true,
                            reload_apache: fs_root.is_none(),
                            ..Default::default()
                        };
                        crate::sync_apache_vhost_local(&vhost_req, &apache_dir).await?;
                    }
                }
                post_commit_ingress = planned_ingress;
                Ok(())
            }
            .await;
            if let Err(error) = post_commit {
                execution = Err(error);
                if self.request.action != "remove" {
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
            } else {
                self.reconcile_post_lifecycle_dns_best_effort().await;
                if self.effective_fs_root().is_none()
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
        let finished_at = self.conn.with_db(|conn| {
            lifecycle::finish_job_with_diagnostics(
                conn,
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
                    sanitized_summary: sanitized_diag_summary.as_deref().or(
                        if target_match_failed {
                            Some("Post-execution installed version did not match expected target")
                        } else if restore_failed {
                            Some("Service restart verification failed")
                        } else if execution.is_err() {
                            Some("Lifecycle execution failed")
                        } else if receipt_restore_error.is_some() {
                            Some("Receipt restoration failed")
                        } else {
                            None
                        },
                    ),
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
            let finished_at: String = conn.query_row(
                "SELECT finished_at FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
                rusqlite::params![self.request.package_id, self.request.lifecycle_job_id],
                |row| row.get(0),
            )?;
            Ok(finished_at)
        })?;
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

    async fn reconcile_post_lifecycle_dns_best_effort(&mut self) {
        let fs_root = self.effective_fs_root();
        let should_skip = fs_root.is_none() && !has_explicit_dns_override() && cfg!(test);
        if should_skip {
            return;
        }
        let package_id = self.request.package_id.clone();
        let action = self.request.action.clone();
        let db_path = self.conn.db_path.clone().filter(|p| p.exists());
        let res = if let Some(db_path) = db_path {
            reconcile_dns_for_db_path_serialized(db_path, fs_root).await
        } else {
            let _dns_guard = POST_LIFECYCLE_DNS_RECONCILE_LOCK.lock().await;
            let snapshot = match self.conn.with_db(read_reconciled_dns_db_snapshot) {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    tracing::warn!(
                        package = %package_id,
                        action = %action,
                        error = %err,
                        "post-lifecycle DNS domain collection failed"
                    );
                    return;
                }
            };
            tokio::task::spawn_blocking(move || {
                let (aether_local_domains, authoritative_domains) =
                    finalize_reconciled_dns_domains(snapshot, fs_root.as_deref());
                apply_reconciled_dns_domains(
                    &aether_local_domains,
                    &authoritative_domains,
                    fs_root.as_deref(),
                )
            })
            .await
            .map_err(|join_err| {
                anyhow::anyhow!("post-lifecycle DNS reconciliation task failed: {join_err}")
            })
            .and_then(|inner| inner)
        };
        if let Err(err) = res {
            tracing::warn!(
                package = %package_id,
                action = %action,
                error = %err,
                "post-lifecycle DNS reconciliation failed"
            );
        }
    }
}

static POST_LIFECYCLE_DNS_RECONCILE_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

async fn reconcile_dns_for_db_path_serialized(
    db_path: PathBuf,
    fs_root: Option<PathBuf>,
) -> Result<()> {
    let _dns_guard = POST_LIFECYCLE_DNS_RECONCILE_LOCK.lock().await;
    tokio::task::spawn_blocking(move || {
        let conn = OwnerScopedConnection::open_hardened(&db_path, false)?;
        let snapshot = conn.with_db(|c| {
            c.busy_timeout(Duration::from_secs(5))?;
            read_reconciled_dns_db_snapshot(c)
        })?;
        drop(conn);
        let (aether_local_domains, authoritative_domains) =
            finalize_reconciled_dns_domains(snapshot, fs_root.as_deref());
        apply_reconciled_dns_domains(
            &aether_local_domains,
            &authoritative_domains,
            fs_root.as_deref(),
        )
    })
    .await
    .map_err(|join_err| {
        anyhow::anyhow!("post-lifecycle DNS reconciliation task failed: {join_err}")
    })?
}

fn isolated_hosts_lock_path(hosts_path: &Path) -> PathBuf {
    let parent = hosts_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = hosts_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("hosts");
    let stem = file_name.trim_start_matches('.');
    let stem = if stem.is_empty() { "hosts" } else { stem };
    parent.join(format!(".{stem}.lock"))
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |r| r.get(0),
    )?;
    Ok(exists != 0)
}

fn format_app_public_domain(app_name: &str, base_domain: &str) -> String {
    let norm = af_db::normalize_base_domain(base_domain);
    if norm.is_empty() {
        return String::new();
    }
    let clean_app: String = app_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let slug = clean_app.trim_matches('-');
    if slug.is_empty() {
        String::new()
    } else {
        format!("{slug}.{norm}")
    }
}

fn detect_lifecycle_lan_ip() -> std::result::Result<Option<String>, String> {
    if let Some(raw_os) = std::env::var_os("AETHERFLOW_LAN_IP") {
        let raw = raw_os
            .into_string()
            .map_err(|_| "Invalid AETHERFLOW_LAN_IP: value is not valid UTF-8".to_string())?;
        let ip = crate::hosts_dns::validate_hosts_ip(&raw)
            .map_err(|e| format!("Invalid AETHERFLOW_LAN_IP: {e}"))?;
        return Ok(Some(ip.to_string()));
    }
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("1.1.1.1:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                let ip = addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return Ok(Some(ip.to_string()));
                }
            }
        }
    }
    Ok(None)
}

fn resolve_explicit_hosts_override() -> Option<(&'static str, String)> {
    for key in ["AF_HOSTS_FILE", "AETHERFLOW_HOSTS_FILE"] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some((key, trimmed.to_string()));
            }
        }
    }
    None
}

fn has_explicit_hosts_override() -> bool {
    resolve_explicit_hosts_override().is_some()
}

fn has_explicit_dns_provider_override() -> bool {
    [
        "AETHERFLOW_DNSMASQ_DIR",
        "AETHERFLOW_PIHOLE_DIR",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_FS_ROOT",
    ]
    .iter()
    .any(|key| {
        std::env::var(key)
            .ok()
            .is_some_and(|val| !val.trim().is_empty())
    })
}

fn has_explicit_dns_override() -> bool {
    has_explicit_hosts_override() || has_explicit_dns_provider_override()
}

struct ReconciledDnsDbSnapshot {
    base_domain: String,
    domain_set: std::collections::BTreeSet<String>,
    configured_public_apps: std::collections::HashSet<String>,
    retained_apps: std::collections::HashSet<String>,
}

fn read_reconciled_dns_db_snapshot(conn: &Connection) -> Result<ReconciledDnsDbSnapshot> {
    use std::collections::{BTreeSet, HashSet};

    let mut domain_set: BTreeSet<String> = BTreeSet::new();
    domain_set.insert("aetherflow.aether.local".to_string());

    let base_raw: Option<String> = if table_exists(conn, "settings")? {
        conn.query_row(
            "SELECT COALESCE(base_domain, '') FROM settings WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?
    } else {
        None
    };
    let base_domain = base_raw
        .as_deref()
        .map(af_db::normalize_base_domain)
        .unwrap_or_default();

    let mut configured_public_apps: HashSet<String> = HashSet::new();
    if table_exists(conn, "app_ingress_configs")? {
        let mut stmt =
            conn.prepare("SELECT app_name, COALESCE(public_domain, ''), COALESCE(listen_port, 0) FROM app_ingress_configs")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i32>(2)?,
            ))
        })?;
        for row in rows {
            let (app_name, public_domain, listen_port) = row?;
            let app_key = app_name.trim().to_ascii_lowercase();
            if !app_key.is_empty() {
                domain_set.insert(format!("{app_key}.aether.local"));
            }
            if !public_domain.trim().is_empty() {
                if !app_key.is_empty() {
                    configured_public_apps.insert(app_key);
                }
                domain_set.insert(public_domain.trim().to_ascii_lowercase());
            } else if !base_domain.is_empty() && listen_port > 0 {
                let pub_dom = format_app_public_domain(&app_name, &base_domain);
                if !pub_dom.is_empty() {
                    if !app_key.is_empty() {
                        configured_public_apps.insert(app_key);
                    }
                    domain_set.insert(pub_dom);
                }
            }
        }
    }

    let mut retained_apps: HashSet<String> = HashSet::new();
    if table_exists(conn, "retained_app_ingress_configs")? {
        let mut stmt = conn.prepare("SELECT app_name FROM retained_app_ingress_configs")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for app in rows.flatten() {
            let app_key = app.trim().to_ascii_lowercase();
            if !app_key.is_empty() {
                retained_apps.insert(app_key);
            }
        }
    }

    Ok(ReconciledDnsDbSnapshot {
        base_domain,
        domain_set,
        configured_public_apps,
        retained_apps,
    })
}

fn finalize_reconciled_dns_domains(
    mut snapshot: ReconciledDnsDbSnapshot,
    fs_root: Option<&Path>,
) -> (Vec<String>, Vec<String>) {
    if let Ok(pkgs) = crate::load_runner_package_definitions_in_root(fs_root) {
        for p in pkgs {
            let app_key = p.name.trim().to_ascii_lowercase();
            let lock_key = af_models::resolve_package_lock_name(&app_key).to_string();
            if snapshot.retained_apps.contains(&app_key)
                || snapshot.retained_apps.contains(&lock_key)
            {
                continue;
            }
            let explicit_lock = (!p.lock_file.trim().is_empty()).then_some(p.lock_file.as_str());
            let installed = af_models::inspect_package_receipts(&p.name, explicit_lock, fs_root)
                .is_ok_and(|receipts| receipts.has_any_receipt());
            if !installed {
                continue;
            }
            if p.default_port > 0 || !p.web_path.trim().is_empty() {
                snapshot
                    .domain_set
                    .insert(format!("{app_key}.aether.local"));
                if !snapshot.base_domain.is_empty()
                    && !snapshot.configured_public_apps.contains(&app_key)
                {
                    let pub_dom = format_app_public_domain(&p.name, &snapshot.base_domain);
                    if !pub_dom.is_empty() {
                        snapshot.domain_set.insert(pub_dom);
                    }
                }
            }
        }
    }

    let mut aether_local_domains = Vec::new();
    let mut authoritative_domains = Vec::new();
    for raw in snapshot.domain_set {
        if let Ok(clean) = crate::hosts_dns::validate_hosts_domain(&raw) {
            if clean.ends_with(".aether.local") {
                aether_local_domains.push(clean.clone());
            }
            authoritative_domains.push(clean);
        }
    }
    (aether_local_domains, authoritative_domains)
}

fn apply_reconciled_dns_domains(
    aether_local_domains: &[String],
    authoritative_domains: &[String],
    fs_root: Option<&Path>,
) -> Result<()> {
    let hosts_override = resolve_explicit_hosts_override();
    if let Some(root) = fs_root {
        let confined_override = hosts_override.as_ref().and_then(|(key, trimmed)| {
            af_models::validate_path_within_isolated_root(Path::new(trimmed), root, key).ok()
        });
        if let Some(hosts_path) = confined_override {
            let lock_path = isolated_hosts_lock_path(&hosts_path);
            crate::hosts_dns::reconcile_hosts_file_at_path(
                &hosts_path,
                &lock_path,
                aether_local_domains,
                "127.0.0.1",
            )?;
        } else {
            let etc_dir = root.join("etc");
            if etc_dir.is_dir() {
                let hosts_path = etc_dir.join("hosts");
                let lock_path = isolated_hosts_lock_path(&hosts_path);
                crate::hosts_dns::reconcile_hosts_file_at_path(
                    &hosts_path,
                    &lock_path,
                    aether_local_domains,
                    "127.0.0.1",
                )?;
            }
        }
    } else if let Some((_, trimmed)) = hosts_override {
        let hosts_path = Path::new(&trimmed);
        let lock_path = crate::hosts_dns::resolve_hosts_lock_path(hosts_path);
        crate::hosts_dns::reconcile_hosts_file_at_path(
            hosts_path,
            &lock_path,
            aether_local_domains,
            "127.0.0.1",
        )?;
    } else {
        crate::hosts_dns::reconcile_hosts_file(aether_local_domains, "127.0.0.1")?;
    }

    let should_sync_providers =
        fs_root.is_some() || !cfg!(test) || has_explicit_dns_provider_override();
    if should_sync_providers {
        match detect_lifecycle_lan_ip() {
            Ok(Some(lan_ip)) => {
                crate::hosts_dns::sync_dns_provider_files_for_root(
                    &lan_ip,
                    authoritative_domains,
                    true,
                    fs_root,
                )?;
            }
            Ok(None) => {
                tracing::warn!(
                    "Skipping LAN DNS provider sync: unable to determine a non-loopback LAN IP"
                );
            }
            Err(err) => {
                anyhow::bail!("{err}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn reconcile_dns_for_state(conn: &Connection, fs_root: Option<&Path>) -> Result<()> {
    let snapshot = read_reconciled_dns_db_snapshot(conn)?;
    let (aether_local_domains, authoritative_domains) =
        finalize_reconciled_dns_domains(snapshot, fs_root);
    apply_reconciled_dns_domains(&aether_local_domains, &authoritative_domains, fs_root)
}

#[cfg(test)]
mod coordinator_parity_tests {
    use super::*;
    use uuid::Uuid;

    struct EnvVarGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvVarGuard {
        fn set(vars: &[(&'static str, &str)]) -> Self {
            let mut saved = Vec::with_capacity(vars.len());
            for &(key, val) in vars {
                saved.push((key, std::env::var_os(key)));
                std::env::set_var(key, val);
            }
            Self { saved }
        }

        fn clear(keys: &[&'static str]) -> Self {
            let mut saved = Vec::with_capacity(keys.len());
            for &key in keys {
                saved.push((key, std::env::var_os(key)));
                std::env::remove_var(key);
            }
            Self { saved }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            for (key, old) in self.saved.drain(..).rev() {
                if let Some(val) = old {
                    std::env::set_var(key, val);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn lifecycle_ingress_sync_atomically_bumps_epoch_and_invalidates_app_updates() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE app_ingress_configs (
                 app_name TEXT PRIMARY KEY,
                 public_domain TEXT,
                 external_access_enabled BOOLEAN,
                 listen_port INTEGER,
                 tls_enabled BOOLEAN,
                 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                 updated_at TEXT DEFAULT CURRENT_TIMESTAMP
             );
             CREATE TABLE package_lifecycle_jobs (
                 package_id TEXT PRIMARY KEY,
                 job_id TEXT,
                 action TEXT,
                 status TEXT,
                 service_units TEXT
             );
             CREATE TABLE app_updates (package_name TEXT PRIMARY KEY, installed_version TEXT);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_updates (package_name, installed_version) VALUES ('sonarr', '4.0.0'), ('radarr', '5.0.0')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_jobs VALUES ('sonarr', 'upd-1', 'update', 'updating', '[\"sonarr\"]')",
            [],
        )
        .unwrap();

        af_db::synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn, "sonarr", "update", "upd-1", 8989, None, false, "",
        )
        .unwrap();
        let e1: String = conn
            .query_row(
                "SELECT value FROM system_config WHERE key = 'package_lifecycle_epoch'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(e1, "1");
        let remaining: Vec<String> = conn
            .prepare("SELECT package_name FROM app_updates ORDER BY package_name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining, vec!["radarr"]);

        conn.execute(
            "UPDATE package_lifecycle_jobs SET job_id='rm-2', action='remove', status='uninstalling' WHERE package_id='sonarr'",
            [],
        )
        .unwrap();
        af_db::synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn, "sonarr", "remove", "rm-2", 0, None, false, "",
        )
        .unwrap();
        let e2: String = conn
            .query_row(
                "SELECT value FROM system_config WHERE key = 'package_lifecycle_epoch'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(e2, "2");
    }

    #[test]
    fn isolated_hosts_lock_path_aligns_hosts_and_avoids_lock_extension_collisions() {
        let default_hosts = Path::new("/tmp/root/etc/hosts");
        assert_eq!(
            isolated_hosts_lock_path(default_hosts),
            Path::new("/tmp/root/etc/.hosts.lock")
        );
        let dot_lock_hosts = Path::new("/tmp/root/etc/custom.lock");
        assert_ne!(isolated_hosts_lock_path(dot_lock_hosts), dot_lock_hosts);
        assert_eq!(
            isolated_hosts_lock_path(dot_lock_hosts),
            Path::new("/tmp/root/etc/.custom.lock.lock")
        );
        let leading_dot_hosts = Path::new("/tmp/root/etc/.custom");
        assert_eq!(
            isolated_hosts_lock_path(leading_dot_hosts),
            Path::new("/tmp/root/etc/.custom.lock")
        );
    }

    #[tokio::test]
    async fn post_lifecycle_dns_reconciliation_serializes_snapshot_and_write() {
        let _lock = crate::ENV_TEST_MUTEX.lock().await;
        let root = std::env::temp_dir().join(format!("af-coord-dns-ser-{}", Uuid::new_v4()));
        let etc_dir = root.join("etc");
        let dnsmasq_dir = etc_dir.join("dnsmasq.d");
        std::fs::create_dir_all(&dnsmasq_dir).unwrap();
        std::fs::write(etc_dir.join("hosts"), "127.0.0.1 localhost\n").unwrap();

        let db_path = root.join("aetherflow.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE app_ingress_configs (
                 app_name TEXT PRIMARY KEY,
                 public_domain TEXT,
                 external_access_enabled INTEGER,
                 tls_enabled INTEGER,
                 listen_port INTEGER,
                 updated_at TEXT
             );
             INSERT INTO app_ingress_configs VALUES ('sonarr', '', 0, 0, 8989, '2026-11-27');",
        )
        .unwrap();

        let _env = EnvVarGuard::set(&[("AETHERFLOW_LAN_IP", "10.40.50.60")]);

        // Hold the runner-wide DNS reconciliation mutex to simulate an in-flight older op
        // while a second lifecycle op commits 'radarr' and queues its reconciliation.
        let held_guard = POST_LIFECYCLE_DNS_RECONCILE_LOCK.lock().await;
        let queued = tokio::spawn(reconcile_dns_for_db_path_serialized(
            db_path.clone(),
            Some(root.clone()),
        ));

        // Commit newer DB state before the queued task can enter the critical section.
        conn.execute(
            "INSERT INTO app_ingress_configs VALUES ('radarr', '', 0, 0, 7878, '2026-11-27')",
            [],
        )
        .unwrap();
        drop(held_guard);

        queued.await.unwrap().unwrap();
        let hosts_after = std::fs::read_to_string(etc_dir.join("hosts")).unwrap();
        assert!(hosts_after.contains("sonarr.aether.local"));
        assert!(hosts_after.contains("radarr.aether.local"));
        let dnsmasq_after =
            std::fs::read_to_string(dnsmasq_dir.join("05-aetherflow-dns.conf")).unwrap();
        assert!(dnsmasq_after.contains("address=/sonarr.aether.local/10.40.50.60"));
        assert!(dnsmasq_after.contains("address=/radarr.aether.local/10.40.50.60"));

        drop(conn);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn post_lifecycle_dns_reconciliation_syncs_install_and_cleans_remove_in_isolated_root() {
        let _lock = crate::ENV_TEST_MUTEX.blocking_lock();
        let root = std::env::temp_dir().join(format!("af-coord-dns-{}", Uuid::new_v4()));
        let etc_dir = root.join("etc");
        let dnsmasq_dir = etc_dir.join("dnsmasq.d");
        let pihole_dir = etc_dir.join("pihole");
        let adguard_dir = root.join("opt/AdGuardHome");
        let install_dir = root.join("install");
        std::fs::create_dir_all(&dnsmasq_dir).unwrap();
        std::fs::create_dir_all(&pihole_dir).unwrap();
        std::fs::create_dir_all(&adguard_dir).unwrap();
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(etc_dir.join("hosts"), "127.0.0.1 localhost\n").unwrap();
        std::fs::write(pihole_dir.join("custom.list"), "").unwrap();
        std::fs::write(
            adguard_dir.join("AdGuardHome.yaml"),
            "filtering:\n  rewrites: []\n",
        )
        .unwrap();
        std::fs::write(install_dir.join(".sonarr.lock"), "installed\n").unwrap();

        let root_str = root.to_string_lossy().into_owned();
        let _env = EnvVarGuard::set(&[
            ("AETHERFLOW_FS_ROOT", &root_str),
            ("AETHERFLOW_LAN_IP", "10.20.30.40"),
        ]);

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT);
             INSERT INTO settings VALUES (1, 'example.com');
             CREATE TABLE app_ingress_configs (
                 app_name TEXT PRIMARY KEY,
                 public_domain TEXT,
                 external_access_enabled INTEGER,
                 tls_enabled INTEGER,
                 listen_port INTEGER,
                 updated_at TEXT
             );
             INSERT INTO app_ingress_configs VALUES ('sonarr', '', 0, 0, 8989, '2026-11-26');
             CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);",
        )
        .unwrap();

        reconcile_dns_for_state(&conn, Some(&root)).unwrap();
        let hosts_after_install = std::fs::read_to_string(etc_dir.join("hosts")).unwrap();
        assert!(hosts_after_install.contains("aetherflow.aether.local"));
        assert!(hosts_after_install.contains("sonarr.aether.local"));
        let dnsmasq_after_install =
            std::fs::read_to_string(dnsmasq_dir.join("05-aetherflow-dns.conf")).unwrap();
        assert!(dnsmasq_after_install.contains("address=/sonarr.aether.local/10.20.30.40"));
        assert!(dnsmasq_after_install.contains("address=/sonarr.example.com/10.20.30.40"));
        let pihole_after_install = std::fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(pihole_after_install.contains("10.20.30.40 sonarr.example.com"));
        let adguard_after_install =
            std::fs::read_to_string(adguard_dir.join("AdGuardHome.yaml")).unwrap();
        assert!(adguard_after_install.contains("sonarr.aether.local"));
        assert!(adguard_after_install.contains("10.20.30.40"));

        // Simulate remove completion: drop ingress row + lockfile and reconcile DNS again
        conn.execute(
            "DELETE FROM app_ingress_configs WHERE app_name = 'sonarr'",
            [],
        )
        .unwrap();
        std::fs::remove_file(install_dir.join(".sonarr.lock")).unwrap();
        reconcile_dns_for_state(&conn, Some(&root)).unwrap();

        let hosts_after_remove = std::fs::read_to_string(etc_dir.join("hosts")).unwrap();
        assert!(hosts_after_remove.contains("aetherflow.aether.local"));
        assert!(!hosts_after_remove.contains("sonarr.aether.local"));
        let dnsmasq_after_remove =
            std::fs::read_to_string(dnsmasq_dir.join("05-aetherflow-dns.conf")).unwrap();
        assert!(!dnsmasq_after_remove.contains("sonarr."));
        assert!(dnsmasq_after_remove.contains("aetherflow.aether.local"));
        let pihole_after_remove = std::fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(!pihole_after_remove.contains("sonarr."));
        let adguard_after_remove =
            std::fs::read_to_string(adguard_dir.join("AdGuardHome.yaml")).unwrap();
        assert!(!adguard_after_remove.contains("sonarr.aether.local"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn isolated_root_dns_stays_confined_with_af_hosts_file_and_outside_provider_env() {
        let _lock = crate::ENV_TEST_MUTEX.blocking_lock();
        let root = std::env::temp_dir().join(format!("af-coord-iso-{}", Uuid::new_v4()));
        let outside = std::env::temp_dir().join(format!("af-coord-out-{}", Uuid::new_v4()));
        let etc_dir = root.join("etc");
        let dnsmasq_dir = etc_dir.join("dnsmasq.d");
        let outside_dnsmasq = outside.join("dnsmasq.d");
        let outside_hosts = outside.join("hosts");
        let confined_default_hosts = etc_dir.join("hosts");
        let inside_custom_hosts = etc_dir.join("custom.hosts");
        let inside_fallback_hosts = etc_dir.join("fallback.hosts");
        std::fs::create_dir_all(&dnsmasq_dir).unwrap();
        std::fs::create_dir_all(&outside_dnsmasq).unwrap();
        std::fs::write(&outside_hosts, "UNTOUCHED_HOSTS\n").unwrap();
        std::fs::write(&confined_default_hosts, "127.0.0.1 localhost\n").unwrap();
        std::fs::write(&inside_custom_hosts, "127.0.0.1 localhost\n").unwrap();
        std::fs::write(&inside_fallback_hosts, "127.0.0.1 localhost\n").unwrap();
        std::fs::write(
            outside_dnsmasq.join("05-aetherflow-dns.conf"),
            "UNTOUCHED\n",
        )
        .unwrap();

        let outside_hosts_str = outside_hosts.to_string_lossy().into_owned();
        let outside_dnsmasq_str = outside_dnsmasq.to_string_lossy().into_owned();
        let inside_custom_hosts_str = inside_custom_hosts.to_string_lossy().into_owned();
        let inside_fallback_hosts_str = inside_fallback_hosts.to_string_lossy().into_owned();
        let _clear = EnvVarGuard::clear(&[
            "AETHERFLOW_FS_ROOT",
            "AETHERFLOW_CONFIG_ROOT",
            "AETHERFLOW_PIHOLE_DIR",
            "AETHERFLOW_HOSTS_FILE",
        ]);

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE app_ingress_configs (
                 app_name TEXT PRIMARY KEY,
                 public_domain TEXT,
                 external_access_enabled INTEGER,
                 tls_enabled INTEGER,
                 listen_port INTEGER,
                 updated_at TEXT
             );
             INSERT INTO app_ingress_configs VALUES ('radarr', '', 0, 0, 7878, '2026-11-26');",
        )
        .unwrap();

        // 1. Outside AF_HOSTS_FILE and outside AETHERFLOW_DNSMASQ_DIR must stay untouched;
        //    reconciliation falls back strictly inside `root/etc/hosts` and `root/etc/dnsmasq.d`.
        {
            let _env = EnvVarGuard::set(&[
                ("AF_HOSTS_FILE", &outside_hosts_str),
                ("AETHERFLOW_DNSMASQ_DIR", &outside_dnsmasq_str),
                ("AETHERFLOW_LAN_IP", "10.30.40.50"),
            ]);
            reconcile_dns_for_state(&conn, Some(&root)).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&outside_hosts).unwrap(),
            "UNTOUCHED_HOSTS\n",
            "outside AF_HOSTS_FILE must stay untouched when isolated fs_root is active"
        );
        assert!(
            std::fs::read_to_string(&confined_default_hosts)
                .unwrap()
                .contains("radarr.aether.local"),
            "fallback inside isolated root/etc/hosts must be reconciled"
        );
        assert_eq!(
            std::fs::read_to_string(outside_dnsmasq.join("05-aetherflow-dns.conf")).unwrap(),
            "UNTOUCHED\n"
        );
        let confined_dnsmasq =
            std::fs::read_to_string(dnsmasq_dir.join("05-aetherflow-dns.conf")).unwrap();
        assert!(confined_dnsmasq.contains("address=/radarr.aether.local/10.30.40.50"));

        // 2. Inside AF_HOSTS_FILE under isolated root IS honored.
        {
            let _env = EnvVarGuard::set(&[
                ("AF_HOSTS_FILE", &inside_custom_hosts_str),
                ("AETHERFLOW_LAN_IP", "10.30.40.50"),
            ]);
            reconcile_dns_for_state(&conn, Some(&root)).unwrap();
        }
        assert!(
            std::fs::read_to_string(&inside_custom_hosts)
                .unwrap()
                .contains("radarr.aether.local"),
            "confined AF_HOSTS_FILE inside isolated root must be honored"
        );

        // 3. Empty AF_HOSTS_FILE="" must NOT shadow a confined AETHERFLOW_HOSTS_FILE.
        {
            let _env = EnvVarGuard::set(&[
                ("AF_HOSTS_FILE", "   "),
                ("AETHERFLOW_HOSTS_FILE", &inside_fallback_hosts_str),
                ("AETHERFLOW_LAN_IP", "10.30.40.50"),
            ]);
            reconcile_dns_for_state(&conn, Some(&root)).unwrap();
        }
        assert!(
            std::fs::read_to_string(&inside_fallback_hosts)
                .unwrap()
                .contains("radarr.aether.local"),
            "empty AF_HOSTS_FILE must fall through to confined AETHERFLOW_HOSTS_FILE"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn detect_lifecycle_lan_ip_fails_closed_on_invalid_or_empty_env() {
        let _lock = crate::ENV_TEST_MUTEX.blocking_lock();
        let root = std::env::temp_dir().join(format!("af-coord-badip-{}", Uuid::new_v4()));
        let dnsmasq_dir = root.join("etc/dnsmasq.d");
        std::fs::create_dir_all(&dnsmasq_dir).unwrap();
        let conf_path = dnsmasq_dir.join("05-aetherflow-dns.conf");
        std::fs::write(
            &conf_path,
            "# keep existing\naddress=/keep.aether.local/10.0.0.9\n",
        )
        .unwrap();

        let conn = Connection::open_in_memory().unwrap();
        for bad in [
            "",
            "   ",
            " 10.20.30.40 ",
            "not-an-ip",
            "10.0.0.1\n127.0.0.1",
        ] {
            let _env = EnvVarGuard::set(&[("AETHERFLOW_LAN_IP", bad)]);
            assert!(
                detect_lifecycle_lan_ip().is_err(),
                "expected invalid AETHERFLOW_LAN_IP={bad:?} to fail closed"
            );
            assert!(
                reconcile_dns_for_state(&conn, Some(&root)).is_err(),
                "expected reconcile_dns_for_state to fail closed for AETHERFLOW_LAN_IP={bad:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&conf_path).unwrap(),
                "# keep existing\naddress=/keep.aether.local/10.0.0.9\n",
                "existing DNS provider file must remain untouched on invalid AETHERFLOW_LAN_IP"
            );
        }

        let _ok_env = EnvVarGuard::set(&[("AETHERFLOW_LAN_IP", "192.168.1.55")]);
        assert_eq!(
            detect_lifecycle_lan_ip().unwrap(),
            Some("192.168.1.55".to_string())
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
