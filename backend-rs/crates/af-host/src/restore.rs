//! Non-destructive restore planning, preflight inspection, and archive verification for `af-host`.
//!
//! # Security & Non-Destructive Invariants
//! 1. **Non-Destructive Planning & Preflight Only:** `plan_restore`, `preflight_restore_directory`,
//!    and `preflight_tar_gz_archive` never overwrite, delete, or mutate live host files.
//! 2. **Explicitly Unsupported Destructive Execution:** `execute_destructive_restore` always fails
//!    closed with [`HostBackupError::DestructiveRestoreUnsupported`] rather than performing an
//!    unsafe or uncoordinated live overwrite while `aetherflow-api` or systemd services hold open
//!    SQLite/configuration descriptors.
//! 3. **Path Traversal Rejection:** Any manifest or archive entry containing `..`, `.`, leading
//!    `/`, `\`, drive prefixes, or NUL bytes is rejected immediately.
//! 4. **Symlink & Link Rejection:** Symbolic links (`EntryType::Symlink`), hard links (`EntryType::Link`),
//!    FIFOs, character/block devices, and existing destination symlinks along any ancestor chain
//!    under `target_root` (including ancestors of `target_root` itself) are rejected.
//! 5. **Unsafe Overwrite Rejection:** Direct system roots (`/`, `/etc`, `/var`, `/usr`, `C:\`, etc.),
//!    relative roots, or paths with fewer than two normal components are unconditionally rejected as
//!    `target_root`. Under `OverwritePolicy::RejectExisting` (the default), any existing file or
//!    directory collision under `target_root` is rejected unless the caller explicitly opts into
//!    `OverwritePolicy::AllowRegularFilesInStaging` on a non-production staging root.

use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::{BackupManifest, BackupTargetKind, CompatibilityReport, SqliteSnapshotMetadata};
use crate::snapshot::{
    verify_sqlite_snapshot_integrity, verify_sqlite_snapshot_integrity_with_trusted_uid,
};
use crate::verify::{
    atomic_install_file_at_destination, atomic_install_file_at_destination_with_verification,
    checksum_sidecar_path, compute_file_sha256, ensure_private_dir_all, verify_file_with_sidecar, open_existing_regular_file_nofollow, open_or_create_dir_nofollow,
    open_or_create_provenance_dir_nofollow, parse_sha256_sidecar_str,
    read_verified_text_file_nofollow, reject_if_symlink, reject_symlink_chain,
    safe_backup_file_path, sync_parent_directory, unlink_file_at_destination,
    unlink_file_at_destination_with_trusted_ancestor_uid, validate_backup_filename,
    validate_no_parent_traversal, validate_relative_backup_path, verify_file_sha256,
    verify_file_sha256_with_trusted_uid, verify_file_with_sidecar_and_trusted_uid,
    write_private_file_atomic, write_private_file_atomic_tracking_rename, write_sha256_sidecar,
};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tar::{Archive, EntryType};

/// Policy governing how restore planning handles existing files under `target_root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverwritePolicy {
    /// Fail closed with [`HostBackupError::UnsafeOverwriteRejected`] if any planned destination
    /// file already exists on disk.
    #[default]
    RejectExisting,
    /// Allow overwriting existing regular files only when planning against an isolated staging root
    /// (still rejects overwriting directories, symlinks, or special files).
    AllowRegularFilesInStaging,
}

/// Planned action for an individual verified backup entry during non-destructive restore preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedRestoreAction {
    /// Target file does not exist and would be created under `target_root`.
    CreateNew,
    /// Target regular file exists and `OverwritePolicy::AllowRegularFilesInStaging` permitted replacement.
    ReplaceExistingRegularFile,
}

/// Single validated item inside a [`RestorePlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePlanItem {
    pub relative_path: String,
    pub destination_path: PathBuf,
    pub kind: BackupTargetKind,
    pub sha256: String,
    pub size_bytes: u64,
    pub action: PlannedRestoreAction,
}

/// Non-destructive restore plan and preflight verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePlan {
    pub backup_id: String,
    pub target_root: PathBuf,
    pub overwrite_policy: OverwritePolicy,
    pub compatibility: CompatibilityReport,
    pub items: Vec<RestorePlanItem>,
    pub total_bytes: u64,
    /// `true` only when a standalone SQLite snapshot file on disk has passed `PRAGMA quick_check`
    /// (`preflight_restore_directory`). Streaming `.tar.gz` archive preflight (`preflight_tar_gz_archive`)
    /// verifies the snapshot member's SHA-256 and byte length without extracting to disk, so this
    /// field remains `false` for `.tar.gz` preflight.
    pub sqlite_integrity_verified: bool,
    pub non_destructive_only: bool,
}

/// Options for computing and validating a [`RestorePlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePreflightOptions {
    /// Current host AetherFlow version (e.g., `"v4.0.0"`).
    pub host_app_version: String,
    /// Optional maximum SQLite `PRAGMA user_version` supported by the host binary.
    pub max_supported_sqlite_user_version: Option<i64>,
    /// Overwrite behavior when a planned destination file already exists.
    pub overwrite_policy: OverwritePolicy,
    /// Whether to require `.sha256` sidecars on the primary archive/snapshot before planning.
    pub require_artifact_sidecar: bool,
}

impl Default for RestorePreflightOptions {
    fn default() -> Self {
        Self {
            host_app_version: "4.0.0".to_string(),
            max_supported_sqlite_user_version: None,
            overwrite_policy: OverwritePolicy::RejectExisting,
            require_artifact_sidecar: true,
        }
    }
}

/// Trusted caller-supplied recovery context used by [`recover_interrupted_restore_with_context`]
/// so privileged recovery never trusts service-writable journal assertions as configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecoveryContext {
    /// Expected restore `target_root` (`PathBuf::from("/")` on production hosts or an isolated staging root).
    pub expected_target_root: Option<PathBuf>,
    /// Optional server-configured trusted SQLite database destination path.
    pub trusted_sqlite_db_path: Option<PathBuf>,
    /// Optional server-configured trusted SQLite owner UID override.
    pub trusted_sqlite_uid: Option<u32>,
    /// Optional server-configured trusted SQLite owner GID override.
    pub trusted_sqlite_gid: Option<u32>,
    /// Optional explicit protected provenance directory override outside service-writable `backup_dir`.
    #[serde(default)]
    pub provenance_dir: Option<PathBuf>,
}

impl RecoveryContext {
    /// Builds a [`RecoveryContext`] for the canonical host root (`/`).
    pub fn for_canonical_host(trusted_sqlite_db_path: Option<PathBuf>) -> Self {
        Self {
            expected_target_root: Some(PathBuf::from("/")),
            trusted_sqlite_db_path,
            trusted_sqlite_uid: None,
            trusted_sqlite_gid: None,
            provenance_dir: None,
        }
    }

    /// Builds a [`RecoveryContext`] for an explicit `target_root` (either `/` or an isolated staging root).
    pub fn for_target_root(
        target_root: impl Into<PathBuf>,
        trusted_sqlite_db_path: Option<PathBuf>,
    ) -> Self {
        Self {
            expected_target_root: Some(target_root.into()),
            trusted_sqlite_db_path,
            trusted_sqlite_uid: None,
            trusted_sqlite_gid: None,
            provenance_dir: None,
        }
    }

    /// Builds a [`RecoveryContext`] from an optional isolated root and server-owned SQLite DB path.
    pub fn from_host_config(
        isolated_root: Option<&Path>,
        trusted_sqlite_db_path: Option<PathBuf>,
    ) -> Self {
        let target_root = isolated_root
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        Self::for_target_root(target_root, trusted_sqlite_db_path)
    }
}

/// Resolves the protected recovery provenance directory outside service-writable `backup_dir`.
pub fn resolve_recovery_provenance_dir(
    target_root: &Path,
    explicit_provenance_dir: Option<&Path>,
) -> PathBuf {
    if let Some(custom_dir) = explicit_provenance_dir {
        return custom_dir.to_path_buf();
    }
    if target_root == Path::new("/") {
        PathBuf::from("/etc/AetherFlow/.restore-provenance")
    } else {
        target_root.join(".restore-provenance")
    }
}

pub fn validate_destination_not_provenance(
    dest: &Path,
    target_root: &Path,
    explicit_provenance_dir: Option<&Path>,
) -> HostBackupResult<()> {
    for comp in dest.components() {
        if let Component::Normal(seg) = comp {
            let seg_lower = seg.to_string_lossy().to_ascii_lowercase();
            if seg_lower == ".restore-provenance"
                || seg_lower.starts_with(".rollback-restore.")
                || seg_lower.starts_with(".staging-restore.")
                || (seg_lower.starts_with(".rollback-restore.") && seg_lower.contains(".journal.json"))
            {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest.to_path_buf(),
                    reason:
                        "restore destination must not target protected .restore-provenance or recovery authority"
                            .to_string(),
                });
            }
        }
    }

    let resolved_prov = resolve_recovery_provenance_dir(target_root, explicit_provenance_dir);
    let canonical_prov = PathBuf::from("/etc/AetherFlow/.restore-provenance");
    let canonical_prov_lower = PathBuf::from("/etc/aetherflow/.restore-provenance");
    let target_etc_prov = target_root.join("etc/AetherFlow/.restore-provenance");
    let target_etc_prov_lower = target_root.join("etc/aetherflow/.restore-provenance");
    let root_prov = target_root.join(".restore-provenance");

    let forbidden_dirs = [
        resolved_prov.as_path(),
        canonical_prov.as_path(),
        canonical_prov_lower.as_path(),
        target_etc_prov.as_path(),
        target_etc_prov_lower.as_path(),
        root_prov.as_path(),
    ];

    let (wal_candidate, shm_candidate) = sqlite_sidecar_paths(dest);
    let candidate_paths = [dest, wal_candidate.as_path(), shm_candidate.as_path()];

    for prov_dir in forbidden_dirs {
        for candidate_path in candidate_paths {
            if candidate_path == prov_dir
                || candidate_path.starts_with(prov_dir)
                || prov_dir.starts_with(candidate_path)
            {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest.to_path_buf(),
                    reason: format!(
                        "restore destination '{}' overlaps protected recovery provenance directory '{}'",
                        dest.display(),
                        prov_dir.display()
                    ),
                });
            }
        }
    }

    for inspect_dir in dest.ancestors() {
        if inspect_dir.as_os_str().is_empty() || inspect_dir == Path::new("/") {
            break;
        }
        if let Ok(entries) = fs::read_dir(inspect_dir) {
            for entry_res in entries.flatten() {
                let entry_name = entry_res.file_name().to_string_lossy().to_ascii_lowercase();
                if entry_name.starts_with(".rollback-restore.")
                    && entry_name.contains(".journal.json")
                {
                    return Err(HostBackupError::UnsafeOverwriteRejected {
                        target: dest.to_path_buf(),
                        reason: format!(
                            "restore destination '{}' overlaps directory '{}' containing pending recovery provenance authority",
                            dest.display(),
                            inspect_dir.display()
                        ),
                    });
                }
            }
        }
        if inspect_dir == target_root {
            break;
        }
    }

    Ok(())
}

fn validate_safe_target_root(target_root: &Path) -> HostBackupResult<PathBuf> {
    validate_no_parent_traversal(target_root, "restore target_root")?;

    if !target_root.is_absolute() {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: target_root.to_path_buf(),
            reason: format!(
                "restore target_root '{}' must be an absolute path",
                target_root.display()
            ),
        });
    }

    let mut normalized = PathBuf::new();
    let mut normal_segments: Vec<String> = Vec::new();
    for comp in target_root.components() {
        match comp {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir | Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: target_root.to_string_lossy().into_owned(),
                    reason: "restore target_root must not contain '.' or '..' segments".to_string(),
                });
            }
            Component::Normal(seg) => {
                let seg_str = seg.to_string_lossy();
                if seg_str.is_empty() || seg_str == "." || seg_str == ".." {
                    return Err(HostBackupError::TraversalRejected {
                        path: target_root.to_string_lossy().into_owned(),
                        reason: "restore target_root must not contain '.' or '..' segments"
                            .to_string(),
                    });
                }
                normalized.push(seg);
                normal_segments.push(seg_str.into_owned());
            }
        }
    }

    if normal_segments.len() < 2 {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: target_root.to_path_buf(),
            reason: format!(
                "refusing to plan restore directly onto root or top-level system directory '{}' (at least two normal path components required)",
                target_root.display()
            ),
        });
    }

    let first_lower = normal_segments[0].to_ascii_lowercase();
    let second_lower = normal_segments[1].to_ascii_lowercase();
    let forbidden_top = matches!(
        first_lower.as_str(),
        "etc"
            | "proc"
            | "sys"
            | "dev"
            | "boot"
            | "bin"
            | "sbin"
            | "lib"
            | "lib64"
            | "usr"
            | "windows"
            | "system32"
    );
    let forbidden_var_or_run = (first_lower == "var"
        && matches!(
            second_lower.as_str(),
            "lib" | "www" | "log" | "mail" | "spool" | "backups"
        )
        && normal_segments.len() == 2)
        || (first_lower == "home" && normal_segments.len() == 2);

    if forbidden_top || forbidden_var_or_run {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: target_root.to_path_buf(),
            reason: format!(
                "refusing to plan restore onto protected system directory '{}'",
                target_root.display()
            ),
        });
    }

    reject_if_symlink(&normalized, "restore target_root")?;

    match fs::symlink_metadata(&normalized) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: normalized,
                    reason: "restore target_root is a symbolic link".to_string(),
                });
            }
            if !meta.is_dir() {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: normalized,
                    reason: "restore target_root exists and is not a directory".to_string(),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(HostBackupError::io(
                format!("inspecting target_root {}", normalized.display()),
                err,
            ));
        }
    }

    Ok(normalized)
}

/// Default mandatory writer services that must be quiesced before any live SQLite or host
/// configuration restore replacement if the caller passes an empty `quiesce_services` list.
pub const DEFAULT_MANDATORY_QUIESCE_SERVICES: &[&str] = &[
    "aetherflow-api.service",
];

fn is_control_worker_service_unit(unit: &str) -> bool {
    let lower = unit.trim().to_ascii_lowercase();
    lower == "aetherflow-runner.service" || lower == "aetherflow-runner"
}

fn is_safe_systemd_service_unit(unit: &str) -> bool {
    let trimmed = unit.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || !trimmed.ends_with(".service")
    {
        return false;
    }
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '-'))
}

pub fn validate_quiesce_service_entries(requested: &[String]) -> HostBackupResult<Vec<String>> {
    let mut validated: Vec<String> = Vec::new();
    for raw in requested {
        let trimmed = raw.trim();
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.is_empty()
            || matches!(
                lower.as_str(),
                "none" | "noop" | "skip" | "false" | "0" | "null" | "off" | "disabled"
            )
        {
            return Err(HostBackupError::InvalidConfig(format!(
                "unsafe quiesce_services bypass entry rejected: {:?}",
                raw
            )));
        }
        if is_control_worker_service_unit(trimmed) {
            return Err(HostBackupError::InvalidConfig(format!(
                "quiesce_services must not include the active control worker unit {:?} inside its own cgroup",
                raw
            )));
        }
        if !is_safe_systemd_service_unit(trimmed) {
            return Err(HostBackupError::InvalidConfig(format!(
                "invalid quiesce service unit name: {:?}",
                raw
            )));
        }
        if !validated.iter().any(|existing| existing == trimmed) {
            validated.push(trimmed.to_string());
        }
    }
    Ok(validated)
}

/// Resolves the effective ordered list of writer services to quiesce during [`execute_staged_restore`].
///
/// Always includes [`DEFAULT_MANDATORY_QUIESCE_SERVICES`] first and unions any additional
/// caller-requested writer `.service` units while excluding the active control worker (`aetherflow-runner.service`).
pub fn resolve_effective_quiesce_services(requested: &[String]) -> Vec<String> {
    let mut effective: Vec<String> = DEFAULT_MANDATORY_QUIESCE_SERVICES
        .iter()
        .map(|svc| (*svc).to_string())
        .collect();
    for raw in requested {
        let trimmed = raw.trim();
        if trimmed.is_empty() || is_control_worker_service_unit(trimmed) {
            continue;
        }
        if !effective.iter().any(|existing| existing == trimmed) {
            effective.push(trimmed.to_string());
        }
    }
    effective
}

/// Validates a server-configured trusted SQLite database destination path.
pub fn validate_trusted_sqlite_db_path(custom_db_path: &Path) -> HostBackupResult<PathBuf> {
    validate_no_parent_traversal(custom_db_path, "trusted_sqlite_db_path")?;
    if !custom_db_path.is_absolute() {
        return Err(HostBackupError::PathValidation {
            path: custom_db_path.to_path_buf(),
            reason: "trusted_sqlite_db_path must be an absolute path".to_string(),
        });
    }
    let mut normalized = PathBuf::new();
    let mut normal_segments: Vec<String> = Vec::new();
    for comp in custom_db_path.components() {
        match comp {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir | Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: custom_db_path.to_string_lossy().into_owned(),
                    reason: "trusted_sqlite_db_path must not contain '.' or '..' segments"
                        .to_string(),
                });
            }
            Component::Normal(seg) => {
                let seg_str = seg.to_string_lossy();
                if seg_str.is_empty() || seg_str == "." || seg_str == ".." {
                    return Err(HostBackupError::TraversalRejected {
                        path: custom_db_path.to_string_lossy().into_owned(),
                        reason: "trusted_sqlite_db_path must not contain '.' or '..' segments"
                            .to_string(),
                    });
                }
                normalized.push(seg);
                normal_segments.push(seg_str.into_owned());
            }
        }
    }
    if normal_segments.len() < 2 {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: custom_db_path.to_path_buf(),
            reason: "trusted_sqlite_db_path must contain at least two normal path components"
                .to_string(),
        });
    }
    let first_lower = normal_segments[0].to_ascii_lowercase();
    if matches!(
        first_lower.as_str(),
        "etc"
            | "proc"
            | "sys"
            | "dev"
            | "boot"
            | "bin"
            | "sbin"
            | "lib"
            | "lib64"
            | "usr"
            | "windows"
            | "system32"
    ) {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: custom_db_path.to_path_buf(),
            reason: format!(
                "trusted_sqlite_db_path '{}' targets a forbidden system directory",
                custom_db_path.display()
            ),
        });
    }
    reject_if_symlink(&normalized, "trusted_sqlite_db_path")?;
    validate_destination_not_provenance(&normalized, Path::new("/"), None)?;
    Ok(normalized)
}

/// Checks whether a normalized relative archive path (`etc/AetherFlow/...`, `var/lib/aetherflow/aetherflow.sqlite`, etc.)
/// is an explicitly allowlisted canonical AetherFlow host backup entry, and maps it to its trusted
/// destination root + relative path under `canonical_base` (which is `/` on production hosts or an
/// isolated test root), honoring an optional server-configured `trusted_sqlite_db_path` for the
/// SQLite database entry.
pub fn resolve_trusted_canonical_host_destination_with_sqlite_override(
    canonical_base: &Path,
    relative_path: &str,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<(PathBuf, PathBuf)> {
    let rel_buf = validate_relative_backup_path(relative_path)?;
    let key = rel_buf.to_string_lossy().replace('\\', "/");

    let allowed = key == "var/lib/aetherflow/aetherflow.sqlite"
        || key == "etc/aetherflow/aetherflow.env"
        || key == "var/www/html/dashboard/inc/config.php"
        || key == "home/owner/.rtorrent.rc"
        || key == "home/aetherflow/.rtorrent.rc"
        || key.starts_with("etc/AetherFlow/")
        || key.starts_with("var/www/html/dashboard/custom/");

    if !allowed {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: canonical_base.join(&rel_buf),
            reason: format!(
                "archive entry '{}' is not in the trusted canonical host destination allowlist",
                key
            ),
        });
    }

    if key == "var/lib/aetherflow/aetherflow.sqlite" {
        if let Some(custom_db) = trusted_sqlite_db_path {
            let validated_db = validate_trusted_sqlite_db_path(custom_db)?;
            let mapped_dest = if canonical_base == Path::new("/") || validated_db.starts_with(canonical_base) {
                validated_db
            } else {
                let stripped = validated_db
                    .strip_prefix(Path::new("/"))
                    .unwrap_or(&validated_db);
                canonical_base.join(stripped)
            };
            validate_destination_not_provenance(&mapped_dest, canonical_base, None)?;
            let anchor = mapped_dest
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| canonical_base.to_path_buf());
            reject_symlink_chain(&anchor, &mapped_dest)?;
            return Ok((anchor, mapped_dest));
        }
    }

    let mapped_rel = if key == "home/owner/.rtorrent.rc" {
        if let Ok(custom_home) = std::env::var("AETHERFLOW_OWNER_HOME") {
            let trimmed = custom_home.trim().trim_start_matches('/');
            if !trimmed.is_empty() && !trimmed.contains("..") {
                PathBuf::from(trimmed).join(".rtorrent.rc")
            } else {
                rel_buf
            }
        } else if canonical_base.join("home/aetherflow").exists()
            && !canonical_base.join("home/owner").exists()
        {
            PathBuf::from("home/aetherflow/.rtorrent.rc")
        } else {
            rel_buf
        }
    } else {
        rel_buf
    };

    let dest = canonical_base.join(&mapped_rel);
    validate_destination_not_provenance(&dest, canonical_base, None)?;
    let mut comps = mapped_rel.components();
    let first = comps.next().map(|comp| comp.as_os_str()).unwrap_or_default();
    let second = comps.next().map(|comp| comp.as_os_str()).unwrap_or_default();
    let anchor = canonical_base.join(first).join(second);
    reject_symlink_chain(&anchor, &dest)?;
    Ok((anchor, dest))
}

/// Checks whether a normalized relative archive path (`etc/AetherFlow/...`, `var/lib/aetherflow/aetherflow.sqlite`, etc.)
/// is an explicitly allowlisted canonical AetherFlow host backup entry, and maps it to its trusted
/// destination root + relative path under `canonical_base` (which is `/` on production hosts or an
/// isolated test root).
pub fn resolve_trusted_canonical_host_destination(
    canonical_base: &Path,
    relative_path: &str,
) -> HostBackupResult<(PathBuf, PathBuf)> {
    resolve_trusted_canonical_host_destination_with_sqlite_override(
        canonical_base,
        relative_path,
        None,
    )
}

fn validate_execution_target_root(target_root: &Path) -> HostBackupResult<(PathBuf, bool)> {
    validate_no_parent_traversal(target_root, "restore target_root")?;
    let raw = target_root.to_string_lossy();
    if raw == "/" {
        reject_if_symlink(Path::new("/"), "canonical host root")?;
        return Ok((PathBuf::from("/"), true));
    }
    let norm = validate_safe_target_root(target_root)?;
    Ok((norm, false))
}

fn resolve_effective_relative_destination<'a>(
    relative_path: &'a str,
    entry_kind: Option<BackupTargetKind>,
    sqlite_target_rel_path: Option<&'a str>,
) -> &'a str {
    if entry_kind == Some(BackupTargetKind::SqliteSnapshot) {
        if let Some(custom_rel) = sqlite_target_rel_path
            .map(|raw_rel| raw_rel.trim())
            .filter(|raw_rel| !raw_rel.is_empty())
        {
            custom_rel
        } else {
            "var/lib/aetherflow/aetherflow.sqlite"
        }
    } else {
        relative_path
    }
}

fn split_sqlite_override_path(
    sqlite_override: Option<&Path>,
) -> HostBackupResult<(Option<String>, Option<&Path>)> {
    match sqlite_override {
        None => Ok((None, None)),
        Some(path_val) if path_val.is_absolute() => Ok((None, Some(path_val))),
        Some(path_val) => {
            let rel_str = path_val.to_str().ok_or_else(|| HostBackupError::PathValidation {
                path: path_val.to_path_buf(),
                reason: "relative sqlite override path must be valid UTF-8".to_string(),
            })?;
            let _ = validate_relative_backup_path(rel_str)?;
            Ok((Some(rel_str.to_string()), None))
        }
    }
}

fn plan_single_destination_with_options(
    target_root: &Path,
    relative_path: &str,
    entry_kind: Option<BackupTargetKind>,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
    overwrite_policy: OverwritePolicy,
) -> HostBackupResult<(PathBuf, PlannedRestoreAction)> {
    let effective_rel =
        resolve_effective_relative_destination(relative_path, entry_kind, sqlite_target_rel_path);
    let rel_buf = validate_relative_backup_path(effective_rel)?;
    let is_sqlite_entry = entry_kind == Some(BackupTargetKind::SqliteSnapshot);
    let has_explicit_sqlite_rel = sqlite_target_rel_path
        .map(|raw_rel| !raw_rel.trim().is_empty())
        .unwrap_or(false);

    if !is_sqlite_entry {
        let normalized_rel = rel_buf.to_string_lossy().replace('\\', "/");
        if normalized_rel == "var/lib/aetherflow/aetherflow.sqlite"
            || normalized_rel == "var/lib/aetherflow/aetherflow.sqlite-wal"
            || normalized_rel == "var/lib/aetherflow/aetherflow.sqlite-shm"
        {
            return Err(HostBackupError::InvalidManifest(format!(
                "non-SQLite entry '{}' must not target canonical SQLite database or WAL/SHM paths",
                relative_path
            )));
        }
    }

    let dest = if let (true, Some(custom_db)) = (is_sqlite_entry, trusted_sqlite_db_path) {
        let validated_db = validate_trusted_sqlite_db_path(custom_db)?;
        let parent_anchor = validated_db
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| target_root.to_path_buf());
        reject_symlink_chain(&parent_anchor, &validated_db)?;
        validated_db
    } else if target_root == Path::new("/") {
        if is_sqlite_entry && has_explicit_sqlite_rel {
            let candidate_abs = Path::new("/").join(&rel_buf);
            let validated_db = validate_trusted_sqlite_db_path(&candidate_abs)?;
            let parent_anchor = validated_db
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| target_root.to_path_buf());
            reject_symlink_chain(&parent_anchor, &validated_db)?;
            validated_db
        } else {
            let (_anchor, mapped_dest) =
                resolve_trusted_canonical_host_destination_with_sqlite_override(
                    target_root,
                    effective_rel,
                    trusted_sqlite_db_path,
                )?;
            mapped_dest
        }
    } else {
        let dest_under_root = target_root.join(&rel_buf);
        reject_symlink_chain(target_root, &dest_under_root)?;
        dest_under_root
    };

    validate_destination_not_provenance(&dest, target_root, None)?;

    match fs::symlink_metadata(&dest) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: dest,
                    reason: "destination path is a symbolic link".to_string(),
                });
            }
            if meta.is_dir() {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest,
                    reason: "cannot overwrite an existing directory with a file entry".to_string(),
                });
            }
            if !meta.is_file() {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest,
                    reason: "cannot overwrite special non-regular file".to_string(),
                });
            }
            match overwrite_policy {
                OverwritePolicy::RejectExisting => Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest,
                    reason: "destination file already exists and OverwritePolicy::RejectExisting is active".to_string(),
                }),
                OverwritePolicy::AllowRegularFilesInStaging => {
                    Ok((dest, PlannedRestoreAction::ReplaceExistingRegularFile))
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok((dest, PlannedRestoreAction::CreateNew))
        }
        Err(err) => Err(HostBackupError::io(
            format!("inspecting destination {}", dest.display()),
            err,
        )),
    }
}

fn validate_unique_resolved_destinations<'a, I>(items: I) -> HostBackupResult<()>
where
    I: IntoIterator<Item = (&'a str, &'a Path, BackupTargetKind)>,
{
    let mut seen_destinations: HashMap<PathBuf, String> = HashMap::new();
    let mut reserved_sidecars: HashMap<PathBuf, String> = HashMap::new();
    let collected: Vec<(&'a str, &'a Path, BackupTargetKind)> = items.into_iter().collect();

    for (rel_label, dest_path, kind) in &collected {
        if let Some(prev_label) =
            seen_destinations.insert(dest_path.to_path_buf(), (*rel_label).to_string())
        {
            return Err(HostBackupError::InvalidManifest(format!(
                "duplicate resolved restore destination '{}' shared by '{}' and '{}'",
                dest_path.display(),
                prev_label,
                rel_label
            )));
        }
        if *kind == BackupTargetKind::SqliteSnapshot {
            let (wal_path, shm_path) = sqlite_sidecar_paths(dest_path);
            reserved_sidecars.insert(wal_path, (*rel_label).to_string());
            reserved_sidecars.insert(shm_path, (*rel_label).to_string());
        }
    }

    for (rel_label, dest_path, _) in &collected {
        if let Some(sqlite_owner) = reserved_sidecars.get(*dest_path) {
            return Err(HostBackupError::InvalidManifest(format!(
                "restore entry '{}' resolves to SQLite WAL/SHM sidecar path '{}' owned by '{}'",
                rel_label,
                dest_path.display(),
                sqlite_owner
            )));
        }
    }

    Ok(())
}

/// Computes a purely non-destructive [`RestorePlan`] from a validated [`BackupManifest`]
/// without touching any files under `target_root`.
pub fn plan_restore_from_manifest(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    plan_restore_from_manifest_with_sqlite_override(manifest, target_root, options, None)
}

/// Computes a purely non-destructive [`RestorePlan`] from a validated [`BackupManifest`]
/// with an optional server-configured trusted SQLite destination override (`trusted_sqlite_db_path`).
/// Accepts either a relative override (`sqlite_target_rel_path`) or an absolute `trusted_sqlite_db_path`.
pub fn plan_restore_from_manifest_with_sqlite_override(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (sqlite_rel, sqlite_abs) = split_sqlite_override_path(trusted_sqlite_db_path)?;
    plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_rel.as_deref(),
        sqlite_abs,
    )
}

pub fn plan_restore_from_manifest_with_sqlite_overrides(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
    )
}

pub fn plan_restore_from_manifest_for_execution(
    manifest: &BackupManifest,
    target_root: &Path,
    exec_options: &RestoreExecutionOptions,
) -> HostBackupResult<RestorePlan> {
    let overwrite_policy = if exec_options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };
    let preflight_opts = RestorePreflightOptions {
        host_app_version: exec_options.host_app_version.clone(),
        max_supported_sqlite_user_version: exec_options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let plan = plan_restore_from_manifest_internal(
        manifest,
        target_root,
        &preflight_opts,
        exec_options.sqlite_target_rel_path.as_deref(),
        exec_options.trusted_sqlite_db_path.as_deref(),
    )?;
    for item in &plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &plan.target_root,
            exec_options.provenance_dir.as_deref(),
        )?;
    }
    Ok(plan)
}

fn plan_restore_from_manifest_internal(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (normalized_root, _) = validate_execution_target_root(target_root)?;
    let compatibility = manifest.check_compatibility(
        &options.host_app_version,
        options.max_supported_sqlite_user_version,
    )?;

    let mut items = Vec::with_capacity(manifest.entries.len());
    let mut total_bytes = 0u64;

    for entry in &manifest.entries {
        let (dest, action) = plan_single_destination_with_options(
            &normalized_root,
            &entry.relative_path,
            Some(entry.kind),
            sqlite_target_rel_path,
            trusted_sqlite_db_path,
            options.overwrite_policy,
        )?;
        total_bytes = total_bytes.saturating_add(entry.size_bytes);
        items.push(RestorePlanItem {
            relative_path: entry.relative_path.clone(),
            destination_path: dest,
            kind: entry.kind,
            sha256: entry.sha256.clone(),
            size_bytes: entry.size_bytes,
            action,
        });
    }

    validate_unique_resolved_destinations(items.iter().map(|item| {
        (
            item.relative_path.as_str(),
            item.destination_path.as_path(),
            item.kind,
        )
    }))?;

    Ok(RestorePlan {
        backup_id: manifest.backup_id.clone(),
        target_root: normalized_root,
        overwrite_policy: options.overwrite_policy,
        compatibility,
        items,
        total_bytes,
        sqlite_integrity_verified: false,
        non_destructive_only: true,
    })
}

/// Runs a full non-destructive preflight over a backup staging directory containing a
/// [`BackupManifest`] and its referenced files on disk.
pub fn preflight_restore_directory(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    preflight_restore_directory_with_sqlite_override(
        backup_source_dir,
        manifest,
        target_root,
        options,
        None,
    )
}

/// Runs [`preflight_restore_directory`] with an optional server-configured trusted SQLite destination override.
pub fn preflight_restore_directory_with_sqlite_override(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (sqlite_rel, sqlite_abs) = split_sqlite_override_path(trusted_sqlite_db_path)?;
    preflight_restore_directory_with_sqlite_overrides(
        backup_source_dir,
        manifest,
        target_root,
        options,
        sqlite_rel.as_deref(),
        sqlite_abs,
    )
}

pub fn preflight_restore_directory_with_sqlite_overrides(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
        backup_source_dir,
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
        None,
    )
}

pub fn preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
    trusted_sqlite_uid: Option<u32>,
) -> HostBackupResult<RestorePlan> {
    validate_no_parent_traversal(backup_source_dir, "backup_source_dir")?;
    reject_if_symlink(backup_source_dir, "backup_source_dir")?;

    let mut plan = plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
    )?;

    for entry in &manifest.entries {
        let rel = validate_relative_backup_path(&entry.relative_path)?;
        let src_path = backup_source_dir.join(&rel);
        reject_symlink_chain(backup_source_dir, &src_path)?;

        let entry_trusted_uid = if entry.kind == BackupTargetKind::SqliteSnapshot {
            trusted_sqlite_uid
        } else {
            None
        };

        let opened = open_existing_regular_file_nofollow(
            &src_path,
            entry_trusted_uid,
            "preflight backup entry",
        )?;
        if opened.is_none() {
            if entry.required {
                return Err(HostBackupError::PathValidation {
                    path: src_path,
                    reason: format!(
                        "required backup entry '{}' is missing from backup directory",
                        entry.relative_path
                    ),
                });
            }
            continue;
        }
        drop(opened);

        let verification =
            verify_file_sha256_with_trusted_uid(&src_path, &entry.sha256, entry_trusted_uid)?;
        if verification.size_bytes != entry.size_bytes {
            return Err(HostBackupError::InvalidManifest(format!(
                "size mismatch for '{}': manifest declared {} bytes, actual {} bytes",
                entry.relative_path, entry.size_bytes, verification.size_bytes
            )));
        }
    }

    if let Some(ref snap) = manifest.sqlite_snapshot {
        let snap_rel = validate_relative_backup_path(&snap.snapshot_relative_path)?;
        let snap_path = backup_source_dir.join(&snap_rel);
        reject_symlink_chain(backup_source_dir, &snap_path)?;

        if options.require_artifact_sidecar {
            verify_file_with_sidecar_and_trusted_uid(&snap_path, trusted_sqlite_uid)?;
        }
        let verification =
            verify_file_sha256_with_trusted_uid(&snap_path, &snap.sha256, trusted_sqlite_uid)?;
        if verification.size_bytes != snap.size_bytes {
            return Err(HostBackupError::InvalidManifest(format!(
                "SQLite snapshot size mismatch for '{}': expected {}, got {}",
                snap.snapshot_relative_path, snap.size_bytes, verification.size_bytes
            )));
        }
        let (uv, _, _) =
            verify_sqlite_snapshot_integrity_with_trusted_uid(&snap_path, trusted_sqlite_uid)?;
        if uv != snap.sqlite_user_version {
            return Err(HostBackupError::InvalidManifest(format!(
                "SQLite snapshot user_version mismatch for '{}': manifest declared {}, actual {}",
                snap.snapshot_relative_path, snap.sqlite_user_version, uv
            )));
        }
        if let Some(max_uv) = options.max_supported_sqlite_user_version {
            if uv > max_uv {
                return Err(HostBackupError::IncompatibleVersion {
                    backup_version: format!("sqlite_user_version={}", uv),
                    host_version: format!("max_sqlite_user_version={}", max_uv),
                    reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                });
            }
        }
        plan.sqlite_integrity_verified = true;
    }

    Ok(plan)
}

pub fn preflight_restore_directory_for_execution(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    exec_options: &RestoreExecutionOptions,
) -> HostBackupResult<RestorePlan> {
    let overwrite_policy = if exec_options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };
    let preflight_opts = RestorePreflightOptions {
        host_app_version: exec_options.host_app_version.clone(),
        max_supported_sqlite_user_version: exec_options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let plan = preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
        backup_source_dir,
        manifest,
        target_root,
        &preflight_opts,
        exec_options.sqlite_target_rel_path.as_deref(),
        exec_options.trusted_sqlite_db_path.as_deref(),
        exec_options.trusted_sqlite_uid,
    )?;
    for item in &plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &plan.target_root,
            exec_options.provenance_dir.as_deref(),
        )?;
    }
    Ok(plan)
}

/// Inspects a `.tar.gz` backup archive completely in-memory (streaming without extracting to disk).
pub fn preflight_tar_gz_archive(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    preflight_tar_gz_archive_with_sqlite_override(
        archive_path,
        manifest,
        target_root,
        options,
        None,
    )
}

/// Runs [`preflight_tar_gz_archive`] with an optional server-configured trusted SQLite destination override.
pub fn preflight_tar_gz_archive_with_sqlite_override(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (sqlite_rel, sqlite_abs) = split_sqlite_override_path(trusted_sqlite_db_path)?;
    preflight_tar_gz_archive_with_sqlite_overrides(
        archive_path,
        manifest,
        target_root,
        options,
        sqlite_rel.as_deref(),
        sqlite_abs,
    )
}

pub fn preflight_tar_gz_archive_with_sqlite_overrides(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
        archive_path,
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
        None,
    )
}

pub fn preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
    trusted_uid: Option<u32>,
) -> HostBackupResult<RestorePlan> {
    validate_no_parent_traversal(archive_path, "archive_path")?;
    reject_if_symlink(archive_path, "backup tar.gz archive")?;

    if options.require_artifact_sidecar {
        verify_file_with_sidecar_and_trusted_uid(archive_path, trusted_uid)?;
    }

    let plan = plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
    )?;

    verify_tar_gz_against_manifest_with_options_and_uid(
        archive_path,
        manifest,
        Some((
            &plan.target_root,
            options.overwrite_policy,
            sqlite_target_rel_path,
            trusted_sqlite_db_path,
        )),
        trusted_uid,
    )?;

    Ok(plan)
}

pub fn preflight_tar_gz_archive_for_execution(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    exec_options: &RestoreExecutionOptions,
) -> HostBackupResult<RestorePlan> {
    let overwrite_policy = if exec_options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };
    let preflight_opts = RestorePreflightOptions {
        host_app_version: exec_options.host_app_version.clone(),
        max_supported_sqlite_user_version: exec_options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let plan = preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
        archive_path,
        manifest,
        target_root,
        &preflight_opts,
        exec_options.sqlite_target_rel_path.as_deref(),
        exec_options.trusted_sqlite_db_path.as_deref(),
        exec_options.trusted_sqlite_uid,
    )?;
    for item in &plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &plan.target_root,
            exec_options.provenance_dir.as_deref(),
        )?;
    }
    Ok(plan)
}

pub(crate) fn verify_tar_gz_against_manifest_with_trusted_uid(
    archive_path: &Path,
    manifest: &BackupManifest,
    trusted_uid: Option<u32>,
) -> HostBackupResult<()> {
    verify_tar_gz_against_manifest_with_options_and_uid(archive_path, manifest, None, trusted_uid)
}

#[allow(clippy::type_complexity)]
pub(crate) fn verify_tar_gz_against_manifest_with_options_and_uid(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root_check: Option<(&Path, OverwritePolicy, Option<&str>, Option<&Path>)>,
    trusted_uid: Option<u32>,
) -> HostBackupResult<()> {
    manifest.validate()?;
    validate_no_parent_traversal(archive_path, "archive_path")?;
    reject_if_symlink(archive_path, "backup tar.gz archive")?;

    let expected_by_path: HashMap<String, &crate::manifest::BackupManifestEntry> = manifest
        .entries
        .iter()
        .filter(|entry_item| entry_item.kind != BackupTargetKind::TarGzArchive)
        .map(|entry_item| (entry_item.relative_path.replace('\\', "/"), entry_item))
        .collect();

    let (file, _, _, _) =
        open_existing_regular_file_nofollow(archive_path, trusted_uid, "backup tar.gz archive")?
            .ok_or_else(|| HostBackupError::PathValidation {
                path: archive_path.to_path_buf(),
                reason: "backup tar.gz archive does not exist".to_string(),
            })?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut seen_entries = HashSet::new();
    let mut resolved_for_uniqueness: Vec<(String, PathBuf, BackupTargetKind)> = Vec::new();
    let entries_iter = archive.entries().map_err(|err| HostBackupError::Archive {
        archive: archive_path.to_path_buf(),
        reason: format!("failed to read tar header stream: {}", err),
    })?;

    for entry_result in entries_iter {
        let mut entry = entry_result.map_err(|err| HostBackupError::Archive {
            archive: archive_path.to_path_buf(),
            reason: format!("corrupt tar entry header: {}", err),
        })?;

        let entry_type = entry.header().entry_type();
        let raw_path_bytes = entry.path_bytes();
        let raw_path_str = String::from_utf8_lossy(&raw_path_bytes).into_owned();

        if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
            return Err(HostBackupError::SymlinkRejected {
                path: PathBuf::from(&raw_path_str),
                reason: format!(
                    "tar archive '{}' contains forbidden {:?} entry '{}'",
                    archive_path.display(),
                    entry_type,
                    raw_path_str
                ),
            });
        }

        let norm_rel = validate_relative_backup_path(&raw_path_str)?;
        let key = norm_rel.to_string_lossy().replace('\\', "/");

        if entry_type == EntryType::Directory {
            if let Some((target_root, _, _, _)) = target_root_check {
                if target_root != Path::new("/") {
                    let dir_dest = target_root.join(&norm_rel);
                    reject_symlink_chain(target_root, &dir_dest)?;
                }
            }
            continue;
        }

        if entry_type != EntryType::Regular && entry_type != EntryType::Continuous {
            return Err(HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!(
                    "tar archive contains unsupported special entry type {:?} at '{}'",
                    entry_type, key
                ),
            });
        }

        if !seen_entries.insert(key.clone()) {
            return Err(HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!("duplicate tar entry '{}' in archive", key),
            });
        }

        let expected_opt = expected_by_path.get(&key).copied();
        if let Some((target_root, overwrite_policy, sqlite_rel_opt, trusted_sqlite_db_path)) =
            target_root_check
        {
            let (resolved_dest, _) = plan_single_destination_with_options(
                target_root,
                &key,
                expected_opt.map(|item| item.kind),
                sqlite_rel_opt,
                trusted_sqlite_db_path,
                overwrite_policy,
            )?;
            if let Some(expected_entry) = expected_opt {
                resolved_for_uniqueness.push((key.clone(), resolved_dest, expected_entry.kind));
            }
        }

        let Some(expected) = expected_opt else {
            return Err(HostBackupError::InvalidManifest(format!(
                "tar archive contains undeclared file '{}' not present in BackupManifest",
                key
            )));
        };

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut read_bytes = 0u64;
        loop {
            let bytes_read = entry.read(&mut buf).map_err(|err| HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!("failed reading tar payload for '{}': {}", key, err),
            })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buf[..bytes_read]);
            read_bytes += bytes_read as u64;
        }

        let actual_sha = hex::encode(hasher.finalize());
        if !actual_sha.eq_ignore_ascii_case(&expected.sha256) {
            return Err(HostBackupError::ChecksumMismatch {
                artifact: format!("{}:{}", archive_path.display(), key),
                expected: expected.sha256.clone(),
                actual: actual_sha,
            });
        }
        if read_bytes != expected.size_bytes {
            return Err(HostBackupError::InvalidManifest(format!(
                "tar entry '{}' byte size mismatch: manifest expected {}, got {}",
                key, expected.size_bytes, read_bytes
            )));
        }
    }

    for (key, expected) in &expected_by_path {
        if expected.required && !seen_entries.contains(key) {
            return Err(HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!("required manifest entry '{}' is missing from tar archive", key),
            });
        }
    }

    if !resolved_for_uniqueness.is_empty() {
        validate_unique_resolved_destinations(resolved_for_uniqueness.iter().map(
            |(rel_key, dest_path, kind)| (rel_key.as_str(), dest_path.as_path(), *kind),
        ))?;
    }

    Ok(())
}

/// Explicitly unsupported unconfirmed/in-place destructive live-host restore entry point.
pub fn execute_destructive_restore(
    _plan: &RestorePlan,
) -> HostBackupResult<()> {
    Err(HostBackupError::DestructiveRestoreUnsupported {
        reason: "in-place destructive host/database overwrite is disabled by design; run preflight verification and perform state replacement only under an offline maintenance window".to_string(),
    })
}

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
                    if let Err(comp_err) = self.start_and_verify_services(std::slice::from_ref(prev)) {
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
                let stderr_msg = String::from_utf8_lossy(&start_out.stderr).trim().to_string();
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

fn stop_services_with_compensation<Q: ServiceQuiescenceController>(
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

fn stop_services_for_recovery<Q: ServiceQuiescenceController>(
    quiescence: &Q,
    units: &[String],
) -> HostBackupResult<()> {
    for unit in units {
        quiescence.stop_services(std::slice::from_ref(unit))?;
    }
    Ok(())
}

/// Options governing a verified, staged, rollback-protected restore execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreExecutionOptions {
    /// Current host AetherFlow version (e.g., `"v4.0.0"`).
    pub host_app_version: String,
    /// Optional maximum SQLite `PRAGMA user_version` supported by the host binary.
    pub max_supported_sqlite_user_version: Option<i64>,
    /// Explicit confirmation required before any target file replacement is allowed.
    /// When `false`, [`execute_staged_restore`] fails closed with [`HostBackupError::DestructiveRestoreUnsupported`].
    pub confirm_destructive_restore: bool,
    /// Whether existing regular files under `target_root` may be replaced (after staging rollback copies).
    pub allow_overwrite: bool,
    /// Ordered list of systemd service units to stop before replacement and restart/verify afterwards.
    /// When empty, [`DEFAULT_MANDATORY_QUIESCE_SERVICES`] is enforced automatically.
    pub quiesce_services: Vec<String>,
    /// File mode (`0o600` default) applied to restored SQLite databases, `.env` secrets, and credentials.
    pub secret_file_mode: u32,
    /// Fallback file mode (`0o640` default) applied to restored config files without an explicit manifest mode.
    pub regular_file_mode: u32,
    /// Optional relative destination path override for standalone `.sqlite` snapshot restores
    /// (e.g. `"aetherflow.sqlite"` when `target_root` is the SQLite database's parent directory).
    #[serde(default)]
    pub sqlite_target_rel_path: Option<String>,
    /// Optional server-configured trusted SQLite database destination path (e.g. `/opt/AetherFlow/backend/data/aetherflow.sqlite`).
    /// Never derived from untrusted archive or manifest fields.
    #[serde(default)]
    pub trusted_sqlite_db_path: Option<PathBuf>,
    /// Optional server-configured trusted SQLite owner UID override.
    #[serde(default)]
    pub trusted_sqlite_uid: Option<u32>,
    /// Optional server-configured trusted SQLite owner GID override.
    #[serde(default)]
    pub trusted_sqlite_gid: Option<u32>,
    /// Optional explicit protected provenance directory override outside `backup_dir`.
    #[serde(default)]
    pub provenance_dir: Option<PathBuf>,
    /// Deterministic fault-injection hook: if set to `Some(limit)`, fails after `limit` file replacements
    /// so tests can verify automatic mid-restore rollback and service recovery.
    pub fail_after_replacements: Option<usize>,
    /// Deterministic rollback fault-injection hook: if set to `Some(limit)`, fails during rollback after `limit`
    /// file rollback steps so tests can verify that pre-restore recovery copies, WAL/SHM sidecars,
    /// and the durable `rollback-failure-journal.json` survive a failed rollback and services remain stopped.
    #[serde(default)]
    pub fail_rollback_after_restores: Option<usize>,
    /// Deterministic fault-injection hook: fail the local recovery journal write when publishing `committed`
    /// after the authoritative provenance journal has already been durably committed.
    #[serde(default)]
    pub fail_local_journal_on_commit: bool,
    /// Deterministic fault-injection hook: fail the authoritative provenance journal write when publishing `committed`.
    #[serde(default)]
    pub fail_provenance_on_commit: bool,
    /// Deterministic fault-injection hook: fail the parent directory sync immediately after renaming
    /// the authoritative provenance journal into place when publishing `committed`.
    #[serde(default)]
    pub fail_provenance_parent_sync_on_commit: bool,
    /// Deterministic fault-injection hook: fail the initial local journal write during `QUIESCING`
    /// after the initial provenance journal has been written.
    #[serde(default)]
    pub fail_initial_local_journal_write: bool,
    /// Deterministic fault-injection hook: fail removing the recovery directory during early pre-replacement cleanup.
    #[serde(default)]
    pub fail_early_cleanup_remove_rb_dir: bool,
    /// Deterministic fault-injection hook: fail removing the recovery directory during terminal cleanup.
    #[serde(default)]
    pub fail_cleanup_remove_rb_dir: bool,
}

impl Default for RestoreExecutionOptions {
    fn default() -> Self {
        Self {
            host_app_version: "4.0.0".to_string(),
            max_supported_sqlite_user_version: None,
            confirm_destructive_restore: false,
            allow_overwrite: false,
            quiesce_services: DEFAULT_MANDATORY_QUIESCE_SERVICES
                .iter()
                .map(|svc| (*svc).to_string())
                .collect(),
            secret_file_mode: 0o600,
            regular_file_mode: 0o640,
            sqlite_target_rel_path: None,
            trusted_sqlite_db_path: None,
            trusted_sqlite_uid: None,
            trusted_sqlite_gid: None,
            provenance_dir: None,
            fail_after_replacements: None,
            fail_rollback_after_restores: None,
            fail_local_journal_on_commit: false,
            fail_provenance_on_commit: false,
            fail_provenance_parent_sync_on_commit: false,
            fail_initial_local_journal_write: false,
            fail_early_cleanup_remove_rb_dir: false,
            fail_cleanup_remove_rb_dir: false,
        }
    }
}

/// Receipt returned by [`execute_staged_restore`] after a verified, atomic restore completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreExecutionReport {
    pub backup_id: String,
    pub primary_artifact: String,
    pub target_root: PathBuf,
    pub sqlite_restored: bool,
    pub sqlite_user_version: Option<i64>,
    pub sqlite_integrity_verified: bool,
    pub restored_files: Vec<PathBuf>,
    pub quiesced_services: Vec<String>,
    pub rolled_back: bool,
}

/// Durable journal entry written to `rollback-failure-journal.json` and `.restore-recovery-journal.json`
/// inside `.rollback-restore.<run_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackFailureJournalEntry {
    pub destination_path: PathBuf,
    #[serde(default)]
    pub kind: Option<BackupTargetKind>,
    pub existed_before: bool,
    pub rollback_copy_path: Option<PathBuf>,
    #[serde(default)]
    pub rollback_copy_sha256: Option<String>,
    pub had_wal_copy: Option<PathBuf>,
    #[serde(default)]
    pub wal_copy_sha256: Option<String>,
    pub had_shm_copy: Option<PathBuf>,
    #[serde(default)]
    pub shm_copy_sha256: Option<String>,
    #[serde(default)]
    pub original_mode: Option<u32>,
    #[serde(default)]
    pub original_uid: Option<u32>,
    #[serde(default)]
    pub original_gid: Option<u32>,
    #[serde(default)]
    pub wal_mode: Option<u32>,
    #[serde(default)]
    pub wal_uid: Option<u32>,
    #[serde(default)]
    pub wal_gid: Option<u32>,
    #[serde(default)]
    pub shm_mode: Option<u32>,
    #[serde(default)]
    pub shm_uid: Option<u32>,
    #[serde(default)]
    pub shm_gid: Option<u32>,
    pub restored_during_rollback: bool,
}

/// Durable failure journal persisted to `<recovery_dir>/rollback-failure-journal.json` when
/// automatic rollback cannot cleanly restore all files or restart services, AND written ahead
/// of replacement as `<recovery_dir>/.restore-recovery-journal.json` for crash-interruption recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackFailureJournal {
    pub backup_id: String,
    pub primary_artifact: String,
    pub target_root: PathBuf,
    pub recovery_dir: PathBuf,
    pub apply_failure_reason: String,
    pub rollback_errors: Vec<String>,
    pub file_rollback_incomplete: bool,
    pub services_left_stopped: bool,
    pub quiesced_services: Vec<String>,
    pub entries: Vec<RollbackFailureJournalEntry>,
    #[serde(default)]
    pub journal_state: String,
    #[serde(default)]
    pub trusted_sqlite_db_path: Option<PathBuf>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub journal_digest_sha256: Option<String>,
}

/// Canonical filename for the write-ahead interruption recovery journal inside `.rollback-restore.<run_id>`.
pub const IN_PROGRESS_RECOVERY_JOURNAL_FILENAME: &str = ".restore-recovery-journal.json";

const JOURNAL_STATE_QUIESCING: &str = "quiescing";
const JOURNAL_STATE_IN_PROGRESS: &str = "in_progress";
const JOURNAL_STATE_COMMITTED: &str = "committed";
const JOURNAL_STATE_ROLLED_BACK: &str = "rolled_back";
const JOURNAL_STATE_RECOVERED: &str = "recovered";
const JOURNAL_STATE_ABORTED_CLEAN: &str = "aborted_clean";
const JOURNAL_STATE_ROLLBACK_FAILED: &str = "rollback_failed";

fn is_terminal_journal_state(state: &str) -> bool {
    matches!(
        state,
        JOURNAL_STATE_COMMITTED
            | JOURNAL_STATE_ROLLED_BACK
            | JOURNAL_STATE_RECOVERED
            | JOURNAL_STATE_ABORTED_CLEAN
    )
}

#[derive(Debug)]
struct StagedRestoreEntry {
    relative_key: String,
    staged_path: PathBuf,
    _pinned_file: fs::File,
    staged_dev_ino: Option<(u64, u64)>,
    expected_sha256: String,
    expected_size: u64,
    destination_path: PathBuf,
    kind: BackupTargetKind,
    unix_mode: u32,
    unix_uid: Option<u32>,
    unix_gid: Option<u32>,
}

#[derive(Debug, Clone)]
struct RollbackRecord {
    destination_path: PathBuf,
    kind: BackupTargetKind,
    existed_before: bool,
    rollback_copy_path: Option<PathBuf>,
    _rollback_copy_file: Option<std::sync::Arc<fs::File>>,
    rollback_copy_dev_ino: Option<(u64, u64)>,
    rollback_copy_sha256: Option<String>,
    rollback_copy_size: Option<u64>,
    had_wal_copy: Option<PathBuf>,
    _wal_copy_file: Option<std::sync::Arc<fs::File>>,
    wal_copy_dev_ino: Option<(u64, u64)>,
    wal_copy_sha256: Option<String>,
    wal_copy_size: Option<u64>,
    had_shm_copy: Option<PathBuf>,
    _shm_copy_file: Option<std::sync::Arc<fs::File>>,
    shm_copy_dev_ino: Option<(u64, u64)>,
    shm_copy_sha256: Option<String>,
    shm_copy_size: Option<u64>,
    original_mode: Option<u32>,
    original_uid: Option<u32>,
    original_gid: Option<u32>,
    wal_mode: Option<u32>,
    wal_uid: Option<u32>,
    wal_gid: Option<u32>,
    shm_mode: Option<u32>,
    shm_uid: Option<u32>,
    shm_gid: Option<u32>,
}

fn is_secret_credential_entry(relative_path: &str, kind: BackupTargetKind) -> bool {
    if kind == BackupTargetKind::SqliteSnapshot {
        return false;
    }
    let lower = relative_path.to_ascii_lowercase();
    lower.ends_with(".env")
        || lower.ends_with(".key")
        || lower.ends_with(".pem")
        || lower.contains("secret")
        || lower.contains("token")
}

fn resolve_restored_entry_mode(
    raw_mode: Option<u32>,
    relative_path: &str,
    kind: BackupTargetKind,
    options: &RestoreExecutionOptions,
) -> u32 {
    let secret_cap = (options.secret_file_mode & 0o777).max(0o600) & 0o600;
    let regular_default = {
        let masked = options.regular_file_mode & 0o777;
        if masked == 0 {
            0o640
        } else {
            masked & 0o755
        }
    };

    if is_secret_credential_entry(relative_path, kind) {
        let candidate = raw_mode
            .map(|mode_val| mode_val & 0o777)
            .filter(|&mode_val| mode_val != 0)
            .unwrap_or(secret_cap);
        let capped = candidate & secret_cap;
        if capped == 0 {
            secret_cap
        } else {
            capped
        }
    } else if kind == BackupTargetKind::SqliteSnapshot {
        let sqlite_default = regular_default & 0o660;
        let candidate = raw_mode
            .map(|mode_val| mode_val & 0o777)
            .filter(|&mode_val| mode_val != 0)
            .unwrap_or(sqlite_default);
        let sanitized = candidate & 0o660;
        if sanitized == 0 {
            0o600
        } else {
            sanitized
        }
    } else {
        let candidate = raw_mode
            .map(|mode_val| mode_val & 0o777)
            .filter(|&mode_val| mode_val != 0)
            .unwrap_or(regular_default);
        let sanitized = candidate & 0o755;
        if sanitized == 0 {
            regular_default
        } else {
            sanitized
        }
    }
}

fn sanitize_sqlite_sidecar_mode(raw_mode: Option<u32>) -> u32 {
    let candidate = raw_mode
        .map(|mode_val| mode_val & 0o660)
        .filter(|&mode_val| mode_val != 0)
        .unwrap_or(0o600);
    if candidate == 0 {
        0o600
    } else {
        candidate
    }
}

fn sqlite_sidecar_paths(db_path: &Path) -> (PathBuf, PathBuf) {
    let mut wal_os = db_path.as_os_str().to_os_string();
    wal_os.push("-wal");
    let mut shm_os = db_path.as_os_str().to_os_string();
    shm_os.push("-shm");
    (PathBuf::from(wal_os), PathBuf::from(shm_os))
}

#[allow(clippy::type_complexity)]
fn write_exclusive_staged_file(
    path: &Path,
    reader: &mut dyn Read,
    mode: u32,
) -> HostBackupResult<(fs::File, Option<(u64, u64)>, String, u64)> {
    if let Some(parent) = path.parent() {
        open_or_create_dir_nofollow(parent, 0o700, "staging parent directory")?;
    }
    let mut open_opts = fs::OpenOptions::new();
    open_opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(mode & 0o777);
        open_opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut out = open_opts
        .open(path)
        .map_err(|err| HostBackupError::io(format!("creating staged file {}", path.display()), err))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = reader
            .read(&mut buf)
            .map_err(|err| HostBackupError::io(format!("reading stream for {}", path.display()), err))?;
        if count == 0 {
            break;
        }
        std::io::Write::write_all(&mut out, &buf[..count])
            .map_err(|err| HostBackupError::io(format!("writing staged file {}", path.display()), err))?;
        hasher.update(&buf[..count]);
        total += count as u64;
    }
    out.sync_all()
        .map_err(|err| HostBackupError::io(format!("fsyncing staged file {}", path.display()), err))?;
    std::io::Seek::seek(&mut out, std::io::SeekFrom::Start(0))
        .map_err(|err| HostBackupError::io(format!("rewinding staged file {}", path.display()), err))?;

    #[cfg(unix)]
    let staged_dev_ino = {
        use std::os::unix::io::AsRawFd;
        let mut fd_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(out.as_raw_fd(), &mut fd_stat) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat staged file {}", path.display()),
                std::io::Error::last_os_error(),
            ));
        }
        if (fd_stat.st_mode & libc::S_IFMT) != libc::S_IFREG || fd_stat.st_nlink != 1 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: "staged file descriptor is not a single-link regular file".to_string(),
            });
        }
        Some((fd_stat.st_dev as u64, fd_stat.st_ino as u64))
    };
    #[cfg(not(unix))]
    let staged_dev_ino: Option<(u64, u64)> = None;

    if let Some(parent) = path.parent() {
        sync_parent_directory(parent, "fsyncing staged file parent directory")?;
    }
    Ok((out, staged_dev_ino, hex::encode(hasher.finalize()), total))
}

fn compute_journal_canonical_digest(journal: &RollbackFailureJournal) -> HostBackupResult<String> {
    let mut normalized_journal = journal.clone();
    normalized_journal.journal_digest_sha256 = None;
    let canonical_bytes = serde_json::to_vec(&normalized_journal).map_err(|err| {
        HostBackupError::InvalidManifest(format!("serializing recovery journal digest payload: {}", err))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn provenance_journal_path_for_recovery_dir(
    provenance_dir: &Path,
    rb_dir: &Path,
) -> HostBackupResult<PathBuf> {
    let dir_name = rb_dir
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .filter(|name_str| name_str.starts_with(".rollback-restore."))
        .ok_or_else(|| {
            HostBackupError::InvalidManifest(format!(
                "recovery directory '{}' does not have a valid .rollback-restore.* name",
                rb_dir.display()
            ))
        })?;
    Ok(provenance_dir.join(format!("{}.journal.json", dir_name)))
}

fn provenance_prev_journal_path(prov_journal_path: &Path) -> PathBuf {
    let mut os_str = prov_journal_path.as_os_str().to_os_string();
    os_str.push(".prev");
    PathBuf::from(os_str)
}

fn preserve_previous_provenance_checkpoint(prov_journal_path: &Path) -> HostBackupResult<()> {
    let sidecar_path = checksum_sidecar_path(prov_journal_path);
    let Some(existing_json) = read_verified_text_file_nofollow(
        prov_journal_path,
        None,
        16 * 1024 * 1024,
        "existing provenance journal",
    )?
    else {
        return Ok(());
    };
    let Some(existing_sidecar) = read_verified_text_file_nofollow(
        &sidecar_path,
        None,
        16 * 1024,
        "existing provenance sidecar",
    )?
    else {
        return Ok(());
    };
    let Ok(expected_hex) = parse_sha256_sidecar_str(&existing_sidecar) else {
        return Ok(());
    };
    let actual_hex = hex::encode(Sha256::digest(existing_json.as_bytes()));
    if !actual_hex.eq_ignore_ascii_case(&expected_hex) {
        return Ok(());
    }
    let prev_path = provenance_prev_journal_path(prov_journal_path);
    write_private_file_atomic(
        &prev_path,
        existing_json.as_bytes(),
        "provenance-prev",
        "previous provenance checkpoint",
    )?;
    let _ = write_sha256_sidecar(&prev_path)?;
    Ok(())
}

fn write_journal_with_sidecar_and_provenance(
    journal_path: &Path,
    provenance_dir: &Path,
    rb_dir: &Path,
    journal: &mut RollbackFailureJournal,
    generation: &mut u64,
    label: &str,
    context: &str,
) -> HostBackupResult<()> {
    write_journal_with_sidecar_and_provenance_with_fault(
        journal_path,
        provenance_dir,
        rb_dir,
        journal,
        generation,
        label,
        context,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_journal_with_sidecar_and_provenance_with_fault(
    journal_path: &Path,
    provenance_dir: &Path,
    rb_dir: &Path,
    journal: &mut RollbackFailureJournal,
    generation: &mut u64,
    label: &str,
    context: &str,
    fail_local_write: bool,
) -> HostBackupResult<()> {
    *generation = generation.saturating_add(1);
    journal.generation = *generation;
    let digest = compute_journal_canonical_digest(journal)?;
    journal.journal_digest_sha256 = Some(digest);

    let bytes = serde_json::to_vec_pretty(journal).map_err(|err| {
        HostBackupError::InvalidManifest(format!("serializing {}: {}", context, err))
    })?;

    open_or_create_provenance_dir_nofollow(provenance_dir, "recovery provenance directory")?;
    let prov_journal_path = provenance_journal_path_for_recovery_dir(provenance_dir, rb_dir)?;
    let _ = preserve_previous_provenance_checkpoint(&prov_journal_path);
    write_private_file_atomic(&prov_journal_path, &bytes, "provenance-journal", context)?;
    let _ = write_sha256_sidecar(&prov_journal_path)?;

    if fail_local_write {
        return Err(HostBackupError::InvalidManifest(
            "simulated initial local recovery journal write failure after provenance write".to_string(),
        ));
    }

    write_private_file_atomic(journal_path, &bytes, label, context)?;
    let _ = write_sha256_sidecar(journal_path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_recovery_journal_snapshot(
    journal_path: &Path,
    provenance_dir: &Path,
    generation: &mut u64,
    backup_id: &str,
    primary_artifact: &str,
    target_root: &Path,
    rollback_dir: &Path,
    quiesced_services: &[String],
    records: &[RollbackRecord],
    state: &str,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<()> {
    persist_recovery_journal_snapshot_with_fault(
        journal_path,
        provenance_dir,
        generation,
        backup_id,
        primary_artifact,
        target_root,
        rollback_dir,
        quiesced_services,
        records,
        state,
        trusted_sqlite_db_path,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn persist_recovery_journal_snapshot_with_fault(
    journal_path: &Path,
    provenance_dir: &Path,
    generation: &mut u64,
    backup_id: &str,
    primary_artifact: &str,
    target_root: &Path,
    rollback_dir: &Path,
    quiesced_services: &[String],
    records: &[RollbackRecord],
    state: &str,
    trusted_sqlite_db_path: Option<&Path>,
    fail_local_write: bool,
) -> HostBackupResult<()> {
    let is_terminal = is_terminal_journal_state(state);
    let entries: Vec<RollbackFailureJournalEntry> = records
        .iter()
        .map(|rec| RollbackFailureJournalEntry {
            destination_path: rec.destination_path.clone(),
            kind: Some(rec.kind),
            existed_before: rec.existed_before,
            rollback_copy_path: rec.rollback_copy_path.clone(),
            rollback_copy_sha256: rec.rollback_copy_sha256.clone(),
            had_wal_copy: rec.had_wal_copy.clone(),
            wal_copy_sha256: rec.wal_copy_sha256.clone(),
            had_shm_copy: rec.had_shm_copy.clone(),
            shm_copy_sha256: rec.shm_copy_sha256.clone(),
            original_mode: rec.original_mode,
            original_uid: rec.original_uid,
            original_gid: rec.original_gid,
            wal_mode: rec.wal_mode,
            wal_uid: rec.wal_uid,
            wal_gid: rec.wal_gid,
            shm_mode: rec.shm_mode,
            shm_uid: rec.shm_uid,
            shm_gid: rec.shm_gid,
            restored_during_rollback: is_terminal,
        })
        .collect();

    let services_left_stopped = match state {
        JOURNAL_STATE_ABORTED_CLEAN => false,
        _ => !quiesced_services.is_empty(),
    };

    let mut journal = RollbackFailureJournal {
        backup_id: backup_id.to_string(),
        primary_artifact: primary_artifact.to_string(),
        target_root: target_root.to_path_buf(),
        recovery_dir: rollback_dir.to_path_buf(),
        apply_failure_reason: state.to_string(),
        rollback_errors: Vec::new(),
        file_rollback_incomplete: !is_terminal,
        services_left_stopped,
        quiesced_services: quiesced_services.to_vec(),
        entries,
        journal_state: state.to_string(),
        trusted_sqlite_db_path: trusted_sqlite_db_path.map(Path::to_path_buf),
        generation: 0,
        journal_digest_sha256: None,
    };

    write_journal_with_sidecar_and_provenance_with_fault(
        journal_path,
        provenance_dir,
        rollback_dir,
        &mut journal,
        generation,
        "recovery-journal",
        "durable restore recovery journal",
        fail_local_write,
    )
}

#[allow(clippy::too_many_arguments)]
fn persist_committed_journal_snapshot(
    journal_path: &Path,
    provenance_dir: &Path,
    generation: &mut u64,
    backup_id: &str,
    primary_artifact: &str,
    target_root: &Path,
    rollback_dir: &Path,
    quiesced_services: &[String],
    records: &[RollbackRecord],
    trusted_sqlite_db_path: Option<&Path>,
    fail_provenance_on_commit: bool,
    fail_provenance_parent_sync_on_commit: bool,
    fail_local_journal_on_commit: bool,
    committed_durably: &mut bool,
) -> HostBackupResult<()> {
    let entries: Vec<RollbackFailureJournalEntry> = records
        .iter()
        .map(|rec| RollbackFailureJournalEntry {
            destination_path: rec.destination_path.clone(),
            kind: Some(rec.kind),
            existed_before: rec.existed_before,
            rollback_copy_path: rec.rollback_copy_path.clone(),
            rollback_copy_sha256: rec.rollback_copy_sha256.clone(),
            had_wal_copy: rec.had_wal_copy.clone(),
            wal_copy_sha256: rec.wal_copy_sha256.clone(),
            had_shm_copy: rec.had_shm_copy.clone(),
            shm_copy_sha256: rec.shm_copy_sha256.clone(),
            original_mode: rec.original_mode,
            original_uid: rec.original_uid,
            original_gid: rec.original_gid,
            wal_mode: rec.wal_mode,
            wal_uid: rec.wal_uid,
            wal_gid: rec.wal_gid,
            shm_mode: rec.shm_mode,
            shm_uid: rec.shm_uid,
            shm_gid: rec.shm_gid,
            restored_during_rollback: true,
        })
        .collect();

    *generation = generation.saturating_add(1);
    let mut journal = RollbackFailureJournal {
        backup_id: backup_id.to_string(),
        primary_artifact: primary_artifact.to_string(),
        target_root: target_root.to_path_buf(),
        recovery_dir: rollback_dir.to_path_buf(),
        apply_failure_reason: JOURNAL_STATE_COMMITTED.to_string(),
        rollback_errors: Vec::new(),
        file_rollback_incomplete: false,
        services_left_stopped: !quiesced_services.is_empty(),
        quiesced_services: quiesced_services.to_vec(),
        entries,
        journal_state: JOURNAL_STATE_COMMITTED.to_string(),
        trusted_sqlite_db_path: trusted_sqlite_db_path.map(Path::to_path_buf),
        generation: *generation,
        journal_digest_sha256: None,
    };
    let digest = compute_journal_canonical_digest(&journal)?;
    journal.journal_digest_sha256 = Some(digest);

    let bytes = serde_json::to_vec_pretty(&journal).map_err(|err| {
        HostBackupError::InvalidManifest(format!("serializing committed recovery journal: {}", err))
    })?;

    open_or_create_provenance_dir_nofollow(provenance_dir, "recovery provenance directory")?;
    let prov_journal_path = provenance_journal_path_for_recovery_dir(provenance_dir, rollback_dir)?;
    let _ = preserve_previous_provenance_checkpoint(&prov_journal_path);

    if fail_provenance_on_commit {
        return Err(HostBackupError::InvalidManifest(
            "simulated provenance commit failure before authority publication".to_string(),
        ));
    }

    write_private_file_atomic_tracking_rename(
        &prov_journal_path,
        &bytes,
        "provenance-journal",
        "durable restore recovery journal",
        fail_provenance_parent_sync_on_commit,
        committed_durably,
    )?;
    let _ = write_sha256_sidecar(&prov_journal_path)?;

    if fail_local_journal_on_commit {
        return Err(HostBackupError::InvalidManifest(
            "simulated local journal commit failure after provenance commit".to_string(),
        ));
    }

    write_private_file_atomic(
        journal_path,
        &bytes,
        "recovery-journal",
        "durable restore recovery journal",
    )?;
    let _ = write_sha256_sidecar(journal_path)?;
    Ok(())
}

fn remove_recovery_dir_and_provenance(
    rb_dir: &Path,
    provenance_dir: &Path,
) -> HostBackupResult<()> {
    remove_recovery_dir_and_provenance_with_fault(rb_dir, provenance_dir, false)
}

fn remove_recovery_dir_and_provenance_with_fault(
    rb_dir: &Path,
    provenance_dir: &Path,
    fail_remove_rb_dir: bool,
) -> HostBackupResult<()> {
    let prov_journal = provenance_journal_path_for_recovery_dir(provenance_dir, rb_dir)?;
    if fail_remove_rb_dir {
        return Err(HostBackupError::io(
            format!("removing completed recovery directory {}", rb_dir.display()),
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "simulated recovery directory removal failure",
            ),
        ));
    }
    if rb_dir.exists() {
        fs::remove_dir_all(rb_dir).map_err(|err| {
            HostBackupError::io(
                format!("removing completed recovery directory {}", rb_dir.display()),
                err,
            )
        })?;
        if let Some(parent) = rb_dir.parent() {
            sync_parent_directory(
                parent,
                "fsyncing backup_dir after removing recovery directory",
            )?;
        }
    }

    let prov_sidecar = checksum_sidecar_path(&prov_journal);
    let prev_journal = provenance_prev_journal_path(&prov_journal);
    let prev_sidecar = checksum_sidecar_path(&prev_journal);

    unlink_file_at_destination(&prov_sidecar, "removing provenance journal sidecar")?;
    unlink_file_at_destination(&prev_sidecar, "removing previous provenance journal sidecar")?;
    unlink_file_at_destination(&prev_journal, "removing previous provenance journal")?;
    unlink_file_at_destination(&prov_journal, "removing provenance journal")?;

    if let Ok(mut iter) = fs::read_dir(provenance_dir) {
        if iter.next().is_none() {
            let _ = fs::remove_dir(provenance_dir);
        }
    }
    Ok(())
}

/// Executes a verified, offline-staged, service-quiesced, rollback-protected restore of a backup
/// artifact (`<filename>` inside `backup_dir`) into `target_root`.
pub fn execute_staged_restore<Q: ServiceQuiescenceController>(
    backup_dir: &Path,
    filename: &str,
    target_root: &Path,
    options: &RestoreExecutionOptions,
    quiescence: &Q,
) -> HostBackupResult<RestoreExecutionReport> {
    if !options.confirm_destructive_restore {
        return Err(HostBackupError::DestructiveRestoreUnsupported {
            reason: "destructive restore requires explicit confirmation (confirm_destructive_restore=true) after non-destructive preflight".to_string(),
        });
    }

    let (normalized_root, is_canonical_root) = validate_execution_target_root(target_root)?;
    if let Some(ref custom_db) = options.trusted_sqlite_db_path {
        let validated_custom_db = validate_trusted_sqlite_db_path(custom_db)?;
        validate_destination_not_provenance(
            &validated_custom_db,
            &normalized_root,
            options.provenance_dir.as_deref(),
        )?;
    }
    let validated_requested = validate_quiesce_service_entries(&options.quiesce_services)?;
    let effective_services = resolve_effective_quiesce_services(&validated_requested);

    let (verification, maybe_manifest) = crate::backup::verify_backup_artifact_with_trusted_uid(
        backup_dir,
        filename,
        options.trusted_sqlite_uid,
    )?;
    if !verification.verified {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: filename.to_string(),
            expected: verification.expected_sha256,
            actual: verification.actual_sha256,
        });
    }

    let manifest = maybe_manifest.ok_or_else(|| {
        HostBackupError::InvalidManifest(format!(
            "backup '{}' does not have a verified .manifest.json sidecar required for safe staged restore",
            filename
        ))
    })?;

    let _compat = manifest.check_compatibility(
        &options.host_app_version,
        options.max_supported_sqlite_user_version,
    )?;

    let overwrite_policy = if options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };

    let preflight_opts = RestorePreflightOptions {
        host_app_version: options.host_app_version.clone(),
        max_supported_sqlite_user_version: options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let validated_plan = plan_restore_from_manifest_internal(
        &manifest,
        &normalized_root,
        &preflight_opts,
        options.sqlite_target_rel_path.as_deref(),
        options.trusted_sqlite_db_path.as_deref(),
    )?;
    for item in &validated_plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &validated_plan.target_root,
            options.provenance_dir.as_deref(),
        )?;
    }

    let artifact_path = safe_backup_file_path(backup_dir, filename)?;
    let provenance_dir = resolve_recovery_provenance_dir(
        &normalized_root,
        options.provenance_dir.as_deref(),
    );

    let run_id = format!("{}.{}", std::process::id(), uuid::Uuid::new_v4());
    let staging_dir = backup_dir.join(format!(".staging-restore.{}", run_id));
    let rollback_dir = backup_dir.join(format!(".rollback-restore.{}", run_id));

    open_or_create_dir_nofollow(&staging_dir, 0o700, "restore staging dir")?;

    let stage_result = (|| -> HostBackupResult<(Vec<StagedRestoreEntry>, Option<i64>, bool)> {
        let mut staged_entries = Vec::new();
        let mut sqlite_uv = None;
        let mut sqlite_verified = false;

        if filename.ends_with(".tar.gz") {
            let expected_by_path: HashMap<String, &crate::manifest::BackupManifestEntry> = manifest
                .entries
                .iter()
                .filter(|entry| entry.kind != BackupTargetKind::TarGzArchive)
                .map(|entry| (entry.relative_path.replace('\\', "/"), entry))
                .collect();

            let (file, _, _, _) = open_existing_regular_file_nofollow(
                &artifact_path,
                options.trusted_sqlite_uid,
                "backup tar.gz archive",
            )?
            .ok_or_else(|| HostBackupError::PathValidation {
                path: artifact_path.clone(),
                reason: "backup tar.gz archive does not exist".to_string(),
            })?;
            let gz = GzDecoder::new(file);
            let mut archive = Archive::new(gz);
            let mut seen = HashSet::new();

            let entries_iter = archive.entries().map_err(|err| HostBackupError::Archive {
                archive: artifact_path.clone(),
                reason: format!("reading tar entries: {}", err),
            })?;

            for entry_res in entries_iter {
                let mut entry = entry_res.map_err(|err| HostBackupError::Archive {
                    archive: artifact_path.clone(),
                    reason: format!("corrupt tar entry: {}", err),
                })?;
                let entry_type = entry.header().entry_type();
                let header_mode = entry.header().mode().ok().map(|mode_val| mode_val & 0o7777);
                let header_uid = entry.header().uid().ok().and_then(|uid_val| u32::try_from(uid_val).ok());
                let header_gid = entry.header().gid().ok().and_then(|gid_val| u32::try_from(gid_val).ok());

                let raw_path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
                if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
                    return Err(HostBackupError::SymlinkRejected {
                        path: PathBuf::from(&raw_path),
                        reason: format!("tar archive contains forbidden {:?} entry '{}'", entry_type, raw_path),
                    });
                }
                let norm_rel = validate_relative_backup_path(&raw_path)?;
                let key = norm_rel.to_string_lossy().replace('\\', "/");
                if entry_type == EntryType::Directory {
                    if !is_canonical_root {
                        let dir_dest = normalized_root.join(&norm_rel);
                        reject_symlink_chain(&normalized_root, &dir_dest)?;
                    }
                    continue;
                }
                if entry_type != EntryType::Regular && entry_type != EntryType::Continuous {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!("unsupported tar entry type {:?} at '{}'", entry_type, key),
                    });
                }
                if !seen.insert(key.clone()) {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!("duplicate tar entry '{}'", key),
                    });
                }

                let expected = expected_by_path.get(&key).ok_or_else(|| {
                    HostBackupError::InvalidManifest(format!("undeclared tar entry '{}'", key))
                })?;

                let (dest_path, _) = plan_single_destination_with_options(
                    &normalized_root,
                    &key,
                    Some(expected.kind),
                    options.sqlite_target_rel_path.as_deref(),
                    options.trusted_sqlite_db_path.as_deref(),
                    overwrite_policy,
                )?;
                validate_destination_not_provenance(
                    &dest_path,
                    &normalized_root,
                    options.provenance_dir.as_deref(),
                )?;
                let staged_path = staging_dir.join(&norm_rel);
                reject_symlink_chain(&staging_dir, &staged_path)?;

                let mode = resolve_restored_entry_mode(
                    expected.unix_mode.or(header_mode),
                    &key,
                    expected.kind,
                    options,
                );
                let uid = if expected.kind == BackupTargetKind::SqliteSnapshot {
                    options.trusted_sqlite_uid.or(expected.unix_uid).or(header_uid)
                } else {
                    expected.unix_uid.or(header_uid)
                };
                let gid = if expected.kind == BackupTargetKind::SqliteSnapshot {
                    options.trusted_sqlite_gid.or(expected.unix_gid).or(header_gid)
                } else {
                    expected.unix_gid.or(header_gid)
                };

                let (pinned_file, staged_dev_ino, actual_sha, actual_size) =
                    write_exclusive_staged_file(&staged_path, &mut entry, 0o600)?;
                if !actual_sha.eq_ignore_ascii_case(&expected.sha256) {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: format!("{}:{}", filename, key),
                        expected: expected.sha256.clone(),
                        actual: actual_sha,
                    });
                }
                if actual_size != expected.size_bytes {
                    return Err(HostBackupError::InvalidManifest(format!(
                        "size mismatch for '{}': expected {}, got {}",
                        key, expected.size_bytes, actual_size
                    )));
                }

                if expected.kind == BackupTargetKind::SqliteSnapshot {
                    let (uv, _, _) = verify_sqlite_snapshot_integrity(&staged_path)?;
                    if let Some(ref snap_meta) = manifest.sqlite_snapshot {
                        if uv != snap_meta.sqlite_user_version {
                            return Err(HostBackupError::InvalidManifest(format!(
                                "staged SQLite user_version mismatch: manifest declared {}, actual {}",
                                snap_meta.sqlite_user_version, uv
                            )));
                        }
                    }
                    sqlite_uv = Some(uv);
                    sqlite_verified = true;
                }

                staged_entries.push(StagedRestoreEntry {
                    relative_key: key,
                    staged_path,
                    _pinned_file: pinned_file,
                    staged_dev_ino,
                    expected_sha256: actual_sha,
                    expected_size: actual_size,
                    destination_path: dest_path,
                    kind: expected.kind,
                    unix_mode: mode,
                    unix_uid: uid,
                    unix_gid: gid,
                });
            }

            for (key, expected) in &expected_by_path {
                if expected.required && !seen.contains(key) {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!("required manifest entry '{}' missing from archive", key),
                    });
                }
            }
        } else if filename.ends_with(".sqlite") {
            let entry = manifest
                .entries
                .iter()
                .find(|item| item.kind == BackupTargetKind::SqliteSnapshot)
                .ok_or_else(|| {
                    HostBackupError::InvalidManifest(
                        "standalone SQLite backup manifest has no SqliteSnapshot entry".to_string(),
                    )
                })?;

            let rel_dest = resolve_effective_relative_destination(
                &entry.relative_path,
                Some(BackupTargetKind::SqliteSnapshot),
                options.sqlite_target_rel_path.as_deref(),
            );

            let (dest_path, _) = plan_single_destination_with_options(
                &normalized_root,
                rel_dest,
                Some(BackupTargetKind::SqliteSnapshot),
                options.sqlite_target_rel_path.as_deref(),
                options.trusted_sqlite_db_path.as_deref(),
                overwrite_policy,
            )?;
            validate_destination_not_provenance(
                &dest_path,
                &normalized_root,
                options.provenance_dir.as_deref(),
            )?;
            let staged_path = staging_dir.join("staged_snapshot.sqlite");
            let (mut src_file, _, _, _) = open_existing_regular_file_nofollow(
                &artifact_path,
                options.trusted_sqlite_uid,
                "SQLite backup snapshot",
            )?
            .ok_or_else(|| HostBackupError::PathValidation {
                path: artifact_path.clone(),
                reason: "SQLite backup snapshot does not exist".to_string(),
            })?;
            let (pinned_file, staged_dev_ino, actual_sha, actual_size) =
                write_exclusive_staged_file(&staged_path, &mut src_file, 0o600)?;
            if !actual_sha.eq_ignore_ascii_case(&entry.sha256) {
                return Err(HostBackupError::ChecksumMismatch {
                    artifact: filename.to_string(),
                    expected: entry.sha256.clone(),
                    actual: actual_sha,
                });
            }
            if actual_size != entry.size_bytes {
                return Err(HostBackupError::InvalidManifest(format!(
                    "SQLite snapshot size mismatch: expected {}, got {}",
                    entry.size_bytes, actual_size
                )));
            }
            let (uv, _, _) = verify_sqlite_snapshot_integrity(&staged_path)?;
            sqlite_uv = Some(uv);
            sqlite_verified = true;

            staged_entries.push(StagedRestoreEntry {
                relative_key: rel_dest.to_string(),
                staged_path,
                _pinned_file: pinned_file,
                staged_dev_ino,
                expected_sha256: actual_sha,
                expected_size: actual_size,
                destination_path: dest_path,
                kind: BackupTargetKind::SqliteSnapshot,
                unix_mode: resolve_restored_entry_mode(
                    entry.unix_mode,
                    rel_dest,
                    BackupTargetKind::SqliteSnapshot,
                    options,
                ),
                unix_uid: options.trusted_sqlite_uid.or(entry.unix_uid),
                unix_gid: options.trusted_sqlite_gid.or(entry.unix_gid),
            });
        } else {
            return Err(HostBackupError::PathValidation {
                path: artifact_path.clone(),
                reason: format!("unsupported backup artifact extension for '{}'", filename),
            });
        }

        validate_unique_resolved_destinations(staged_entries.iter().map(|staged_item| {
            (
                staged_item.relative_key.as_str(),
                staged_item.destination_path.as_path(),
                staged_item.kind,
            )
        }))?;

        Ok((staged_entries, sqlite_uv, sqlite_verified))
    })();

    let (staged_entries, sqlite_uv, sqlite_verified) = match stage_result {
        Ok(staged_val) => staged_val,
        Err(err) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(err);
        }
    };

    if let Err(err) = open_or_create_dir_nofollow(&rollback_dir, 0o700, "restore rollback dir") {
        drop(staged_entries);
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(err);
    }

    let in_progress_journal_path = rollback_dir.join(IN_PROGRESS_RECOVERY_JOURNAL_FILENAME);
    let mut rollback_records: Vec<RollbackRecord> = Vec::new();
    let mut journal_generation = 0u64;

    if let Err(err) = persist_recovery_journal_snapshot_with_fault(
        &in_progress_journal_path,
        &provenance_dir,
        &mut journal_generation,
        &manifest.backup_id,
        filename,
        &normalized_root,
        &rollback_dir,
        &effective_services,
        &rollback_records,
        JOURNAL_STATE_QUIESCING,
        options.trusted_sqlite_db_path.as_deref(),
        options.fail_initial_local_journal_write,
    ) {
        drop(staged_entries);
        let _ = fs::remove_dir_all(&staging_dir);
        if let Err(cleanup_err) = remove_recovery_dir_and_provenance_with_fault(
            &rollback_dir,
            &provenance_dir,
            options.fail_early_cleanup_remove_rb_dir,
        ) {
            return Err(HostBackupError::InvalidManifest(format!(
                "initial recovery journal persistence failed ({}) and cleanup of '{}' failed ({})",
                err,
                rollback_dir.display(),
                cleanup_err
            )));
        }
        return Err(err);
    }

    if let Err((stop_err, comp_failed)) = stop_services_with_compensation(quiescence, &effective_services) {
        drop(staged_entries);
        let _ = fs::remove_dir_all(&staging_dir);
        if !comp_failed
            && persist_recovery_journal_snapshot(
                &in_progress_journal_path,
                &provenance_dir,
                &mut journal_generation,
                &manifest.backup_id,
                filename,
                &normalized_root,
                &rollback_dir,
                &effective_services,
                &rollback_records,
                JOURNAL_STATE_ABORTED_CLEAN,
                options.trusted_sqlite_db_path.as_deref(),
            )
            .is_ok()
        {
            if let Err(cleanup_err) = remove_recovery_dir_and_provenance_with_fault(
                &rollback_dir,
                &provenance_dir,
                options.fail_early_cleanup_remove_rb_dir,
            ) {
                return Err(HostBackupError::InvalidManifest(format!(
                    "service quiescence failed ({}) and cleanup of aborted recovery directory '{}' failed ({})",
                    stop_err,
                    rollback_dir.display(),
                    cleanup_err
                )));
            }
        }
        return Err(stop_err);
    }

    let mut restored_files: Vec<PathBuf> = Vec::new();
    let mut sqlite_restored = false;
    let mut committed_durably = false;

    let apply_result = (|| -> HostBackupResult<()> {
        persist_recovery_journal_snapshot(
            &in_progress_journal_path,
            &provenance_dir,
            &mut journal_generation,
            &manifest.backup_id,
            filename,
            &normalized_root,
            &rollback_dir,
            &effective_services,
            &rollback_records,
            JOURNAL_STATE_IN_PROGRESS,
            options.trusted_sqlite_db_path.as_deref(),
        )?;

        for (idx, item) in staged_entries.iter().enumerate() {
            if !is_canonical_root {
                reject_symlink_chain(&normalized_root, &item.destination_path)?;
            }

            let trusted_ancestor_uid = if item.kind == BackupTargetKind::SqliteSnapshot {
                options.trusted_sqlite_uid
            } else {
                None
            };

            let existing_dest = open_existing_regular_file_nofollow(
                &item.destination_path,
                trusted_ancestor_uid,
                "existing restore destination file",
            )?;

            let mut existed_before = false;
            let mut orig_mode = None;
            let mut orig_uid = None;
            let mut orig_gid = None;
            let mut rollback_copy_path = None;
            let mut rollback_copy_file = None;
            let mut rollback_copy_dev_ino = None;
            let mut rollback_copy_sha256 = None;
            let mut rollback_copy_size = None;

            if let Some((mut orig_file, fd_mode, fd_uid, fd_gid)) = existing_dest {
                existed_before = true;
                orig_mode = Some(fd_mode & 0o7777);
                orig_uid = Some(fd_uid);
                orig_gid = Some(fd_gid);
                let rb_file = rollback_dir.join(format!("entry_{}.bak", idx));
                let (copy_file, copy_dev_ino, copy_sha, copy_size) =
                    write_exclusive_staged_file(&rb_file, &mut orig_file, 0o600)?;
                rollback_copy_path = Some(rb_file);
                rollback_copy_file = Some(std::sync::Arc::new(copy_file));
                rollback_copy_dev_ino = copy_dev_ino;
                rollback_copy_sha256 = Some(copy_sha);
                rollback_copy_size = Some(copy_size);
            }

            let mut had_wal_copy = None;
            let mut wal_copy_file = None;
            let mut wal_copy_dev_ino = None;
            let mut wal_copy_sha256 = None;
            let mut wal_copy_size = None;
            let mut had_shm_copy = None;
            let mut shm_copy_file = None;
            let mut shm_copy_dev_ino = None;
            let mut shm_copy_sha256 = None;
            let mut shm_copy_size = None;
            let mut wal_attrs = (None, None, None);
            let mut shm_attrs = (None, None, None);

            if item.kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&item.destination_path);
                if let Some((mut wal_file, wal_fd_mode, wal_fd_uid, wal_fd_gid)) =
                    open_existing_regular_file_nofollow(
                        &wal_path,
                        trusted_ancestor_uid,
                        "existing SQLite WAL sidecar",
                    )?
                {
                    wal_attrs = (Some(wal_fd_mode & 0o7777), Some(wal_fd_uid), Some(wal_fd_gid));
                    let rb_wal = rollback_dir.join(format!("entry_{}.wal.bak", idx));
                    let (wal_pinned, wal_dev_ino, wal_sha, wal_sz) =
                        write_exclusive_staged_file(&rb_wal, &mut wal_file, 0o600)?;
                    had_wal_copy = Some(rb_wal);
                    wal_copy_file = Some(std::sync::Arc::new(wal_pinned));
                    wal_copy_dev_ino = wal_dev_ino;
                    wal_copy_sha256 = Some(wal_sha);
                    wal_copy_size = Some(wal_sz);
                }
                if let Some((mut shm_file, shm_fd_mode, shm_fd_uid, shm_fd_gid)) =
                    open_existing_regular_file_nofollow(
                        &shm_path,
                        trusted_ancestor_uid,
                        "existing SQLite SHM sidecar",
                    )?
                {
                    shm_attrs = (Some(shm_fd_mode & 0o7777), Some(shm_fd_uid), Some(shm_fd_gid));
                    let rb_shm = rollback_dir.join(format!("entry_{}.shm.bak", idx));
                    let (shm_pinned, shm_dev_ino, shm_sha, shm_sz) =
                        write_exclusive_staged_file(&rb_shm, &mut shm_file, 0o600)?;
                    had_shm_copy = Some(rb_shm);
                    shm_copy_file = Some(std::sync::Arc::new(shm_pinned));
                    shm_copy_dev_ino = shm_dev_ino;
                    shm_copy_sha256 = Some(shm_sha);
                    shm_copy_size = Some(shm_sz);
                }
            }

            rollback_records.push(RollbackRecord {
                destination_path: item.destination_path.clone(),
                kind: item.kind,
                existed_before,
                rollback_copy_path,
                _rollback_copy_file: rollback_copy_file,
                rollback_copy_dev_ino,
                rollback_copy_sha256,
                rollback_copy_size,
                had_wal_copy,
                _wal_copy_file: wal_copy_file,
                wal_copy_dev_ino,
                wal_copy_sha256,
                wal_copy_size,
                had_shm_copy,
                _shm_copy_file: shm_copy_file,
                shm_copy_dev_ino,
                shm_copy_sha256,
                shm_copy_size,
                original_mode: orig_mode,
                original_uid: orig_uid,
                original_gid: orig_gid,
                wal_mode: wal_attrs.0,
                wal_uid: wal_attrs.1,
                wal_gid: wal_attrs.2,
                shm_mode: shm_attrs.0,
                shm_uid: shm_attrs.1,
                shm_gid: shm_attrs.2,
            });

            persist_recovery_journal_snapshot(
                &in_progress_journal_path,
                &provenance_dir,
                &mut journal_generation,
                &manifest.backup_id,
                filename,
                &normalized_root,
                &rollback_dir,
                &effective_services,
                &rollback_records,
                JOURNAL_STATE_IN_PROGRESS,
                options.trusted_sqlite_db_path.as_deref(),
            )?;

            if let Some(limit) = options.fail_after_replacements {
                if idx >= limit {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!(
                            "simulated mid-restore failure triggered after {} file replacement(s)",
                            idx
                        ),
                    });
                }
            }

            if item.kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&item.destination_path);
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &wal_path,
                    trusted_ancestor_uid,
                    "removing stale WAL before restore",
                )?;
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &shm_path,
                    trusted_ancestor_uid,
                    "removing stale SHM before restore",
                )?;
            }

            let effective_uid = item.unix_uid.or(orig_uid);
            let effective_gid = item.unix_gid.or(orig_gid);
            let effective_mode = item.unix_mode & 0o777;

            atomic_install_file_at_destination_with_verification(
                &item.staged_path,
                item.staged_dev_ino,
                Some(&item.expected_sha256),
                Some(item.expected_size),
                &item.destination_path,
                effective_mode,
                effective_uid,
                effective_gid,
                trusted_ancestor_uid,
                "restoring staged entry to destination",
            )?;

            if item.kind == BackupTargetKind::SqliteSnapshot {
                let _ = verify_sqlite_snapshot_integrity_with_trusted_uid(
                    &item.destination_path,
                    trusted_ancestor_uid,
                )?;
                let post_sqlite_verify = verify_file_sha256_with_trusted_uid(
                    &item.destination_path,
                    &item.expected_sha256,
                    trusted_ancestor_uid,
                )?;
                if post_sqlite_verify.size_bytes != item.expected_size {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: item.destination_path.display().to_string(),
                        expected: format!("size={}", item.expected_size),
                        actual: format!("size={}", post_sqlite_verify.size_bytes),
                    });
                }
                sqlite_restored = true;
            }

            restored_files.push(item.destination_path.clone());
        }

        if let Some(limit) = options.fail_after_replacements {
            if staged_entries.len() <= limit {
                return Err(HostBackupError::Archive {
                    archive: artifact_path.clone(),
                    reason: format!(
                        "simulated post-replacement failure triggered at threshold {}",
                        limit
                    ),
                });
            }
        }

        persist_committed_journal_snapshot(
            &in_progress_journal_path,
            &provenance_dir,
            &mut journal_generation,
            &manifest.backup_id,
            filename,
            &normalized_root,
            &rollback_dir,
            &effective_services,
            &rollback_records,
            options.trusted_sqlite_db_path.as_deref(),
            options.fail_provenance_on_commit,
            options.fail_provenance_parent_sync_on_commit,
            options.fail_local_journal_on_commit,
            &mut committed_durably,
        )?;

        quiescence.start_and_verify_services(&effective_services)?;
        Ok(())
    })();

    drop(staged_entries);
    let _ = fs::remove_dir_all(&staging_dir);

    if let Err(apply_err) = apply_result {
        if committed_durably {
            if options.fail_local_journal_on_commit
                || options.fail_provenance_parent_sync_on_commit
            {
                drop(rollback_records);
                return Err(apply_err);
            }
            let committed_entries: Vec<RollbackFailureJournalEntry> = rollback_records
                .iter()
                .map(|rec| RollbackFailureJournalEntry {
                    destination_path: rec.destination_path.clone(),
                    kind: Some(rec.kind),
                    existed_before: rec.existed_before,
                    rollback_copy_path: rec.rollback_copy_path.clone(),
                    rollback_copy_sha256: rec.rollback_copy_sha256.clone(),
                    had_wal_copy: rec.had_wal_copy.clone(),
                    wal_copy_sha256: rec.wal_copy_sha256.clone(),
                    had_shm_copy: rec.had_shm_copy.clone(),
                    shm_copy_sha256: rec.shm_copy_sha256.clone(),
                    original_mode: rec.original_mode,
                    original_uid: rec.original_uid,
                    original_gid: rec.original_gid,
                    wal_mode: rec.wal_mode,
                    wal_uid: rec.wal_uid,
                    wal_gid: rec.wal_gid,
                    shm_mode: rec.shm_mode,
                    shm_uid: rec.shm_uid,
                    shm_gid: rec.shm_gid,
                    restored_during_rollback: true,
                })
                .collect();
            drop(rollback_records);

            let mut committed_journal = RollbackFailureJournal {
                backup_id: manifest.backup_id,
                primary_artifact: filename.to_string(),
                target_root: normalized_root,
                recovery_dir: rollback_dir.clone(),
                apply_failure_reason: apply_err.to_string(),
                rollback_errors: vec![format!(
                    "post-commit service start failed (committed state preserved without rollback): {}",
                    apply_err
                )],
                file_rollback_incomplete: false,
                services_left_stopped: true,
                quiesced_services: effective_services,
                entries: committed_entries,
                journal_state: JOURNAL_STATE_COMMITTED.to_string(),
                trusted_sqlite_db_path: options.trusted_sqlite_db_path.clone(),
                generation: 0,
                journal_digest_sha256: None,
            };
            let _ = write_journal_with_sidecar_and_provenance(
                &in_progress_journal_path,
                &provenance_dir,
                &rollback_dir,
                &mut committed_journal,
                &mut journal_generation,
                "recovery-journal",
                "committed restore journal awaiting service restart",
            );
            return Err(apply_err);
        }

        let mut rollback_errors = Vec::new();
        let mut journal_entries = Vec::with_capacity(rollback_records.len());

        for (rb_idx, rec) in rollback_records.iter().rev().enumerate() {
            let mut rec_ok = true;

            if let Some(rb_limit) = options.fail_rollback_after_restores {
                if rb_idx >= rb_limit {
                    rec_ok = false;
                    rollback_errors.push(format!(
                        "simulated rollback failure triggered at rollback step {} for {}",
                        rb_idx,
                        rec.destination_path.display()
                    ));
                }
            }

            if rec_ok {
                let trusted_ancestor_uid = if rec.kind == BackupTargetKind::SqliteSnapshot {
                    options.trusted_sqlite_uid
                } else {
                    None
                };

                if rec.kind == BackupTargetKind::SqliteSnapshot {
                    let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                    if let Err(wal_err) = unlink_file_at_destination_with_trusted_ancestor_uid(
                        &wal_path,
                        trusted_ancestor_uid,
                        "rollback WAL cleanup",
                    ) {
                        rec_ok = false;
                        rollback_errors
                            .push(format!("unlink WAL {}: {}", wal_path.display(), wal_err));
                    }
                    if let Err(shm_err) = unlink_file_at_destination_with_trusted_ancestor_uid(
                        &shm_path,
                        trusted_ancestor_uid,
                        "rollback SHM cleanup",
                    ) {
                        rec_ok = false;
                        rollback_errors
                            .push(format!("unlink SHM {}: {}", shm_path.display(), shm_err));
                    }
                }

                if rec_ok {
                    if rec.existed_before {
                        if let Some(ref rb_copy) = rec.rollback_copy_path {
                            let rb_mode = rec.original_mode.unwrap_or(0o600);
                            if let Err(err) = atomic_install_file_at_destination_with_verification(
                                rb_copy,
                                rec.rollback_copy_dev_ino,
                                rec.rollback_copy_sha256.as_deref(),
                                rec.rollback_copy_size,
                                &rec.destination_path,
                                rb_mode,
                                rec.original_uid,
                                rec.original_gid,
                                trusted_ancestor_uid,
                                "rolling back destination file",
                            ) {
                                rec_ok = false;
                                rollback_errors.push(format!(
                                    "restore {}: {}",
                                    rec.destination_path.display(),
                                    err
                                ));
                            }
                        } else {
                            rec_ok = false;
                            rollback_errors.push(format!(
                                "missing rollback copy for existing file {}",
                                rec.destination_path.display()
                            ));
                        }
                    } else if rec.destination_path.exists() {
                        if let Err(err) = unlink_file_at_destination_with_trusted_ancestor_uid(
                            &rec.destination_path,
                            trusted_ancestor_uid,
                            "rolling back newly created destination file",
                        ) {
                            rec_ok = false;
                            rollback_errors.push(format!(
                                "remove new file {}: {}",
                                rec.destination_path.display(),
                                err
                            ));
                        }
                    }
                }

                if rec_ok && rec.kind == BackupTargetKind::SqliteSnapshot {
                    let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                    if let Some(ref rb_wal) = rec.had_wal_copy {
                        if let Err(err) = atomic_install_file_at_destination_with_verification(
                            rb_wal,
                            rec.wal_copy_dev_ino,
                            rec.wal_copy_sha256.as_deref(),
                            rec.wal_copy_size,
                            &wal_path,
                            sanitize_sqlite_sidecar_mode(rec.wal_mode),
                            rec.wal_uid.or(rec.original_uid),
                            rec.wal_gid.or(rec.original_gid),
                            trusted_ancestor_uid,
                            "rolling back SQLite WAL sidecar",
                        ) {
                            rec_ok = false;
                            rollback_errors
                                .push(format!("restore WAL {}: {}", wal_path.display(), err));
                        }
                    }
                    if let Some(ref rb_shm) = rec.had_shm_copy {
                        if let Err(err) = atomic_install_file_at_destination_with_verification(
                            rb_shm,
                            rec.shm_copy_dev_ino,
                            rec.shm_copy_sha256.as_deref(),
                            rec.shm_copy_size,
                            &shm_path,
                            sanitize_sqlite_sidecar_mode(rec.shm_mode),
                            rec.shm_uid.or(rec.original_uid),
                            rec.shm_gid.or(rec.original_gid),
                            trusted_ancestor_uid,
                            "rolling back SQLite SHM sidecar",
                        ) {
                            rec_ok = false;
                            rollback_errors
                                .push(format!("restore SHM {}: {}", shm_path.display(), err));
                        }
                    }
                }
            }

            journal_entries.push(RollbackFailureJournalEntry {
                destination_path: rec.destination_path.clone(),
                kind: Some(rec.kind),
                existed_before: rec.existed_before,
                rollback_copy_path: rec.rollback_copy_path.clone(),
                rollback_copy_sha256: rec.rollback_copy_sha256.clone(),
                had_wal_copy: rec.had_wal_copy.clone(),
                wal_copy_sha256: rec.wal_copy_sha256.clone(),
                had_shm_copy: rec.had_shm_copy.clone(),
                shm_copy_sha256: rec.shm_copy_sha256.clone(),
                original_mode: rec.original_mode,
                original_uid: rec.original_uid,
                original_gid: rec.original_gid,
                wal_mode: rec.wal_mode,
                wal_uid: rec.wal_uid,
                wal_gid: rec.wal_gid,
                shm_mode: rec.shm_mode,
                shm_uid: rec.shm_uid,
                shm_gid: rec.shm_gid,
                restored_during_rollback: rec_ok,
            });
        }

        journal_entries.reverse();

        let file_rollback_incomplete = !rollback_errors.is_empty();
        let mut services_left_stopped = false;

        if file_rollback_incomplete {
            services_left_stopped = !effective_services.is_empty();
        } else if let Err(journal_err) = persist_recovery_journal_snapshot(
            &in_progress_journal_path,
            &provenance_dir,
            &mut journal_generation,
            &manifest.backup_id,
            filename,
            &normalized_root,
            &rollback_dir,
            &effective_services,
            &rollback_records,
            JOURNAL_STATE_ROLLED_BACK,
            options.trusted_sqlite_db_path.as_deref(),
        ) {
            services_left_stopped = true;
            rollback_errors.push(format!(
                "persisting terminal rolled_back journal before restarting services: {}",
                journal_err
            ));
        } else if let Err(svc_err) = quiescence.start_and_verify_services(&effective_services) {
            services_left_stopped = true;
            rollback_errors.push(format!("service restart after rollback: {}", svc_err));
        }

        let rollback_record_count = rollback_records.len();
        drop(rollback_records);

        if rollback_errors.is_empty() {
            if let Err(cleanup_err) = remove_recovery_dir_and_provenance_with_fault(
                &rollback_dir,
                &provenance_dir,
                options.fail_cleanup_remove_rb_dir,
            ) {
                rollback_errors.push(format!(
                    "cleaning up recovery directory after rollback: {}",
                    cleanup_err
                ));
            } else {
                let rollback_summary = format!(
                    "all {} touched target file(s) and SQLite WAL/SHM sidecars restored cleanly to pre-restore state",
                    rollback_record_count
                );
                return Err(HostBackupError::RestoreRolledBack {
                    reason: apply_err.to_string(),
                    rollback_summary,
                });
            }
        }

        let journal_path = rollback_dir.join("rollback-failure-journal.json");
        let failure_state = if file_rollback_incomplete {
            JOURNAL_STATE_ROLLBACK_FAILED
        } else {
            JOURNAL_STATE_ROLLED_BACK
        };
        let mut journal = RollbackFailureJournal {
            backup_id: manifest.backup_id,
            primary_artifact: filename.to_string(),
            target_root: normalized_root,
            recovery_dir: rollback_dir.clone(),
            apply_failure_reason: apply_err.to_string(),
            rollback_errors: rollback_errors.clone(),
            file_rollback_incomplete,
            services_left_stopped,
            quiesced_services: effective_services,
            entries: journal_entries,
            journal_state: failure_state.to_string(),
            trusted_sqlite_db_path: options.trusted_sqlite_db_path.clone(),
            generation: 0,
            journal_digest_sha256: None,
        };
        let _ = write_journal_with_sidecar_and_provenance(
            &journal_path,
            &provenance_dir,
            &rollback_dir,
            &mut journal,
            &mut journal_generation,
            "failure-journal",
            "rollback failure journal",
        );

        return Err(HostBackupError::RestoreRollbackFailed {
            reason: apply_err.to_string(),
            rollback_errors: rollback_errors.join("; "),
            recovery_dir: rollback_dir,
            failure_journal_path: journal_path,
            services_left_stopped,
        });
    }

    drop(rollback_records);
    remove_recovery_dir_and_provenance_with_fault(
        &rollback_dir,
        &provenance_dir,
        options.fail_cleanup_remove_rb_dir,
    )?;

    Ok(RestoreExecutionReport {
        backup_id: manifest.backup_id,
        primary_artifact: filename.to_string(),
        target_root: normalized_root,
        sqlite_restored,
        sqlite_user_version: sqlite_uv,
        sqlite_integrity_verified: sqlite_verified,
        restored_files,
        quiesced_services: effective_services,
        rolled_back: false,
    })
}

fn verify_private_journal_or_backup_file(path: &Path, context: &str) -> HostBackupResult<()> {
    reject_if_symlink(path, context)?;
    let meta = fs::symlink_metadata(path)
        .map_err(|err| HostBackupError::io(format!("stat {} ({})", path.display(), context), err))?;
    if !meta.file_type().is_file() {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} is not a regular file", context),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let euid = unsafe { libc::geteuid() };
        let mut open_opts = fs::OpenOptions::new();
        open_opts
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let opened = open_opts.open(path).map_err(|err| {
            HostBackupError::io(format!("opening {} ({})", path.display(), context), err)
        })?;
        let mut fd_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(opened.as_raw_fd(), &mut fd_stat) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat {} ({})", path.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if (fd_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} is not a regular file", context),
            });
        }
        if fd_stat.st_nlink > 1 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} must not have multiple hard links", context),
            });
        }
        if fd_stat.st_uid != euid {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "{} is owned by untrusted uid {} (expected effective uid {})",
                    context, fd_stat.st_uid, euid
                ),
            });
        }
        let mode = (fd_stat.st_mode as u32) & 0o777;
        if mode != 0o600 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "{} must have mode 0600, found {:04o}",
                    context, mode
                ),
            });
        }
    }
    Ok(())
}

fn verify_recovery_dir_owned_by_euid(rb_dir: &Path, context: &str) -> HostBackupResult<()> {
    reject_if_symlink(rb_dir, context)?;
    let meta = fs::symlink_metadata(rb_dir)
        .map_err(|err| HostBackupError::io(format!("stat {} ({})", rb_dir.display(), context), err))?;
    if !meta.file_type().is_dir() {
        return Err(HostBackupError::PathValidation {
            path: rb_dir.to_path_buf(),
            reason: format!("{} is not a directory", context),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(HostBackupError::PathValidation {
                path: rb_dir.to_path_buf(),
                reason: format!(
                    "{} is owned by untrusted uid {} (expected effective uid {})",
                    context,
                    meta.uid(),
                    euid
                ),
            });
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(HostBackupError::PathValidation {
                path: rb_dir.to_path_buf(),
                reason: format!("{} must have mode 0700, found {:04o}", context, mode),
            });
        }
    }
    Ok(())
}

fn validate_recovery_copy_path(
    copy_path: &Path,
    rb_dir: &Path,
    expected_prefix: &str,
    expected_suffix: &str,
    expected_sha256: Option<&str>,
) -> HostBackupResult<(Option<(u64, u64)>, u64)> {
    validate_no_parent_traversal(copy_path, "recovery copy path")?;
    if copy_path.parent() != Some(rb_dir) {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery copy '{}' is not a direct child of recovery dir '{}'",
            copy_path.display(),
            rb_dir.display()
        )));
    }
    let name = copy_path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .ok_or_else(|| {
            HostBackupError::InvalidManifest(format!(
                "recovery copy '{}' has invalid filename",
                copy_path.display()
            ))
        })?;
    if !name.starts_with(expected_prefix) || !name.ends_with(expected_suffix) {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery copy '{}' does not match expected pattern '{}*{}'",
            copy_path.display(),
            expected_prefix,
            expected_suffix
        )));
    }
    verify_private_journal_or_backup_file(copy_path, "recovery backup copy")?;
    let expected_digest = expected_sha256.ok_or_else(|| {
        HostBackupError::InvalidManifest(format!(
            "recovery journal is missing SHA-256 digest for backup copy '{}'",
            copy_path.display()
        ))
    })?;
    let verification = verify_file_sha256(copy_path, expected_digest)?;
    #[cfg(unix)]
    let copy_dev_ino = {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(copy_path)
            .map_err(|err| HostBackupError::io(format!("lstat {}", copy_path.display()), err))?;
        Some((meta.dev(), meta.ino()))
    };
    #[cfg(not(unix))]
    let copy_dev_ino: Option<(u64, u64)> = None;
    Ok((copy_dev_ino, verification.size_bytes))
}

fn validate_recovery_journal(
    journal: &RollbackFailureJournal,
    rb_dir: &Path,
    context: &RecoveryContext,
) -> HostBackupResult<()> {
    if journal.backup_id.trim().is_empty() {
        return Err(HostBackupError::InvalidManifest(
            "recovery journal backup_id must not be empty".to_string(),
        ));
    }
    validate_backup_filename(&journal.primary_artifact)?;
    if journal.recovery_dir != rb_dir {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal recovery_dir '{}' does not match actual directory '{}'",
            journal.recovery_dir.display(),
            rb_dir.display()
        )));
    }
    if journal.generation == 0 {
        return Err(HostBackupError::InvalidManifest(
            "recovery journal generation must be >= 1".to_string(),
        ));
    }
    let expected_digest = journal.journal_digest_sha256.as_deref().ok_or_else(|| {
        HostBackupError::InvalidManifest(
            "recovery journal is missing journal_digest_sha256".to_string(),
        )
    })?;
    let computed_digest = compute_journal_canonical_digest(journal)?;
    if !computed_digest.eq_ignore_ascii_case(expected_digest) {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: rb_dir.display().to_string(),
            expected: expected_digest.to_string(),
            actual: computed_digest,
        });
    }

    let _ = validate_quiesce_service_entries(&journal.quiesced_services)?;
    let (norm_root, is_canonical) = validate_execution_target_root(&journal.target_root)?;

    let caller_expected_root = context.expected_target_root.as_deref().ok_or_else(|| {
        HostBackupError::InvalidConfig(
            "RecoveryContext::expected_target_root is required for recovery".to_string(),
        )
    })?;
    let (validated_caller_root, _) = validate_execution_target_root(caller_expected_root)?;
    if norm_root != validated_caller_root {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal target_root '{}' does not match trusted RecoveryContext target_root '{}'",
            norm_root.display(),
            validated_caller_root.display()
        )));
    }

    let validated_context_sqlite = match context.trusted_sqlite_db_path.as_deref() {
        Some(custom_db) => Some(validate_trusted_sqlite_db_path(custom_db)?),
        None => None,
    };
    let validated_journal_sqlite = match journal.trusted_sqlite_db_path.as_deref() {
        Some(custom_db) => Some(validate_trusted_sqlite_db_path(custom_db)?),
        None => None,
    };
    if let Some(ref journal_sqlite) = validated_journal_sqlite {
        if validated_context_sqlite.as_ref() != Some(journal_sqlite) {
            return Err(HostBackupError::InvalidManifest(format!(
                "recovery journal trusted_sqlite_db_path '{}' is not authorized by trusted RecoveryContext",
                journal_sqlite.display()
            )));
        }
    }

    match journal.journal_state.as_str() {
        JOURNAL_STATE_QUIESCING
        | JOURNAL_STATE_IN_PROGRESS
        | JOURNAL_STATE_COMMITTED
        | JOURNAL_STATE_ROLLED_BACK
        | JOURNAL_STATE_RECOVERED
        | JOURNAL_STATE_ABORTED_CLEAN
        | JOURNAL_STATE_ROLLBACK_FAILED => {}
        other => {
            return Err(HostBackupError::InvalidManifest(format!(
                "recovery journal contains invalid or empty journal_state '{}'",
                other
            )));
        }
    }

    if journal.journal_state == JOURNAL_STATE_COMMITTED {
        let has_rollback_error = journal
            .rollback_errors
            .iter()
            .any(|err_msg| !err_msg.starts_with("post-commit service start failed"));
        let has_unrestored_entry = journal
            .entries
            .iter()
            .any(|entry_item| !entry_item.restored_during_rollback);
        if journal.file_rollback_incomplete || has_rollback_error || has_unrestored_entry {
            return Err(HostBackupError::InvalidManifest(format!(
                "recovery journal for '{}' cannot claim terminal committed state while rollback is in progress or incomplete",
                rb_dir.display()
            )));
        }
    }

    let is_terminal = is_terminal_journal_state(&journal.journal_state);
    let mut seen_destinations = HashSet::new();

    for (idx, rec) in journal.entries.iter().enumerate() {
        let entry_kind = rec.kind.ok_or_else(|| {
            HostBackupError::InvalidManifest(format!(
                "journal entry {} for '{}' is missing required kind",
                idx,
                rec.destination_path.display()
            ))
        })?;
        validate_no_parent_traversal(&rec.destination_path, "journal destination_path")?;
        if !rec.destination_path.is_absolute() {
            return Err(HostBackupError::InvalidManifest(format!(
                "journal entry {} destination_path '{}' must be absolute",
                idx,
                rec.destination_path.display()
            )));
        }
        if !seen_destinations.insert(rec.destination_path.clone()) {
            return Err(HostBackupError::InvalidManifest(format!(
                "journal contains duplicate destination_path '{}'",
                rec.destination_path.display()
            )));
        }
        validate_destination_not_provenance(
            &rec.destination_path,
            &norm_root,
            context.provenance_dir.as_deref(),
        )?;
        if rec.destination_path == rb_dir
            || rec.destination_path.starts_with(rb_dir)
            || rb_dir.starts_with(&rec.destination_path)
        {
            return Err(HostBackupError::PathValidation {
                path: rec.destination_path.clone(),
                reason: format!(
                    "journal entry {} destination '{}' overlaps recovery directory '{}'",
                    idx,
                    rec.destination_path.display(),
                    rb_dir.display()
                ),
            });
        }

        let matches_trusted_sqlite = entry_kind == BackupTargetKind::SqliteSnapshot
            && validated_journal_sqlite
                .as_ref()
                .map(|trusted_path| trusted_path == &rec.destination_path)
                .unwrap_or(false);

        if is_canonical {
            if !matches_trusted_sqlite {
                let rel_trimmed = rec
                    .destination_path
                    .to_string_lossy()
                    .trim_start_matches('/')
                    .to_string();
                let (_, canonical_dest) =
                    resolve_trusted_canonical_host_destination_with_sqlite_override(
                        &norm_root,
                        &rel_trimmed,
                        validated_journal_sqlite.as_deref(),
                    )?;
                if canonical_dest != rec.destination_path {
                    return Err(HostBackupError::InvalidManifest(format!(
                        "journal entry {} canonical destination '{}' does not match allowlisted path '{}'",
                        idx,
                        rec.destination_path.display(),
                        canonical_dest.display()
                    )));
                }
            }
        } else if !matches_trusted_sqlite {
            if !rec.destination_path.starts_with(&norm_root) || rec.destination_path == norm_root {
                return Err(HostBackupError::InvalidManifest(format!(
                    "journal entry {} destination '{}' is outside target_root '{}'",
                    idx,
                    rec.destination_path.display(),
                    norm_root.display()
                )));
            }
            reject_symlink_chain(&norm_root, &rec.destination_path)?;
        }

        if entry_kind != BackupTargetKind::SqliteSnapshot
            && (rec.had_wal_copy.is_some() || rec.had_shm_copy.is_some())
        {
            return Err(HostBackupError::InvalidManifest(format!(
                "non-SQLite journal entry {} ('{}') must not declare WAL or SHM sidecar copies",
                idx,
                rec.destination_path.display()
            )));
        }

        if rec.existed_before {
            let rb_copy = rec.rollback_copy_path.as_ref().ok_or_else(|| {
                HostBackupError::InvalidManifest(format!(
                    "journal entry {} for existing destination '{}' is missing rollback_copy_path",
                    idx,
                    rec.destination_path.display()
                ))
            })?;
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    rb_copy,
                    rb_dir,
                    "entry_",
                    ".bak",
                    rec.rollback_copy_sha256.as_deref(),
                )?;
            }
        } else if let Some(ref rb_copy) = rec.rollback_copy_path {
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    rb_copy,
                    rb_dir,
                    "entry_",
                    ".bak",
                    rec.rollback_copy_sha256.as_deref(),
                )?;
            }
        }

        if let Some(ref wal_copy) = rec.had_wal_copy {
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    wal_copy,
                    rb_dir,
                    "entry_",
                    ".wal.bak",
                    rec.wal_copy_sha256.as_deref(),
                )?;
            }
        }
        if let Some(ref shm_copy) = rec.had_shm_copy {
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    shm_copy,
                    rb_dir,
                    "entry_",
                    ".shm.bak",
                    rec.shm_copy_sha256.as_deref(),
                )?;
            }
        }
    }

    Ok(())
}

fn load_validated_journal_checkpoint(
    journal_path: &Path,
    rb_dir: &Path,
    context: &RecoveryContext,
    allowed_stale_sidecar_digests: &[String],
    allow_missing_sidecar_if_digest_in: &[String],
) -> HostBackupResult<(RollbackFailureJournal, String)> {
    verify_private_journal_or_backup_file(journal_path, "recovery journal")?;
    let raw_text = read_verified_text_file_nofollow(
        journal_path,
        None,
        16 * 1024 * 1024,
        "recovery journal",
    )?
    .ok_or_else(|| {
        HostBackupError::InvalidManifest(format!(
            "recovery journal '{}' does not exist",
            journal_path.display()
        ))
    })?;
    let actual_file_sha256 = hex::encode(Sha256::digest(raw_text.as_bytes()));
    let parsed_journal: RollbackFailureJournal = serde_json::from_str(&raw_text).map_err(|err| {
        HostBackupError::InvalidManifest(format!(
            "corrupt recovery journal {}: {}",
            journal_path.display(),
            err
        ))
    })?;
    validate_recovery_journal(&parsed_journal, rb_dir, context)?;
    let internal_digest = parsed_journal
        .journal_digest_sha256
        .clone()
        .unwrap_or_default();

    let sidecar_path = checksum_sidecar_path(journal_path);
    if fs::symlink_metadata(&sidecar_path).is_ok() {
        verify_private_journal_or_backup_file(&sidecar_path, "recovery journal sidecar")?;
        let raw_sidecar = read_verified_text_file_nofollow(
            &sidecar_path,
            None,
            16 * 1024,
            "recovery journal sidecar",
        )?
        .ok_or_else(|| HostBackupError::MissingChecksumSidecar {
            artifact: journal_path.to_path_buf(),
            sidecar_path: sidecar_path.clone(),
        })?;
        let sidecar_hex = parse_sha256_sidecar_str(&raw_sidecar)?;
        if !sidecar_hex.eq_ignore_ascii_case(&actual_file_sha256) {
            let matches_allowed_stale = allowed_stale_sidecar_digests
                .iter()
                .any(|allowed_hex| allowed_hex.eq_ignore_ascii_case(&sidecar_hex))
                || allow_missing_sidecar_if_digest_in.iter().any(|allowed_hex| {
                    allowed_hex.eq_ignore_ascii_case(&actual_file_sha256)
                        || (!internal_digest.is_empty()
                            && allowed_hex.eq_ignore_ascii_case(&internal_digest))
                });
            if !matches_allowed_stale {
                return Err(HostBackupError::ChecksumMismatch {
                    artifact: journal_path.display().to_string(),
                    expected: sidecar_hex,
                    actual: actual_file_sha256,
                });
            }
        }
    } else {
        let allowed_missing = allow_missing_sidecar_if_digest_in
            .iter()
            .any(|allowed_hex| {
                allowed_hex.eq_ignore_ascii_case(&actual_file_sha256)
                    || allowed_hex.eq_ignore_ascii_case(&internal_digest)
            });
        if !allowed_missing {
            return Err(HostBackupError::MissingChecksumSidecar {
                artifact: journal_path.to_path_buf(),
                sidecar_path,
            });
        }
    }

    Ok((parsed_journal, actual_file_sha256))
}

fn check_journal_metadata_matches_provenance(
    rb_journal: &RollbackFailureJournal,
    prov_journal: &RollbackFailureJournal,
    journal_path: &Path,
    prov_journal_path: &Path,
) -> HostBackupResult<()> {
    if rb_journal.backup_id != prov_journal.backup_id
        || rb_journal.primary_artifact != prov_journal.primary_artifact
        || rb_journal.target_root != prov_journal.target_root
        || rb_journal.recovery_dir != prov_journal.recovery_dir
        || rb_journal.trusted_sqlite_db_path != prov_journal.trusted_sqlite_db_path
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal '{}' metadata diverges from protected provenance journal '{}'",
            journal_path.display(),
            prov_journal_path.display()
        )));
    }
    if rb_journal.generation > prov_journal.generation
        || prov_journal.generation.saturating_sub(rb_journal.generation) > 1
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal generation {} is inconsistent with protected provenance generation {}",
            rb_journal.generation, prov_journal.generation
        )));
    }
    if rb_journal.generation == prov_journal.generation
        && rb_journal.journal_digest_sha256 != prov_journal.journal_digest_sha256
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal digest does not match protected provenance digest at generation {}",
            prov_journal.generation
        )));
    }
    if prov_journal.journal_state == JOURNAL_STATE_COMMITTED
        && rb_journal.journal_state == JOURNAL_STATE_ROLLBACK_FAILED
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal '{}' records rollback_failed while provenance '{}' claims committed",
            journal_path.display(),
            prov_journal_path.display()
        )));
    }
    Ok(())
}

/// Legacy context-free recovery entrypoint.
///
/// Always fails closed with [`HostBackupError::InvalidConfig`] so privileged callers can never
/// recover an interrupted restore without supplying a trusted [`RecoveryContext`].
pub fn recover_interrupted_restore<Q: ServiceQuiescenceController>(
    _backup_dir: &Path,
    _quiescence: &Q,
) -> HostBackupResult<Vec<PathBuf>> {
    Err(HostBackupError::InvalidConfig(
        "recover_interrupted_restore without explicit RecoveryContext is disabled; use recover_interrupted_restore_with_context".to_string(),
    ))
}

/// Scans `backup_dir` for any `.rollback-restore.*` directories containing an interrupted
/// write-ahead `.restore-recovery-journal.json` (or an unrecovered `rollback-failure-journal.json`),
/// authenticates each recovery directory against its protected provenance record outside `backup_dir`
/// and the caller's trusted [`RecoveryContext`], quiesces the recorded writer services, restores
/// pre-restore `.bak` / `.wal.bak` / `.shm.bak` files when uncommitted, restarts services, and
/// cleans up the recovery directory and provenance record once recovery succeeds.
pub fn recover_interrupted_restore_with_context<Q: ServiceQuiescenceController>(
    backup_dir: &Path,
    context: &RecoveryContext,
    quiescence: &Q,
) -> HostBackupResult<Vec<PathBuf>> {
    let caller_expected_root = context.expected_target_root.as_deref().ok_or_else(|| {
        HostBackupError::InvalidConfig(
            "RecoveryContext::expected_target_root is required for recover_interrupted_restore_with_context".to_string(),
        )
    })?;
    let (validated_caller_root, _) = validate_execution_target_root(caller_expected_root)?;
    if let Some(ref custom_db) = context.trusted_sqlite_db_path {
        let _ = validate_trusted_sqlite_db_path(custom_db)?;
    }

    validate_no_parent_traversal(backup_dir, "backup_dir")?;
    if !backup_dir.exists() {
        return Ok(Vec::new());
    }
    reject_if_symlink(backup_dir, "backup_dir")?;
    open_or_create_dir_nofollow(backup_dir, 0o700, "backup_dir")?;

    let provenance_dir = resolve_recovery_provenance_dir(
        &validated_caller_root,
        context.provenance_dir.as_deref(),
    );

    let mut recovered_dirs = Vec::new();
    for entry in fs::read_dir(backup_dir)
        .map_err(|err| HostBackupError::io(format!("reading {}", backup_dir.display()), err))?
    {
        let entry = entry.map_err(|err| HostBackupError::io("reading dir entry", err))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(".rollback-restore.") {
            continue;
        }
        let rb_dir = entry.path();
        reject_symlink_chain(backup_dir, &rb_dir)?;
        verify_recovery_dir_owned_by_euid(&rb_dir, "restore recovery directory")?;
        open_or_create_dir_nofollow(&rb_dir, 0o700, "restore recovery directory")?;

        let in_prog = rb_dir.join(IN_PROGRESS_RECOVERY_JOURNAL_FILENAME);
        let failed_j = rb_dir.join("rollback-failure-journal.json");

        open_or_create_provenance_dir_nofollow(&provenance_dir, "recovery provenance directory")?;
        let prov_journal_path = provenance_journal_path_for_recovery_dir(&provenance_dir, &rb_dir)?;
        let prev_prov_path = provenance_prev_journal_path(&prov_journal_path);

        if fs::symlink_metadata(&prov_journal_path).is_err()
            && fs::symlink_metadata(&prev_prov_path).is_err()
        {
            for candidate_local in [&failed_j, &in_prog] {
                if fs::symlink_metadata(candidate_local).is_ok() {
                    verify_private_journal_or_backup_file(candidate_local, "recovery journal")?;
                    let sidecar_local = checksum_sidecar_path(candidate_local);
                    if fs::symlink_metadata(&sidecar_local).is_err() {
                        return Err(HostBackupError::MissingChecksumSidecar {
                            artifact: candidate_local.clone(),
                            sidecar_path: sidecar_local,
                        });
                    }
                }
            }
            if fs::symlink_metadata(&failed_j).is_err() && fs::symlink_metadata(&in_prog).is_err() {
                return Err(HostBackupError::InvalidManifest(format!(
                    "recovery directory '{}' contains no recovery journal",
                    rb_dir.display()
                )));
            }
            return Err(HostBackupError::InvalidManifest(format!(
                "unauthenticated recovery directory '{}': missing protected provenance journal '{}'",
                rb_dir.display(),
                prov_journal_path.display()
            )));
        }

        let prev_prov_opt: Option<(RollbackFailureJournal, String)> =
            if fs::symlink_metadata(&prev_prov_path).is_ok() {
                load_validated_journal_checkpoint(&prev_prov_path, &rb_dir, context, &[], &[]).ok()
            } else {
                None
            };

        let mut allowed_prov_stale_digests: Vec<String> = Vec::new();
        if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
            allowed_prov_stale_digests.push(prev_sha.clone());
            if let Some(ref prev_internal_dig) = prev_j.journal_digest_sha256 {
                allowed_prov_stale_digests.push(prev_internal_dig.clone());
            }
        }
        for local_cand in [&failed_j, &in_prog] {
            if fs::symlink_metadata(local_cand).is_ok() {
                if let Ok((local_j, local_sha)) =
                    load_validated_journal_checkpoint(local_cand, &rb_dir, context, &[], &[])
                {
                    allowed_prov_stale_digests.push(local_sha);
                    if let Some(ref local_internal_dig) = local_j.journal_digest_sha256 {
                        allowed_prov_stale_digests.push(local_internal_dig.clone());
                    }
                }
            }
        }

        let (prov_journal, prov_file_sha256) = match load_validated_journal_checkpoint(
            &prov_journal_path,
            &rb_dir,
            context,
            &allowed_prov_stale_digests,
            &allowed_prov_stale_digests,
        ) {
            Ok((loaded_prov, loaded_sha)) => {
                if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
                    let prov_sidecar = checksum_sidecar_path(&prov_journal_path);
                    let sidecar_matches_current = read_verified_text_file_nofollow(
                        &prov_sidecar,
                        None,
                        16 * 1024,
                        "provenance sidecar",
                    )
                    .ok()
                    .flatten()
                    .and_then(|raw_sc| parse_sha256_sidecar_str(&raw_sc).ok())
                    .map(|sc_hex| sc_hex.eq_ignore_ascii_case(&loaded_sha))
                    .unwrap_or(false);
                    if !sidecar_matches_current {
                        if loaded_prov.backup_id != prev_j.backup_id
                            || loaded_prov.primary_artifact != prev_j.primary_artifact
                            || loaded_prov.target_root != prev_j.target_root
                            || loaded_prov.recovery_dir != prev_j.recovery_dir
                            || loaded_prov.generation != prev_j.generation.saturating_add(1)
                        {
                            (prev_j.clone(), prev_sha.clone())
                        } else {
                            (loaded_prov, loaded_sha)
                        }
                    } else {
                        (loaded_prov, loaded_sha)
                    }
                } else {
                    (loaded_prov, loaded_sha)
                }
            }
            Err(prov_err) => {
                if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
                    (prev_j.clone(), prev_sha.clone())
                } else {
                    return Err(prov_err);
                }
            }
        };

        let mut allowed_local_digests = vec![prov_file_sha256.clone()];
        if let Some(ref internal_dig) = prov_journal.journal_digest_sha256 {
            allowed_local_digests.push(internal_dig.clone());
        }
        if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
            allowed_local_digests.push(prev_sha.clone());
            if let Some(ref prev_internal_dig) = prev_j.journal_digest_sha256 {
                allowed_local_digests.push(prev_internal_dig.clone());
            }
        }

        let mut valid_local_candidates: Vec<(PathBuf, RollbackFailureJournal)> = Vec::new();
        let mut first_local_err: Option<HostBackupError> = None;
        let mut any_local_exists = false;

        for candidate_path in [&failed_j, &in_prog] {
            if fs::symlink_metadata(candidate_path).is_err() {
                continue;
            }
            any_local_exists = true;
            match load_validated_journal_checkpoint(
                candidate_path,
                &rb_dir,
                context,
                &allowed_local_digests,
                &allowed_local_digests,
            ) {
                Ok((cand_journal, _)) => {
                    match check_journal_metadata_matches_provenance(
                        &cand_journal,
                        &prov_journal,
                        candidate_path,
                        &prov_journal_path,
                    ) {
                        Ok(()) => {
                            valid_local_candidates.push((candidate_path.clone(), cand_journal));
                        }
                        Err(meta_err) => {
                            if (cand_journal.journal_state == JOURNAL_STATE_ROLLBACK_FAILED
                                && prov_journal.journal_state == JOURNAL_STATE_COMMITTED)
                                || cand_journal.generation == prov_journal.generation
                            {
                                return Err(meta_err);
                            }
                            if first_local_err.is_none() {
                                first_local_err = Some(meta_err);
                            }
                        }
                    }
                }
                Err(load_err) => {
                    let is_generation_zero = matches!(
                        &load_err,
                        HostBackupError::InvalidManifest(msg_str)
                            if msg_str.contains("generation must be >= 1")
                    );
                    if !is_generation_zero {
                        return Err(load_err);
                    }
                    if first_local_err.is_none() {
                        first_local_err = Some(load_err);
                    }
                }
            }
        }

        if !any_local_exists {
            let allow_provenance_only_quiescing = prov_journal.entries.is_empty()
                && matches!(
                    prov_journal.journal_state.as_str(),
                    JOURNAL_STATE_QUIESCING | JOURNAL_STATE_ABORTED_CLEAN
                );
            if !allow_provenance_only_quiescing {
                return Err(HostBackupError::InvalidManifest(format!(
                    "recovery directory '{}' contains no recovery journal",
                    rb_dir.display()
                )));
            }
        }

        let (journal_path, _selected_local_journal) = if !valid_local_candidates.is_empty() {
            valid_local_candidates.sort_by(|left_item, right_item| {
                right_item.1.generation.cmp(&left_item.1.generation)
            });
            valid_local_candidates.remove(0)
        } else if let Some(local_err) = first_local_err {
            return Err(local_err);
        } else {
            (in_prog.clone(), prov_journal.clone())
        };

        let mut journal = prov_journal;
        let mut generation = journal.generation;
        let services = resolve_effective_quiesce_services(&journal.quiesced_services);
        let is_terminal = is_terminal_journal_state(&journal.journal_state);

        if is_terminal {
            if journal.services_left_stopped {
                quiescence.start_and_verify_services(&services)?;
                journal.services_left_stopped = false;
                write_journal_with_sidecar_and_provenance(
                    &journal_path,
                    &provenance_dir,
                    &rb_dir,
                    &mut journal,
                    &mut generation,
                    "recovery-journal",
                    "terminal restore recovery journal",
                )?;
            }
            remove_recovery_dir_and_provenance(&rb_dir, &provenance_dir)?;
            recovered_dirs.push(rb_dir);
            continue;
        }

        if journal.entries.is_empty() {
            if let Err((stop_err, _)) = stop_services_with_compensation(quiescence, &services) {
                return Err(stop_err);
            }
        } else {
            stop_services_for_recovery(quiescence, &services)?;
        }

        for rec in journal.entries.iter().rev() {
            let entry_kind = rec.kind.unwrap_or(BackupTargetKind::ConfigFile);
            let trusted_ancestor_uid = if entry_kind == BackupTargetKind::SqliteSnapshot {
                context.trusted_sqlite_uid
            } else {
                None
            };

            if entry_kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &wal_path,
                    trusted_ancestor_uid,
                    "interrupted recovery WAL cleanup",
                )?;
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &shm_path,
                    trusted_ancestor_uid,
                    "interrupted recovery SHM cleanup",
                )?;
            }

            if rec.existed_before {
                let rb_copy = rec.rollback_copy_path.as_ref().ok_or_else(|| {
                    HostBackupError::InvalidManifest(format!(
                        "missing rollback copy for existing file {}",
                        rec.destination_path.display()
                    ))
                })?;
                let (copy_dev_ino, copy_size) = validate_recovery_copy_path(
                    rb_copy,
                    &rb_dir,
                    "entry_",
                    ".bak",
                    rec.rollback_copy_sha256.as_deref(),
                )?;
                atomic_install_file_at_destination_with_verification(
                    rb_copy,
                    copy_dev_ino,
                    rec.rollback_copy_sha256.as_deref(),
                    Some(copy_size),
                    &rec.destination_path,
                    rec.original_mode.unwrap_or(0o600),
                    rec.original_uid,
                    rec.original_gid,
                    trusted_ancestor_uid,
                    "recovering interrupted destination file",
                )?;
            } else if rec.destination_path.exists() {
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &rec.destination_path,
                    trusted_ancestor_uid,
                    "removing newly created file from interrupted restore",
                )?;
            }

            if entry_kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                if let Some(ref rb_wal) = rec.had_wal_copy {
                    let (wal_dev_ino, wal_size) = validate_recovery_copy_path(
                        rb_wal,
                        &rb_dir,
                        "entry_",
                        ".wal.bak",
                        rec.wal_copy_sha256.as_deref(),
                    )?;
                    atomic_install_file_at_destination_with_verification(
                        rb_wal,
                        wal_dev_ino,
                        rec.wal_copy_sha256.as_deref(),
                        Some(wal_size),
                        &wal_path,
                        sanitize_sqlite_sidecar_mode(rec.wal_mode),
                        rec.wal_uid.or(rec.original_uid),
                        rec.wal_gid.or(rec.original_gid),
                        trusted_ancestor_uid,
                        "recovering interrupted WAL sidecar",
                    )?;
                }
                if let Some(ref rb_shm) = rec.had_shm_copy {
                    let (shm_dev_ino, shm_size) = validate_recovery_copy_path(
                        rb_shm,
                        &rb_dir,
                        "entry_",
                        ".shm.bak",
                        rec.shm_copy_sha256.as_deref(),
                    )?;
                    atomic_install_file_at_destination_with_verification(
                        rb_shm,
                        shm_dev_ino,
                        rec.shm_copy_sha256.as_deref(),
                        Some(shm_size),
                        &shm_path,
                        sanitize_sqlite_sidecar_mode(rec.shm_mode),
                        rec.shm_uid.or(rec.original_uid),
                        rec.shm_gid.or(rec.original_gid),
                        trusted_ancestor_uid,
                        "recovering interrupted SHM sidecar",
                    )?;
                }
            }
        }

        for entry_rec in &mut journal.entries {
            entry_rec.restored_during_rollback = true;
        }
        journal.file_rollback_incomplete = false;
        journal.journal_state = JOURNAL_STATE_RECOVERED.to_string();
        write_journal_with_sidecar_and_provenance(
            &journal_path,
            &provenance_dir,
            &rb_dir,
            &mut journal,
            &mut generation,
            "recovery-journal",
            "durable terminal recovered journal",
        )?;

        quiescence.start_and_verify_services(&services)?;
        journal.services_left_stopped = false;
        write_journal_with_sidecar_and_provenance(
            &journal_path,
            &provenance_dir,
            &rb_dir,
            &mut journal,
            &mut generation,
            "recovery-journal",
            "durable terminal recovered journal after service restart",
        )?;

        remove_recovery_dir_and_provenance(&rb_dir, &provenance_dir)?;
        recovered_dirs.push(rb_dir);
    }

    Ok(recovered_dirs)
}

#[allow(dead_code)]
fn _keep_legacy_imports() {
    let _ = atomic_install_file_at_destination;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReceipt {
    pub backup_id: String,
    pub target_root: PathBuf,
    pub restored_files: Vec<PathBuf>,
    pub total_bytes: u64,
    pub sqlite_verified: bool,
    pub manifest: BackupManifest,
}

pub fn execute_coordinated_restore(
    archive_or_dir: &Path,
    target_root: &Path,
    options: RestorePreflightOptions,
) -> HostBackupResult<RestoreReceipt> {
    validate_no_parent_traversal(archive_or_dir, "archive_or_dir")?;
    reject_if_symlink(archive_or_dir, "archive_or_dir")?;

    let normalized_root = validate_safe_target_root(target_root)?;
    reject_symlink_chain(target_root, &normalized_root)?;

    if archive_or_dir.is_file() {
        let filename = archive_or_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if filename.ends_with(".tar.gz") {
            if options.require_artifact_sidecar {
                verify_file_with_sidecar(archive_or_dir)?;
            }

            let manifest_path = archive_or_dir
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(format!("{}.manifest.json", filename));

            let manifest = if manifest_path.is_file() {
                BackupManifest::load_from_path(&manifest_path, true)?
            } else {
                // Search inside tar archive for manifest
                let f = File::open(archive_or_dir).map_err(|e| {
                    HostBackupError::io(format!("opening archive {}", archive_or_dir.display()), e)
                })?;
                let mut ar = Archive::new(GzDecoder::new(f));
                let mut found_manifest: Option<BackupManifest> = None;
                if let Ok(entries) = ar.entries() {
                    for entry in entries.flatten() {
                        let p = entry.path_bytes();
                        let p_str = String::from_utf8_lossy(&p);
                        if p_str.ends_with(".manifest.json") || p_str == "manifest.json" {
                            let mut bytes = Vec::new();
                            let mut r = entry;
                            if r.read_to_end(&mut bytes).is_ok() {
                                if let Ok(m) = serde_json::from_slice::<BackupManifest>(&bytes) {
                                    found_manifest = Some(m);
                                    break;
                                }
                            }
                        }
                    }
                }
                found_manifest.ok_or_else(|| {
                    HostBackupError::InvalidManifest(format!(
                        "missing required backup manifest for archive '{}'",
                        archive_or_dir.display()
                    ))
                })?
            };

            manifest.validate()?;
            manifest.check_compatibility(
                &options.host_app_version,
                options.max_supported_sqlite_user_version,
            )?;
            preflight_tar_gz_archive(archive_or_dir, &manifest, &normalized_root, &options)?;

            ensure_private_dir_all(&normalized_root, "target_root")?;

            let file = File::open(archive_or_dir).map_err(|e| {
                HostBackupError::io(format!("opening archive {}", archive_or_dir.display()), e)
            })?;
            let mut archive = Archive::new(GzDecoder::new(file));

            let mut restored_files = Vec::new();
            let mut total_bytes = 0u64;

            let entries = archive.entries().map_err(|e| HostBackupError::Archive {
                archive: archive_or_dir.to_path_buf(),
                reason: format!("failed to read tar entries: {}", e),
            })?;

            for entry_res in entries {
                let mut entry = entry_res.map_err(|e| HostBackupError::Archive {
                    archive: archive_or_dir.to_path_buf(),
                    reason: format!("failed reading tar entry: {}", e),
                })?;

                let entry_type = entry.header().entry_type();
                let raw_path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();

                if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
                    return Err(HostBackupError::SymlinkRejected {
                        path: PathBuf::from(&raw_path),
                        reason: "symlinks are forbidden in staged restore".to_string(),
                    });
                }

                let norm_rel = validate_relative_backup_path(&raw_path)?;

                if entry_type == EntryType::Directory {
                    let dir_dest = normalized_root.join(&norm_rel);
                    ensure_private_dir_all(&dir_dest, "target_dir")?;
                    continue;
                }

                if entry_type != EntryType::Regular && entry_type != EntryType::Continuous {
                    continue;
                }

                let entry_kind = manifest.entries.iter()
                    .find(|manifest_entry| Path::new(&manifest_entry.relative_path) == norm_rel)
                    .map(|manifest_entry| manifest_entry.kind);
                let (dest_path, _) = plan_single_destination_with_options(
                    &normalized_root,
                    &raw_path,
                    entry_kind,
                    None,
                    None,
                    options.overwrite_policy,
                )?;
                let parent = dest_path.parent().ok_or_else(|| {
                    HostBackupError::InvalidConfig(format!(
                        "invalid parent for destination {}",
                        dest_path.display()
                    ))
                })?;
                ensure_private_dir_all(parent, "destination_parent")?;

                let temp_file_path = parent.join(format!(
                    ".tmp_restore_{}_{}",
                    std::process::id(),
                    uuid::Uuid::new_v4()
                ));
                let mut hasher = Sha256::new();
                let mut written = 0u64;

                {
                    let mut out = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&temp_file_path)
                        .map_err(|e| {
                            HostBackupError::io(
                                format!("creating temp file {}", temp_file_path.display()),
                                e,
                            )
                        })?;

                    #[cfg(unix)]
                    {
                        let mut p = out
                            .metadata()
                            .map_err(|e| HostBackupError::io("temp file metadata", e))?
                            .permissions();
                        p.set_mode(0o600);
                        let _ = out.set_permissions(p);
                    }

                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        let n = entry.read(&mut buf).map_err(|e| HostBackupError::Archive {
                            archive: archive_or_dir.to_path_buf(),
                            reason: format!("reading tar entry {}: {}", raw_path, e),
                        })?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                        out.write_all(&buf[..n])
                            .map_err(|e| HostBackupError::io("writing restored entry", e))?;
                        written += n as u64;
                    }
                    out.sync_all()
                        .map_err(|e| HostBackupError::io("syncing restored file", e))?;
                }

                let actual_sha = hex::encode(hasher.finalize());
                let key = norm_rel.to_string_lossy().replace('\\', "/");
                let exp = manifest
                    .entries
                    .iter()
                    .find(|e| e.relative_path.replace('\\', "/") == key)
                    .ok_or_else(|| {
                        let _ = fs::remove_file(&temp_file_path);
                        HostBackupError::Archive {
                            archive: archive_or_dir.to_path_buf(),
                            reason: format!(
                                "archive entry '{}' is not registered in backup manifest",
                                raw_path
                            ),
                        }
                    })?;

                if !actual_sha.eq_ignore_ascii_case(&exp.sha256) {
                    let _ = fs::remove_file(&temp_file_path);
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest_path.display().to_string(),
                        expected: exp.sha256.clone(),
                        actual: actual_sha,
                    });
                }

                fs::rename(&temp_file_path, &dest_path).map_err(|e| {
                    let _ = fs::remove_file(&temp_file_path);
                    HostBackupError::io(
                        format!(
                            "atomic rename {} -> {}",
                            temp_file_path.display(),
                            dest_path.display()
                        ),
                        e,
                    )
                })?;

                restored_files.push(dest_path);
                total_bytes += written;
            }

            let mut sqlite_verified = false;
            for rf in &restored_files {
                let rf_name = rf.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if rf_name.ends_with(".sqlite") {
                    let wal = rf.with_file_name(format!("{}-wal", rf_name));
                    let shm = rf.with_file_name(format!("{}-shm", rf_name));
                    if wal.exists() {
                        let _ = fs::remove_file(&wal);
                    }
                    if shm.exists() {
                        let _ = fs::remove_file(&shm);
                    }

                    let (uv, _, _) = verify_sqlite_snapshot_integrity(rf)?;
                    if let Some(max_uv) = options.max_supported_sqlite_user_version {
                        if uv > max_uv {
                            return Err(HostBackupError::IncompatibleVersion {
                                backup_version: format!("sqlite_user_version={}", uv),
                                host_version: format!("max_sqlite_user_version={}", max_uv),
                                reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                            });
                        }
                    }
                    sqlite_verified = true;
                }
            }

            Ok(RestoreReceipt {
                backup_id: manifest.backup_id.clone(),
                target_root: normalized_root,
                restored_files,
                total_bytes,
                sqlite_verified,
                manifest,
            })
        } else if filename.ends_with(".sqlite") {
            if options.require_artifact_sidecar {
                verify_file_with_sidecar(archive_or_dir)?;
            }

            let manifest_path = archive_or_dir
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(format!("{}.manifest.json", filename));

            let manifest = if manifest_path.is_file() {
                BackupManifest::load_from_path(&manifest_path, true)?
            } else {
                let (uv, jm, ic) = verify_sqlite_snapshot_integrity(archive_or_dir)?;
                let (sha, size) = compute_file_sha256(archive_or_dir)?;

                let mut m = BackupManifest::new(&options.host_app_version, filename)?;
                m.entries.push(crate::manifest::BackupManifestEntry {
                    relative_path: filename.to_string(),
                    logical_target_path: None,
                    kind: BackupTargetKind::SqliteSnapshot,
                    sha256: sha.clone(),
                    size_bytes: size,
                    unix_mode: Some(0o600),
                    unix_uid: None,
                    unix_gid: None,
                    required: true,
                });
                m.sqlite_snapshot = Some(SqliteSnapshotMetadata {
                    snapshot_relative_path: filename.to_string(),
                    capture_method: "sqlite_snapshot".to_string(),
                    sqlite_user_version: uv,
                    journal_mode: jm,
                    integrity_check: ic,
                    size_bytes: size,
                    sha256: sha,
                });
                m
            };

            manifest.validate()?;
            manifest.check_compatibility(
                &options.host_app_version,
                options.max_supported_sqlite_user_version,
            )?;

            ensure_private_dir_all(&normalized_root, "target_root")?;
            let (dest_path, _) = plan_single_destination_with_options(
                &normalized_root,
                filename,
                Some(BackupTargetKind::SqliteSnapshot),
                None,
                None,
                options.overwrite_policy,
            )?;

            let parent = dest_path.parent().unwrap();
            ensure_private_dir_all(parent, "destination_parent")?;

            let temp_file_path = parent.join(format!(
                ".tmp_restore_{}_{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));

            let size = {
                let mut src = File::open(archive_or_dir)
                    .map_err(|e| HostBackupError::io("opening source sqlite file", e))?;
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_file_path)
                    .map_err(|e| HostBackupError::io("creating temp sqlite file", e))?;

                #[cfg(unix)]
                {
                    let mut p = out
                        .metadata()
                        .map_err(|e| HostBackupError::io("temp file metadata", e))?
                        .permissions();
                    p.set_mode(0o600);
                    let _ = out.set_permissions(p);
                }

                let mut hasher = Sha256::new();
                let mut buf = [0u8; 64 * 1024];
                let mut written = 0u64;
                loop {
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| HostBackupError::io("reading sqlite bytes", e))?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    out.write_all(&buf[..n])
                        .map_err(|e| HostBackupError::io("writing sqlite bytes", e))?;
                    written += n as u64;
                }
                out.sync_all()
                    .map_err(|e| HostBackupError::io("syncing restored sqlite", e))?;

                let actual_sha = hex::encode(hasher.finalize());
                let expected_sha = manifest
                    .entries
                    .iter()
                    .find(|e| e.relative_path == filename || e.kind == BackupTargetKind::SqliteSnapshot)
                    .map(|e| e.sha256.as_str())
                    .or_else(|| manifest.sqlite_snapshot.as_ref().map(|s| s.sha256.as_str()));
                if let Some(exp_sha) = expected_sha {
                    if !actual_sha.eq_ignore_ascii_case(exp_sha) {
                        let _ = fs::remove_file(&temp_file_path);
                        return Err(HostBackupError::ChecksumMismatch {
                            artifact: dest_path.display().to_string(),
                            expected: exp_sha.to_string(),
                            actual: actual_sha,
                        });
                    }
                }
                written
            };

            fs::rename(&temp_file_path, &dest_path).map_err(|e| {
                let _ = fs::remove_file(&temp_file_path);
                HostBackupError::io("renaming restored sqlite file", e)
            })?;

            let wal = dest_path.with_file_name(format!("{}-wal", filename));
            let shm = dest_path.with_file_name(format!("{}-shm", filename));
            if wal.exists() {
                let _ = fs::remove_file(&wal);
            }
            if shm.exists() {
                let _ = fs::remove_file(&shm);
            }

            let (uv, _, _) = verify_sqlite_snapshot_integrity(&dest_path)?;
            if let Some(max_uv) = options.max_supported_sqlite_user_version {
                if uv > max_uv {
                    return Err(HostBackupError::IncompatibleVersion {
                        backup_version: format!("sqlite_user_version={}", uv),
                        host_version: format!("max_sqlite_user_version={}", max_uv),
                        reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                    });
                }
            }

            Ok(RestoreReceipt {
                backup_id: manifest.backup_id.clone(),
                target_root: normalized_root,
                restored_files: vec![dest_path],
                total_bytes: size,
                sqlite_verified: true,
                manifest,
            })
        } else {
            Err(HostBackupError::InvalidConfig(format!(
                "unsupported backup file extension for '{}'; expected .tar.gz or .sqlite",
                filename
            )))
        }
    } else if archive_or_dir.is_dir() {
        let manifest_path = fs::read_dir(archive_or_dir)
            .map_err(|e| HostBackupError::io("reading backup directory", e))?
            .filter_map(|e| e.ok())
            .find(|e| {
                let n = e.file_name();
                let s = n.to_string_lossy();
                s.ends_with(".manifest.json") || s == "manifest.json"
            })
            .map(|e| e.path())
            .ok_or_else(|| {
                HostBackupError::InvalidManifest(format!(
                    "no .manifest.json found in backup directory '{}'",
                    archive_or_dir.display()
                ))
            })?;

        let manifest = BackupManifest::load_from_path(&manifest_path, true)?;
        preflight_restore_directory(archive_or_dir, &manifest, &normalized_root, &options)?;

        ensure_private_dir_all(&normalized_root, "target_root")?;

        let mut restored_files = Vec::new();
        let mut total_bytes = 0u64;

        for entry in &manifest.entries {
            let rel = validate_relative_backup_path(&entry.relative_path)?;
            let src_path = archive_or_dir.join(&rel);
            if !src_path.is_file() {
                if entry.required {
                    return Err(HostBackupError::PathValidation {
                        path: src_path,
                        reason: format!(
                            "required file '{}' missing in backup directory",
                            entry.relative_path
                        ),
                    });
                }
                continue;
            }

            let (dest_path, _) = plan_single_destination_with_options(
                &normalized_root,
                &entry.relative_path,
                Some(entry.kind),
                None,
                None,
                options.overwrite_policy,
            )?;
            let parent = dest_path.parent().unwrap();
            ensure_private_dir_all(parent, "destination_parent")?;

            let temp_file_path = parent.join(format!(
                ".tmp_restore_{}_{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));

            {
                let mut src = File::open(&src_path)
                    .map_err(|e| HostBackupError::io("opening source file", e))?;
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_file_path)
                    .map_err(|e| HostBackupError::io("creating temp file", e))?;

                #[cfg(unix)]
                {
                    let mut p = out
                        .metadata()
                        .map_err(|e| HostBackupError::io("temp file metadata", e))?
                        .permissions();
                    p.set_mode(0o600);
                    let _ = out.set_permissions(p);
                }

                let mut hasher = Sha256::new();
                let mut buf = [0u8; 64 * 1024];
                let mut written = 0u64;
                loop {
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| HostBackupError::io("reading file bytes", e))?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    out.write_all(&buf[..n])
                        .map_err(|e| HostBackupError::io("writing file bytes", e))?;
                    written += n as u64;
                }
                out.sync_all()
                    .map_err(|e| HostBackupError::io("syncing restored file", e))?;

                let actual_sha = hex::encode(hasher.finalize());
                if !actual_sha.eq_ignore_ascii_case(&entry.sha256) {
                    let _ = fs::remove_file(&temp_file_path);
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest_path.display().to_string(),
                        expected: entry.sha256.clone(),
                        actual: actual_sha,
                    });
                }
                total_bytes += written;
            }

            fs::rename(&temp_file_path, &dest_path).map_err(|e| {
                let _ = fs::remove_file(&temp_file_path);
                HostBackupError::io("renaming restored file", e)
            })?;

            restored_files.push(dest_path);
        }

        let mut sqlite_verified = false;
        for rf in &restored_files {
            let rf_name = rf.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if rf_name.ends_with(".sqlite") {
                let wal = rf.with_file_name(format!("{}-wal", rf_name));
                let shm = rf.with_file_name(format!("{}-shm", rf_name));
                if wal.exists() {
                    let _ = fs::remove_file(&wal);
                }
                if shm.exists() {
                    let _ = fs::remove_file(&shm);
                }

                let (uv, _, _) = verify_sqlite_snapshot_integrity(rf)?;
                if let Some(max_uv) = options.max_supported_sqlite_user_version {
                    if uv > max_uv {
                        return Err(HostBackupError::IncompatibleVersion {
                            backup_version: format!("sqlite_user_version={}", uv),
                            host_version: format!("max_sqlite_user_version={}", max_uv),
                            reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                        });
                    }
                }
                sqlite_verified = true;
            }
        }

        Ok(RestoreReceipt {
            backup_id: manifest.backup_id.clone(),
            target_root: normalized_root,
            restored_files,
            total_bytes,
            sqlite_verified,
            manifest,
        })
    } else {
        Err(HostBackupError::PathValidation {
            path: archive_or_dir.to_path_buf(),
            reason: "backup source must be a regular file or directory".to_string(),
        })
    }
}
