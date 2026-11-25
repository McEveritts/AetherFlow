use super::journal::sqlite_sidecar_paths;
use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::{BackupTargetKind, CompatibilityReport};
use crate::verify::{
    reject_if_symlink, reject_symlink_chain, validate_no_parent_traversal,
    validate_relative_backup_path,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

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
            host_app_version: crate::default_host_app_version(),
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
                || (seg_lower.starts_with(".rollback-restore.")
                    && seg_lower.contains(".journal.json"))
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

pub(super) fn validate_safe_target_root(target_root: &Path) -> HostBackupResult<PathBuf> {
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
pub const DEFAULT_MANDATORY_QUIESCE_SERVICES: &[&str] = &["aetherflow-api.service"];

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

pub(super) fn is_service_data_dir_secret_key(relative_key: &str) -> bool {
    matches!(
        relative_key,
        "var/lib/aetherflow/.master.creds" | "var/lib/aetherflow/oidc_rsa.pem"
    )
}

pub(super) fn is_service_data_dir_secret_destination(dest: &Path) -> bool {
    dest.ends_with("var/lib/aetherflow/.master.creds")
        || dest.ends_with("var/lib/aetherflow/oidc_rsa.pem")
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
        || is_service_data_dir_secret_key(&key)
        || key == "etc/aetherflow/aetherflow.env"
        || key.starts_with("etc/aetherflow/")
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
            let mapped_dest =
                if canonical_base == Path::new("/") || validated_db.starts_with(canonical_base) {
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
    let first = comps
        .next()
        .map(|comp| comp.as_os_str())
        .unwrap_or_default();
    let second = comps
        .next()
        .map(|comp| comp.as_os_str())
        .unwrap_or_default();
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
