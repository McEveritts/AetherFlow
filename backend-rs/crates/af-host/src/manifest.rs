//! Typed versioned backup manifest (`af-host.backup-manifest.v1`) and compatibility checks.
//!
//! Covers both SQLite snapshot backups (`af-api`, `af-services`, `af-release`) and
//! multi-target host configuration archives (`packages/system/af-backup`), ensuring
//! every backup entry records its relative path, kind, SHA-256 digest, byte size,
//! and schema/application version metadata.

use crate::error::{HostBackupError, HostBackupResult};
use crate::verify::{
    compute_file_sha256, reject_if_symlink, validate_backup_filename, validate_no_parent_traversal,
    validate_relative_backup_path, write_private_file_atomic,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Canonical schema identifier for `af-host` backup manifests.
pub const BACKUP_MANIFEST_FORMAT: &str = "af-host.backup-manifest.v1";

/// Current manifest schema version emitted by `af-host`.
pub const CURRENT_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Minimum manifest schema version supported by this build of `af-host`.
pub const MIN_SUPPORTED_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Maximum manifest schema version supported by this build of `af-host`.
pub const MAX_SUPPORTED_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Default supported AetherFlow major version line (`4` for `v4.x`).
pub const SUPPORTED_APP_MAJOR_VERSION: u32 = 4;

/// Classification of an individual item recorded inside a backup manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupTargetKind {
    /// Consistent SQLite database snapshot created via `VACUUM INTO` or SQLite Online Backup API.
    SqliteSnapshot,
    /// Host or application configuration file (e.g., `/etc/aetherflow/aetherflow.env`, `.rtorrent.rc`).
    ConfigFile,
    /// Host configuration directory tree entry (e.g., `/etc/AetherFlow/...`).
    ConfigDirectoryEntry,
    /// Bundled `.tar.gz` archive containing verified configuration targets.
    TarGzArchive,
}

/// Metadata for a single verified file entry inside a [`BackupManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifestEntry {
    /// Normalized relative path inside the backup root or archive (never leading `/`, never `..`).
    pub relative_path: String,
    /// Optional logical host destination path on a standard FHS AetherFlow system (informational;
    /// restore planning always binds relative to the caller's configured target root).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub logical_target_path: Option<String>,
    /// Entry classification (`sqlite_snapshot`, `config_file`, `config_directory_entry`, `tar_gz_archive`).
    pub kind: BackupTargetKind,
    /// Lowercase 64-character hex SHA-256 digest of the file payload.
    pub sha256: String,
    /// Exact payload size in bytes.
    pub size_bytes: u64,
    /// Optional POSIX octal permissions mode (e.g., `0o600` or `0o644`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unix_mode: Option<u32>,
    /// Whether this entry is mandatory for the backup to be considered complete.
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool {
    true
}

impl BackupManifestEntry {
    /// Validates that `relative_path` is safe, `sha256` is well-formed, and `logical_target_path`
    /// (if present) contains no parent traversal or NUL bytes.
    pub fn validate(&self) -> HostBackupResult<PathBuf> {
        let rel = validate_relative_backup_path(&self.relative_path)?;
        if self.sha256.len() != 64 || !self.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(HostBackupError::InvalidManifest(format!(
                "entry '{}' has invalid SHA-256 digest {:?}",
                self.relative_path, self.sha256
            )));
        }
        if let Some(ref logical) = self.logical_target_path {
            if logical.contains('\0') || logical.contains("..") {
                return Err(HostBackupError::TraversalRejected {
                    path: logical.clone(),
                    reason: "logical_target_path must not contain '..' or NUL bytes".to_string(),
                });
            }
        }
        Ok(rel)
    }
}

/// SQLite snapshot provenance recorded inside a [`BackupManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqliteSnapshotMetadata {
    /// Relative path to the snapshot file within the backup root.
    pub snapshot_relative_path: String,
    /// Method used to capture the consistent snapshot (`vacuum_into` or `online_backup_api`).
    pub capture_method: String,
    /// SQLite `PRAGMA user_version` recorded at snapshot time.
    pub sqlite_user_version: i64,
    /// SQLite `PRAGMA journal_mode` of the snapshot file.
    pub journal_mode: String,
    /// Result of running `PRAGMA quick_check` on the snapshot (`ok`).
    pub integrity_check: String,
    /// Byte size of the consistent SQLite snapshot file.
    pub size_bytes: u64,
    /// Lowercase SHA-256 hex digest of the snapshot file.
    pub sha256: String,
}

/// Typed, versioned backup manifest (`af-host.backup-manifest.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Fixed format identifier (`"af-host.backup-manifest.v1"`).
    pub format: String,
    /// Schema version number (`1`).
    pub schema_version: u32,
    /// Unique backup identifier (UUID v4 or deterministic backup slug).
    pub backup_id: String,
    /// RFC-3339 UTC timestamp when the backup was created.
    pub created_at: String,
    /// AetherFlow application version that created the backup (e.g., `"v4.0.0"` or `"4.0.0"`).
    pub app_version: String,
    /// Minimum AetherFlow application version compatible with this backup (e.g., `"4.0.0"`).
    pub min_compatible_app_version: String,
    /// Operating system / architecture tuple (e.g., `"linux/x86_64"`).
    pub host_platform: String,
    /// Primary artifact filename associated with this manifest (e.g., `"aetherflow-backup-2026-10-31.tar.gz"`
    /// or `"aetherflow_2026-10-31_12-00-00.sqlite"`).
    pub primary_artifact: String,
    /// Optional consistent SQLite database snapshot metadata.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sqlite_snapshot: Option<SqliteSnapshotMetadata>,
    /// Ordered list of all verified files included in the backup.
    pub entries: Vec<BackupManifestEntry>,
    /// Optional chunk count (`0` when unchunked).
    #[serde(default)]
    pub chunk_count: usize,
    /// Optional chunk size in bytes when split via `af-backup chunk`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chunk_size_bytes: Option<u64>,
}

/// Result of checking a [`BackupManifest`] for schema, structural, and version compatibility
/// against the current host runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub compatible: bool,
    pub manifest_schema_version: u32,
    pub backup_app_version: String,
    pub host_app_version: String,
    pub entry_count: usize,
    pub has_sqlite_snapshot: bool,
    pub warnings: Vec<String>,
}

impl BackupManifest {
    /// Constructs a new `v1` backup manifest for `app_version` and `primary_artifact`.
    pub fn new(
        app_version: impl Into<String>,
        primary_artifact: impl Into<String>,
    ) -> HostBackupResult<Self> {
        let primary = validate_backup_filename(&primary_artifact.into())?;
        let app_ver = app_version.into();
        let parsed_ver = parse_semver_triplet(&app_ver)?;

        Ok(Self {
            format: BACKUP_MANIFEST_FORMAT.to_string(),
            schema_version: CURRENT_MANIFEST_SCHEMA_VERSION,
            backup_id: uuid::Uuid::new_v4().to_string(),
            created_at: Utc::now().to_rfc3339(),
            app_version: app_ver,
            min_compatible_app_version: format!("{}.0.0", parsed_ver.0),
            host_platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            primary_artifact: primary,
            sqlite_snapshot: None,
            entries: Vec::new(),
            chunk_count: 0,
            chunk_size_bytes: None,
        })
    }

    /// Adds a verified file entry to the manifest, computing its SHA-256 and size from disk.
    pub fn add_file_from_disk(
        &mut self,
        relative_path: impl Into<String>,
        disk_path: &Path,
        kind: BackupTargetKind,
        logical_target_path: Option<String>,
        required: bool,
    ) -> HostBackupResult<&BackupManifestEntry> {
        let rel_str = relative_path.into();
        let _ = validate_relative_backup_path(&rel_str)?;
        reject_if_symlink(disk_path, "manifest source file")?;

        let (sha256, size_bytes) = compute_file_sha256(disk_path)?;
        #[cfg(unix)]
        let unix_mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::symlink_metadata(disk_path)
                .ok()
                .map(|m| m.permissions().mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let unix_mode = None;

        let entry = BackupManifestEntry {
            relative_path: rel_str,
            logical_target_path,
            kind,
            sha256,
            size_bytes,
            unix_mode,
            required,
        };
        entry.validate()?;
        self.entries.push(entry);
        Ok(self.entries.last().expect("entry just pushed"))
    }

    /// Validates the structural integrity, schema version, path safety, chunk metadata,
    /// and cross-consistency of `sqlite_snapshot` against `entries`.
    pub fn validate(&self) -> HostBackupResult<()> {
        if self.format != BACKUP_MANIFEST_FORMAT {
            return Err(HostBackupError::InvalidManifest(format!(
                "unsupported manifest format {:?} (expected {:?})",
                self.format, BACKUP_MANIFEST_FORMAT
            )));
        }
        if self.schema_version < MIN_SUPPORTED_MANIFEST_SCHEMA_VERSION
            || self.schema_version > MAX_SUPPORTED_MANIFEST_SCHEMA_VERSION
        {
            return Err(HostBackupError::IncompatibleManifest {
                found: self.schema_version,
                min: MIN_SUPPORTED_MANIFEST_SCHEMA_VERSION,
                max: MAX_SUPPORTED_MANIFEST_SCHEMA_VERSION,
                reason: "manifest schema version is outside the supported range".to_string(),
            });
        }
        if self.backup_id.trim().is_empty() {
            return Err(HostBackupError::InvalidManifest(
                "backup_id must not be empty".to_string(),
            ));
        }
        validate_backup_filename(&self.primary_artifact)?;
        let _ = parse_semver_triplet(&self.app_version)?;
        let _ = parse_semver_triplet(&self.min_compatible_app_version)?;

        if self.entries.is_empty() {
            return Err(HostBackupError::InvalidManifest(
                "backup manifest must contain at least one entry".to_string(),
            ));
        }

        if let Some(chunk_sz) = self.chunk_size_bytes {
            if chunk_sz == 0 {
                return Err(HostBackupError::InvalidManifest(
                    "chunk_size_bytes must be greater than zero when specified".to_string(),
                ));
            }
            if self.chunk_count == 0 {
                return Err(HostBackupError::InvalidManifest(
                    "chunk_count must be greater than zero when chunk_size_bytes is set"
                        .to_string(),
                ));
            }
        } else if self.chunk_count > 0 {
            return Err(HostBackupError::InvalidManifest(
                "chunk_size_bytes must be specified when chunk_count > 0".to_string(),
            ));
        }

        let mut seen_paths = HashSet::new();
        for entry in &self.entries {
            let norm = entry.validate()?;
            let key = norm.to_string_lossy().replace('\\', "/");
            if !seen_paths.insert(key) {
                return Err(HostBackupError::InvalidManifest(format!(
                    "duplicate manifest entry relative_path '{}'",
                    entry.relative_path
                )));
            }
        }

        if let Some(ref snap) = self.sqlite_snapshot {
            let snap_norm = validate_relative_backup_path(&snap.snapshot_relative_path)?;
            let snap_key = snap_norm.to_string_lossy().replace('\\', "/");
            if snap.sha256.len() != 64 || !snap.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(HostBackupError::InvalidManifest(
                    "sqlite_snapshot has invalid SHA-256 digest".to_string(),
                ));
            }
            if snap.sqlite_user_version < 0 {
                return Err(HostBackupError::InvalidManifest(
                    "sqlite_user_version cannot be negative".to_string(),
                ));
            }
            if !snap.integrity_check.eq_ignore_ascii_case("ok") {
                return Err(HostBackupError::SqliteIntegrity {
                    db_path: PathBuf::from(&snap.snapshot_relative_path),
                    detail: snap.integrity_check.clone(),
                });
            }
            if snap.capture_method != "vacuum_into" && snap.capture_method != "online_backup_api" {
                return Err(HostBackupError::InvalidManifest(format!(
                    "unsupported sqlite_snapshot capture_method {:?} (plain file copies of live DBs are forbidden)",
                    snap.capture_method
                )));
            }

            let matching_entry = self
                .entries
                .iter()
                .find(|e| e.relative_path.replace('\\', "/") == snap_key)
                .ok_or_else(|| {
                    HostBackupError::InvalidManifest(format!(
                        "sqlite_snapshot '{}' has no matching entry in manifest.entries",
                        snap.snapshot_relative_path
                    ))
                })?;

            if matching_entry.kind != BackupTargetKind::SqliteSnapshot {
                return Err(HostBackupError::InvalidManifest(format!(
                    "manifest entry '{}' matching sqlite_snapshot must have kind SqliteSnapshot (found {:?})",
                    matching_entry.relative_path, matching_entry.kind
                )));
            }
            if !matching_entry.sha256.eq_ignore_ascii_case(&snap.sha256) {
                return Err(HostBackupError::ChecksumMismatch {
                    artifact: snap.snapshot_relative_path.clone(),
                    expected: snap.sha256.to_ascii_lowercase(),
                    actual: matching_entry.sha256.to_ascii_lowercase(),
                });
            }
            if matching_entry.size_bytes != snap.size_bytes {
                return Err(HostBackupError::InvalidManifest(format!(
                    "sqlite_snapshot '{}' size_bytes ({}) does not match manifest entry size_bytes ({})",
                    snap.snapshot_relative_path, snap.size_bytes, matching_entry.size_bytes
                )));
            }
        }

        for entry in &self.entries {
            if entry.kind == BackupTargetKind::SqliteSnapshot {
                let entry_key = entry.relative_path.replace('\\', "/");
                match self.sqlite_snapshot {
                    Some(ref snap)
                        if snap.snapshot_relative_path.replace('\\', "/") == entry_key => {}
                    _ => {
                        return Err(HostBackupError::InvalidManifest(format!(
                            "manifest entry '{}' has kind SqliteSnapshot but does not match sqlite_snapshot metadata",
                            entry.relative_path
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Evaluates schema and application version compatibility against `host_app_version`
    /// (and optional `max_supported_sqlite_user_version`).
    pub fn check_compatibility(
        &self,
        host_app_version: &str,
        max_supported_sqlite_user_version: Option<i64>,
    ) -> HostBackupResult<CompatibilityReport> {
        self.validate()?;

        let backup_ver = parse_semver_triplet(&self.app_version)?;
        let min_compat_ver = parse_semver_triplet(&self.min_compatible_app_version)?;
        let host_ver = parse_semver_triplet(host_app_version)?;

        // Major version must match and host version must be >= min_compatible_app_version
        if backup_ver.0 != host_ver.0 {
            return Err(HostBackupError::IncompatibleVersion {
                backup_version: self.app_version.clone(),
                host_version: host_app_version.to_string(),
                reason: format!(
                    "backup major version {} does not match host major version {}",
                    backup_ver.0, host_ver.0
                ),
            });
        }

        if host_ver < min_compat_ver {
            return Err(HostBackupError::IncompatibleVersion {
                backup_version: self.app_version.clone(),
                host_version: host_app_version.to_string(),
                reason: format!(
                    "host version {} is older than manifest min_compatible_app_version {}",
                    host_app_version, self.min_compatible_app_version
                ),
            });
        }

        // Prevent restoring a backup from a newer minor/patch onto an older host binary
        if backup_ver > host_ver {
            return Err(HostBackupError::IncompatibleVersion {
                backup_version: self.app_version.clone(),
                host_version: host_app_version.to_string(),
                reason: format!(
                    "backup was created by newer AetherFlow version {} than running host {}",
                    self.app_version, host_app_version
                ),
            });
        }

        let mut warnings = Vec::new();
        if let Some(ref snap) = self.sqlite_snapshot {
            if snap.sqlite_user_version < 0 {
                return Err(HostBackupError::InvalidManifest(
                    "sqlite_user_version cannot be negative".to_string(),
                ));
            }
            if let Some(max_uv) = max_supported_sqlite_user_version {
                if snap.sqlite_user_version > max_uv {
                    return Err(HostBackupError::IncompatibleVersion {
                        backup_version: format!("sqlite_user_version={}", snap.sqlite_user_version),
                        host_version: format!("max_sqlite_user_version={}", max_uv),
                        reason: "backup SQLite schema user_version is newer than supported by this host".to_string(),
                    });
                }
            }
        }

        let current_platform = format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH);
        if !self.host_platform.is_empty() && self.host_platform != current_platform {
            warnings.push(format!(
                "backup was created on platform '{}' (current host is '{}')",
                self.host_platform, current_platform
            ));
        }

        Ok(CompatibilityReport {
            compatible: true,
            manifest_schema_version: self.schema_version,
            backup_app_version: self.app_version.clone(),
            host_app_version: host_app_version.to_string(),
            entry_count: self.entries.len(),
            has_sqlite_snapshot: self.sqlite_snapshot.is_some(),
            warnings,
        })
    }

    /// Atomically writes the manifest JSON to `manifest_path` with `0600` permissions
    /// and creates a `.sha256` sidecar.
    pub fn save_atomic(&self, manifest_path: &Path) -> HostBackupResult<PathBuf> {
        self.validate()?;
        validate_no_parent_traversal(manifest_path, "manifest path")?;
        reject_if_symlink(manifest_path, "manifest path")?;

        let payload = serde_json::to_vec_pretty(self).map_err(|e| {
            HostBackupError::InvalidManifest(format!("failed to serialize manifest: {}", e))
        })?;
        write_private_file_atomic(manifest_path, &payload, "manifest-tmp", "manifest file")?;

        let (sidecar_path, _, _) = crate::verify::write_sha256_sidecar(manifest_path)?;
        Ok(sidecar_path)
    }

    /// Loads and validates a [`BackupManifest`] from disk. If a `.sha256` sidecar is present
    /// alongside `manifest_path` (or `require_sidecar` is `true`), verifies the manifest's
    /// SHA-256 digest before parsing JSON.
    pub fn load_from_path(manifest_path: &Path, require_sidecar: bool) -> HostBackupResult<Self> {
        validate_no_parent_traversal(manifest_path, "manifest file")?;
        reject_if_symlink(manifest_path, "manifest file")?;
        let sidecar = crate::verify::checksum_sidecar_path(manifest_path);
        if require_sidecar || sidecar.exists() {
            crate::verify::verify_file_with_sidecar(manifest_path)?;
        }

        let raw = fs::read_to_string(manifest_path).map_err(|e| {
            HostBackupError::io(format!("reading manifest {}", manifest_path.display()), e)
        })?;
        let manifest: Self = serde_json::from_str(&raw).map_err(|e| {
            HostBackupError::InvalidManifest(format!(
                "failed to parse manifest {}: {}",
                manifest_path.display(),
                e
            ))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Parses a semantic version string such as `"v4.0.0"`, `"4.1.2-nightly"`, or `"4.0"`
/// into `(major, minor, patch)`.
pub fn parse_semver_triplet(raw: &str) -> HostBackupResult<(u32, u32, u32)> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    if trimmed.is_empty() {
        return Err(HostBackupError::InvalidManifest(
            "version string must not be empty".to_string(),
        ));
    }
    let core = trimmed
        .split(['-', '+'])
        .next()
        .unwrap_or(trimmed)
        .trim();
    let mut parts = core.split('.');
    let major_str = parts.next().unwrap_or("");
    let minor_str = parts.next().unwrap_or("0");
    let patch_str = parts.next().unwrap_or("0");

    if parts.next().is_some() {
        return Err(HostBackupError::InvalidManifest(format!(
            "invalid semantic version format: {:?}",
            raw
        )));
    }

    let major = major_str.parse::<u32>().map_err(|_| {
        HostBackupError::InvalidManifest(format!("invalid major version in {:?}", raw))
    })?;
    let minor = minor_str.parse::<u32>().map_err(|_| {
        HostBackupError::InvalidManifest(format!("invalid minor version in {:?}", raw))
    })?;
    let patch = patch_str.parse::<u32>().map_err(|_| {
        HostBackupError::InvalidManifest(format!("invalid patch version in {:?}", raw))
    })?;

    Ok((major, minor, patch))
}
