use super::policy::{validate_safe_target_root, RestorePreflightOptions};
use super::preflight::{
    plan_single_destination_with_options, preflight_restore_directory, preflight_tar_gz_archive,
};
use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::{BackupManifest, BackupTargetKind, SqliteSnapshotMetadata};
use crate::snapshot::verify_sqlite_snapshot_integrity;
use crate::verify::{
    compute_file_sha256, ensure_private_dir_all, reject_if_symlink, reject_symlink_chain,
    validate_no_parent_traversal, validate_relative_backup_path, verify_file_with_sidecar,
};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::{Archive, EntryType};

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

                let entry_kind = manifest
                    .entries
                    .iter()
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
                                reason: "SQLite snapshot user_version exceeds host maximum"
                                    .to_string(),
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
                    .find(|e| {
                        e.relative_path == filename || e.kind == BackupTargetKind::SqliteSnapshot
                    })
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
