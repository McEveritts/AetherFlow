use super::parse_ops::parse_byte_size_arg;
use super::{BackupCliCommand, BackupCreateKind};
use crate::commands::backup::resolve_runtime_host_version;
use crate::error::{CliError, CliResult};
use af_host::OverwritePolicy;
use std::path::{Path, PathBuf};

pub(super) fn parse_backup_subcommand(
    args: &[String],
    isolated_root: Option<&Path>,
) -> CliResult<BackupCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af backup <create|list|verify|restore-preflight|restore|delete|prune|chunk|assemble|ownership> [options]".to_string(),
        ));
    };
    let tail = &args[1..];

    match sub {
        "create" => {
            let mut kind = BackupCreateKind::Archive;
            let mut backup_dir: Option<PathBuf> = None;
            let mut db_path: Option<PathBuf> = None;
            let mut app_version = resolve_runtime_host_version(isolated_root);
            let mut chunk_size_bytes: Option<u64> = None;
            let mut timestamp_slug: Option<String> = None;
            let mut operator_privileged = false;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut trusted_sqlite_gid: Option<u32> = None;

            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--sqlite-only" | "--db-only" => {
                        kind = BackupCreateKind::Sqlite;
                        i += 1;
                    }
                    "--archive" => {
                        kind = BackupCreateKind::Archive;
                        i += 1;
                    }
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--db-path" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--db-path requires a SQLite file path".to_string())
                        })?;
                        db_path = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--app-version" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--app-version requires a semver string".to_string())
                        })?;
                        let _ = af_host::parse_semver_triplet(val)?;
                        app_version = val.clone();
                        i += 2;
                    }
                    "--chunk-size" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--chunk-size requires a size (e.g. 50M or 1048576)".to_string())
                        })?;
                        chunk_size_bytes = Some(parse_byte_size_arg(val)?);
                        i += 2;
                    }
                    "--timestamp" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--timestamp requires a slug".to_string())
                        })?;
                        timestamp_slug = Some(val.clone());
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    "--trusted-sqlite-gid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-gid requires a numeric GID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-gid {:?}", val))
                        })?;
                        trusted_sqlite_gid = Some(parsed);
                        i += 2;
                    }
                    other => {
                        if !other.starts_with('-') && chunk_size_bytes.is_none() {
                            chunk_size_bytes = Some(parse_byte_size_arg(other)?);
                            i += 1;
                        } else {
                            return Err(CliError::Usage(format!(
                                "unknown argument for 'af backup create': {}",
                                other
                            )));
                        }
                    }
                }
            }

            Ok(BackupCliCommand::Create {
                kind,
                backup_dir,
                db_path,
                app_version,
                chunk_size_bytes,
                timestamp_slug,
                operator_privileged,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
            })
        }
        "list" | "ls" => {
            let mut backup_dir: Option<PathBuf> = None;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unknown argument for 'af backup list': {}",
                            other
                        )));
                    }
                }
            }
            Ok(BackupCliCommand::List { backup_dir })
        }
        "verify" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup verify': {}",
                            other
                        )));
                    }
                }
            }
            let filename = filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup verify <filename> [--backup-dir <dir>]".to_string(),
                )
            })?;
            Ok(BackupCliCommand::Verify {
                filename,
                backup_dir,
                trusted_sqlite_uid,
            })
        }
        "restore-preflight" | "plan-restore" | "preflight" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut target_root: Option<PathBuf> = None;
            let mut host_version = resolve_runtime_host_version(isolated_root);
            let mut max_sqlite_user_version: Option<i64> = None;
            let mut overwrite_policy = OverwritePolicy::RejectExisting;
            let mut trusted_sqlite_uid: Option<u32> = None;

            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--target-root" | "--staging-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--target-root requires a staging directory path".to_string())
                        })?;
                        target_root = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--host-version" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--host-version requires a semver string".to_string())
                        })?;
                        let _ = af_host::parse_semver_triplet(val)?;
                        host_version = val.clone();
                        i += 2;
                    }
                    "--max-sqlite-user-version" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--max-sqlite-user-version requires an integer".to_string())
                        })?;
                        let parsed = val.parse::<i64>().map_err(|_| {
                            CliError::Validation(format!(
                                "invalid --max-sqlite-user-version {:?}",
                                val
                            ))
                        })?;
                        max_sqlite_user_version = Some(parsed);
                        i += 2;
                    }
                    "--allow-staging-overwrite" | "--allow-overwrite" => {
                        overwrite_policy = OverwritePolicy::AllowRegularFilesInStaging;
                        i += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup restore-preflight': {}",
                            other
                        )));
                    }
                }
            }

            let filename = filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup restore-preflight <filename> --target-root <staging_dir> [--backup-dir <dir>]".to_string(),
                )
            })?;
            let target_root = target_root.ok_or_else(|| {
                CliError::Usage(
                    "af backup restore-preflight requires --target-root <staging_dir>".to_string(),
                )
            })?;

            Ok(BackupCliCommand::RestorePreflight {
                filename,
                backup_dir,
                target_root,
                host_version,
                max_sqlite_user_version,
                overwrite_policy,
                trusted_sqlite_uid,
            })
        }
        "restore" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut target_root: Option<PathBuf> = None;
            let mut confirm_destructive_restore = false;
            let mut allow_overwrite = false;
            let mut operator_privileged = false;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut trusted_sqlite_gid: Option<u32> = None;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--target-root" | "--staging-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--target-root requires a directory path".to_string())
                        })?;
                        target_root = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--confirm-destructive-restore" | "--confirm" => {
                        confirm_destructive_restore = true;
                        i += 1;
                    }
                    "--allow-overwrite" | "--allow-staging-overwrite" => {
                        allow_overwrite = true;
                        i += 1;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    "--trusted-sqlite-gid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-gid requires a numeric GID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-gid {:?}", val))
                        })?;
                        trusted_sqlite_gid = Some(parsed);
                        i += 2;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            let filename = filename.unwrap_or_else(|| "unspecified".to_string());
            Ok(BackupCliCommand::RestoreDestructive {
                filename,
                backup_dir,
                target_root,
                confirm_destructive_restore,
                allow_overwrite,
                operator_privileged,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
            })
        }
        "delete" | "rm" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup delete': {}",
                            other
                        )));
                    }
                }
            }
            let filename = filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup delete <filename> [--backup-dir <dir>]".to_string(),
                )
            })?;
            Ok(BackupCliCommand::Delete {
                filename,
                backup_dir,
                operator_privileged,
            })
        }
        "prune" => {
            let mut backup_dir: Option<PathBuf> = None;
            let mut max_retained = af_host::DEFAULT_MAX_RETAINED_BACKUPS;
            let mut retention_days = af_host::DEFAULT_RETENTION_DAYS;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--max-retained" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--max-retained requires an integer".to_string())
                        })?;
                        max_retained = val.parse::<usize>().map_err(|_| {
                            CliError::Validation(format!("invalid --max-retained {:?}", val))
                        })?;
                        i += 2;
                    }
                    "--retention-days" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--retention-days requires an integer".to_string())
                        })?;
                        retention_days = val.parse::<i64>().map_err(|_| {
                            CliError::Validation(format!("invalid --retention-days {:?}", val))
                        })?;
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup prune': {}",
                            other
                        )));
                    }
                }
            }
            Ok(BackupCliCommand::Prune {
                backup_dir,
                max_retained,
                retention_days,
                operator_privileged,
            })
        }
        "chunk" => {
            let mut filename: Option<String> = None;
            let mut chunk_size_bytes: Option<u64> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--size" | "--chunk-size" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--size requires a byte size".to_string())
                        })?;
                        chunk_size_bytes = Some(parse_byte_size_arg(val)?);
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        if filename.is_none() {
                            filename = Some(af_host::validate_backup_filename(arg)?);
                        } else if chunk_size_bytes.is_none() {
                            chunk_size_bytes = Some(parse_byte_size_arg(arg)?);
                        } else {
                            return Err(CliError::Usage(format!(
                                "unexpected argument for 'af backup chunk': {}",
                                arg
                            )));
                        }
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup chunk': {}",
                            other
                        )));
                    }
                }
            }
            let filename = filename.ok_or_else(|| {
                CliError::Usage("usage: af backup chunk <filename> <size>".to_string())
            })?;
            let chunk_size_bytes = chunk_size_bytes.unwrap_or(50 * 1024 * 1024);
            Ok(BackupCliCommand::Chunk {
                filename,
                chunk_size_bytes,
                backup_dir,
                operator_privileged,
            })
        }
        "assemble" => {
            let mut output_filename: Option<String> = None;
            let mut expected_sha256: Option<String> = None;
            let mut chunks: Vec<PathBuf> = Vec::new();
            let mut backup_dir: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--output" | "-o" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--output requires a filename".to_string())
                        })?;
                        output_filename = Some(af_host::validate_backup_filename(val)?);
                        i += 2;
                    }
                    "--sha256" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--sha256 requires a 64-character hex digest".to_string())
                        })?;
                        expected_sha256 = Some(val.trim().to_ascii_lowercase());
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        chunks.push(PathBuf::from(arg));
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup assemble': {}",
                            other
                        )));
                    }
                }
            }
            let output_filename = output_filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup assemble --output <filename> --sha256 <hex> <chunk1> [chunk2...]".to_string(),
                )
            })?;
            let expected_sha256 = expected_sha256.ok_or_else(|| {
                CliError::Usage("af backup assemble requires --sha256 <hex>".to_string())
            })?;
            if chunks.is_empty() {
                return Err(CliError::Usage(
                    "af backup assemble requires at least one chunk file path".to_string(),
                ));
            }
            Ok(BackupCliCommand::Assemble {
                output_filename,
                expected_sha256,
                chunks,
                backup_dir,
                operator_privileged,
            })
        }
        "recover" | "recover-interrupted" => {
            let mut backup_dir: Option<PathBuf> = None;
            let mut target_root: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut trusted_sqlite_gid: Option<u32> = None;
            let mut index = 0usize;
            while index < tail.len() {
                match tail[index].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        index += 2;
                    }
                    "--target-root" | "--staging-dir" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--target-root requires a directory path".to_string())
                        })?;
                        target_root = Some(PathBuf::from(val));
                        index += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        index += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        index += 2;
                    }
                    "--trusted-sqlite-gid" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-gid requires a numeric GID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-gid {:?}", val))
                        })?;
                        trusted_sqlite_gid = Some(parsed);
                        index += 2;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup {}': {}",
                            sub, other
                        )));
                    }
                }
            }
            Ok(BackupCliCommand::RecoverInterrupted {
                backup_dir,
                target_root,
                operator_privileged,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
            })
        }
        "ownership" | "registry" => Ok(BackupCliCommand::OwnershipRegistry),
        other => Err(CliError::Usage(format!(
            "unknown backup subcommand {:?} (expected: create, list, verify, restore-preflight, restore, recover, delete, prune, chunk, assemble, ownership)",
            other
        ))),
    }
}
