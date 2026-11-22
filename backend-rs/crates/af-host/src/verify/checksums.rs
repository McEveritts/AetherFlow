use super::dirfd::open_existing_regular_file_nofollow;
use super::paths::{
    create_private_new_file, create_unique_private_temp_file, ensure_private_dir_all,
    parse_exact_chunk_index, reject_if_symlink, sync_parent_directory,
    validate_no_parent_traversal, write_private_file_atomic,
};
use crate::error::{HostBackupError, HostBackupResult};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Strict 64-character hexadecimal SHA-256 digest matcher.
static SHA256_HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-fA-F]{64}$").unwrap());

/// Result of verifying a file against an expected SHA-256 digest or `.sha256` sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumVerification {
    pub artifact_path: PathBuf,
    pub sidecar_path: Option<PathBuf>,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub size_bytes: u64,
    pub verified: bool,
}

/// Returns the canonical `.sha256` sidecar path for `file_path` (`<file_path>.sha256`).
pub fn checksum_sidecar_path(file_path: &Path) -> PathBuf {
    let mut os = file_path.as_os_str().to_os_string();
    os.push(".sha256");
    PathBuf::from(os)
}

/// Computes the lowercase hexadecimal SHA-256 digest and byte size of `file_path`
/// using a streaming 64 KiB buffer. Rejects symlinks (including ancestor symlinks) before opening.
pub fn compute_file_sha256(file_path: &Path) -> HostBackupResult<(String, u64)> {
    let Some((mut file, _)) =
        open_verified_regular_file_for_read(file_path, None, "checksummed file")?
    else {
        return Err(HostBackupError::io(
            format!("opening {}", file_path.display()),
            std::io::Error::new(std::io::ErrorKind::NotFound, "checksummed file not found"),
        ));
    };
    compute_reader_sha256(&mut file, file_path)
}

pub(crate) fn compute_reader_sha256<R: Read>(
    reader: &mut R,
    file_path: &Path,
) -> HostBackupResult<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let count = reader
            .read(&mut buf)
            .map_err(|err| HostBackupError::io(format!("reading {}", file_path.display()), err))?;
        if count == 0 {
            break;
        }
        hasher.update(&buf[..count]);
        total_bytes += count as u64;
    }

    Ok((hex::encode(hasher.finalize()), total_bytes))
}

pub fn open_verified_regular_file_for_read(
    path: &Path,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<Option<(File, u64)>> {
    validate_no_parent_traversal(path, context)?;
    let resolved_abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        reject_if_symlink(path, context)?;
        let cwd = std::env::current_dir().map_err(|err| {
            HostBackupError::io(
                format!(
                    "resolving current working directory for {} ({})",
                    path.display(),
                    context
                ),
                err,
            )
        })?;
        cwd.join(path)
    };
    let Some((file, _, _, _)) =
        open_existing_regular_file_nofollow(&resolved_abs, extra_trusted_uid, context)?
    else {
        return Ok(None);
    };
    #[cfg(unix)]
    let byte_len = {
        use std::os::unix::io::AsRawFd;
        let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st_buf) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat {} ({})", path.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if st_buf.st_nlink == 0 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} was unlinked during open", context),
            });
        }
        st_buf.st_size.max(0) as u64
    };
    #[cfg(not(unix))]
    let byte_len = file
        .metadata()
        .map_err(|err| {
            HostBackupError::io(format!("metadata {} ({})", path.display(), context), err)
        })?
        .len();
    Ok(Some((file, byte_len)))
}

pub fn read_verified_text_file_nofollow(
    path: &Path,
    extra_trusted_uid: Option<u32>,
    max_bytes: u64,
    context: &str,
) -> HostBackupResult<Option<String>> {
    let Some((file, byte_len)) =
        open_verified_regular_file_for_read(path, extra_trusted_uid, context)?
    else {
        return Ok(None);
    };
    if byte_len > max_bytes {
        return Err(HostBackupError::InvalidManifest(format!(
            "{} '{}' exceeds maximum allowed size ({} > {} bytes)",
            context,
            path.display(),
            byte_len,
            max_bytes
        )));
    }
    let mut raw_bytes = Vec::new();
    let mut bounded = file.take(max_bytes.saturating_add(1));
    bounded.read_to_end(&mut raw_bytes).map_err(|err| {
        HostBackupError::io(format!("reading {} ({})", path.display(), context), err)
    })?;
    if raw_bytes.len() as u64 > max_bytes {
        return Err(HostBackupError::InvalidManifest(format!(
            "{} '{}' exceeds maximum allowed size ({} bytes)",
            context,
            path.display(),
            max_bytes
        )));
    }
    String::from_utf8(raw_bytes)
        .map_err(|_| {
            HostBackupError::InvalidManifest(format!(
                "{} '{}' contains invalid UTF-8 bytes (contents redacted)",
                context,
                path.display()
            ))
        })
        .map(Some)
}

/// Parses a `.sha256` sidecar content string.
///
/// Supports both GNU coreutils `sha256sum` output (`<hex>  <filename>` or `<hex> *<filename>`)
/// emitted by `packages/system/af-backup` and bare `<hex>\n` sidecars emitted by `af-api`/`af-services`.
pub fn parse_sha256_sidecar_str(content: &str) -> HostBackupResult<String> {
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let first_token = line.split_whitespace().next().unwrap_or("");
        if SHA256_HEX_RE.is_match(first_token) {
            return Ok(first_token.to_ascii_lowercase());
        }
        return Err(HostBackupError::InvalidManifest(format!(
            "malformed SHA-256 digest in sidecar (expected 64 hex characters, got {} characters; token redacted)",
            first_token.chars().count()
        )));
    }

    Err(HostBackupError::InvalidManifest(
        "empty SHA-256 sidecar file".to_string(),
    ))
}

/// Writes a GNU `sha256sum`-compatible `.sha256` sidecar file (`<sha256>  <basename>\n`)
/// atomically for `file_path` (using a `0600` UUID-suffixed temporary file) and returns
/// `(sidecar_path, sha256_hex, size_bytes)`.
pub fn write_sha256_sidecar(file_path: &Path) -> HostBackupResult<(PathBuf, String, u64)> {
    let (digest, size_bytes) = compute_file_sha256(file_path)?;
    let sidecar = checksum_sidecar_path(file_path);
    reject_if_symlink(&sidecar, "checksum sidecar")?;

    let basename = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    let formatted = format!("{}  {}\n", digest, basename);

    write_private_file_atomic(
        &sidecar,
        formatted.as_bytes(),
        "sidecar-tmp",
        "checksum sidecar",
    )?;

    Ok((sidecar, digest, size_bytes))
}

/// Verifies `file_path` against an explicit expected SHA-256 hex digest.
pub fn verify_file_sha256(
    file_path: &Path,
    expected_sha256: &str,
) -> HostBackupResult<ChecksumVerification> {
    verify_file_sha256_with_trusted_uid(file_path, expected_sha256, None)
}

/// Variant of [`verify_file_sha256`] that accepts an explicit caller-configured `trusted_uid`.
pub fn verify_file_sha256_with_trusted_uid(
    file_path: &Path,
    expected_sha256: &str,
    trusted_uid: Option<u32>,
) -> HostBackupResult<ChecksumVerification> {
    let expected_clean = expected_sha256.trim().to_ascii_lowercase();
    if !SHA256_HEX_RE.is_match(&expected_clean) {
        return Err(HostBackupError::InvalidManifest(format!(
            "expected SHA-256 is not a valid 64-char hex digest (length={}; value redacted)",
            expected_clean.chars().count()
        )));
    }

    let Some((mut file, _)) =
        open_verified_regular_file_for_read(file_path, trusted_uid, "checksummed file")?
    else {
        return Err(HostBackupError::PathValidation {
            path: file_path.to_path_buf(),
            reason: "checksummed file does not exist or is not a regular file".to_string(),
        });
    };
    let (actual, size_bytes) = compute_reader_sha256(&mut file, file_path)?;
    if actual != expected_clean {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: file_path.display().to_string(),
            expected: expected_clean,
            actual,
        });
    }

    Ok(ChecksumVerification {
        artifact_path: file_path.to_path_buf(),
        sidecar_path: None,
        expected_sha256: expected_clean,
        actual_sha256: actual,
        size_bytes,
        verified: true,
    })
}

/// Verifies `file_path` against its `<file_path>.sha256` sidecar file on disk.
/// Fails closed if either the artifact or the sidecar is missing, a symlink, or mismatched.
pub fn verify_file_with_sidecar(file_path: &Path) -> HostBackupResult<ChecksumVerification> {
    verify_file_with_sidecar_and_trusted_uid(file_path, None)
}

/// Variant of [`verify_file_with_sidecar`] that accepts an explicit caller-configured `trusted_uid`.
pub fn verify_file_with_sidecar_and_trusted_uid(
    file_path: &Path,
    trusted_uid: Option<u32>,
) -> HostBackupResult<ChecksumVerification> {
    let Some((mut art_file, _)) =
        open_verified_regular_file_for_read(file_path, trusted_uid, "backup artifact")?
    else {
        return Err(HostBackupError::PathValidation {
            path: file_path.to_path_buf(),
            reason: "backup artifact does not exist or is not a regular file".to_string(),
        });
    };

    let sidecar = checksum_sidecar_path(file_path);
    let raw_sidecar = match read_verified_text_file_nofollow(
        &sidecar,
        trusted_uid,
        64 * 1024,
        "checksum sidecar",
    ) {
        Ok(Some(text)) => text,
        Ok(None) => {
            return Err(HostBackupError::MissingChecksumSidecar {
                artifact: file_path.to_path_buf(),
                sidecar_path: sidecar,
            });
        }
        Err(HostBackupError::UnsafeOverwriteRejected { .. }) => {
            return Err(HostBackupError::MissingChecksumSidecar {
                artifact: file_path.to_path_buf(),
                sidecar_path: sidecar,
            });
        }
        Err(other_err) => return Err(other_err),
    };

    let expected = parse_sha256_sidecar_str(&raw_sidecar)?;
    let (actual, size_bytes) = compute_reader_sha256(&mut art_file, file_path)?;
    if actual != expected {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: file_path.display().to_string(),
            expected,
            actual,
        });
    }

    Ok(ChecksumVerification {
        artifact_path: file_path.to_path_buf(),
        sidecar_path: Some(sidecar),
        expected_sha256: expected,
        actual_sha256: actual,
        size_bytes,
        verified: true,
    })
}

/// Removes or rejects any pre-existing `<file_path>.part.<5 digits>` files before splitting
/// so stale trailing chunks from an earlier split with a smaller chunk size can never survive.
fn remove_existing_safe_chunks(file_path: &Path) -> HostBackupResult<()> {
    let Some(parent) = file_path.parent() else {
        return Ok(());
    };
    let Some(base_name) = file_path.file_name().and_then(|s| s.to_str()) else {
        return Ok(());
    };
    if !parent.exists() {
        return Ok(());
    }
    reject_if_symlink(parent, "chunk parent directory")?;
    for entry in fs::read_dir(parent)
        .map_err(|err| HostBackupError::io(format!("reading {}", parent.display()), err))?
    {
        let entry = entry.map_err(|err| HostBackupError::io("reading chunk dir entry", err))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if parse_exact_chunk_index(base_name, &name).is_some() {
            let chunk_path = entry.path();
            let meta = fs::symlink_metadata(&chunk_path).map_err(|err| {
                HostBackupError::io(format!("stat chunk {}", chunk_path.display()), err)
            })?;
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: chunk_path,
                    reason: "existing backup chunk is a symbolic link".to_string(),
                });
            }
            if !meta.is_file() {
                return Err(HostBackupError::ChunkError {
                    artifact: file_path.to_path_buf(),
                    reason: format!(
                        "existing chunk path '{}' is not a regular file",
                        chunk_path.display()
                    ),
                });
            }
            fs::remove_file(&chunk_path).map_err(|err| {
                HostBackupError::io(
                    format!("removing stale chunk {}", chunk_path.display()),
                    err,
                )
            })?;
        }
    }
    Ok(())
}

/// Splits a verified backup file into fixed-size chunk files (`<file>.part.00000`, `<file>.part.00001`, ...)
/// matching `packages/system/af-backup`'s `split -b <size> -d -a 5` naming convention.
///
/// Creates each chunk exclusively with mode `0600` after clearing any stale exact-5-digit chunks.
pub fn split_backup_into_chunks(
    file_path: &Path,
    chunk_size_bytes: u64,
) -> HostBackupResult<Vec<PathBuf>> {
    if chunk_size_bytes == 0 {
        return Err(HostBackupError::ChunkError {
            artifact: file_path.to_path_buf(),
            reason: "chunk_size_bytes must be greater than zero".to_string(),
        });
    }
    reject_if_symlink(file_path, "backup file to split")?;
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_private_dir_all(parent, "chunk output directory")?;
        }
    }
    remove_existing_safe_chunks(file_path)?;

    let mut src = File::open(file_path)
        .map_err(|err| HostBackupError::io(format!("opening {}", file_path.display()), err))?;

    let mut chunks: Vec<PathBuf> = Vec::new();
    let mut index = 0usize;
    let mut buf = vec![0u8; 64 * 1024];

    let split_res: HostBackupResult<()> = (|| {
        loop {
            if index > 99_999 {
                return Err(HostBackupError::ChunkError {
                    artifact: file_path.to_path_buf(),
                    reason: "chunk count exceeds 5-digit suffix limit (99999)".to_string(),
                });
            }
            let mut remaining = chunk_size_bytes;
            let part_path = PathBuf::from(format!("{}.part.{:05}", file_path.display(), index));
            let mut wrote_any = false;
            let mut part_file: Option<File> = None;

            while remaining > 0 {
                let to_read = (remaining as usize).min(buf.len());
                let count = src.read(&mut buf[..to_read]).map_err(|err| {
                    HostBackupError::io(format!("reading {}", file_path.display()), err)
                })?;
                if count == 0 {
                    break;
                }
                if part_file.is_none() {
                    let created_file = create_private_new_file(&part_path, "backup chunk output")?;
                    chunks.push(part_path.clone());
                    part_file = Some(created_file);
                }
                if let Some(ref mut out) = part_file {
                    out.write_all(&buf[..count]).map_err(|err| {
                        HostBackupError::io(format!("writing chunk {}", part_path.display()), err)
                    })?;
                }
                wrote_any = true;
                remaining -= count as u64;
            }

            if let Some(out) = part_file {
                out.sync_all().map_err(|err| {
                    HostBackupError::io(format!("syncing chunk {}", part_path.display()), err)
                })?;
                index += 1;
            }

            if !wrote_any {
                break;
            }
        }
        Ok(())
    })();

    if let Err(err) = split_res {
        for created in &chunks {
            let _ = fs::remove_file(created);
        }
        return Err(err);
    }

    if let Some(parent) = file_path.parent() {
        sync_parent_directory(parent, "chunk split directory")?;
    }

    Ok(chunks)
}

/// Reassembles sequential `<output_path>.part.00000` chunk files into `output_path`
/// and verifies the reassembled file against `expected_sha256` before activating it.
pub fn assemble_verified_chunks(
    chunk_paths: &[PathBuf],
    output_path: &Path,
    expected_sha256: &str,
) -> HostBackupResult<ChecksumVerification> {
    if chunk_paths.is_empty() {
        return Err(HostBackupError::ChunkError {
            artifact: output_path.to_path_buf(),
            reason: "no chunk files provided for assembly".to_string(),
        });
    }
    validate_no_parent_traversal(output_path, "assembled backup target")?;
    reject_if_symlink(output_path, "assembled backup target")?;

    let (tmp_out, mut out) =
        create_unique_private_temp_file(output_path, "assembling", "temporary assembly file")?;

    for part in chunk_paths {
        let mut part_file =
            match open_verified_regular_file_for_read(part, None, "backup chunk part") {
                Ok(Some((opened, _))) => opened,
                Ok(None) => {
                    drop(out);
                    let _ = fs::remove_file(&tmp_out);
                    return Err(HostBackupError::ChunkError {
                        artifact: output_path.to_path_buf(),
                        reason: format!("missing chunk file: {}", part.display()),
                    });
                }
                Err(HostBackupError::UnsafeOverwriteRejected { .. })
                | Err(HostBackupError::PathValidation { .. }) => {
                    drop(out);
                    let _ = fs::remove_file(&tmp_out);
                    return Err(HostBackupError::ChunkError {
                        artifact: output_path.to_path_buf(),
                        reason: format!("chunk path is not a regular file: {}", part.display()),
                    });
                }
                Err(err) => {
                    drop(out);
                    let _ = fs::remove_file(&tmp_out);
                    return Err(err);
                }
            };
        if let Err(err) = std::io::copy(&mut part_file, &mut out) {
            drop(out);
            let _ = fs::remove_file(&tmp_out);
            return Err(HostBackupError::io(
                format!("copying chunk {}", part.display()),
                err,
            ));
        }
    }

    if let Err(err) = out.sync_all() {
        drop(out);
        let _ = fs::remove_file(&tmp_out);
        return Err(HostBackupError::io(
            format!("syncing assembled file {}", tmp_out.display()),
            err,
        ));
    }
    drop(out);

    let verification = match verify_file_sha256(&tmp_out, expected_sha256) {
        Ok(ver) => ver,
        Err(err) => {
            let _ = fs::remove_file(&tmp_out);
            return Err(err);
        }
    };

    if let Err(err) = reject_if_symlink(output_path, "assembled backup target") {
        let _ = fs::remove_file(&tmp_out);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_out, output_path) {
        let _ = fs::remove_file(&tmp_out);
        return Err(HostBackupError::io(
            format!("activating assembled backup {}", output_path.display()),
            err,
        ));
    }

    if let Some(parent) = output_path.parent() {
        sync_parent_directory(parent, "activating assembled backup")?;
    }

    Ok(ChecksumVerification {
        artifact_path: output_path.to_path_buf(),
        ..verification
    })
}
