use super::fs_helpers::{ensure_no_symlink_ancestors, write_file_atomic_exclusive};
use crate::error::{CliError, CliResult};
use af_host::compute_file_sha256;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Outcome classification when overlaying a managed configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOverlayOutcome {
    /// Target did not exist and was newly installed with its `.aetherflow-sha256` sidecar.
    InstalledNew,
    /// Target already matched the incoming source SHA-256; no disk writes were needed.
    UnchangedIdentical,
    /// Target matched the previous `.aetherflow-sha256` sidecar (unmodified by user) and was cleanly updated.
    UpdatedUnmodifiedStock,
    /// Target was modified by the operator, so `<target>.user-backup.<ts>` was saved before applying the new config.
    BackedUpUserModifiedAndUpdated,
}

/// Receipt returned by [`safe_overlay_config_file`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigOverlayReceipt {
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    pub sidecar_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub sha256: String,
    pub outcome: ConfigOverlayOutcome,
    pub dry_run: bool,
}

/// Safely overlays `source_path` onto `target_path`, matching `_safe_overlay_config` in `setup/modules/06-state.sh`:
/// 1. Rejects symlinks on `source_path`, `target_path`, `<target_path>.aetherflow-sha256`, and all ancestor directories.
/// 2. Computes SHA-256 of `source_path`.
/// 3. If `target_path` exists:
///    - If `target_sha == source_sha`, returns `UnchangedIdentical` (ensuring `.aetherflow-sha256` exists).
///    - If `force == false` and `target_sha != previous_sidecar_sha`, preserves the operator's customized file
///      at `<target_path>.user-backup.<timestamp>` before writing the new config.
/// 4. Atomically writes `target_path` using an exclusive unique sibling temporary file and records `source_sha`
///    in `<target_path>.aetherflow-sha256`.
pub fn safe_overlay_config_file(
    source_path: &Path,
    target_path: &Path,
    force: bool,
    dry_run: bool,
) -> CliResult<ConfigOverlayReceipt> {
    ensure_no_symlink_ancestors(source_path, "overlay source_path")?;
    ensure_no_symlink_ancestors(target_path, "overlay target_path")?;

    if !source_path.is_file() {
        return Err(CliError::Validation(format!(
            "overlay source file does not exist: {}",
            source_path.display()
        )));
    }

    let mut sidecar_os = target_path.as_os_str().to_os_string();
    sidecar_os.push(".aetherflow-sha256");
    let sidecar_path = PathBuf::from(sidecar_os);
    ensure_no_symlink_ancestors(&sidecar_path, "overlay sha256 sidecar")?;

    let (new_sha, _) = compute_file_sha256(source_path)?;
    let mut backup_path: Option<PathBuf> = None;

    let outcome = if !target_path.exists() {
        ConfigOverlayOutcome::InstalledNew
    } else {
        let (current_sha, _) = compute_file_sha256(target_path)?;
        if current_sha.eq_ignore_ascii_case(&new_sha) {
            if !dry_run && !sidecar_path.exists() {
                let sidecar_body = format!("{}\n", new_sha);
                write_file_atomic_exclusive(
                    &sidecar_path,
                    sidecar_body.as_bytes(),
                    0o640,
                    "overlay sha256 sidecar",
                )?;
            }
            return Ok(ConfigOverlayReceipt {
                source_path: source_path.to_path_buf(),
                target_path: target_path.to_path_buf(),
                sidecar_path,
                backup_path: None,
                sha256: new_sha,
                outcome: ConfigOverlayOutcome::UnchangedIdentical,
                dry_run,
            });
        }

        let prev_stock_sha = if sidecar_path.is_file() {
            fs::read_to_string(&sidecar_path)
                .ok()
                .map(|s| s.trim().to_ascii_lowercase())
        } else {
            None
        };

        let is_unmodified_stock = prev_stock_sha
            .as_deref()
            .map(|prev| prev.eq_ignore_ascii_case(&current_sha))
            .unwrap_or(false);

        if force || is_unmodified_stock {
            ConfigOverlayOutcome::UpdatedUnmodifiedStock
        } else {
            let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let mut bak_os = target_path.as_os_str().to_os_string();
            bak_os.push(format!(".user-backup.{}", ts));
            let bak = PathBuf::from(bak_os);
            ensure_no_symlink_ancestors(&bak, "overlay user backup file")?;
            backup_path = Some(bak);
            ConfigOverlayOutcome::BackedUpUserModifiedAndUpdated
        }
    };

    if !dry_run {
        let source_bytes = fs::read(source_path).map_err(|e| {
            CliError::io(
                format!("reading overlay source {}", source_path.display()),
                e,
            )
        })?;

        if let Some(ref bak) = backup_path {
            let existing_bytes = fs::read(target_path).map_err(|e| {
                CliError::io(
                    format!("reading user-modified config {}", target_path.display()),
                    e,
                )
            })?;
            write_file_atomic_exclusive(bak, &existing_bytes, 0o600, "overlay user backup file")?;
        }

        write_file_atomic_exclusive(target_path, &source_bytes, 0o640, "overlay target file")?;

        let sidecar_body = format!("{}\n", new_sha);
        write_file_atomic_exclusive(
            &sidecar_path,
            sidecar_body.as_bytes(),
            0o640,
            "overlay sha256 sidecar",
        )?;
    }

    Ok(ConfigOverlayReceipt {
        source_path: source_path.to_path_buf(),
        target_path: target_path.to_path_buf(),
        sidecar_path,
        backup_path,
        sha256: new_sha,
        outcome,
        dry_run,
    })
}
