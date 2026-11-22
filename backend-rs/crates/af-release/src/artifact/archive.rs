use super::{EMBEDDED_LOG_RETENTION_PY, EMBEDDED_VERIFY_PROVENANCE_PY};
use crate::config::ReleaseConfig;
use crate::error::{ReleaseError, ReleaseResult};
use flate2::read::GzDecoder;
use std::fs;
use std::path::{Component, Path, PathBuf};
use tar::{Archive, EntryType};

/// Safely extracts a `.tar.gz` release archive into `release_dir` with strict Zip-Slip / path-traversal,
/// ancestor symlink, destination collision, and symlink/device-node rejection, then validates the
/// extracted `aetherflow-api` binary, `.version` stamp, and external frontend assets.
pub fn extract_and_validate_release_archive(
    archive_path: &Path,
    release_dir: &Path,
    tag: &str,
    config: &ReleaseConfig,
) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(archive_path)?;
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;

    if fs::symlink_metadata(release_dir).is_ok() {
        let meta = fs::symlink_metadata(release_dir).map_err(|e| {
            ReleaseError::io(
                format!("stat release directory {}", release_dir.display()),
                e,
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: format!(
                    "release directory '{}' exists and is a symlink or non-directory",
                    release_dir.display()
                ),
            });
        }
        let mut existing = fs::read_dir(release_dir).map_err(|e| {
            ReleaseError::io(
                format!("reading release directory {}", release_dir.display()),
                e,
            )
        })?;
        if existing.next().is_some() {
            return Err(ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: format!(
                    "refusing to extract into non-empty release directory '{}'",
                    release_dir.display()
                ),
            });
        }
    } else {
        crate::fs_security::create_new_dir_exclusive(release_dir, 0o755, 0o755)?;
    }

    let file = fs::File::open(archive_path).map_err(|e| ReleaseError::ArchiveExtraction {
        archive: archive_path.to_path_buf(),
        reason: format!("failed to open archive: {}", e),
    })?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let entries = archive
        .entries()
        .map_err(|e| ReleaseError::ArchiveExtraction {
            archive: archive_path.to_path_buf(),
            reason: format!("invalid tar header stream: {}", e),
        })?;

    for entry_result in entries {
        let mut entry = entry_result.map_err(|e| ReleaseError::ArchiveExtraction {
            archive: archive_path.to_path_buf(),
            reason: format!("corrupt tar entry: {}", e),
        })?;

        let entry_path = entry
            .path()
            .map_err(|e| ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: format!("invalid entry path encoding: {}", e),
            })?
            .into_owned();

        let rel_path = sanitize_archive_entry_path(&entry_path, archive_path)?;
        if rel_path.as_os_str().is_empty() {
            continue;
        }

        crate::fs_security::ensure_no_symlink_in_relative_chain(release_dir, &rel_path).map_err(
            |e| ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: e.to_string(),
            },
        )?;

        let entry_type = entry.header().entry_type();
        match entry_type {
            EntryType::Directory => {
                let dest = release_dir.join(&rel_path);
                crate::fs_security::create_dir_all_no_symlinks(&dest, 0o755).map_err(|e| {
                    ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!("failed to create directory {}: {}", dest.display(), e),
                    }
                })?;
            }
            EntryType::Regular | EntryType::Continuous => {
                let dest = release_dir.join(&rel_path);
                if let Some(parent) = dest.parent() {
                    crate::fs_security::create_dir_all_no_symlinks(parent, 0o755).map_err(|e| {
                        ReleaseError::ArchiveExtraction {
                            archive: archive_path.to_path_buf(),
                            reason: format!("failed to create parent {}: {}", parent.display(), e),
                        }
                    })?;
                }
                if fs::symlink_metadata(&dest).is_ok() {
                    return Err(ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!(
                            "duplicate or pre-planted destination entry rejected: {}",
                            dest.display()
                        ),
                    });
                }
                let raw_mode = entry.header().mode().unwrap_or(0o644) & 0o777;
                let safe_mode = if raw_mode == 0 { 0o644 } else { raw_mode };
                let mut out_file = crate::fs_security::open_exclusive_private_file(
                    &dest, safe_mode,
                )
                .map_err(|e| ReleaseError::ArchiveExtraction {
                    archive: archive_path.to_path_buf(),
                    reason: format!("failed to create exclusive file {}: {}", dest.display(), e),
                })?;
                std::io::copy(&mut entry, &mut out_file).map_err(|e| {
                    ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!("failed to extract {}: {}", dest.display(), e),
                    }
                })?;
                let _ = out_file.sync_all();
            }
            other => {
                return Err(ReleaseError::ArchiveExtraction {
                    archive: archive_path.to_path_buf(),
                    reason: format!(
                        "disallowed tar entry type {:?} for path '{}' (symlinks, hardlinks, and device nodes are rejected)",
                        other,
                        entry_path.display()
                    ),
                });
            }
        }
    }

    let binary_path = release_dir.join("aetherflow-api");
    let Ok(meta) = fs::symlink_metadata(&binary_path) else {
        return Err(ReleaseError::ArtifactVerification(
            "Release archive has no ./aetherflow-api. Refusing to continue.".to_string(),
        ));
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(ReleaseError::ArtifactVerification(
            "Release archive ./aetherflow-api is not a regular file. Refusing to continue."
                .to_string(),
        ));
    }
    if meta.len() == 0 {
        return Err(ReleaseError::ArtifactVerification(
            "Extracted ./aetherflow-api binary is 0 bytes. Refusing to continue.".to_string(),
        ));
    }

    set_executable_permission(&binary_path)?;

    let version_path = release_dir.join(".version");
    let has_non_empty_version = fs::symlink_metadata(&version_path)
        .map(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0)
        .unwrap_or(false);
    if !has_non_empty_version {
        return Err(ReleaseError::ArtifactVerification(
            "Extracted release archive is missing a non-empty regular .version stamp. Refusing unverified archive."
                .to_string(),
        ));
    }
    let actual_version = fs::read_to_string(&version_path).map_err(|e| {
        ReleaseError::ArtifactVerification(format!(
            "Failed to read extracted .version at {}: {}",
            version_path.display(),
            e
        ))
    })?;
    let trimmed_version = actual_version.trim();
    if trimmed_version != tag {
        return Err(ReleaseError::ArtifactVerification(format!(
            "Extracted release .version {:?} does not match expected tag {:?}",
            trimmed_version, tag
        )));
    }

    validate_external_frontend_assets(release_dir)?;
    stage_running_release_manager(release_dir, config)?;
    prepare_release_permissions(release_dir)?;
    Ok(())
}

/// Checks the external UI layout without following links in the required paths.
/// Archive extraction independently rejects all links and special entries.
pub(super) fn validate_external_frontend_assets(release_dir: &Path) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    for relative in ["web", "web/dist"] {
        let path = release_dir.join(relative);
        let is_safe_dir = fs::symlink_metadata(&path)
            .map(|m| !m.file_type().is_symlink() && m.is_dir())
            .unwrap_or(false);
        if !is_safe_dir {
            return Err(ReleaseError::ArtifactVerification(format!(
                "Release archive is missing a regular directory {} for external frontend assets.",
                path.display()
            )));
        }
    }

    let dist = release_dir.join("web/dist");
    let index = dist.join("index.html");
    let has_index = fs::symlink_metadata(&index)
        .map(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0)
        .unwrap_or(false);
    if !has_index {
        return Err(ReleaseError::ArtifactVerification(
            "Release archive is missing a non-empty regular web/dist/index.html.".to_string(),
        ));
    }

    let entries = fs::read_dir(&dist).map_err(|e| {
        ReleaseError::ArtifactVerification(format!(
            "Failed to inspect external frontend directory {}: {}",
            dist.display(),
            e
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            ReleaseError::ArtifactVerification(format!(
                "Failed to inspect external frontend directory {}: {}",
                dist.display(),
                e
            ))
        })?;
        if !entry.file_name().to_string_lossy().ends_with(".wasm") {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            ReleaseError::ArtifactVerification(format!(
                "Failed to inspect frontend asset {}: {}",
                path.display(),
                e
            ))
        })?;
        if !metadata.file_type().is_symlink() && metadata.is_file() && metadata.len() > 0 {
            return Ok(());
        }
    }
    Err(ReleaseError::ArtifactVerification(
        "Release archive is missing a non-empty regular web/dist/*.wasm file.".to_string(),
    ))
}

/// Normalizes permissions across an extracted or staged release directory before symlink swap,
/// matching `prepare_release_permissions` in `deploy/release-manager.sh`:
/// - `0755` on all directories
/// - `a+r,go-w` (`(mode | 0o444) & !0o022`) on all regular files
/// - `0755` on `aetherflow-api`, companion binaries (`af`, `bin/af`, `speedtest-backend`,
///   `bin/speedtest-backend`), and deploy helper scripts (if present)
/// - Verifies `.version` is readable and `./aetherflow-api` is executable.
pub fn prepare_release_permissions(release_dir: &Path) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    normalize_release_tree_permissions(release_dir)?;

    let api_bin = release_dir.join("aetherflow-api");
    crate::fs_security::set_file_mode(&api_bin, 0o755)?;

    for rel_exec in [
        "af",
        "bin/af",
        "speedtest-backend",
        "bin/speedtest-backend",
        "deploy/release-manager.sh",
        "deploy/verify-provenance.py",
        "deploy/log-retention.py",
        "plugins/telemetry-inspector/backend/hooks/start.sh",
    ] {
        let staged_exec = release_dir.join(rel_exec);
        if let Ok(meta) = fs::symlink_metadata(&staged_exec) {
            if !meta.file_type().is_symlink() && meta.is_file() {
                crate::fs_security::set_file_mode(&staged_exec, 0o755)?;
            }
        }
    }

    // Verify `.version` is readable and `aetherflow-api` is executable
    let version_path = release_dir.join(".version");
    let version_content = fs::read_to_string(&version_path).map_err(|e| {
        ReleaseError::ArtifactVerification(format!(
            "Release .version at {} is unreadable: {}",
            version_path.display(),
            e
        ))
    })?;
    if version_content.trim().is_empty() {
        return Err(ReleaseError::ArtifactVerification(format!(
            "Release .version at {} is empty",
            version_path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin_meta = fs::symlink_metadata(&api_bin).map_err(|e| {
            ReleaseError::ArtifactVerification(format!(
                "Release binary at {} is inaccessible: {}",
                api_bin.display(),
                e
            ))
        })?;
        if bin_meta.file_type().is_symlink()
            || !bin_meta.is_file()
            || (bin_meta.permissions().mode() & 0o111) == 0
        {
            return Err(ReleaseError::ArtifactVerification(format!(
                "Release binary at {} is not executable",
                api_bin.display()
            )));
        }
        let ver_meta = fs::symlink_metadata(&version_path).map_err(|e| {
            ReleaseError::ArtifactVerification(format!(
                "Release .version at {} metadata error: {}",
                version_path.display(),
                e
            ))
        })?;
        if (ver_meta.permissions().mode() & 0o444) != 0o444 {
            return Err(ReleaseError::ArtifactVerification(format!(
                "Release .version at {} is not world-readable (a+r)",
                version_path.display()
            )));
        }
    }

    Ok(())
}

fn normalize_release_tree_permissions(dir: &Path) -> ReleaseResult<()> {
    crate::fs_security::set_dir_mode(dir, 0o755)?;
    let entries = fs::read_dir(dir).map_err(|e| {
        ReleaseError::io(
            format!(
                "reading release directory {} for permission normalization",
                dir.display()
            ),
            e,
        )
    })?;

    for entry_res in entries {
        let entry = entry_res.map_err(|e| {
            ReleaseError::io(format!("iterating release directory {}", dir.display()), e)
        })?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| ReleaseError::io(format!("stat release entry {}", path.display()), e))?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path,
                reason: "symlink entry rejected during release permission normalization"
                    .to_string(),
            });
        }
        if meta.is_dir() {
            normalize_release_tree_permissions(&path)?;
        } else if meta.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let current_mode = meta.permissions().mode() & 0o777;
                let normalized = (current_mode | 0o444) & !0o022;
                crate::fs_security::set_file_mode(&path, normalized)?;
            }
            #[cfg(not(unix))]
            {
                crate::fs_security::set_file_mode(&path, 0o644)?;
            }
        }
    }
    Ok(())
}

/// Validates and normalizes an archive entry path, stripping leading `./` and rejecting
/// absolute paths, drive prefixes, or `..` traversal components.
fn sanitize_archive_entry_path(entry_path: &Path, archive_path: &Path) -> ReleaseResult<PathBuf> {
    let mut normalized = PathBuf::new();
    for comp in entry_path.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.contains('\0') {
                    return Err(ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!(
                            "NUL byte in archive entry path '{}'",
                            entry_path.display()
                        ),
                    });
                }
                normalized.push(part);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ReleaseError::ArchiveExtraction {
                    archive: archive_path.to_path_buf(),
                    reason: format!(
                        "unsafe path traversal or absolute path in archive entry: '{}'",
                        entry_path.display()
                    ),
                });
            }
        }
    }
    Ok(normalized)
}

/// Resolves a configured staging source path (`release-manager.sh` or `release-manager.conf`),
/// allowing ONLY the managed `config.current_link` symlink when it points to a direct child
/// release directory inside `config.releases_dir`.
///
/// Any untrusted ancestor symlink, `current_link` pointing outside `releases_dir`, or nested
/// symlink inside the active release directory is rejected with `ReleaseError::PathValidation`.
/// If the source file simply does not exist on disk, returns `Ok(None)`.
pub fn resolve_managed_current_source_path(
    src: &Path,
    config: &ReleaseConfig,
) -> ReleaseResult<Option<PathBuf>> {
    crate::config::validate_no_parent_traversal(src, "staging source path")?;

    if let Ok(rel) = src.strip_prefix(&config.current_link) {
        if rel.as_os_str().is_empty() {
            return Err(ReleaseError::PathValidation {
                path: src.to_path_buf(),
                reason: "staging source path must reference a file inside current release"
                    .to_string(),
            });
        }
        crate::config::validate_no_parent_traversal(rel, "relative staging source path")?;

        let parent = config
            .current_link
            .parent()
            .ok_or_else(|| ReleaseError::PathValidation {
                path: config.current_link.clone(),
                reason: "current release link has no parent".to_string(),
            })?;
        crate::fs_security::ensure_no_symlink_ancestors(parent)?;
        crate::fs_security::ensure_no_symlink_ancestors(&config.releases_dir)?;

        let current_meta = match fs::symlink_metadata(&config.current_link) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ReleaseError::io(
                    format!(
                        "inspecting current release link {}",
                        config.current_link.display()
                    ),
                    e,
                ))
            }
        };

        let target_release_dir = if current_meta.file_type().is_symlink() {
            let link_target = fs::read_link(&config.current_link).map_err(|e| {
                ReleaseError::io(
                    format!(
                        "reading current release link {}",
                        config.current_link.display()
                    ),
                    e,
                )
            })?;
            crate::config::validate_no_parent_traversal(
                &link_target,
                "current release link target",
            )?;
            let resolved = if link_target.is_absolute() {
                link_target
            } else {
                parent.join(link_target)
            };
            crate::config::validate_no_parent_traversal(&resolved, "resolved current release dir")?;
            if resolved.parent() != Some(config.releases_dir.as_path()) {
                return Err(ReleaseError::PathValidation {
                    path: resolved,
                    reason: "current release link must target a direct child of releases_dir"
                        .to_string(),
                });
            }
            crate::fs_security::ensure_no_symlink_ancestors(&resolved)?;
            let target_meta = match fs::symlink_metadata(&resolved) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    return Err(ReleaseError::io(
                        format!("inspecting resolved current release {}", resolved.display()),
                        e,
                    ))
                }
            };
            if target_meta.file_type().is_symlink() || !target_meta.is_dir() {
                return Err(ReleaseError::PathValidation {
                    path: resolved,
                    reason: "resolved current release target is not a real directory".to_string(),
                });
            }
            resolved
        } else if current_meta.is_dir() {
            crate::fs_security::ensure_no_symlink_ancestors(&config.current_link)?;
            config.current_link.clone()
        } else {
            return Err(ReleaseError::PathValidation {
                path: config.current_link.clone(),
                reason: "current release path is neither a symlink nor a directory".to_string(),
            });
        };

        crate::fs_security::ensure_no_symlink_in_relative_chain(&target_release_dir, rel)?;
        let resolved_src = target_release_dir.join(rel);
        match fs::symlink_metadata(&resolved_src) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(ReleaseError::PathValidation {
                        path: resolved_src,
                        reason: "staging source entry is not a regular file".to_string(),
                    });
                }
                Ok(Some(resolved_src))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ReleaseError::io(
                format!("inspecting staging source file {}", resolved_src.display()),
                e,
            )),
        }
    } else {
        crate::fs_security::ensure_no_symlink_ancestors(src)?;
        match fs::symlink_metadata(src) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(ReleaseError::PathValidation {
                        path: src.to_path_buf(),
                        reason: "staging source entry is not a regular file".to_string(),
                    });
                }
                Ok(Some(src.to_path_buf()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ReleaseError::io(
                format!("inspecting staging source file {}", src.display()),
                e,
            )),
        }
    }
}

/// Ensures `release-manager.sh`, `verify-provenance.py`, `log-retention.py`, and `release-manager.conf`
/// are present and executable in `${RELEASE_DIR}/deploy`, preserving candidate archive deploy scripts when
/// already shipped in the release bundle and backfilling from the running release only when absent.
pub fn stage_running_release_manager(
    release_dir: &Path,
    config: &ReleaseConfig,
) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    let deploy_dir = release_dir.join("deploy");
    crate::fs_security::create_dir_all_no_symlinks(&deploy_dir, 0o755)?;

    for candidate_helper in [
        "release-manager.sh",
        "verify-provenance.py",
        "log-retention.py",
    ] {
        let helper_path = deploy_dir.join(candidate_helper);
        if let Ok(meta) = fs::symlink_metadata(&helper_path) {
            if meta.file_type().is_symlink() {
                return Err(ReleaseError::PathValidation {
                    path: helper_path,
                    reason: format!("refusing symlinked deploy helper {candidate_helper}"),
                });
            }
            if meta.is_file() {
                set_executable_permission(&helper_path)?;
            }
        }
    }

    let mut staged_script = false;
    if let Some(ref script_src) = config.stage_script_path {
        if let Some(resolved_src) = resolve_managed_current_source_path(script_src, config)? {
            let dst = deploy_dir.join("release-manager.sh");
            if !dst.exists() {
                crate::fs_security::atomic_copy_file_with_mode(&resolved_src, &dst, 0o755, None)?;
            }
            set_executable_permission(&dst)?;
            staged_script = true;
        }
    }
    if staged_script || deploy_dir.join("release-manager.sh").is_file() {
        let verifier_dst = deploy_dir.join("verify-provenance.py");
        if !verifier_dst.exists() {
            let mut copied_verifier = false;
            if let Some(parent) = config.stage_script_path.as_deref().and_then(Path::parent) {
                if let Some(resolved_vp) = resolve_managed_current_source_path(
                    &parent.join("verify-provenance.py"),
                    config,
                )? {
                    crate::fs_security::atomic_copy_file_with_mode(
                        &resolved_vp,
                        &verifier_dst,
                        0o755,
                        None,
                    )?;
                    copied_verifier = true;
                }
            }
            if !copied_verifier {
                crate::fs_security::atomic_write_bytes_with_mode(
                    &verifier_dst,
                    EMBEDDED_VERIFY_PROVENANCE_PY.as_bytes(),
                    0o755,
                )?;
            }
        }
        set_executable_permission(&verifier_dst)?;

        let retention_dst = deploy_dir.join("log-retention.py");
        if !retention_dst.exists() {
            let mut copied_retention = false;
            if let Some(parent) = config.stage_script_path.as_deref().and_then(Path::parent) {
                if let Some(resolved_lr) =
                    resolve_managed_current_source_path(&parent.join("log-retention.py"), config)?
                {
                    crate::fs_security::atomic_copy_file_with_mode(
                        &resolved_lr,
                        &retention_dst,
                        0o755,
                        None,
                    )?;
                    copied_retention = true;
                }
            }
            if !copied_retention {
                crate::fs_security::atomic_write_bytes_with_mode(
                    &retention_dst,
                    EMBEDDED_LOG_RETENTION_PY.as_bytes(),
                    0o755,
                )?;
            }
        }
        set_executable_permission(&retention_dst)?;
    }
    if let Some(ref conf_src) = config.stage_conf_path {
        if let Some(resolved_src) = resolve_managed_current_source_path(conf_src, config)? {
            let dst = deploy_dir.join("release-manager.conf");
            if let Ok(meta) = fs::symlink_metadata(&dst) {
                if meta.file_type().is_symlink() {
                    return Err(ReleaseError::PathValidation {
                        path: dst,
                        reason: "refusing to overwrite symlinked release-manager.conf".to_string(),
                    });
                }
            }
            if resolved_src != dst {
                crate::fs_security::atomic_copy_file_with_mode(&resolved_src, &dst, 0o644, None)?;
            }
        }
    }
    Ok(())
}

/// Simulates the v4 release layout during `--dry-run --offline`.
/// The generated binaries and frontend files are placeholders, not runnable release assets.
pub fn simulate_offline_artifact(
    release_dir: &Path,
    config: &ReleaseConfig,
) -> ReleaseResult<String> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    for sub in [
        "deploy/systemd",
        "packages",
        "config",
        "bin",
        "web/dist",
        "plugins/telemetry-inspector/backend/hooks",
        "plugins/telemetry-inspector/frontend/dist",
    ] {
        let dir = release_dir.join(sub);
        crate::fs_security::create_dir_all_no_symlinks(&dir, 0o755)?;
    }
    for binary in [
        "aetherflow-api",
        "bin/af",
        "bin/speedtest-backend",
        "plugins/telemetry-inspector/backend/hooks/start.sh",
    ] {
        let bin_path = release_dir.join(binary);
        crate::fs_security::atomic_write_bytes_with_mode(
            &bin_path,
            b"#!/bin/bash\n# Offline dry-run placeholder; not a release binary.\n",
            0o755,
        )?;
        set_executable_permission(&bin_path)?;
    }
    for (asset, contents) in [
        (
            "web/dist/index.html",
            &b"<!-- Offline dry-run placeholder; not a frontend. -->\n"[..],
        ),
        ("web/dist/dry-run-placeholder.wasm", &b""[..]),
        (
            "plugins/telemetry-inspector/plugin.manifest.json",
            &b"{\"id\":\"telemetry-inspector\",\"name\":\"Telemetry Inspector\",\"version\":\"1.0.0\",\"runtime_status\":\"managed\"}\n"[..],
        ),
        (
            "plugins/telemetry-inspector/backend/runtime.py",
            &b"# Offline dry-run placeholder; not a plugin runtime.\n"[..],
        ),
        (
            "plugins/telemetry-inspector/frontend/dist/index.html",
            &b"<!-- Offline dry-run placeholder; not a plugin UI. -->\n"[..],
        ),
    ] {
        crate::fs_security::atomic_write_bytes_with_mode(
            &release_dir.join(asset),
            contents,
            0o644,
        )?;
    }

    let version_stamp = "v4.0.0-dryrun";
    let version_path = release_dir.join(".version");
    crate::fs_security::atomic_write_bytes_with_mode(
        &version_path,
        format!("{}\n", version_stamp).as_bytes(),
        0o644,
    )?;

    stage_running_release_manager(release_dir, config)?;
    prepare_release_permissions(release_dir)?;
    Ok(version_stamp.to_string())
}

fn set_executable_permission(path: &Path) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path)
            .map_err(|e| ReleaseError::io(format!("metadata {}", path.display()), e))?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing chmod +x on symlink".to_string(),
            });
        }
        let mut perms = meta.permissions();
        perms.set_mode((perms.mode() & !0o022) | 0o755);
        fs::set_permissions(path, perms)
            .map_err(|e| ReleaseError::io(format!("chmod +x {}", path.display()), e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
