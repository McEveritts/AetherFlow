use super::*;

// -----------------------------------------------------------------------------
// Security Validation Helpers
// -----------------------------------------------------------------------------

/// Validates that `logical_path` is an absolute Unix path without parent traversal (`..`),
/// NUL bytes, or shell metacharacters, and resides inside `ALLOWED_MANAGED_PREFIXES`
/// while not matching `FORBIDDEN_EXACT_PATHS`.
pub fn validate_managed_path(logical_path: &str) -> Result<(), PackageExecutorError> {
    let trimmed = logical_path.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "path must be absolute: {:?}",
            logical_path
        )));
    }
    if trimmed.contains('\0')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains('$')
        || trimmed.contains('`')
        || trimmed.contains(';')
    {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "path contains forbidden control or shell characters: {:?}",
            logical_path
        )));
    }
    let normalized = trimmed.trim_end_matches('/');
    let check_exact = if normalized.is_empty() {
        "/"
    } else {
        normalized
    };
    if FORBIDDEN_EXACT_PATHS.contains(&check_exact) {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to mutate protected system path: {:?}",
            logical_path
        )));
    }

    let path = Path::new(trimmed);
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "path traversal '..' is forbidden: {:?}",
                logical_path
            )));
        }
    }

    if !ALLOWED_MANAGED_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
    {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "path {:?} is outside allowed managed prefixes {:?}",
            logical_path, ALLOWED_MANAGED_PREFIXES
        )));
    }

    Ok(())
}

/// Validates that a concrete filesystem path and all of its ancestors (from `root_bound` when set,
/// or from the filesystem/temp root) are free of symlinks and unexpected `lstat` errors.
pub fn validate_filesystem_path(
    target: &Path,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_path_ancestors_with_lstat(target, root_bound, |p| {
        fs::symlink_metadata(p).map(|m| m.file_type().is_symlink())
    })
}

pub(crate) fn validate_path_ancestors_with_lstat<F>(
    target: &Path,
    root_bound: Option<&Path>,
    mut is_symlink_lstat: F,
) -> Result<(), PackageExecutorError>
where
    F: FnMut(&Path) -> std::io::Result<bool>,
{
    if target.as_os_str().is_empty() {
        return Err(PackageExecutorError::SecurityViolation(
            "empty filesystem path is forbidden".into(),
        ));
    }
    for comp in target.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "path traversal '..' is forbidden in concrete path: {}",
                target.display()
            )));
        }
    }

    let mut check_one = |p: &Path| -> Result<(), PackageExecutorError> {
        match is_symlink_lstat(p) {
            Ok(true) => Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to traverse or mutate symlink path component: {}",
                p.display()
            ))),
            Ok(false) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(PackageExecutorError::Io(err)),
        }
    };

    if let Some(root) = root_bound {
        for comp in root.components() {
            if matches!(comp, Component::ParentDir) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "isolated root contains parent traversal: {}",
                    root.display()
                )));
            }
        }
        let rel = target.strip_prefix(root).map_err(|_| {
            PackageExecutorError::SecurityViolation(format!(
                "concrete path {} escaped isolated root {}",
                target.display(),
                root.display()
            ))
        })?;
        let mut ancestor = PathBuf::new();
        for component in root.components() {
            ancestor.push(component.as_os_str());
            check_one(&ancestor)?;
        }
        let mut cursor = root.to_path_buf();
        for comp in rel.components() {
            if let Component::Normal(part) = comp {
                cursor.push(part);
                check_one(&cursor)?;
            }
        }
        return Ok(());
    }

    let mut cursor = PathBuf::new();
    for comp in target.components() {
        match comp {
            Component::Prefix(p) => cursor.push(p.as_os_str()),
            Component::RootDir => cursor.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::Normal(part) => {
                cursor.push(part);
                check_one(&cursor)?;
            }
            Component::ParentDir => {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "path traversal '..' is forbidden: {}",
                    target.display()
                )));
            }
        }
    }
    Ok(())
}

/// Validates that a symlink target path has no '..' traversal and that all ancestor directories
/// are legitimate non-symlink paths within `root_bound`. The leaf target itself is permitted to be a symlink.
pub fn validate_filesystem_symlink_path(
    target: &Path,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    if target.as_os_str().is_empty() {
        return Err(PackageExecutorError::SecurityViolation(
            "empty filesystem path is forbidden".into(),
        ));
    }
    for comp in target.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "path traversal '..' is forbidden in concrete path: {}",
                target.display()
            )));
        }
    }
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            validate_filesystem_path(parent, root_bound)?;
        }
    }
    Ok(())
}

/// Validates that a directory path is safe for ownership change (`chown`) and is not a shared system root.
pub fn validate_chown_target_path(logical_path: &str) -> Result<(), PackageExecutorError> {
    validate_managed_path(logical_path)?;
    let normalized = logical_path.trim().trim_end_matches('/');
    let check_exact = if normalized.is_empty() {
        "/"
    } else {
        normalized
    };
    if SHARED_SYSTEM_CHOWN_PATHS.contains(&check_exact) {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to chown shared system directory: {:?}",
            logical_path
        )));
    }
    Ok(())
}

pub(super) fn validate_step(step: &DeclarativeStep) -> Result<(), PackageExecutorError> {
    match step {
        DeclarativeStep::AptUpdate { .. } => Ok(()),
        DeclarativeStep::AptInstall { packages, .. }
        | DeclarativeStep::AptRemove { packages, .. }
        | DeclarativeStep::AptPurge { packages, .. } => {
            if packages.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "APT step requires at least one package".into(),
                ));
            }
            for pkg in packages {
                if !SAFE_APT_PKG_NAME.is_match(pkg) {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid APT package name: {:?}",
                        pkg
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::EnsureSystemUser {
            username, home_dir, ..
        } => {
            if !SAFE_USERNAME.is_match(username) || username == "root" || username == "www-data" {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "disallowed system username: {:?}",
                    username
                )));
            }
            validate_chown_target_path(home_dir)
        }
        DeclarativeStep::PurgeSystemUser {
            username, home_dir, ..
        } => {
            if !SAFE_USERNAME.is_match(username) || username == "root" || username == "www-data" {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "disallowed system username for purge: {:?}",
                    username
                )));
            }
            if let Some(ref hd) = home_dir {
                validate_chown_target_path(hd)?;
            }
            Ok(())
        }
        DeclarativeStep::EnsureDirectories {
            paths,
            owner,
            group,
            ..
        } => {
            if paths.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "EnsureDirectories requires at least one path".into(),
                ));
            }
            let has_ownership = owner.is_some() || group.is_some();
            for p in paths {
                validate_managed_path(p)?;
                if has_ownership {
                    validate_chown_target_path(p)?;
                }
            }
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::ProbeSshPort { .. }
        | DeclarativeStep::EnsureThreadfinConfig { .. }
        | DeclarativeStep::InstallRcloneBinary { .. }
        | DeclarativeStep::RemoveRcloneFiles { .. } => Ok(()),
        DeclarativeStep::GenerateSelfSignedTlsCert {
            cert_path,
            key_out_path,
            days,
            subject,
            owner,
            group,
            ..
        } => {
            validate_managed_path(cert_path)?;
            if let Some(ref kp) = key_out_path {
                validate_managed_path(kp)?;
            }
            if *days == 0 || *days > 36500 {
                return Err(PackageExecutorError::Validation(format!(
                    "TLS certificate validity days must be in 1..=36500, got {}",
                    days
                )));
            }
            if !SAFE_TLS_SUBJECT.is_match(subject) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid TLS X.509 subject: {:?}",
                    subject
                )));
            }
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::CaptureDpkgVersion {
            package,
            fallback_version,
            version_file_path,
            owner,
            group,
            ..
        } => {
            if !SAFE_APT_PKG_NAME.is_match(package) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid dpkg package name: {:?}",
                    package
                )));
            }
            if !SAFE_VERSION_TAG.is_match(fallback_version) {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid fallback version tag: {:?}",
                    fallback_version
                )));
            }
            if let Some(ref vp) = version_file_path {
                validate_managed_path(vp)?;
            }
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::ResolveGitHubReleaseTag {
            repo,
            fallback_version,
            ..
        } => {
            if !SAFE_GITHUB_REPO.is_match(repo) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid GitHub repository identifier: {:?}",
                    repo
                )));
            }
            if !SAFE_VERSION_TAG.is_match(fallback_version) {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid fallback version tag: {:?}",
                    fallback_version
                )));
            }
            Ok(())
        }
        DeclarativeStep::DownloadAndExtractTarGz {
            url_template,
            dest_dir,
            extract_binaries,
            ..
        } => {
            if !url_template.starts_with("https://") && !url_template.starts_with("file://") {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "artifact download URL must use https:// (or file:// in tests): {:?}",
                    url_template
                )));
            }
            validate_managed_path(dest_dir)?;
            if extract_binaries.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "DownloadAndExtractTarGz requires at least one binary member name".into(),
                ));
            }
            for bin in extract_binaries {
                if !SAFE_PKG_ID.is_match(bin) || bin.contains('/') || bin.contains("..") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid binary member name: {:?}",
                        bin
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::DownloadBinary {
            url_template,
            dest_path,
            ..
        } => {
            if !url_template.starts_with("https://") && !url_template.starts_with("file://") {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "binary download URL must use https:// (or file:// in tests): {:?}",
                    url_template
                )));
            }
            validate_managed_path(dest_path)
        }
        DeclarativeStep::MergeIniSettings {
            path,
            section,
            settings,
            ..
        } => {
            validate_managed_path(path)?;
            if section.is_empty()
                || section.contains(['\n', '\r', '[', ']'])
                || settings.is_empty()
                || settings.iter().any(|(key, value)| {
                    key.is_empty()
                        || key.contains(['\n', '\r', '=', '[', ']'])
                        || value.contains(['\n', '\r'])
                })
            {
                return Err(PackageExecutorError::Validation(
                    "invalid INI settings".into(),
                ));
            }
            Ok(())
        }
        DeclarativeStep::WriteTemplateFile {
            path, owner, group, ..
        } => {
            validate_managed_path(path)?;
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::WriteSystemdUnit { unit_name, .. }
        | DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
            let norm = normalize_unit_filename(unit_name);
            if !SAFE_SERVICE_NAME.is_match(&norm) || norm.contains("..") {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid systemd unit name: {:?}",
                    unit_name
                )));
            }
            Ok(())
        }
        DeclarativeStep::Systemctl {
            unit, operation, ..
        } => {
            if *operation != SystemctlOp::DaemonReload {
                let Some(u) = unit else {
                    return Err(PackageExecutorError::Validation(format!(
                        "systemctl {:?} requires a unit name",
                        operation
                    )));
                };
                if !SAFE_SERVICE_NAME.is_match(u) || u.contains("..") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid systemctl unit name: {:?}",
                        u
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::UnmountPaths { paths, .. } => {
            if paths.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "UnmountPaths requires at least one path".into(),
                ));
            }
            for p in paths {
                validate_managed_path(p)?;
            }
            Ok(())
        }
        DeclarativeStep::RemovePaths { paths, .. } => {
            if paths.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "RemovePaths requires at least one path".into(),
                ));
            }
            for p in paths {
                validate_managed_path(p)?;
            }
            Ok(())
        }
        DeclarativeStep::RunCommand { program, args, .. } => {
            if program.trim().is_empty() {
                return Err(PackageExecutorError::Validation(
                    "RunCommand requires a non-empty program".into(),
                ));
            }
            if args.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "RunCommand requires at least one argument".into(),
                ));
            }
            Ok(())
        }
        DeclarativeStep::WaitForHttpReady { path, .. } => {
            if !path.starts_with('/') || path.contains(['\0', '\n', '\r', ' ']) {
                return Err(PackageExecutorError::Validation(format!(
                    "WaitForHttpReady requires an absolute path starting with '/': {:?}",
                    path
                )));
            }
            Ok(())
        }
    }
}

pub(super) fn normalize_unit_filename(unit: &str) -> String {
    let trimmed = unit.trim();
    if trimmed.ends_with(".service") || trimmed.ends_with(".timer") || trimmed.ends_with(".socket")
    {
        trimmed.to_string()
    } else {
        format!("{}.service", trimmed)
    }
}

// -----------------------------------------------------------------------------
// Artifact Verification Engine
// -----------------------------------------------------------------------------

/// Verifies that an ELF header's `e_machine` field (if populated with a known architecture constant)
/// matches `expected_arch` (`amd64`, `arm64`, or `armhf`).
pub fn verify_elf_header_architecture(
    header: &[u8],
    expected_arch: &str,
    artifact_label: &str,
) -> Result<(), PackageExecutorError> {
    if header.len() < 20 || header[..4] != [0x7f, b'E', b'L', b'F'] {
        return Ok(());
    }
    let is_big_endian = header[5] == 2;
    let e_machine = if is_big_endian {
        u16::from_be_bytes([header[18], header[19]])
    } else {
        u16::from_le_bytes([header[18], header[19]])
    };
    let actual_arch = match e_machine {
        62 => Some("amd64"),    // EM_X86_64
        183 => Some("arm64"),   // EM_AARCH64
        40 => Some("armhf"),    // EM_ARM
        3 => Some("i386"),      // EM_386
        243 => Some("riscv64"), // EM_RISCV
        _ => None,
    };
    if let Some(actual) = actual_arch {
        let norm_expected = match expected_arch.trim() {
            "x86_64" | "amd64" => "amd64",
            "aarch64" | "arm64" => "arm64",
            "armv7l" | "arm" | "armhf" => "armhf",
            other => other,
        };
        if actual != norm_expected {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "ELF architecture mismatch for {}: binary header is '{}' (e_machine=0x{:04x}) but target architecture is '{}'",
                artifact_label, actual, e_machine, norm_expected
            )));
        }
    }
    Ok(())
}

/// Verifies a downloaded or staged artifact file against size bounds, optional SHA-256 digest,
/// and magic header signatures. Returns the computed lowercase hex SHA-256 digest.
pub fn verify_artifact_file(
    path: &Path,
    policy: &ArtifactVerificationPolicy,
) -> Result<String, PackageExecutorError> {
    verify_artifact_file_for_arch(path, policy, None)
}

/// Verifies a downloaded or staged artifact file against size bounds, architecture-specific or
/// global SHA-256 digest, and magic/ELF architecture header signatures.
pub fn verify_artifact_file_for_arch(
    path: &Path,
    policy: &ArtifactVerificationPolicy,
    target_arch: Option<&str>,
) -> Result<String, PackageExecutorError> {
    let meta = fs::metadata(path).map_err(|e| {
        PackageExecutorError::ArtifactVerification(format!(
            "artifact {} is missing or unreadable: {}",
            path.display(),
            e
        ))
    })?;
    if !meta.is_file() {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} is not a regular file",
            path.display()
        )));
    }
    let len = meta.len();
    if len < policy.min_size_bytes {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} is too small ({} bytes < minimum {} bytes; possible 404 or truncated download)",
            path.display(),
            len,
            policy.min_size_bytes
        )));
    }
    if policy.max_size_bytes > 0 && len > policy.max_size_bytes {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} exceeds maximum size ({} bytes > {} bytes)",
            path.display(),
            len,
            policy.max_size_bytes
        )));
    }

    let mut file = File::open(path)?;
    let mut header = [0u8; 20];
    let head_read = file.read(&mut header)?;

    if policy.require_gzip_magic && (head_read < 2 || header[0] != 0x1f || header[1] != 0x8b) {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} does not have a valid gzip header (0x1f8b)",
            path.display()
        )));
    }
    if policy.require_elf_magic && (head_read < 4 || header[..4] != [0x7f, b'E', b'L', b'F']) {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} does not have a valid ELF executable header (0x7f454c46)",
            path.display()
        )));
    }
    if policy.require_elf_magic {
        if let Some(arch) = target_arch {
            verify_elf_header_architecture(
                &header[..head_read],
                arch,
                &path.display().to_string(),
            )?;
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(&header[..head_read]);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hex::encode(hasher.finalize());

    let expected_opt: Option<&str> = if let Some(ref expected) = policy.expected_sha256 {
        Some(expected.as_str())
    } else if let (Some(ref arch_map), Some(arch)) = (&policy.arch_sha256, target_arch) {
        Some(arch_map.resolve(arch).ok_or_else(|| {
            PackageExecutorError::ArtifactVerification(format!(
                "no pinned SHA-256 digest configured for architecture '{}' on {}",
                arch,
                path.display()
            ))
        })?)
    } else {
        None
    };

    if let Some(expected_raw) = expected_opt {
        let allowed_digests: Vec<String> = expected_raw
            .split('|')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty() && s != "skip")
            .collect();
        if !allowed_digests.is_empty() && !allowed_digests.iter().any(|d| d == &digest) {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "SHA-256 mismatch for {}: expected {}, got {}",
                path.display(),
                allowed_digests.join(" or "),
                digest
            )));
        }
    }

    Ok(digest)
}
