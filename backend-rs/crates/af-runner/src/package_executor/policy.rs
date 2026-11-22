use super::*;

// -----------------------------------------------------------------------------
// Security Allowlists & Validation Constants
// -----------------------------------------------------------------------------

/// Strict Debian/Ubuntu APT package name validator (Debian Policy 5.6.1: lowercase alphanumeric + `+-.`).
pub static SAFE_APT_PKG_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9+.-]{0,127}$").unwrap());

/// Strict GitHub `owner/repo` identifier validator.
pub static SAFE_GITHUB_REPO: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}$").unwrap());

///// Strict release tag/version validator (`v1.2.3`, `1.46.0`, etc.).
pub static SAFE_VERSION_TAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$").unwrap());

/// Strict X.509 Distinguished Name subject validator (`/CN=AetherFlow-Quassel`, etc.).
pub static SAFE_TLS_SUBJECT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^/CN=[A-Za-z0-9_.-]{1,64}(/[A-Za-z]{1,4}=[A-Za-z0-9_.-]{1,64})*$").unwrap()
});

/// Pinned upstream Threadfin release version (`https://github.com/Threadfin/Threadfin/releases/expanded_assets/1.2.37`).
pub const THREADFIN_PINNED_VERSION: &str = "1.2.37";

/// Pinned SHA-256 digest for `Threadfin_linux_amd64_glibc_2.31_compat` (`Threadfin_linux_amd64_compat`) 1.2.37.
pub const THREADFIN_AMD64_COMPAT_SHA256: &str =
    "0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42";

/// Pinned SHA-256 digest for `Threadfin_linux_arm64` 1.2.37.
pub const THREADFIN_ARM64_SHA256: &str =
    "1e5e6f065cf2470d1460fae80c68c9631ca79e67ff76f83d47ab4bcb9ceb6213";

/// Pinned SHA-256 digest for `Threadfin_linux_arm` (armhf) 1.2.37.
pub const THREADFIN_ARMHF_SHA256: &str =
    "d64e6b7f8a1ab8aebdd37d06bfb0bddb991c68c9fed52e25530b92ead10c8328";

/// Secondary upstream SHA-256 digest for plain `Threadfin_linux_amd64` 1.2.37.
pub const THREADFIN_AMD64_PLAIN_SHA256: &str =
    "19183013ec8da826e556bde3b511d9f93b9269f6d7eddd78a9df128529f45e4e";

pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validates Threadfin's pinned version and override environment contract before
/// any state mutation. Returns `(resolved_version, validated_sha256_override)`.
pub fn validate_threadfin_target_policy(
    expected_target_version: Option<&str>,
) -> Result<(String, Option<String>), PackageExecutorError> {
    let mut sha_override: Option<String> = None;
    for var_name in [
        "AETHERFLOW_THREADFIN_SHA256",
        "THREADFIN_SHA256",
        "AF_THREADFIN_SHA256",
        "AETHERFLOW_PACKAGE_SHA256_OVERRIDE",
    ] {
        if let Ok(raw) = env::var(var_name) {
            let trimmed = raw.trim();
            if !is_valid_sha256_hex(trimmed) {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid Threadfin SHA-256 override in {}: expected 64-character hexadecimal SHA-256 digest",
                    var_name
                )));
            }
            if sha_override.is_none() {
                sha_override = Some(trimmed.to_ascii_lowercase());
            }
        }
    }

    let mut version_override: Option<String> = None;
    for var_name in [
        "AETHERFLOW_THREADFIN_VERSION",
        "THREADFIN_VERSION",
        "AF_THREADFIN_VERSION",
        "AETHERFLOW_PACKAGE_VERSION_OVERRIDE",
    ] {
        if let Ok(raw) = env::var(var_name) {
            let trimmed = raw.trim();
            let clean = af_release::lifecycle::strip_version_prefix(trimmed);
            if clean.is_empty()
                || !SAFE_VERSION_TAG.is_match(clean)
                || !af_release::lifecycle::validate_target_version(trimmed)
            {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid Threadfin version override in {}: '{}'",
                    var_name, raw
                )));
            }
            if version_override.is_none() {
                version_override = Some(clean.to_string());
            }
        }
    }

    if let Some(ref custom_ver) = version_override {
        if custom_ver != THREADFIN_PINNED_VERSION && sha_override.is_none() {
            return Err(PackageExecutorError::Validation(format!(
                "Threadfin is pinned to version {}; overriding to '{}' requires an explicit 64-hex SHA-256 override",
                THREADFIN_PINNED_VERSION, custom_ver
            )));
        }
    }

    let resolved_version = version_override.unwrap_or_else(|| THREADFIN_PINNED_VERSION.to_string());

    if let Some(raw_target) = expected_target_version
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !af_release::lifecycle::validate_target_version(raw_target) {
            return Err(PackageExecutorError::Validation(format!(
                "invalid Threadfin target version '{}'",
                raw_target
            )));
        }
        let clean_target = af_release::lifecycle::strip_version_prefix(raw_target);
        if clean_target != resolved_version {
            return Err(PackageExecutorError::Validation(format!(
                "Threadfin is pinned to version {}; requested target version '{}' is unsupported without a matching version and SHA-256 override",
                resolved_version, raw_target
            )));
        }
    }

    Ok((resolved_version, sha_override))
}

/// Maps a host architecture identifier to Listenarr's official Linux release ZIP suffix.
/// Official `Listenarrs/Listenarr` releases currently publish Linux x64 (`amd64`) ZIPs only.
pub fn listenarr_release_asset_suffix_for_arch(arch: &str) -> Result<&'static str, String> {
    match arch.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" => Ok("linux-x64.zip"),
        "aarch64" | "arm64" => Err(
            "Package 'listenarr' is unsupported on architecture 'arm64': official Listenarrs/Listenarr releases publish Linux x64 (amd64) ZIP archives only and currently provide zero Linux ARM64 assets."
                .to_string(),
        ),
        other => Err(format!(
            "Package 'listenarr' is unsupported on architecture '{}': official Listenarrs/Listenarr releases publish Linux x64 (amd64) ZIP archives only.",
            other
        )),
    }
}

/// Validates that a Listenarr release asset download URL belongs to the official
/// `Listenarrs/Listenarr` release download path for `tag_name` and `asset_name`.
pub fn listenarr_is_official_download_url(
    tag_name: &str,
    asset_name: &str,
    download_url: &str,
) -> bool {
    let clean_tag = tag_name.trim();
    let clean_name = asset_name.trim();
    let clean_url = download_url.trim();
    if clean_tag.is_empty()
        || clean_name.is_empty()
        || clean_url.is_empty()
        || clean_url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let Some(rest) = clean_url.strip_prefix("https://github.com/") else {
        return false;
    };
    let Some((owner_repo, after_download)) = rest.split_once("/releases/download/") else {
        return false;
    };
    if !owner_repo.eq_ignore_ascii_case("Listenarrs/Listenarr") {
        return false;
    }
    let Some((url_tag, url_asset)) = after_download.split_once('/') else {
        return false;
    };
    !url_asset.contains('/') && url_tag == clean_tag && url_asset == clean_name
}

/// Returns whether a GitHub release asset entry is an official checksum companion
/// for Listenarr release `tag_name`.
pub fn listenarr_is_official_checksum_companion(
    tag_name: &str,
    asset_name: &str,
    download_url: &str,
) -> bool {
    let lower = asset_name.trim().to_ascii_lowercase();
    (lower.contains("checksum") || lower.contains("sha256"))
        && listenarr_is_official_download_url(tag_name, asset_name, download_url)
}

/// Returns whether a GitHub release asset entry is an eligible official Listenarr archive
/// for `asset_suffix` with an official download URL and either a valid `sha256:` digest
/// or an official checksum companion.
pub fn listenarr_release_asset_is_eligible(
    tag_name: &str,
    asset_name: &str,
    download_url: &str,
    digest: Option<&str>,
    has_checksum_companion: bool,
    asset_suffix: &str,
) -> bool {
    let clean_tag = tag_name.trim();
    let clean_name = asset_name.trim();
    if clean_tag.is_empty() || !clean_name.ends_with(asset_suffix) {
        return false;
    }
    if !listenarr_is_official_download_url(clean_tag, clean_name, download_url) {
        return false;
    }
    match digest.map(str::trim).filter(|d| !d.is_empty()) {
        Some(raw) => raw.strip_prefix("sha256:").is_some_and(is_valid_sha256_hex),
        None => has_checksum_companion,
    }
}

/// Validates exact-version and architecture policy for pinned, vendor, and Listenarr packages
/// before any lifecycle admission, sandbox write, or installer execution.
pub fn validate_package_target_policy(
    package_id: &str,
    update_source: &str,
    update_package: &str,
    action: &str,
    expected_target_version: Option<&str>,
) -> Result<(), String> {
    validate_package_target_policy_for_arch(
        package_id,
        update_source,
        update_package,
        action,
        expected_target_version,
        env::consts::ARCH,
    )
}

/// Architecture-parameterized variant of [`validate_package_target_policy`].
pub fn validate_package_target_policy_for_arch(
    package_id: &str,
    update_source: &str,
    update_package: &str,
    action: &str,
    expected_target_version: Option<&str>,
    host_arch: &str,
) -> Result<(), String> {
    let action_lower = action.trim().to_ascii_lowercase();
    if action_lower == "remove" || action_lower == "uninstall" {
        return Ok(());
    }
    let src = update_source.trim().to_ascii_lowercase();
    if src == "vendor" {
        if action_lower == "update" {
            return Err(format!(
                "Package '{}' uses a multi-component vendor installer and does not support exact-version updates; use reinstall or the vendor updater instead.",
                package_id
            ));
        }
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Err(format!(
                "Package '{}' uses a multi-component vendor installer and cannot honor exact target version '{}'; omit the target version to run the official vendor installer.",
                package_id, target
            ));
        }
        return Ok(());
    }
    if package_id.eq_ignore_ascii_case("threadfin") {
        validate_threadfin_target_policy(expected_target_version)
            .map(|_| ())
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    if package_id.eq_ignore_ascii_case("listenarr") {
        listenarr_release_asset_suffix_for_arch(host_arch)?;
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !af_release::lifecycle::validate_target_version(target) {
                return Err(format!(
                    "Invalid target version '{}' for package '{}'",
                    target, package_id
                ));
            }
        }
        return Ok(());
    }
    if src == "apt" {
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !af_release::lifecycle::validate_exact_apt_version(target) {
                return Err(format!(
                    "Invalid exact Debian/APT target version '{}' for package '{}'",
                    target, package_id
                ));
            }
        }
        return Ok(());
    }
    if src == "pinned" {
        let pinned = af_release::lifecycle::strip_version_prefix(update_package.trim());
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !af_release::lifecycle::validate_target_version(target) {
                return Err(format!(
                    "Invalid target version '{}' for pinned package '{}'",
                    target, package_id
                ));
            }
            if !pinned.is_empty() && af_release::lifecycle::strip_version_prefix(target) != pinned {
                return Err(format!(
                    "Pinned package '{}' can only target version '{}', got '{}'",
                    package_id, pinned, target
                ));
            }
        }
    }
    Ok(())
}

/// Default Quassel IRC core listen port when no custom `app_port` is requested.
pub const QUASSEL_DEFAULT_LISTEN_PORT: i32 = 4242;

pub(crate) const RCLONE_BIN: &str = "/opt/AetherFlow/apps/rclone/rclone";
pub(crate) const RCLONE_BIN_OWNER: &str = "/opt/AetherFlow/apps/rclone/.af-owner";
pub(crate) const RCLONE_ENV: &str = "/etc/rclone/rclone.env";
pub(crate) const RCLONE_LEGACY_ENV: &str = "/etc/aetherflow/rclone.env";

/// Allowed managed prefixes for declarative file writes, creations, and removals.
pub(super) const ALLOWED_MANAGED_PREFIXES: &[&str] = &[
    "/etc/",
    "/var/lib/",
    "/var/log/",
    "/var/run/",
    "/run/",
    "/opt/",
    "/usr/local/bin/",
    "/install/",
    "/mnt/",
];

/// Forbidden exact paths that must never be removed or overwritten even under managed prefixes.
pub(super) const FORBIDDEN_EXACT_PATHS: &[&str] = &[
    "/",
    "/bin",
    "/sbin",
    "/etc",
    "/etc/apt",
    "/etc/default",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/fstab",
    "/etc/ssh",
    "/etc/ssh/sshd_config",
    "/etc/systemd",
    "/etc/systemd/system",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/log",
    "/var/run",
    "/run",
    "/opt",
    "/opt/AetherFlow",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local",
    "/usr/local/bin",
    "/install",
    "/mnt",
];

/// Shared system directories that must never have recursive ownership (`chown -R`) applied.
pub(super) const SHARED_SYSTEM_CHOWN_PATHS: &[&str] = &[
    "/",
    "/bin",
    "/sbin",
    "/etc",
    "/etc/apt",
    "/etc/default",
    "/etc/systemd",
    "/etc/systemd/system",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/log",
    "/var/run",
    "/run",
    "/opt",
    "/opt/AetherFlow",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local",
    "/usr/local/bin",
    "/install",
    "/mnt",
];

/// Maximum stdout/stderr bytes retained per command execution to prevent unbounded memory growth.
pub(super) const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;

pub(super) static PROGRESS_LINE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\[PROGRESS:(\d{1,3})\]\s*(.*)$").unwrap());
pub(super) static SSH_PORT_LINE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*Port\s+([0-9]{1,5})\b").unwrap());

