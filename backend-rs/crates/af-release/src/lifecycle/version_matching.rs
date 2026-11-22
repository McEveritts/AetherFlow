use super::version::{
    commits_match_prefix, is_hex_digits_7_to_40, is_hex_sha_7_to_64,
    is_valid_apt_debian_revision_suffix, normalize_version, strip_semver_build_metadata,
    strip_version_prefix,
};

/// Extracts the raw candidate version token from `apt-cache policy` stdout.
/// Returns `None` when no `Candidate:` line is present or the first candidate is empty / `(none)`.
pub fn parse_apt_policy_candidate(stdout: &str) -> Option<&str> {
    let candidate = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Candidate:"))?
        .trim();
    (!candidate.is_empty() && candidate != "(none)").then_some(candidate)
}

/// Validates an exact Debian/APT package version token per Debian Policy §5.6.12
/// (`[epoch:]upstream_version[-debian_revision]`), rejecting floating tags, globs,
/// release selectors, `v`-prefixed tags, Git SHAs, component manifests, and unsafe characters.
pub fn validate_exact_apt_version(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    let rest = if let Some((epoch, rem)) = trimmed.split_once(':') {
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        rem
    } else {
        trimmed
    };
    if rest.is_empty() || !rest.starts_with(|c: char| c.is_ascii_digit()) || rest.contains(':') {
        return false;
    }
    if let Some((upstream, rev)) = rest.rsplit_once('-') {
        if upstream.is_empty() || rev.is_empty() {
            return false;
        }
        return upstream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~' | b'-'))
            && rev
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~'));
    }
    rest.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~'))
}

/// Parses `dpkg-query -W -f=${db:Status-Status} ${Version}\n <pkg>` output, returning
/// the exact full Debian version only when status is strictly `installed` and the version
/// token is a valid Debian version.
pub fn parse_installed_dpkg_status_version(stdout: &str) -> Option<&str> {
    let mut parts = stdout.split_whitespace();
    let status = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || status != "installed" {
        return None;
    }
    validate_exact_apt_version(version).then_some(version)
}

/// Returns whether a legacy stripped `.af-version` receipt (e.g. `0.14.0` or `1.9.1`)
/// is compatible with a live full Debian version (`1:0.14.0-1+deb12u1` or `1.9.1-2+deb13u1`).
/// Exact target certification still requires full-version equality via `versions_match_target`.
pub fn apt_receipt_matches_live_debian_revision(
    update_source: &str,
    receipt_ver: &str,
    live_ver: &str,
) -> bool {
    if !matches!(
        update_source.trim().to_ascii_lowercase().as_str(),
        "apt" | "deb" | "dpkg"
    ) {
        return false;
    }
    let live_trimmed = live_ver.trim();
    let without_epoch = match live_trimmed.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => live_trimmed,
    };
    let Some((live_upstream, deb_rev)) = without_epoch.rsplit_once('-') else {
        return false;
    };
    !live_upstream.contains('~')
        && is_valid_apt_debian_revision_suffix(deb_rev)
        && (versions_match_target(receipt_ver, live_upstream)
            || versions_match_target(live_upstream, receipt_ver))
}

pub fn single_version_matches(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    if !validate_target_version(ach) || !validate_target_version(exp) {
        return false;
    }
    let ach_lower = ach.to_ascii_lowercase();
    let exp_lower = exp.to_ascii_lowercase();
    let is_manifest = ach.contains(',')
        || exp.contains(',')
        || ach.contains('=')
        || exp.contains('=')
        || ach_lower.contains("frontend:")
        || exp_lower.contains("frontend:")
        || ach_lower.contains("backend:")
        || exp_lower.contains("backend:")
        || ach_lower.contains("proxy:")
        || exp_lower.contains("proxy:");

    if is_manifest {
        return matches_component_manifest(ach, exp);
    }
    if exp.eq_ignore_ascii_case(ach) {
        return true;
    }
    let norm_exp = normalize_version(exp);
    let norm_ach = normalize_version(ach);
    if norm_exp.eq_ignore_ascii_case(norm_ach) {
        return true;
    }
    let sem_exp = strip_semver_build_metadata(norm_exp);
    let sem_ach = strip_semver_build_metadata(norm_ach);
    if sem_exp.eq_ignore_ascii_case(sem_ach) {
        return true;
    }
    commits_match_prefix(norm_exp, norm_ach, false)
}

pub fn single_version_matches_target(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    let norm_exp = strip_version_prefix(exp);
    let norm_ach = strip_version_prefix(ach);

    // Exact case-sensitive equality of normalized strings
    if norm_ach == norm_exp {
        return true;
    }

    // Only compare case-insensitively when BOTH normalized tokens are pure hexadecimal Git commit SHAs
    let ach_is_hex = is_hex_digits_7_to_40(norm_ach);
    let exp_is_hex = is_hex_digits_7_to_40(norm_exp);

    if ach_is_hex && exp_is_hex {
        if norm_ach.eq_ignore_ascii_case(norm_exp) {
            return true;
        }
        if commits_match_prefix(norm_exp, norm_ach, false) {
            return true;
        }
    }

    false
}

fn is_sensitive_key_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("api-key")
        || lower.contains("access_key")
        || lower.contains("access-key")
        || lower.contains("private_key")
        || lower.contains("private-key")
        || lower.contains("client_secret")
        || lower.contains("credential")
        || lower.contains("passphrase")
        || lower.contains("auth")
}

fn check_numeric_semver_debian(s: &str) -> bool {
    if s.contains(':') {
        let colon_count = s.matches(':').count();
        if colon_count != 1 {
            return false;
        }
        let (epoch, rest) = match s.split_once(':') {
            Some(pair) => pair,
            None => return false,
        };
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if !rest.starts_with(|c: char| c.is_ascii_digit()) {
            return false;
        }
        return rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'));
    }

    let rest = if (s.starts_with('v') || s.starts_with('V'))
        && s.len() > 1
        && s[1..]
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        &s[1..]
    } else {
        s
    };

    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }

    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'))
}

pub fn validate_single_version_token(ver: &str) -> bool {
    let trimmed = ver.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    if trimmed.chars().any(|c| {
        matches!(
            c,
            ';' | '&'
                | '|'
                | '`'
                | '$'
                | '('
                | ')'
                | '<'
                | '>'
                | '"'
                | '\''
                | '*'
                | '?'
                | '!'
                | '{'
                | '}'
        )
    }) {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    const FORBIDDEN_TOKENS: &[&str] = &[
        "latest",
        "unknown",
        "none",
        "null",
        "undefined",
        "error",
        "n/a",
        "na",
        "current",
        "installed",
        "pending",
        "default",
        "auto",
        "true",
        "false",
        "head",
        "main",
        "master",
        "stable",
        "beta",
        "nightly",
        "edge",
        "dev",
        "devel",
        "alpha",
        "rc",
        "release",
    ];
    if FORBIDDEN_TOKENS.contains(&lower.as_str()) {
        return false;
    }

    if is_sensitive_key_name(&lower) {
        return false;
    }

    // b) Valid Git commit SHA (7..=64 hex)
    if is_hex_sha_7_to_64(trimmed) {
        return true;
    }

    // a) Concrete numeric/SemVer/Debian version starting with ASCII digit (0-9)
    if check_numeric_semver_debian(trimmed) {
        return true;
    }

    // Standard release/version prefixes (e.g. Release-v1.0.0, ver-1.0.0)
    let stripped = strip_version_prefix(trimmed);
    if !stripped.is_empty() && stripped != trimmed {
        let stripped_lower = stripped.to_ascii_lowercase();
        if !FORBIDDEN_TOKENS.contains(&stripped_lower.as_str())
            && !is_sensitive_key_name(&stripped_lower)
            && (is_hex_sha_7_to_64(stripped) || check_numeric_semver_debian(stripped))
        {
            return true;
        }
    }

    // c) Valid <prefix>-<sha> where <prefix> is [A-Za-z0-9._-]+ (not sensitive key)
    // and <sha> is 7..=64 hex characters or <prefix> starts with a digit.
    if let Some(idx) = trimmed.rfind('-') {
        let prefix = &trimmed[..idx];
        let sha = &trimmed[idx + 1..];
        if is_hex_sha_7_to_64(sha) && !prefix.is_empty() {
            let prefix_lower = prefix.to_ascii_lowercase();
            if prefix.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            }) && (prefix.starts_with(|character: char| character.is_ascii_digit())
                || (!FORBIDDEN_TOKENS.contains(&prefix_lower.as_str())
                    && !is_sensitive_key_name(&prefix_lower)))
            {
                return true;
            }
        }
    }

    false
}

pub fn is_valid_component_version(s: &str) -> bool {
    validate_single_version_token(s)
}

pub fn parse_piped_component_manifest(
    s: &str,
) -> Option<std::collections::HashMap<String, String>> {
    parse_component_manifest(s)
}

pub fn parse_component_manifest(s: &str) -> Option<std::collections::HashMap<String, String>> {
    if !s.contains(':') && !s.contains('=') {
        return None;
    }
    let parts: Vec<&str> = s.split(',').collect();
    let mut map = std::collections::HashMap::new();
    for raw_part in &parts {
        let item = raw_part.trim();
        if item.is_empty() {
            return None;
        }
        let delimiter_index = item.find(['=', ':'])?;
        let key = item[..delimiter_index].trim().to_lowercase();
        let val = item[delimiter_index + 1..].trim().to_string();
        if key.is_empty() || val.is_empty() {
            return None;
        }
        if !validate_single_version_token(&val) {
            return None;
        }
        if map.insert(key, val).is_some() {
            return None;
        }
    }
    if map.len() < 2 {
        return None;
    }
    let has_frontend = map.contains_key("frontend");
    let has_backend = map.contains_key("backend");
    let has_proxy = map.contains_key("proxy");
    if has_frontend || has_backend || has_proxy {
        if !has_frontend || !has_backend || !has_proxy || map.len() != 3 || parts.len() != 3 {
            return None;
        }
        for k in ["frontend", "backend", "proxy"] {
            let val = map.get_mut(k)?;
            let norm = normalize_version(val);
            let val_clean = if is_hex_sha_7_to_64(norm) {
                norm.to_ascii_lowercase()
            } else if is_hex_sha_7_to_64(val) {
                val.to_ascii_lowercase()
            } else {
                val.trim().to_string()
            };
            *val = val_clean;
        }
    }
    Some(map)
}

pub fn matches_component_manifest(achieved: &str, expected: &str) -> bool {
    let exp_map = match parse_component_manifest(expected) {
        Some(m) => m,
        None => return false,
    };
    let ach_map = match parse_component_manifest(achieved) {
        Some(m) => m,
        None => return false,
    };
    if exp_map.len() != ach_map.len() {
        return false;
    }
    for (k, exp_val) in &exp_map {
        match ach_map.get(k) {
            Some(ach_val) => {
                let is_hex_pair = (is_hex_digits_7_to_40(exp_val)
                    || is_hex_digits_7_to_40(normalize_version(exp_val)))
                    && (is_hex_digits_7_to_40(ach_val)
                        || is_hex_digits_7_to_40(normalize_version(ach_val)));
                if is_hex_pair {
                    if !commits_match_prefix(exp_val, ach_val, true) {
                        return false;
                    }
                } else if !single_version_matches_target(ach_val, exp_val) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

pub fn validate_target_version(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    if trimmed.chars().any(|c| {
        matches!(
            c,
            ';' | '&'
                | '|'
                | '`'
                | '$'
                | '('
                | ')'
                | '<'
                | '>'
                | '"'
                | '\''
                | '*'
                | '?'
                | '!'
                | '{'
                | '}'
        )
    }) {
        return false;
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "unknown" | "none" | "null" | "latest"
    ) {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    let is_manifest_candidate = trimmed.contains(',')
        || trimmed.contains('=')
        || lower.contains("frontend:")
        || lower.contains("backend:")
        || lower.contains("proxy:")
        || lower.contains("frontend=")
        || lower.contains("backend=")
        || lower.contains("proxy=");

    if is_manifest_candidate {
        return parse_component_manifest(trimmed).is_some();
    }

    validate_single_version_token(trimmed)
}

pub fn is_valid_target_version_token(s: &str) -> bool {
    validate_target_version(s)
}

pub fn versions_match_target(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    if !validate_target_version(ach) || !validate_target_version(exp) {
        return false;
    }

    let ach_lower = ach.to_ascii_lowercase();
    let exp_lower = exp.to_ascii_lowercase();
    let is_manifest = ach.contains(',')
        || exp.contains(',')
        || ach.contains('=')
        || exp.contains('=')
        || ach_lower.contains("frontend:")
        || exp_lower.contains("frontend:")
        || ach_lower.contains("backend:")
        || exp_lower.contains("backend:")
        || ach_lower.contains("proxy:")
        || exp_lower.contains("proxy:");

    if is_manifest {
        return matches_component_manifest(ach, exp);
    }

    if ach == exp {
        return true;
    }

    single_version_matches_target(ach, exp)
}
