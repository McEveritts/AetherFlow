use super::*;

pub(in crate::workers) static DOTTED_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?\d+\.\d+(?:\.\d+)*(?:~[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)")
        .unwrap()
});
pub(in crate::workers) static DEFAULT_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?[0-9]+(?:\.[0-9]+)*(?:~[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)")
        .unwrap()
});
pub(in crate::workers) static SYNTHETIC_COMMIT_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)-([0-9a-fA-F]{7,40})$").unwrap());

pub fn strip_trailing_version_punctuation(s: &str) -> &str {
    let mut trimmed = s.trim_end_matches(|c: char| {
        c == '.'
            || c == ','
            || c == ';'
            || c == ':'
            || c == ')'
            || c == ']'
            || c == '}'
            || c == '"'
            || c == '\''
    });
    if trimmed.ends_with('+') {
        trimmed = trimmed[..trimmed.len() - 1].trim_end_matches(|c: char| {
            c == '.'
                || c == ','
                || c == ';'
                || c == ':'
                || c == ')'
                || c == ']'
                || c == '}'
                || c == '"'
                || c == '\''
        });
    }
    if trimmed.ends_with('-') {
        let prefix = &trimmed[..trimmed.len() - 1];
        if !prefix.contains('-') && !prefix.contains('+') && !prefix.contains('~') {
            trimmed = prefix.trim_end_matches(|c: char| {
                c == '.'
                    || c == ','
                    || c == ';'
                    || c == ':'
                    || c == ')'
                    || c == ']'
                    || c == '}'
                    || c == '"'
                    || c == '\''
            });
        }
    }
    trimmed
}

pub fn extract_version_from_text(raw: &str) -> String {
    extract_version(raw, "")
}

pub fn extract_version(raw: &str, custom_expr: &str) -> String {
    let text = raw.trim();
    if text.is_empty() {
        return String::new();
    }

    for line in text.lines() {
        let line_trim = line.trim();
        if let Some(map) = parse_component_manifest(line_trim) {
            return normalize_component_manifest(&map);
        }
    }

    let norm_text = af_release::lifecycle::normalize_version(text);

    if !custom_expr.trim().is_empty() {
        if let Ok(re) = Regex::new(custom_expr) {
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(1) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
                if let Some(m) = caps.get(0) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
            if let Some(caps) = re.captures(norm_text) {
                if let Some(m) = caps.get(1) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
                if let Some(m) = caps.get(0) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
        }
    }

    if let Some(caps) = SYNTHETIC_COMMIT_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(0) {
            let s = m.as_str().trim();
            let clean = s
                .strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .unwrap_or(s);
            return clean.to_string();
        }
    }
    if let Some(caps) = SYNTHETIC_COMMIT_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(0) {
            let s = m.as_str().trim();
            let clean = s
                .strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .unwrap_or(s);
            return clean.to_string();
        }
    }

    let clean_text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    if is_git_commit_sha(clean_text) {
        return clean_text.to_string();
    }

    let clean_norm = norm_text
        .strip_prefix('v')
        .or_else(|| norm_text.strip_prefix('V'))
        .unwrap_or(norm_text);
    if is_git_commit_sha(clean_norm) {
        return clean_norm.to_string();
    }

    if let Some(caps) = DOTTED_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Some(caps) = DOTTED_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }

    for token in text.split_whitespace().chain(norm_text.split_whitespace()) {
        let trimmed_token = token.trim_matches(|c: char| {
            c == '(' || c == ')' || c == '[' || c == ']' || c == '"' || c == '\'' || c == ','
        });
        let clean = trimmed_token
            .strip_prefix('v')
            .or_else(|| trimmed_token.strip_prefix('V'))
            .unwrap_or(trimmed_token);
        if is_git_commit_sha(clean) {
            return clean.to_string();
        }
    }

    if let Some(caps) = DEFAULT_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(m) = caps.get(0) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Some(caps) = DEFAULT_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(m) = caps.get(0) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }

    String::new()
}

pub(in crate::workers) fn parse_git_head(output: &str) -> anyhow::Result<String> {
    let head = output.split_whitespace().next().unwrap_or_default();
    if !is_git_commit(head) {
        anyhow::bail!("invalid Git HEAD commit");
    }
    Ok(head.to_string())
}

pub(in crate::workers) fn is_git_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(in crate::workers) fn dpkg_char_order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(b) if b.is_ascii_alphabetic() => b as i32,
        Some(b) => (b as i32) + 256,
    }
}

pub fn dpkg_verrevcmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = 0;
    let mut j = 0;

    while i < ab.len() || j < bb.len() {
        while (i < ab.len() && !ab[i].is_ascii_digit()) || (j < bb.len() && !bb[j].is_ascii_digit())
        {
            let ac = if i < ab.len() && !ab[i].is_ascii_digit() {
                Some(ab[i])
            } else {
                None
            };
            let bc = if j < bb.len() && !bb[j].is_ascii_digit() {
                Some(bb[j])
            } else {
                None
            };
            let ord = dpkg_char_order(ac).cmp(&dpkg_char_order(bc));
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
            if ac.is_some() {
                i += 1;
            }
            if bc.is_some() {
                j += 1;
            }
        }

        while i < ab.len() && ab[i] == b'0' {
            i += 1;
        }
        while j < bb.len() && bb[j] == b'0' {
            j += 1;
        }

        let i_start = i;
        while i < ab.len() && ab[i].is_ascii_digit() {
            i += 1;
        }
        let j_start = j;
        while j < bb.len() && bb[j].is_ascii_digit() {
            j += 1;
        }

        let a_len = i - i_start;
        let b_len = j - j_start;
        if a_len != b_len {
            return a_len.cmp(&b_len);
        }

        let ord = ab[i_start..i].cmp(&bb[j_start..j]);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    std::cmp::Ordering::Equal
}

pub(in crate::workers) fn parse_debian_version(raw: &str) -> (u64, &str, &str) {
    let mut s = raw.trim();
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        s = normalize_tag_or_version_prefix(s);
    }
    let (epoch, remainder) = if let Some((ep, rem)) = s.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().unwrap_or(0), rem)
        } else {
            (0, s)
        }
    } else {
        (0, s)
    };
    let (upstream, debian_revision) = if let Some((up, rev)) = remainder.rsplit_once('-') {
        (up, rev)
    } else {
        (remainder, "")
    };
    (epoch, upstream, debian_revision)
}

pub fn compare_debian_versions_str(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_epoch, a_up, a_rev) = parse_debian_version(a);
    let (b_epoch, b_up, b_rev) = parse_debian_version(b);

    if a_epoch != b_epoch {
        return a_epoch.cmp(&b_epoch);
    }

    let up_ord = dpkg_verrevcmp(a_up, b_up);
    if up_ord != std::cmp::Ordering::Equal {
        return up_ord;
    }

    dpkg_verrevcmp(a_rev, b_rev)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::workers) struct SemverVersion {
    epoch: u64,
    segments: Vec<u64>,
    prerelease: Option<Vec<PrereleaseIdentifier>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::workers) enum PrereleaseIdentifier {
    Numeric(String),
    Alpha(String),
}

pub(in crate::workers) fn parse_semver(raw: &str) -> Option<SemverVersion> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // In SemVer mode, strip build metadata (+...)
    let s_no_build = match s.split_once('+') {
        Some((v, _)) => v.trim(),
        None => s,
    };
    let norm = af_release::lifecycle::normalize_version(s_no_build);
    if norm.is_empty() {
        return None;
    }

    let (epoch, rest) = if let Some((ep, rem)) = norm.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().ok()?, rem)
        } else {
            (0, norm)
        }
    } else {
        (0, norm)
    };

    if rest.is_empty() || !rest.bytes().any(|b| b.is_ascii_digit()) {
        return None;
    }

    let (normal_str, prerelease_opt) = match rest.find(['-', '~']) {
        Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
        None => (rest, None),
    };

    let mut segments = Vec::new();
    for seg in normal_str.split('.') {
        let seg_trim = seg.trim();
        if seg_trim.is_empty() || !seg_trim.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        segments.push(seg_trim.parse::<u64>().ok()?);
    }
    if segments.is_empty() {
        return None;
    }

    let prerelease = match prerelease_opt {
        Some(pre) if !pre.trim().is_empty() => {
            let mut ids = Vec::new();
            for part in pre.trim().split('.') {
                let part_trim = part.trim();
                if part_trim.is_empty() {
                    continue;
                }
                if part_trim.bytes().all(|b| b.is_ascii_digit()) {
                    let canonical = part_trim.trim_start_matches('0');
                    let canonical = if canonical.is_empty() { "0" } else { canonical };
                    ids.push(PrereleaseIdentifier::Numeric(canonical.to_string()));
                } else {
                    ids.push(PrereleaseIdentifier::Alpha(part_trim.to_string()));
                }
            }
            if ids.is_empty() {
                None
            } else {
                Some(ids)
            }
        }
        _ => None,
    };

    Some(SemverVersion {
        epoch,
        segments,
        prerelease,
    })
}

pub(in crate::workers) fn compare_semver_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (Some(sa), Some(sb)) = (parse_semver(a), parse_semver(b)) else {
        let a_norm = af_release::lifecycle::normalize_version(a);
        let b_norm = af_release::lifecycle::normalize_version(b);
        return dpkg_verrevcmp(a_norm, b_norm);
    };

    if sa.epoch != sb.epoch {
        return sa.epoch.cmp(&sb.epoch);
    }

    let max_len = sa.segments.len().max(sb.segments.len());
    for i in 0..max_len {
        let seg_a = sa.segments.get(i).copied().unwrap_or(0);
        let seg_b = sb.segments.get(i).copied().unwrap_or(0);
        let ord = seg_a.cmp(&seg_b);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    match (&sa.prerelease, &sb.prerelease) {
        (None, None) => std::cmp::Ordering::Equal,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(ids_a), Some(ids_b)) => {
            for (id_a, id_b) in ids_a.iter().zip(ids_b.iter()) {
                let ord = match (id_a, id_b) {
                    (PrereleaseIdentifier::Numeric(na), PrereleaseIdentifier::Numeric(nb)) => {
                        na.len().cmp(&nb.len()).then_with(|| na.cmp(nb))
                    }
                    (PrereleaseIdentifier::Numeric(_), PrereleaseIdentifier::Alpha(_)) => {
                        std::cmp::Ordering::Less
                    }
                    (PrereleaseIdentifier::Alpha(_), PrereleaseIdentifier::Numeric(_)) => {
                        std::cmp::Ordering::Greater
                    }
                    (PrereleaseIdentifier::Alpha(sa), PrereleaseIdentifier::Alpha(sb)) => {
                        sa.cmp(sb)
                    }
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            ids_a.len().cmp(&ids_b.len())
        }
    }
}

pub fn is_newer_version(local: &str, remote: &str) -> bool {
    is_remote_version_newer(local, remote)
}

pub fn versions_match_target_internal(expected: &str, achieved: &str) -> bool {
    af_release::lifecycle::versions_match_target(achieved, expected)
}

/// Compares two version strings using Debian Policy (§5.6.12 `dpkg --compare-versions`),
/// SemVer prerelease ordering, git commit SHAs, synthetic commit versions, and component manifests.
pub fn is_remote_version_newer(local: &str, remote: &str) -> bool {
    is_remote_version_newer_for_source(local, remote, "")
}

pub fn is_remote_version_newer_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    let l_trim = local.trim();
    let r_trim = remote.trim();

    // 1. Multi-component manifests (frontend:...,backend:...,proxy:...)
    let l_manifest = parse_component_manifest(l_trim);
    let r_manifest = parse_component_manifest(r_trim);

    if l_manifest.is_some() || r_manifest.is_some() {
        if let (Some(installed_map), Some(latest_map)) = (l_manifest.as_ref(), r_manifest.as_ref())
        {
            if latest_map.len() != installed_map.len() {
                return true;
            }
            for (comp, latest_val) in latest_map {
                let Some(inst_val) = installed_map.get(comp) else {
                    return true;
                };
                let is_hex_pair = (af_release::lifecycle::is_hex_digits_7_to_40(latest_val)
                    || af_release::lifecycle::is_hex_digits_7_to_40(
                        af_release::lifecycle::normalize_version(latest_val),
                    ))
                    && (af_release::lifecycle::is_hex_digits_7_to_40(inst_val)
                        || af_release::lifecycle::is_hex_digits_7_to_40(
                            af_release::lifecycle::normalize_version(inst_val),
                        ));
                if is_hex_pair {
                    if !af_release::lifecycle::commits_match_prefix(latest_val, inst_val, true) {
                        return true;
                    }
                } else {
                    if af_release::lifecycle::commits_match_prefix(latest_val, inst_val, false) {
                        continue;
                    }
                    if af_release::lifecycle::single_version_matches(inst_val, latest_val) {
                        continue;
                    }
                    if is_newer_version_scalar_for_source(inst_val, latest_val, update_source) {
                        return true;
                    }
                }
            }
            return false;
        } else if let Some(l_map) = l_manifest.as_ref() {
            let r_clean = af_release::lifecycle::normalize_version(r_trim);
            if is_git_commit_sha(r_clean) {
                if let Some(l_frontend) = l_map.get("frontend") {
                    return !af_release::lifecycle::commits_match_prefix(l_frontend, r_clean, true);
                }
            }
            return true;
        } else if let Some(r_map) = r_manifest.as_ref() {
            let l_clean = af_release::lifecycle::normalize_version(l_trim);
            if is_git_commit_sha(l_clean) {
                if let Some(r_frontend) = r_map.get("frontend") {
                    return !af_release::lifecycle::commits_match_prefix(l_clean, r_frontend, true);
                }
            }
            return true;
        }
    }

    is_newer_version_scalar_for_source(l_trim, r_trim, update_source)
}

pub fn is_version_newer_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    is_remote_version_newer_for_source(local, remote, update_source)
}

pub fn is_newer_version_scalar(local: &str, remote: &str) -> bool {
    is_newer_version_scalar_for_source(local, remote, "")
}

pub fn is_newer_version_scalar_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    let l_trim = local.trim();
    let r_trim = remote.trim();

    if r_trim.is_empty() || update_source.trim().eq_ignore_ascii_case("vendor") {
        return false;
    }

    if update_source == "apt" {
        return compare_debian_versions_str(l_trim, r_trim) == std::cmp::Ordering::Less;
    }

    let l_norm = af_release::lifecycle::normalize_version(local);
    let r_norm = af_release::lifecycle::normalize_version(remote);

    if l_norm == r_norm
        || (is_git_commit_sha(l_norm)
            && is_git_commit_sha(r_norm)
            && l_norm.eq_ignore_ascii_case(r_norm))
    {
        return false;
    }

    let is_commit_source = matches!(
        update_source.trim().to_ascii_lowercase().as_str(),
        "git" | "git_commit" | "git_head"
    );

    // 2. Synthetic commit versions (0.1.0-<sha>)
    let l_synth = parse_synthetic_commit_version(l_trim);
    let r_synth = parse_synthetic_commit_version(r_trim);

    if let Some((l_base, l_sha)) = l_synth {
        if let Some((r_base, r_sha)) = r_synth {
            if is_commit_source {
                match compare_semver_versions(l_base, r_base) {
                    std::cmp::Ordering::Less => return true,
                    std::cmp::Ordering::Greater => return false,
                    std::cmp::Ordering::Equal => {
                        return !af_release::lifecycle::commits_match_prefix(l_sha, r_sha, true);
                    }
                }
            }
        } else {
            let r_clean = af_release::lifecycle::normalize_version(r_trim);
            if !r_clean.contains('.') && is_git_commit_sha(r_clean) {
                return !af_release::lifecycle::commits_match_prefix(l_sha, r_clean, true);
            }
        }
    } else if let Some((_r_base, r_sha)) = r_synth {
        let l_clean = af_release::lifecycle::normalize_version(l_trim);
        if !l_clean.contains('.') && is_git_commit_sha(l_clean) {
            return !af_release::lifecycle::commits_match_prefix(l_clean, r_sha, true);
        }
    }

    // 3. Short & full git commit SHAs
    let l_clean = af_release::lifecycle::normalize_version(l_trim);
    let r_clean = af_release::lifecycle::normalize_version(r_trim);
    let l_is_hex_sha =
        af_release::lifecycle::is_hex_digits_7_to_40(l_clean) && !l_clean.contains('.');
    let r_is_hex_sha =
        af_release::lifecycle::is_hex_digits_7_to_40(r_clean) && !r_clean.contains('.');
    let l_is_sha = is_git_commit_sha(l_clean) && !l_clean.bytes().all(|b| b.is_ascii_digit());
    let r_is_sha = is_git_commit_sha(r_clean) && !r_clean.bytes().all(|b| b.is_ascii_digit());

    let both_all_digits =
        l_clean.bytes().all(|b| b.is_ascii_digit()) && r_clean.bytes().all(|b| b.is_ascii_digit());
    let unequal_digit_tags = both_all_digits
        && l_clean.len() != r_clean.len()
        && l_clean.len() != 40
        && r_clean.len() != 40;

    if l_is_hex_sha
        && r_is_hex_sha
        && !unequal_digit_tags
        && (is_commit_source || l_is_sha || r_is_sha)
    {
        return !af_release::lifecycle::commits_match_prefix(l_clean, r_clean, true);
    }

    // Untagged branch SHA installed on a release-tag-tracked package
    if l_is_sha && !r_is_sha && parse_semver(r_trim).is_some() {
        return true;
    }

    compare_semver_versions(l_trim, r_trim) == std::cmp::Ordering::Less
}

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    compare_versions_for_source(a, b, "")
}

pub fn compare_versions_for_source(a: &str, b: &str, update_source: &str) -> std::cmp::Ordering {
    if update_source == "apt" {
        return compare_debian_versions_str(a, b);
    }

    let a_norm = af_release::lifecycle::normalize_version(a);
    let b_norm = af_release::lifecycle::normalize_version(b);
    if a_norm == b_norm
        || (is_git_commit_sha(a_norm)
            && is_git_commit_sha(b_norm)
            && a_norm.eq_ignore_ascii_case(b_norm))
    {
        return std::cmp::Ordering::Equal;
    }

    if af_release::lifecycle::commits_match_prefix(a_norm, b_norm, false) {
        return std::cmp::Ordering::Equal;
    }
    if is_git_commit_sha(a_norm)
        && is_git_commit_sha(b_norm)
        && !(a_norm.bytes().all(|b| b.is_ascii_digit())
            && b_norm.bytes().all(|b| b.is_ascii_digit()))
    {
        return a_norm
            .to_ascii_lowercase()
            .cmp(&b_norm.to_ascii_lowercase());
    }

    compare_semver_versions(a, b)
}
