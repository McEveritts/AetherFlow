pub fn is_hex_commit(s: &str) -> bool {
    let len = s.len();
    (7..=40).contains(&len)
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && (len == 40 || s.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')))
}

pub fn is_hex_digits_7_to_40(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn commits_match_prefix(a: &str, b: &str, known_git_context: bool) -> bool {
    if !is_hex_digits_7_to_40(a) || !is_hex_digits_7_to_40(b) {
        return false;
    }
    if !known_git_context && !is_hex_commit(a) && !is_hex_commit(b) {
        return false;
    }
    let al = a.to_ascii_lowercase();
    let bl = b.to_ascii_lowercase();
    al.starts_with(&bl) || bl.starts_with(&al)
}

pub fn is_debian_plus_revision(suffix_after_plus: &str) -> bool {
    let lower = suffix_after_plus.to_ascii_lowercase();
    let trimmed = lower.trim_start_matches(['+', '~']);
    if trimmed.is_empty() {
        return false;
    }

    // 1. deb\d+ (e.g. +deb11u1, +deb12u2 — "deb" followed immediately by an ASCII digit!)
    if let Some(rest) = trimmed.strip_prefix("deb") {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
    }

    // 2. dfsg(\.\d+|\d+|-|$) (e.g. +dfsg, +dfsg1, +dfsg.1, +dfsg-1)
    if let Some(rest) = trimmed.strip_prefix("dfsg") {
        if rest.is_empty()
            || rest.starts_with('-')
            || rest.starts_with(|c: char| c.is_ascii_digit())
            || (rest.starts_with('.') && rest[1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            return true;
        }
    }

    // 3. ds(\.\d+|\d+|-|$) (e.g. +ds, +ds1, +ds.1, +ds-1)
    if let Some(rest) = trimmed.strip_prefix("ds") {
        if rest.is_empty()
            || rest.starts_with('-')
            || rest.starts_with(|c: char| c.is_ascii_digit())
            || (rest.starts_with('.') && rest[1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            return true;
        }
    }

    // 4. really[0-9.] (e.g. +really1.0)
    if let Some(rest) = trimmed.strip_prefix("really") {
        if rest.starts_with(|c: char| c.is_ascii_digit() || c == '.') {
            return true;
        }
    }

    // 5. nmu\d+ (e.g. +nmu1)
    if let Some(rest) = trimmed.strip_prefix("nmu") {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
    }

    // 6. b\d+$ (e.g. +b1, +b2 — 'b' followed ONLY by ASCII digits!)
    if let Some(rest) = trimmed.strip_prefix('b') {
        if !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    // 7. u\d+$ (e.g. +u1 — 'u' followed ONLY by ASCII digits!)
    if let Some(rest) = trimmed.strip_prefix('u') {
        if !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    false
}

pub fn strip_semver_build_metadata(s: &str) -> &str {
    if let Some(idx) = s.find('+') {
        let suffix = &s[idx + 1..];
        if !is_debian_plus_revision(suffix) {
            return &s[..idx];
        }
    }
    s
}

pub fn is_debian_revision_suffix(suffix: &str) -> bool {
    let s = suffix.trim();
    if s.is_empty() || s.starts_with('-') || s.starts_with("0.") {
        return false;
    }
    let starts_valid = s.starts_with(|c: char| c.is_ascii_digit())
        || ((s.starts_with('r') || s.starts_with('R'))
            && s.len() > 1
            && s[1..].starts_with(|c: char| c.is_ascii_digit()));
    if !starts_valid {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "git",
        "svn",
        "test",
        "unstable",
        "experimental",
        "debug",
    ];
    for kw in PRERELEASE_KEYWORDS {
        if lower.contains(kw) {
            return false;
        }
    }

    let has_debian_marker = lower.contains("ubuntu")
        || lower.contains("deb")
        || lower.contains("dfsg")
        || lower.contains("build")
        || lower.contains("+b")
        || (lower.contains('b') && lower.contains('+'))
        || lower.contains(':');

    let is_numeric_dots = s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.');
    !is_numeric_dots || has_debian_marker
}

pub fn is_valid_apt_debian_revision_suffix(suffix: &str) -> bool {
    let s = suffix.trim();
    if s.is_empty() || s.starts_with('-') {
        return false;
    }
    let starts_valid = s.starts_with(|c: char| c.is_ascii_digit())
        || ((s.starts_with('r') || s.starts_with('R'))
            && s.len() > 1
            && s[1..].starts_with(|c: char| c.is_ascii_digit()));
    if !starts_valid {
        return false;
    }
    if s.contains('~') {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "git",
        "svn",
        "test",
        "unstable",
        "experimental",
        "debug",
    ];
    for kw in PRERELEASE_KEYWORDS {
        if lower.contains(kw) {
            return false;
        }
    }
    true
}

pub fn is_prerelease_version_for_channel_with_source(
    version_or_tag: &str,
    update_source: Option<&str>,
) -> bool {
    let clean = strip_version_prefix(version_or_tag);
    let src = update_source.map(|s| s.trim().to_ascii_lowercase());
    let is_apt = matches!(src.as_deref(), Some("apt" | "deb" | "dpkg"));
    let effective_clean = if !is_apt {
        clean.split_once('+').map(|(v, _)| v).unwrap_or(clean)
    } else {
        clean
    };
    let lower = effective_clean.to_ascii_lowercase();

    if lower.contains('~') {
        return true;
    }

    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "unstable",
        "experimental",
        "debug",
        "dirty",
        "wip",
    ];
    for word in PRERELEASE_KEYWORDS {
        if lower.contains(word) {
            return true;
        }
    }

    match src.as_deref() {
        Some("apt") | Some("deb") | Some("dpkg") => {
            let without_epoch = if let Some((_, rem)) = clean.split_once(':') {
                rem
            } else {
                clean
            };
            if let Some((upstream, deb_rev)) = without_epoch.rsplit_once('-') {
                if upstream.contains('~') {
                    return true;
                }
                let segments_numeric = if upstream.contains('-') {
                    upstream
                        .split('-')
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                } else {
                    true
                };
                return !(segments_numeric && is_valid_apt_debian_revision_suffix(deb_rev));
            }
            false
        }
        Some("github")
        | Some("github_release")
        | Some("github_releases")
        | Some("github_tags")
        | Some("git")
        | Some("git_tags")
        | Some("git_tag")
        | Some("git_commit")
        | Some("git_head")
        | Some("gitlab")
        | Some("gitea") => {
            let semver_core_and_pre = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);
            if semver_core_and_pre.contains('-') {
                return true;
            }
            if let Some(sv) = parse_semver(semver_core_and_pre) {
                if let Some(ref pre) = sv.prerelease {
                    if !pre.is_empty() {
                        return true;
                    }
                }
            }
            false
        }
        _ => {
            let semver_core_and_pre = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);
            if let Some((_upstream, rest)) =
                semver_core_and_pre.to_ascii_lowercase().split_once('-')
            {
                let is_plain_debian_rev = if rest.contains('-') {
                    let parts: Vec<&str> = rest.split('-').collect();
                    let earlier_numeric = parts[..parts.len() - 1]
                        .iter()
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
                    earlier_numeric && is_debian_revision_suffix(parts[parts.len() - 1])
                } else {
                    is_debian_revision_suffix(rest)
                };

                if is_plain_debian_rev {
                    return false;
                }
                if !rest.trim().is_empty() {
                    return true;
                }
            }

            if let Some(sv) = parse_semver(semver_core_and_pre) {
                if let Some(ref pre) = sv.prerelease {
                    if !pre.is_empty() {
                        return true;
                    }
                }
            }

            false
        }
    }
}

pub fn is_prerelease_version_for_channel(version_or_tag: &str) -> bool {
    is_prerelease_version_for_channel_with_source(version_or_tag, None)
}

fn dpkg_char_order(c: Option<u8>) -> i32 {
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

fn parse_debian_version(raw: &str) -> (u64, &str, &str) {
    let mut s = raw.trim();
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        s = strip_version_prefix(s);
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
struct SemverVersion {
    epoch: u64,
    segments: Vec<u64>,
    prerelease: Option<Vec<PrereleaseIdentifier>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleaseIdentifier {
    Numeric(String),
    Alpha(String),
}

fn parse_semver(raw: &str) -> Option<SemverVersion> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s_no_build = match s.split_once('+') {
        Some((v, _)) => v.trim(),
        None => s,
    };
    let norm = normalize_version(s_no_build);
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
                    let digits = if canonical.is_empty() {
                        "0".to_string()
                    } else {
                        canonical.to_string()
                    };
                    ids.push(PrereleaseIdentifier::Numeric(digits));
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

fn compare_semver_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (Some(sa), Some(sb)) = (parse_semver(a), parse_semver(b)) else {
        let a_norm = normalize_version(a);
        let b_norm = normalize_version(b);
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

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let an = normalize_version(a);
    let bn = normalize_version(b);
    if an == bn || an.eq_ignore_ascii_case(bn) {
        return std::cmp::Ordering::Equal;
    }
    if commits_match_prefix(an, bn, false) {
        return std::cmp::Ordering::Equal;
    }
    if is_hex_digits_7_to_40(an)
        && is_hex_digits_7_to_40(bn)
        && !(an.bytes().all(|byte| byte.is_ascii_digit())
            && bn.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return an.to_ascii_lowercase().cmp(&bn.to_ascii_lowercase());
    }
    compare_semver_versions(a, b)
}

pub fn strip_version_prefix(s: &str) -> &str {
    let mut trimmed = s.trim();
    loop {
        let prev = trimmed;
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("release-")
            || lower.starts_with("release_")
            || lower.starts_with("release/")
        {
            trimmed = trimmed[8..].trim();
        } else if lower.starts_with("rel-")
            || lower.starts_with("rel_")
            || lower.starts_with("rel/")
        {
            trimmed = trimmed[4..].trim();
        } else if lower.starts_with("version-")
            || lower.starts_with("version_")
            || lower.starts_with("version/")
        {
            trimmed = trimmed[8..].trim();
        } else if lower.starts_with("ver-")
            || lower.starts_with("ver_")
            || lower.starts_with("ver/")
        {
            trimmed = trimmed[4..].trim();
        } else if let Some(idx) = trimmed.find(['-', '/', '_']) {
            let prefix = &trimmed[..idx];
            if prefix.eq_ignore_ascii_case("release")
                || prefix.eq_ignore_ascii_case("rel")
                || prefix.eq_ignore_ascii_case("version")
                || prefix.eq_ignore_ascii_case("ver")
            {
                trimmed = trimmed[idx + 1..].trim();
            }
        }
        if let Some(rest) = trimmed.strip_prefix(|c: char| c == 'v' || c == 'V') {
            if rest.starts_with(|c: char| c.is_ascii_digit()) || rest.is_empty() {
                trimmed = rest.trim();
            }
        }
        if trimmed == prev {
            break;
        }
    }
    trimmed
}

pub fn normalize_version(s: &str) -> &str {
    strip_version_prefix(s)
}

pub fn normalize_version_str(s: &str) -> &str {
    normalize_version(s)
}

pub fn is_hex_sha_7_to_64(s: &str) -> bool {
    let len = s.len();
    (7..=64).contains(&len) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_hex_digits_7_to_64(s: &str) -> bool {
    is_hex_sha_7_to_64(s)
}
