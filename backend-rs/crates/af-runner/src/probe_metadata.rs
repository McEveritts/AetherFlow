//! Non-executing package metadata extraction and subprocess trust/privilege sandbox helpers.
//!
//! Replaces direct `git`, `node -p`, and application-tree Python imports inside version probes
//! with bounded `O_NOFOLLOW` regular-file readers, and enforces `env_clear()`,
//! `PR_SET_NO_NEW_PRIVS`, ancestor ownership checks, and non-root UID/GID dropping before
//! spawning any unavoidable binary probe.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command as StdCommand;
use tokio::process::Command as TokioCommand;

const MAX_STATIC_METADATA_BYTES: usize = 512 * 1024;
const MAX_PACKED_REFS_BYTES: usize = 16 * 1024 * 1024;
const MAX_DLL_SCAN_BYTES: usize = 64 * 1024 * 1024;

static SAFE_HEX_40: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9a-fA-F]{40}$").unwrap());
static SAFE_STABLE_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?:STABLE_VERSION|__version__|__full_version_str__)\s*=\s*['"]([^'"]+)['"]"#)
        .unwrap()
});
static BAZARR_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([0-9]+\.[0-9]+\.[0-9]+)").unwrap());
static NEXTCLOUD_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"OC_VersionString\s*=\s*'([^']+)'").unwrap());
static RUTORRENT_JS_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([0-9]+\.[0-9]+)").unwrap());
static ORGANIZR_PHP_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([0-9]+\.[0-9]+\.[0-9]+)").unwrap());
static ABS_APP_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(/(?:opt|srv|var/www|etc/systemd/system|usr/local/bin|usr/bin)/[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*)")
        .unwrap()
});
static DLL_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^v?([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)$").unwrap());

#[derive(Debug, Clone, Default)]
pub struct ProbeSandboxSpec {
    pub drop_to_path_owner: bool,
    pub fs_root: Option<PathBuf>,
    pub package_user: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NonRootOwner {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
fn open_dir_nofollow_stepwise(dir_path: &Path) -> Result<std::os::fd::OwnedFd, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    if !dir_path.is_absolute() {
        return Err(format!("path {:?} must be absolute", dir_path));
    }
    let root_c = CString::new("/").unwrap();
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(format!(
            "failed to open '/': {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut current_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };
    for comp in dir_path.components() {
        match comp {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                return Err("parent directory traversal ('..') is not permitted".to_string());
            }
            Component::Normal(name) => {
                let c_name = CString::new(name.as_bytes())
                    .map_err(|e| format!("invalid path component {:?}: {}", name, e))?;
                let next_fd = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!(
                        "failed to open directory component {:?} in {:?}: {}",
                        name, dir_path, err
                    ));
                }
                current_fd = unsafe { OwnedFd::from_raw_fd(next_fd) };
            }
            Component::Prefix(_) => {
                return Err("Windows prefixes are unsupported on Unix".to_string());
            }
        }
    }
    Ok(current_fd)
}

#[cfg(unix)]
pub fn read_regular_nofollow(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    if !path.is_absolute() {
        return Err(format!("path {:?} must be absolute", path));
    }
    let Some(parent) = path.parent() else {
        return Err(format!("path {:?} has no parent", path));
    };
    let Some(leaf) = path.file_name() else {
        return Err(format!("path {:?} has no leaf", path));
    };

    let parent_fd = match open_dir_nofollow_stepwise(parent) {
        Ok(fd) => fd,
        Err(e) => {
            if e.contains("No such file or directory") || e.contains("Not a directory") {
                return Ok(None);
            }
            return Err(e);
        }
    };

    let c_leaf =
        CString::new(leaf.as_bytes()).map_err(|e| format!("invalid filename {:?}: {}", leaf, e))?;
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut stat_buf,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) || err.raw_os_error() == Some(libc::ENOTDIR) {
            return Ok(None);
        }
        return Err(format!("fstatat {:?}: {}", path, err));
    }
    if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "refusing non-regular file {:?} (mode {:o})",
            path, stat_buf.st_mode
        ));
    }
    if stat_buf.st_size < 0 || stat_buf.st_size as usize > max_bytes {
        return Err(format!(
            "file {:?} exceeds size limit ({} > {})",
            path, stat_buf.st_size, max_bytes
        ));
    }

    let file_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if file_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("openat {:?}: {}", path, err));
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(file_fd) };
    let mut opened_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(owned_fd.as_raw_fd(), &mut opened_stat) } != 0 {
        return Err(format!("fstat {:?}: {}", path, std::io::Error::last_os_error()));
    }
    if (opened_stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || opened_stat.st_dev != stat_buf.st_dev
        || opened_stat.st_ino != stat_buf.st_ino
    {
        return Err(format!("file {:?} changed identity during open", path));
    }

    let mut file = fs::File::from(owned_fd);
    let mut buf = Vec::new();
    let cap = max_bytes.saturating_add(1) as u64;
    (&mut file)
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading {:?}: {}", path, e))?;
    if buf.len() > max_bytes {
        return Err(format!("file {:?} exceeded {} byte limit", path, max_bytes));
    }
    Ok(Some(buf))
}

#[cfg(not(unix))]
pub fn read_regular_nofollow(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(None);
    };
    if !meta.file_type().is_file() {
        return Err(format!("refusing non-regular file {:?}", path));
    }
    if meta.len() as usize > max_bytes {
        return Err(format!("file {:?} exceeded {} byte limit", path, max_bytes));
    }
    Ok(Some(fs::read(path).map_err(|e| format!("reading {:?}: {}", path, e))?))
}

fn read_text_nofollow(path: &Path, max_bytes: usize) -> Result<Option<String>, String> {
    let Some(bytes) = read_regular_nofollow(path, max_bytes)? else {
        return Ok(None);
    };
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

fn is_safe_git_ref_rel(ref_rel: &str) -> bool {
    !ref_rel.is_empty()
        && ref_rel.starts_with("refs/")
        && !ref_rel.contains("..")
        && !ref_rel.contains('\\')
        && !ref_rel.bytes().any(|b| b <= 0x20 || b >= 0x7f)
}

fn validate_sha40(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if SAFE_HEX_40.is_match(trimmed) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

fn lookup_packed_ref(packed_refs_text: &str, target_ref: &str) -> Option<String> {
    for line in packed_refs_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('^') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(sha) = parts.next() else {
            continue;
        };
        let Some(ref_name) = parts.next() else {
            continue;
        };
        if ref_name == target_ref {
            if let Some(valid) = validate_sha40(sha) {
                return Some(valid);
            }
        }
    }
    None
}

/// Resolves `<git_dir>/HEAD` purely via bounded `O_NOFOLLOW` regular-file reads.
/// Never invokes `git` or parses `.git/config`.
pub fn resolve_git_head_commit_nofollow(git_dir: &Path) -> Result<String, String> {
    let abs_git_dir = if git_dir.is_absolute() {
        git_dir.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|e| format!("current_dir: {}", e))?
            .join(git_dir)
    };
    let head_path = abs_git_dir.join("HEAD");
    let head_text = read_text_nofollow(&head_path, 64 * 1024)?
        .ok_or_else(|| format!("missing git HEAD at {}", head_path.display()))?;
    let trimmed = head_text.trim();
    if let Some(direct_sha) = validate_sha40(trimmed) {
        return Ok(direct_sha);
    }
    let Some(ref_rel) = trimmed.strip_prefix("ref:").map(str::trim) else {
        return Err(format!("unrecognized git HEAD contents in {}", head_path.display()));
    };
    if !is_safe_git_ref_rel(ref_rel) {
        return Err(format!("unsafe git ref target '{}' in {}", ref_rel, head_path.display()));
    }
    let loose_ref_path = abs_git_dir.join(ref_rel);
    if let Some(loose_text) = read_text_nofollow(&loose_ref_path, 64 * 1024)? {
        if let Some(sha) = validate_sha40(&loose_text) {
            return Ok(sha);
        }
    }
    let packed_path = abs_git_dir.join("packed-refs");
    if let Some(packed_text) = read_text_nofollow(&packed_path, MAX_PACKED_REFS_BYTES)? {
        if let Some(sha) = lookup_packed_ref(&packed_text, ref_rel) {
            return Ok(sha);
        }
    }
    Err(format!(
        "could not resolve git ref '{}' in {}",
        ref_rel,
        abs_git_dir.display()
    ))
}

fn collect_loose_tags(
    tags_root: &Path,
    dir: &Path,
    depth: usize,
    head_sha: &str,
    out: &mut Vec<String>,
) {
    if depth > 4 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.file_type().is_dir() {
            collect_loose_tags(tags_root, &p, depth + 1, head_sha, out);
        } else if meta.file_type().is_file() {
            if let Ok(Some(text)) = read_text_nofollow(&p, 64 * 1024) {
                if let Some(sha) = validate_sha40(&text) {
                    if sha == head_sha {
                        if let Ok(rel) = p.strip_prefix(tags_root) {
                            let tag = rel.to_string_lossy().replace('\\', "/");
                            if !tag.is_empty() {
                                out.push(tag);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn parse_version_sort_key(tag: &str) -> (Vec<(u8, u64, String)>, String) {
    let cleaned = tag
        .trim()
        .strip_prefix('v')
        .or_else(|| tag.trim().strip_prefix('V'))
        .unwrap_or(tag.trim());
    let mut segments = Vec::new();
    let mut cur_digits = String::new();
    let mut cur_alpha = String::new();
    let flush = |d: &mut String, a: &mut String, out: &mut Vec<(u8, u64, String)>| {
        if !d.is_empty() {
            out.push((1, d.parse::<u64>().unwrap_or(0), String::new()));
            d.clear();
        }
        if !a.is_empty() {
            out.push((0, 0, a.to_ascii_lowercase()));
            a.clear();
        }
    };
    for ch in cleaned.chars() {
        if ch.is_ascii_digit() {
            if !cur_alpha.is_empty() {
                flush(&mut cur_digits, &mut cur_alpha, &mut segments);
            }
            cur_digits.push(ch);
        } else if ch.is_ascii_alphanumeric() {
            if !cur_digits.is_empty() {
                flush(&mut cur_digits, &mut cur_alpha, &mut segments);
            }
            cur_alpha.push(ch);
        } else {
            flush(&mut cur_digits, &mut cur_alpha, &mut segments);
        }
    }
    flush(&mut cur_digits, &mut cur_alpha, &mut segments);
    (segments, tag.to_string())
}

/// Resolves an exact matching tag pointing to `HEAD` (loose `refs/tags` or `packed-refs`,
/// including annotated peeled `^{}` targets), falling back to `HEAD` commit hash cleanly.
pub fn resolve_git_tag_or_head_nofollow(
    git_dir: &Path,
    allow_short_fallback: bool,
) -> Result<String, String> {
    let abs_git_dir = if git_dir.is_absolute() {
        git_dir.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|e| format!("current_dir: {}", e))?
            .join(git_dir)
    };
    let head_sha = resolve_git_head_commit_nofollow(&abs_git_dir)?;
    let mut matching_tags = Vec::new();

    let tags_dir = abs_git_dir.join("refs/tags");
    collect_loose_tags(&tags_dir, &tags_dir, 0, &head_sha, &mut matching_tags);

    let packed_path = abs_git_dir.join("packed-refs");
    if let Ok(Some(packed_text)) = read_text_nofollow(&packed_path, MAX_PACKED_REFS_BYTES) {
        let mut last_tag: Option<(String, String)> = None;
        for line in packed_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(peeled) = trimmed.strip_prefix('^') {
                if let Some((tag_name, _)) = last_tag.take() {
                    if validate_sha40(peeled).as_deref() == Some(head_sha.as_str()) {
                        matching_tags.push(tag_name);
                    }
                }
                continue;
            }
            if let Some((tag_name, obj_sha)) = last_tag.take() {
                if obj_sha == head_sha {
                    matching_tags.push(tag_name);
                }
            }
            let mut parts = trimmed.split_whitespace();
            let Some(sha) = parts.next() else {
                continue;
            };
            let Some(ref_name) = parts.next() else {
                continue;
            };
            if let Some(tag_name) = ref_name.strip_prefix("refs/tags/") {
                if let Some(valid_sha) = validate_sha40(sha) {
                    last_tag = Some((tag_name.to_string(), valid_sha));
                }
            }
        }
        if let Some((tag_name, obj_sha)) = last_tag {
            if obj_sha == head_sha {
                matching_tags.push(tag_name);
            }
        }
    }

    if let Some(best_tag) = matching_tags
        .into_iter()
        .max_by_key(|t| parse_version_sort_key(t))
    {
        return Ok(best_tag);
    }

    if allow_short_fallback && head_sha.len() >= 7 {
        Ok(head_sha[..7].to_string())
    } else {
        Ok(head_sha)
    }
}

pub fn read_package_json_version_nofollow(path: &Path) -> Result<Option<String>, String> {
    let Some(bytes) = read_regular_nofollow(path, MAX_STATIC_METADATA_BYTES)? else {
        return Ok(None);
    };
    let parsed: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid JSON in {}: {}", path.display(), e))?;
    let ver = parsed
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .filter(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .unwrap_or(s)
                .to_string()
        });
    Ok(ver)
}

fn read_static_regex_nofollow(path: &Path, re: &Regex) -> Result<Option<String>, String> {
    let Some(text) = read_text_nofollow(path, MAX_STATIC_METADATA_BYTES)? else {
        return Ok(None);
    };
    let matched = re.captures(&text).and_then(|cap| {
        cap.get(1)
            .or_else(|| cap.get(0))
            .map(|m| m.as_str().trim().to_string())
    });
    Ok(matched.filter(|s| !s.is_empty()))
}

fn normalize_stripped_v(raw: String) -> String {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
    {
        if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return rest.to_string();
        }
    }
    trimmed.to_string()
}

fn scan_utf16le_and_ascii_versions(bytes: &[u8]) -> (Option<String>, Vec<String>) {
    // 1. Scan UTF-16LE runs (equivalent to `strings -el`) and capture string immediately following `ProductVersion`
    let mut utf16_strings: Vec<String> = Vec::new();
    let mut current = Vec::<u8>::new();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let lo = bytes[i];
        let hi = bytes[i + 1];
        if hi == 0 && (0x20..=0x7e).contains(&lo) {
            current.push(lo);
            i += 2;
        } else {
            if current.len() >= 4 {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    utf16_strings.push(s);
                }
            }
            current.clear();
            i += 2;
        }
    }
    if current.len() >= 4 {
        if let Ok(s) = String::from_utf8(current) {
            utf16_strings.push(s);
        }
    }

    let mut product_version = None;
    let mut all_versions = Vec::new();
    for pair in utf16_strings.windows(2) {
        if pair[0] == "ProductVersion" {
            let trimmed = pair[1].trim();
            if let Some(cap) = DLL_VERSION_RE.captures(trimmed) {
                product_version = cap.get(1).map(|m| m.as_str().to_string());
                break;
            }
        }
    }
    for s in &utf16_strings {
        if let Some(cap) = DLL_VERSION_RE.captures(s.trim()) {
            if let Some(m) = cap.get(1) {
                all_versions.push(m.as_str().to_string());
            }
        }
    }

    // 2. Scan ASCII runs (equivalent to `strings`)
    let mut ascii_buf = Vec::<u8>::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            ascii_buf.push(b);
        } else {
            if ascii_buf.len() >= 5 {
                if let Ok(s) = std::str::from_utf8(&ascii_buf) {
                    if let Some(cap) = DLL_VERSION_RE.captures(s.trim()) {
                        if let Some(m) = cap.get(1) {
                            all_versions.push(m.as_str().to_string());
                        }
                    }
                }
            }
            ascii_buf.clear();
        }
    }
    if ascii_buf.len() >= 5 {
        if let Ok(s) = std::str::from_utf8(&ascii_buf) {
            if let Some(cap) = DLL_VERSION_RE.captures(s.trim()) {
                if let Some(m) = cap.get(1) {
                    all_versions.push(m.as_str().to_string());
                }
            }
        }
    }

    (product_version, all_versions)
}

/// Scans `.NET` / PE DLL metadata purely in memory via bounded `O_NOFOLLOW` reads (no `strings` subprocess).
pub fn read_dll_version_nofollow(
    dll_paths: &[PathBuf],
    skip_placeholder_versions: bool,
) -> Result<Option<String>, String> {
    let is_placeholder = |v: &str| {
        skip_placeholder_versions && matches!(v, "0.0.0.0" | "1.0.0" | "1.0.0.0")
    };
    let mut fallback_candidates = Vec::new();
    for path in dll_paths {
        let Some(bytes) = read_regular_nofollow(path, MAX_DLL_SCAN_BYTES)? else {
            continue;
        };
        let (product_ver, ascii_vers) = scan_utf16le_and_ascii_versions(&bytes);
        if let Some(pv) = product_ver {
            if !is_placeholder(&pv) {
                return Ok(Some(pv));
            }
        }
        for ver in ascii_vers {
            if !is_placeholder(&ver) {
                fallback_candidates.push(ver);
            }
        }
    }
    Ok(fallback_candidates.into_iter().next())
}

fn find_git_dir_candidate(
    rebase_path: &dyn Fn(&str) -> PathBuf,
    logical_dirs: &[&str],
) -> Option<PathBuf> {
    for d in logical_dirs {
        let rebased = rebase_path(d);
        let git_sub = if d.ends_with("/.git") {
            rebased
        } else {
            rebased.join(".git")
        };
        if git_sub.join("HEAD").exists() {
            return Some(git_sub);
        }
    }
    None
}

/// Intercepts metadata/git/receipt probes in pure Rust before spawning any subprocess.
/// Returns `Some(Ok/Err)` when the command was statically resolved or handled safely in-process,
/// or `None` when a compiled/system binary probe needs sandboxed subprocess execution.
pub fn extract_static_package_version(
    package_name: &str,
    version_command: &[String],
    rebase_path: &dyn Fn(&str) -> PathBuf,
) -> Option<Result<String, String>> {
    if version_command.is_empty() {
        return None;
    }

    // `cat /opt/.../.af-version`
    if version_command.len() == 2
        && version_command[0] == "cat"
        && version_command[1].ends_with("/.af-version")
    {
        let p = rebase_path(&version_command[1]);
        return Some(
            read_text_nofollow(&p, 64 * 1024)
                .and_then(|opt| opt.ok_or_else(|| format!("missing receipt {}", p.display())))
                .map(normalize_stripped_v)
                .and_then(|s| {
                    if s.is_empty() {
                        Err(format!("empty receipt {}", p.display()))
                    } else {
                        Ok(s)
                    }
                }),
        );
    }

    let joined = version_command.join(" ");
    let is_meta_pattern = joined.contains("node -p")
        || joined.contains("package.json")
        || joined.contains("git -C")
        || joined.contains("git -c")
        || joined.contains("import cps")
        || joined.contains("cps/constants.py")
        || joined.contains("dispatcharr/version.py")
        || joined.contains("filebot-node")
        || joined.contains("/opt/bazarr/VERSION")
        || joined.contains("/var/www/nextcloud/version.php")
        || joined.contains("/opt/Tautulli")
        || joined.contains("/opt/uptime-kuma")
        || joined.contains("/var/www/rutorrent")
        || joined.contains("/var/www/organizr")
        || joined.contains("/opt/seedcross")
        || joined.contains("/opt/invidious")
        || (joined.contains("strings") && joined.contains(".dll"));

    if !is_meta_pattern {
        return None;
    }

    let lower = package_name.to_ascii_lowercase();
    match lower.as_str() {
        "overseerr" => {
            let p = rebase_path("/opt/overseerr/package.json");
            return Some(
                read_package_json_version_nofollow(&p)
                    .and_then(|o| o.ok_or_else(|| format!("missing version in {}", p.display()))),
            );
        }
        "jellyseerr" => {
            let p = rebase_path("/opt/jellyseerr/package.json");
            return Some(
                read_package_json_version_nofollow(&p)
                    .and_then(|o| o.ok_or_else(|| format!("missing version in {}", p.display()))),
            );
        }
        "flaresolverr" => {
            for rel in ["/opt/flaresolverr/package.json", "/opt/flaresolverr/_internal/package.json"] {
                let p = rebase_path(rel);
                if let Ok(Some(ver)) = read_package_json_version_nofollow(&p) {
                    return Some(Ok(ver));
                }
            }
            return Some(Err("missing version in FlareSolverr package.json".to_string()));
        }
        "filebot" => {
            let base = rebase_path("/opt/filebot-node");
            if !base.join("server/app.js").is_file() {
                return Some(Err("filebot-node server/app.js missing".to_string()));
            }
            for rel in ["package.json", "server/package.json", "client/package.json"] {
                if let Ok(Some(ver)) = read_package_json_version_nofollow(&base.join(rel)) {
                    return Some(Ok(ver));
                }
            }
            return Some(Err("missing version in filebot-node package.json".to_string()));
        }
        "calibreweb" => {
            let constants = rebase_path("/opt/calibre-web/cps/constants.py");
            if let Ok(Some(ver)) = read_static_regex_nofollow(&constants, &SAFE_STABLE_VERSION_RE) {
                return Some(Ok(normalize_stripped_v(ver)));
            }
            let receipt = rebase_path("/opt/calibre-web/.af-version");
            if let Ok(Some(ver)) = read_text_nofollow(&receipt, 64 * 1024) {
                let normalized = normalize_stripped_v(ver);
                if !normalized.is_empty() {
                    return Some(Ok(normalized));
                }
            }
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/opt/calibre-web"]) {
                return Some(resolve_git_tag_or_head_nofollow(&git_dir, true).map(normalize_stripped_v));
            }
            return Some(Err("unable to resolve calibreweb static version".to_string()));
        }
        "dispatcharr" => {
            let vp = rebase_path("/opt/dispatcharr/version.py");
            if let Ok(Some(ver)) = read_static_regex_nofollow(&vp, &SAFE_STABLE_VERSION_RE) {
                return Some(Ok(normalize_stripped_v(ver)));
            }
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/opt/dispatcharr"]) {
                return Some(resolve_git_tag_or_head_nofollow(&git_dir, true).map(normalize_stripped_v));
            }
            return Some(Err("unable to resolve dispatcharr static version".to_string()));
        }
        "bazarr" => {
            let vfile = rebase_path("/opt/bazarr/VERSION");
            if let Ok(Some(ver)) = read_static_regex_nofollow(&vfile, &BAZARR_VERSION_RE) {
                return Some(Ok(ver));
            }
            let get_args = rebase_path("/opt/bazarr/bazarr/app/get_args.py");
            if let Ok(Some(ver)) = read_static_regex_nofollow(&get_args, &BAZARR_VERSION_RE) {
                return Some(Ok(ver));
            }
            return Some(Err("unable to resolve bazarr static version".to_string()));
        }
        "nextcloud" => {
            let vp = rebase_path("/var/www/nextcloud/version.php");
            return Some(
                read_static_regex_nofollow(&vp, &NEXTCLOUD_VERSION_RE)
                    .and_then(|o| o.ok_or_else(|| format!("missing OC_VersionString in {}", vp.display()))),
            );
        }
        "tautulli" => {
            let receipt = rebase_path("/opt/Tautulli/.af-version");
            if let Ok(Some(ver)) = read_text_nofollow(&receipt, 64 * 1024) {
                let normalized = normalize_stripped_v(ver);
                if !normalized.is_empty() {
                    return Some(Ok(normalized));
                }
            }
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/opt/Tautulli", "/opt/tautulli"]) {
                return Some(resolve_git_tag_or_head_nofollow(&git_dir, true).map(normalize_stripped_v));
            }
            return Some(Err("missing /opt/Tautulli/.git repository".to_string()));
        }
        "uptimekuma" => {
            let pkg_json = rebase_path("/opt/uptime-kuma/package.json");
            if let Ok(Some(ver)) = read_package_json_version_nofollow(&pkg_json) {
                return Some(Ok(ver));
            }
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/opt/uptime-kuma"]) {
                return Some(resolve_git_tag_or_head_nofollow(&git_dir, true).map(normalize_stripped_v));
            }
            return Some(Err("missing /opt/uptime-kuma version metadata".to_string()));
        }
        "rutorrent" => {
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/var/www/rutorrent"]) {
                if let Ok(ver) = resolve_git_tag_or_head_nofollow(&git_dir, false) {
                    if !SAFE_HEX_40.is_match(&ver) {
                        return Some(Ok(normalize_stripped_v(ver)));
                    }
                }
            }
            let webui = rebase_path("/var/www/rutorrent/js/webui.js");
            if let Ok(Some(ver)) = read_static_regex_nofollow(&webui, &RUTORRENT_JS_VERSION_RE) {
                return Some(Ok(ver));
            }
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/var/www/rutorrent"]) {
                return Some(resolve_git_tag_or_head_nofollow(&git_dir, true).map(normalize_stripped_v));
            }
            return Some(Err("unable to resolve rutorrent static version".to_string()));
        }
        "organizr" => {
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/var/www/organizr"]) {
                if let Ok(ver) = resolve_git_tag_or_head_nofollow(&git_dir, false) {
                    if !SAFE_HEX_40.is_match(&ver) {
                        return Some(Ok(normalize_stripped_v(ver)));
                    }
                }
            }
            let def_php = rebase_path("/var/www/organizr/api/config/default.php");
            if let Ok(Some(ver)) = read_static_regex_nofollow(&def_php, &ORGANIZR_PHP_VERSION_RE) {
                return Some(Ok(ver));
            }
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/var/www/organizr"]) {
                return Some(resolve_git_tag_or_head_nofollow(&git_dir, true).map(normalize_stripped_v));
            }
            return Some(Err("unable to resolve organizr static version".to_string()));
        }
        "seedcross" => {
            if let Some(git_dir) = find_git_dir_candidate(rebase_path, &["/opt/seedcross"]) {
                return Some(resolve_git_head_commit_nofollow(&git_dir));
            }
            return Some(Err("missing /opt/seedcross/.git repository".to_string()));
        }
        "invidious" => {
            if let Some(git_dir) =
                find_git_dir_candidate(rebase_path, &["/opt/invidious/source", "/opt/invidious"])
            {
                return Some(resolve_git_head_commit_nofollow(&git_dir));
            }
            return Some(Err("missing /opt/invidious git repository".to_string()));
        }
        "sonarr" => {
            let paths = [
                rebase_path("/opt/Sonarr/Sonarr.dll"),
                rebase_path("/opt/Sonarr/Sonarr.Core.dll"),
            ];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Sonarr.dll version".to_string())),
            );
        }
        "radarr" => {
            let paths = [
                rebase_path("/opt/Radarr/Radarr.dll"),
                rebase_path("/opt/Radarr/Radarr.Core.dll"),
            ];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Radarr.dll version".to_string())),
            );
        }
        "lidarr" => {
            let paths = [
                rebase_path("/opt/Lidarr/Lidarr.dll"),
                rebase_path("/opt/Lidarr/Lidarr.Core.dll"),
            ];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Lidarr.dll version".to_string())),
            );
        }
        "readarr" => {
            let paths = [
                rebase_path("/opt/Readarr/Readarr.dll"),
                rebase_path("/opt/Readarr/Readarr.Core.dll"),
            ];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Readarr.dll version".to_string())),
            );
        }
        "prowlarr" => {
            let paths = [
                rebase_path("/opt/Prowlarr/Prowlarr.dll"),
                rebase_path("/opt/Prowlarr/Prowlarr.Core.dll"),
            ];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Prowlarr.dll version".to_string())),
            );
        }
        "kavita" => {
            let paths = [
                rebase_path("/opt/Kavita/Kavita.Common.dll"),
                rebase_path("/opt/Kavita/Kavita.dll"),
            ];
            return Some(
                read_dll_version_nofollow(&paths, true)
                    .and_then(|o| o.ok_or_else(|| "unable to read Kavita DLL version".to_string())),
            );
        }
        "ombi" => {
            let paths = [rebase_path("/opt/Ombi/Ombi.dll")];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Ombi.dll version".to_string())),
            );
        }
        "listenarr" => {
            let paths = [rebase_path("/opt/Listenarr/Listenarr.Api.dll")];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Listenarr.Api.dll version".to_string())),
            );
        }
        "requestrr" => {
            let paths = [rebase_path("/opt/requestrr/Requestrr.WebApi.dll")];
            return Some(
                read_dll_version_nofollow(&paths, false)
                    .and_then(|o| o.ok_or_else(|| "unable to read Requestrr.WebApi.dll version".to_string())),
            );
        }
        _ => {}
    }

    None
}

#[cfg(unix)]
fn lookup_user_uid_gid(username: &str) -> Option<NonRootOwner> {
    let trimmed = username.trim();
    if trimmed.is_empty() || trimmed == "root" {
        return None;
    }
    let c_name = std::ffi::CString::new(trimmed).ok()?;
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    let uid = unsafe { (*pw).pw_uid as u32 };
    let gid = unsafe { (*pw).pw_gid as u32 };
    if uid == 0 {
        None
    } else {
        Some(NonRootOwner { uid, gid })
    }
}

#[cfg(unix)]
fn inspect_ancestors_trust(
    path: &Path,
    fs_root: Option<&Path>,
    current_euid: u32,
    non_root_owners: &mut HashSet<(u32, u32)>,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut ancestors = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => ancestors.push("/"),
            Component::Normal(seg) => {
                ancestors.push(seg);
                let Ok(lmeta) = fs::symlink_metadata(&ancestors) else {
                    continue;
                };
                let mode = lmeta.permissions().mode();
                let uid = lmeta.uid();
                let gid = lmeta.gid();
                let is_symlink = lmeta.file_type().is_symlink();
                let is_sticky_tmp = (ancestors == Path::new("/tmp")
                    || ancestors == Path::new("/var/tmp"))
                    && (mode & 0o1000) != 0;

                // Symlink inodes carry dummy 0777 mode bits (e.g. Debian /bin -> usr/bin);
                // their security is enforced by their parent directory, owner, and resolved target.
                if !is_symlink && (mode & 0o002) != 0 && !is_sticky_tmp {
                    return Err(format!(
                        "refusing world-writable probe path component '{}' (mode {:o})",
                        ancestors.display(),
                        mode & 0o7777
                    ));
                }
                if !is_symlink
                    && fs_root.is_none()
                    && (mode & 0o020) != 0
                    && uid == 0
                    && gid != 0
                    && !is_sticky_tmp
                {
                    return Err(format!(
                        "refusing group-writable root probe path '{}' (mode {:o})",
                        ancestors.display(),
                        mode & 0o7777
                    ));
                }
                if uid != 0 && !(fs_root.is_some() && uid == current_euid) {
                    non_root_owners.insert((uid, gid));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_path_trust(
    path: &Path,
    fs_root: Option<&Path>,
    current_euid: u32,
) -> Result<Option<NonRootOwner>, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.is_absolute() {
        return Ok(None);
    }
    if !path.exists() {
        return Ok(None);
    }
    let is_in_app_tree = path.starts_with("/opt")
        || path.starts_with("/srv")
        || path.starts_with("/var/www")
        || fs_root.is_some_and(|r| {
            path.starts_with(r.join("opt"))
                || path.starts_with(r.join("srv"))
                || path.starts_with(r.join("var/www"))
        });

    let mut non_root_owners: HashSet<(u32, u32)> = HashSet::new();
    inspect_ancestors_trust(path, fs_root, current_euid, &mut non_root_owners)?;

    if let Ok(canon) = fs::canonicalize(path) {
        if canon != path {
            inspect_ancestors_trust(&canon, fs_root, current_euid, &mut non_root_owners)?;
        }
        if let Ok(meta) = fs::metadata(&canon) {
            let mode = meta.permissions().mode();
            let uid = meta.uid();
            let gid = meta.gid();
            if (mode & 0o002) != 0 {
                return Err(format!(
                    "refusing world-writable canonical probe target '{}'",
                    canon.display()
                ));
            }
            if uid != 0 && !(fs_root.is_some() && uid == current_euid) {
                non_root_owners.insert((uid, gid));
            }
        }
    }

    if non_root_owners.len() > 1 {
        return Err(format!(
            "refusing ambiguous multi-owner probe tree under '{}'",
            path.display()
        ));
    }
    if let Some(&(uid, gid)) = non_root_owners.iter().next() {
        return Ok(Some(NonRootOwner { uid, gid }));
    }
    if is_in_app_tree && fs_root.is_none() && current_euid != 0 {
        if let Ok(meta) = fs::metadata(path) {
            if (meta.permissions().mode() & 0o022) != 0 {
                return Err(format!(
                    "refusing writable app-tree probe '{}' as non-root user",
                    path.display()
                ));
            }
        }
    }
    Ok(None)
}

#[cfg(unix)]
fn collect_probe_path_references(prog: &Path, args: &[String], fs_root: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let rebase = |raw: &str| -> PathBuf {
        if let Some(root) = fs_root {
            let p = Path::new(raw);
            if p.starts_with(root) {
                p.to_path_buf()
            } else {
                root.join(raw.trim_start_matches('/'))
            }
        } else {
            PathBuf::from(raw)
        }
    };
    if prog.is_absolute() {
        paths.push(prog.to_path_buf());
    } else if let Some(s) = prog.to_str() {
        let mut matched = false;
        if let Some(root) = fs_root {
            for dir in ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
                let cand = root.join(dir.trim_start_matches('/')).join(s);
                if cand.exists() {
                    paths.push(cand);
                    matched = true;
                    break;
                }
            }
        }
        if !matched {
            for dir in ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
                let cand = Path::new(dir).join(s);
                if cand.exists() {
                    paths.push(cand);
                    break;
                }
            }
        }
    }
    for arg in args {
        if arg.starts_with('/') {
            paths.push(PathBuf::from(arg));
        }
        for cap in ABS_APP_PATH_RE.captures_iter(arg) {
            if let Some(m) = cap.get(1) {
                paths.push(rebase(m.as_str()));
            }
        }
    }
    paths
}

#[cfg(unix)]
pub fn validate_and_resolve_probe_sandbox(
    prog: &Path,
    args: &[String],
    spec: &ProbeSandboxSpec,
) -> Result<Option<(u32, u32)>, String> {
    let euid = unsafe { libc::geteuid() as u32 };
    let fs_root = spec.fs_root.as_deref();
    let refs = collect_probe_path_references(prog, args, fs_root);

    let mut detected_owner: Option<NonRootOwner> = None;
    for p in &refs {
        if let Some(owner) = inspect_path_trust(p, fs_root, euid)? {
            match detected_owner {
                Some(prev) if prev != owner => {
                    return Err(format!(
                        "probe references multiple non-root owners (uid={} vs uid={})",
                        prev.uid, owner.uid
                    ));
                }
                None => detected_owner = Some(owner),
                _ => {}
            }
        }
    }

    if detected_owner.is_none() {
        let touches_app_tree = refs.iter().any(|p| {
            p.starts_with("/opt")
                || p.starts_with("/srv")
                || p.starts_with("/var/www")
        });
        if touches_app_tree && fs_root.is_none() {
            if let Some(ref svc_user) = spec.package_user {
                if let Some(owner) = lookup_user_uid_gid(svc_user) {
                    detected_owner = Some(owner);
                }
            }
            if detected_owner.is_none() && euid == 0 && spec.drop_to_path_owner {
                detected_owner = lookup_user_uid_gid("nobody");
            }
        }
    }

    if euid != 0 {
        if let Some(owner) = detected_owner {
            if fs_root.is_none() || owner.uid != euid {
                return Err(format!(
                    "non-root process uid={} refuses executing app-owned probe uid={}",
                    euid, owner.uid
                ));
            }
        }
        return Ok(None);
    }

    // Running as root (`euid == 0`)
    if let Some(owner) = detected_owner {
        if spec.drop_to_path_owner {
            return Ok(Some((owner.uid, owner.gid)));
        }
        return Err(format!(
            "refusing root execution of app-owned probe uid={}",
            owner.uid
        ));
    }

    Ok(None)
}

#[cfg(not(unix))]
pub fn validate_and_resolve_probe_sandbox(
    _prog: &Path,
    _args: &[String],
    _spec: &ProbeSandboxSpec,
) -> Result<Option<(u32, u32)>, String> {
    Ok(None)
}

fn sandbox_path_for_root(fs_root: Option<&Path>) -> String {
    let base = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let Some(root) = fs_root else {
        return base.to_string();
    };
    let mut parts: Vec<String> = ["usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin"]
        .into_iter()
        .map(|rel| root.join(rel))
        .filter(|dir| dir.exists())
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    parts.push(base.to_string());
    parts.join(":")
}

fn apply_sanitized_env_std(cmd: &mut StdCommand, fs_root: Option<&Path>) {
    cmd.env_clear();
    cmd.env("PATH", sandbox_path_for_root(fs_root));
    cmd.env("LANG", "C.UTF-8");
    cmd.env("LC_ALL", "C.UTF-8");
    cmd.env("HOME", "/tmp");
    if let Some(root) = fs_root {
        cmd.env("AETHERFLOW_FS_ROOT", root);
        cmd.env("AETHERFLOW_INSTALL_ROOT", root);
    }
}

fn apply_sanitized_env_tokio(cmd: &mut TokioCommand, fs_root: Option<&Path>) {
    cmd.env_clear();
    cmd.env("PATH", sandbox_path_for_root(fs_root));
    cmd.env("LANG", "C.UTF-8");
    cmd.env("LC_ALL", "C.UTF-8");
    cmd.env("HOME", "/tmp");
    if let Some(root) = fs_root {
        cmd.env("AETHERFLOW_FS_ROOT", root);
        cmd.env("AETHERFLOW_INSTALL_ROOT", root);
    }
}

#[cfg(unix)]
unsafe fn install_unix_isolation(drop_ugid: Option<(u32, u32)>) -> std::io::Result<()> {
    if let Some((uid, gid)) = drop_ugid {
        let gids = [gid as libc::gid_t];
        if libc::setgroups(1, gids.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::geteuid() == 0 || libc::getegid() == 0 {
            return Err(std::io::Error::other("privilege drop left root uid/gid active"));
        }
    }
    let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    Ok(())
}

/// Configures a `std::process::Command` with cleared secrets, ancestor trust verification,
/// `PR_SET_NO_NEW_PRIVS`, and optional UID/GID drop to the non-root application owner.
pub fn configure_sandboxed_std_command(
    cmd: &mut StdCommand,
    prog: &Path,
    args: &[String],
    spec: &ProbeSandboxSpec,
) -> Result<(), String> {
    let drop_ugid = validate_and_resolve_probe_sandbox(prog, args, spec)?;
    apply_sanitized_env_std(cmd, spec.fs_root.as_deref());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(move || install_unix_isolation(drop_ugid));
        }
    }
    Ok(())
}

/// Configures a `tokio::process::Command` with cleared secrets, ancestor trust verification,
/// `PR_SET_NO_NEW_PRIVS`, and non-root execution guarantees.
pub fn configure_sandboxed_tokio_command(
    cmd: &mut TokioCommand,
    prog: &Path,
    args: &[String],
    spec: &ProbeSandboxSpec,
) -> Result<(), String> {
    let drop_ugid = validate_and_resolve_probe_sandbox(prog, args, spec)?;
    apply_sanitized_env_tokio(cmd, spec.fs_root.as_deref());
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(move || install_unix_isolation(drop_ugid));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn resolve_git_head_and_tag_nofollow_works_without_spawning_git() {
        let dir = env::temp_dir().join(format!("af-meta-git-{}", uuid::Uuid::new_v4()));
        let git_dir = dir.join(".git");
        fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        fs::create_dir_all(git_dir.join("refs/tags")).unwrap();
        let sha = "0123456789abcdef0123456789abcdef01234567";
        fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(git_dir.join("refs/heads/main"), format!("{sha}\n")).unwrap();
        fs::write(git_dir.join("refs/tags/v1.9.0"), format!("{sha}\n")).unwrap();

        assert_eq!(resolve_git_head_commit_nofollow(&git_dir).unwrap(), sha);
        assert_eq!(
            resolve_git_tag_or_head_nofollow(&git_dir, true).unwrap(),
            "v1.9.0"
        );

        // Packed-refs annotated tag peel check
        fs::remove_file(git_dir.join("refs/heads/main")).unwrap();
        fs::remove_file(git_dir.join("refs/tags/v1.9.0")).unwrap();
        let tag_obj = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(
            git_dir.join("packed-refs"),
            format!("# pack-refs with: peeled\n{sha} refs/heads/main\n{tag_obj} refs/tags/v2.0.1\n^{sha}\n"),
        )
        .unwrap();
        assert_eq!(resolve_git_head_commit_nofollow(&git_dir).unwrap(), sha);
        assert_eq!(
            resolve_git_tag_or_head_nofollow(&git_dir, true).unwrap(),
            "v2.0.1"
        );

        // Symlinked HEAD must fail closed
        fs::remove_file(git_dir.join("HEAD")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", git_dir.join("HEAD")).unwrap();
        assert!(resolve_git_head_commit_nofollow(&git_dir).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn static_metadata_extracts_calibreweb_and_overseerr_without_code_execution() {
        let root = env::temp_dir().join(format!("af-meta-static-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("opt/calibre-web/cps")).unwrap();
        fs::create_dir_all(root.join("opt/overseerr")).unwrap();
        fs::write(
            root.join("opt/calibre-web/cps/constants.py"),
            "# poison test\nSTABLE_VERSION = '0.6.28b'\n",
        )
        .unwrap();
        fs::write(
            root.join("opt/overseerr/package.json"),
            r#"{"name":"overseerr","version":"1.34.0"}"#,
        )
        .unwrap();

        let rebase = |raw: &str| root.join(raw.trim_start_matches('/'));
        let cw = extract_static_package_version(
            "calibreweb",
            &[
                "bash".into(),
                "-lc".into(),
                "PYTHONPATH=/opt/calibre-web python -c \"import cps\"".into(),
            ],
            &rebase,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cw, "0.6.28b");

        let ov = extract_static_package_version(
            "overseerr",
            &[
                "bash".into(),
                "-lc".into(),
                "node -p \"require('/opt/overseerr/package.json').version\"".into(),
            ],
            &rebase,
        )
        .unwrap()
        .unwrap();
        assert_eq!(ov, "1.34.0");

        fs::remove_file(root.join("opt/calibre-web/cps/constants.py")).unwrap();
        fs::write(root.join("opt/calibre-web/.af-version"), "v0.6.29\n").unwrap();
        let cw_receipt = extract_static_package_version(
            "calibreweb",
            &[
                "bash".into(),
                "-lc".into(),
                "sed -nE ... /opt/calibre-web/cps/constants.py".into(),
            ],
            &rebase,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cw_receipt, "0.6.29");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sandboxed_command_strips_secrets_and_rejects_world_writable_binary() {
        use std::os::unix::fs::PermissionsExt;

        let dir = env::temp_dir().join(format!("af-meta-sandbox-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("world_writable_probe");
        fs::write(&script, "#!/bin/sh\necho 1.0.0\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o777)).unwrap();

        let spec = ProbeSandboxSpec {
            drop_to_path_owner: false,
            fs_root: Some(dir.clone()),
            package_user: None,
        };
        let mut cmd = TokioCommand::new(&script);
        let res = configure_sandboxed_tokio_command(&mut cmd, &script, &[], &spec);
        assert!(res.is_err(), "world-writable probe binary must be rejected");

        let mut env_cmd = StdCommand::new("/bin/sh");
        let args = vec!["-c".to_string(), "printf %s \"$JWT_SECRET\"".to_string()];
        env_cmd.args(&args);
        env_cmd.env("JWT_SECRET", "super-secret-value");
        configure_sandboxed_std_command(&mut env_cmd, Path::new("/bin/sh"), &args, &spec).unwrap();
        let out = env_cmd.output().unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"");

        let _ = fs::remove_dir_all(dir);
    }
}
