use once_cell::sync::Lazy;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

pub(in crate::routes) fn resolve_candidate_receipt_paths(pkg_name: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let fs_root = std::env::var("AETHERFLOW_FS_ROOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("AF_PACKAGE_ROOT")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .map(PathBuf::from);

    let resolve = |rel: &str| -> PathBuf {
        let rel_trimmed = rel.trim_start_matches(['/', '\\']);
        if let Some(ref root) = fs_root {
            root.join(rel_trimmed)
        } else {
            PathBuf::from(rel)
        }
    };

    for prefix in ["/var/lib", "/etc", "/opt"] {
        if prefix == "/opt" && pkg_name.eq_ignore_ascii_case("filebot") {
            let p = resolve("/opt/filebot-node/.af-version");
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        if prefix == "/opt" && pkg_name.eq_ignore_ascii_case("listenarr") {
            let p = resolve("/opt/Listenarr/.af-version");
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        for candidate_name in [pkg_name, &pkg_name.to_lowercase()] {
            let candidate = format!("{}/{}/.af-version", prefix, candidate_name);
            let p = resolve(&candidate);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    if pkg_name.eq_ignore_ascii_case("piped") {
        for extra in [
            "/opt/piped/.af-components.json",
            "/var/lib/piped/.af-components.json",
        ] {
            let p = resolve(extra);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    for candidate_name in [pkg_name, &pkg_name.to_lowercase()] {
        if let Some(bp) = af_services::get_blueprint(candidate_name) {
            let cfg = bp.config_file_path.trim();
            if !cfg.is_empty() {
                let p = resolve(cfg);
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }
    paths
}

pub(in crate::routes) fn open_dir_nofollow_stepwise_ext(
    dir_path: &std::path::Path,
    create_missing: bool,
) -> Result<Option<OwnedFd>, String> {
    if !dir_path.is_absolute() {
        return Err(format!(
            "Directory path {} is not absolute",
            dir_path.display()
        ));
    }

    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("Failed to open root directory '/': {}", err));
    }
    let mut curr_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    let mut current_path = PathBuf::from("/");
    for comp in dir_path.components() {
        match comp {
            std::path::Component::Prefix(_) => {
                return Err(format!(
                    "Unsupported prefix component in path {}",
                    dir_path.display()
                ));
            }
            std::path::Component::RootDir => {
                continue;
            }
            std::path::Component::CurDir => {
                continue;
            }
            std::path::Component::ParentDir => {
                return Err(format!(
                    "Directory path {} contains invalid '..' parent directory component",
                    dir_path.display()
                ));
            }
            std::path::Component::Normal(part) => {
                current_path.push(part);
                let part_bytes = part.as_bytes();
                let part_cstr = std::ffi::CString::new(part_bytes)
                    .map_err(|e| format!("Invalid directory component {:?}: {}", part, e))?;

                let next_fd = unsafe {
                    libc::openat(
                        curr_fd.as_raw_fd(),
                        part_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    let raw = err.raw_os_error();
                    if raw == Some(libc::ENOENT) {
                        if !create_missing {
                            return Ok(None);
                        }
                        let mkdir_res = unsafe {
                            libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o755)
                        };
                        if mkdir_res != 0 {
                            let mk_err = std::io::Error::last_os_error();
                            if mk_err.raw_os_error() != Some(libc::EEXIST) {
                                return Err(format!(
                                    "Failed to create directory component {}: {}",
                                    current_path.display(),
                                    mk_err
                                ));
                            }
                        }
                        let opened_fd = unsafe {
                            libc::openat(
                                curr_fd.as_raw_fd(),
                                part_cstr.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_DIRECTORY
                                    | libc::O_NOFOLLOW
                                    | libc::O_CLOEXEC,
                            )
                        };
                        if opened_fd < 0 {
                            let open_err = std::io::Error::last_os_error();
                            return Err(format!(
                                "Failed to open directory component {}: {}",
                                current_path.display(),
                                open_err
                            ));
                        }
                        curr_fd = unsafe { OwnedFd::from_raw_fd(opened_fd) };
                        continue;
                    }
                    if raw == Some(libc::ELOOP) || raw == Some(libc::ENOTDIR) {
                        let mut comp_st: libc::stat = unsafe { std::mem::zeroed() };
                        let stat_res = unsafe {
                            libc::fstatat(
                                curr_fd.as_raw_fd(),
                                part_cstr.as_ptr(),
                                &mut comp_st,
                                libc::AT_SYMLINK_NOFOLLOW,
                            )
                        };
                        if stat_res == 0 && (comp_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                            return Err(format!(
                                "Candidate receipt ancestor {} is a symlink",
                                current_path.display()
                            ));
                        }
                        if stat_res == 0 && (comp_st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                            return Err(format!(
                                "Candidate receipt ancestor {} is not a directory",
                                current_path.display()
                            ));
                        }
                        if raw == Some(libc::ELOOP) {
                            return Err(format!(
                                "Candidate receipt ancestor {} is a symlink",
                                current_path.display()
                            ));
                        }
                        return Err(format!(
                            "Candidate receipt ancestor {} is not a directory",
                            current_path.display()
                        ));
                    }
                    return Err(format!(
                        "Failed to open directory component {}: {}",
                        current_path.display(),
                        err
                    ));
                }
                curr_fd = unsafe { OwnedFd::from_raw_fd(next_fd) };
            }
        }
    }

    Ok(Some(curr_fd))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptSnapshotEntry {
    pub bytes: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl std::ops::Deref for ReceiptSnapshotEntry {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for ReceiptSnapshotEntry {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for ReceiptSnapshotEntry {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            mode: 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
}

impl From<&[u8]> for ReceiptSnapshotEntry {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            mode: 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
}

pub(in crate::routes) fn snapshot_candidate_receipts(
    pkg_name: &str,
) -> Result<Vec<(PathBuf, Option<ReceiptSnapshotEntry>)>, String> {
    let paths = resolve_candidate_receipt_paths(pkg_name);
    let mut snapshots = Vec::new();
    for path in paths {
        let parent = path.parent().ok_or_else(|| {
            format!(
                "Candidate receipt {} has no parent directory",
                path.display()
            )
        })?;

        let file_name = path
            .file_name()
            .ok_or_else(|| format!("Candidate receipt {} has no file name", path.display()))?;
        let file_cstr = std::ffi::CString::new(file_name.as_bytes())
            .map_err(|e| format!("Invalid receipt filename {}: {}", path.display(), e))?;

        let is_version_or_components = matches!(
            file_name.to_str(),
            Some(".af-version") | Some(".af-components.json")
        );
        let max_size: i64 = if is_version_or_components {
            64 * 1024
        } else {
            1024 * 1024
        };
        let limit_label = if is_version_or_components {
            "64 KiB"
        } else {
            "1 MiB"
        };

        // 1. Open parent using open_dir_nofollow_stepwise_ext(parent, false)
        let dir_fd = match open_dir_nofollow_stepwise_ext(parent, false) {
            Ok(Some(fd)) => fd,
            Ok(None) => {
                snapshots.push((path, None));
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        };

        // 2. Stat candidate receipt entry relative to dir_fd with AT_SYMLINK_NOFOLLOW
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_res != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                snapshots.push((path, None));
                continue;
            }
            return Err(format!(
                "Failed to stat receipt {}: {}",
                path.display(),
                err
            ));
        }

        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(format!(
                "Candidate receipt {} is a symlink or non-regular file",
                path.display()
            ));
        }

        if st.st_size > max_size || st.st_size < 0 {
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        // 3. Open receipt file relative to dir_fd
        let fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                snapshots.push((path, None));
                continue;
            }
            return Err(format!(
                "Failed to open receipt {}: {}",
                path.display(),
                err
            ));
        }

        // 4. Verify libc::fstat matches (st.st_dev, st.st_ino) and S_IFREG and <= max_size
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        let fstat_res = unsafe { libc::fstat(fd, &mut opened_st) };
        if fstat_res != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!(
                "Failed to stat opened receipt {}: {}",
                path.display(),
                err
            ));
        }

        if (opened_st.st_dev, opened_st.st_ino) != (st.st_dev, st.st_ino) {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} changed during open",
                path.display()
            ));
        }

        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} is a symlink or non-regular file",
                path.display()
            ));
        }

        if opened_st.st_size > max_size || opened_st.st_size < 0 {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        let mode = (opened_st.st_mode & 0o7777) as u32;
        let uid = opened_st.st_uid as u32;
        let gid = opened_st.st_gid as u32;

        // 5. Read bounded at most max_size
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = Vec::new();
        file.by_ref()
            .take((max_size as u64) + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("Failed to read receipt {}: {}", path.display(), e))?;

        if buf.len() > max_size as usize {
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        snapshots.push((
            path,
            Some(ReceiptSnapshotEntry {
                bytes: buf,
                mode,
                uid,
                gid,
            }),
        ));
    }
    Ok(snapshots)
}

pub(in crate::routes) fn restore_candidate_receipts(
    snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (path, prev_entry_opt) in snapshots {
        let parent = match path.parent() {
            Some(p) => p,
            None => {
                errors.push(format!("Receipt path has no parent: {}", path.display()));
                continue;
            }
        };

        let file_name = match path.file_name() {
            Some(name) => name,
            None => {
                errors.push(format!("Receipt path has no file name: {}", path.display()));
                continue;
            }
        };
        let file_cstr = match std::ffi::CString::new(file_name.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!(
                    "Invalid receipt filename {}: {}",
                    path.display(),
                    e
                ));
                continue;
            }
        };

        let dir_fd = if prev_entry_opt.is_some() {
            match open_dir_nofollow_stepwise_ext(parent, true) {
                Ok(Some(fd)) => fd,
                Ok(None) => {
                    errors.push(format!(
                        "Failed to create or open parent directory for receipt {}",
                        path.display()
                    ));
                    continue;
                }
                Err(e) => {
                    errors.push(format!(
                        "Refusing to restore receipt {}: {}",
                        path.display(),
                        e
                    ));
                    continue;
                }
            }
        } else {
            match open_dir_nofollow_stepwise_ext(parent, false) {
                Ok(Some(fd)) => fd,
                Ok(None) => {
                    continue;
                }
                Err(e) => {
                    errors.push(format!(
                        "Refusing to remove uncertified receipt {}: {}",
                        path.display(),
                        e
                    ));
                    continue;
                }
            }
        };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_res == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            errors.push(format!(
                "Refusing to overwrite directory at receipt path {}",
                path.display()
            ));
            continue;
        }

        if let Some(entry) = prev_entry_opt {
            let tmp_name = format!(
                ".af-tmp-receipt-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            );
            let tmp_cstr = match std::ffi::CString::new(tmp_name.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("Invalid temporary receipt filename: {}", e));
                    continue;
                }
            };

            let tmp_fd = unsafe {
                libc::openat(
                    dir_fd.as_raw_fd(),
                    tmp_cstr.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if tmp_fd < 0 {
                let err = std::io::Error::last_os_error();
                errors.push(format!(
                    "Failed to create temporary receipt for {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let write_res = (|| -> Result<(), std::io::Error> {
                let mut written = 0;
                while written < entry.bytes.len() {
                    let res = unsafe {
                        libc::write(
                            tmp_fd,
                            entry.bytes[written..].as_ptr() as *const libc::c_void,
                            entry.bytes.len() - written,
                        )
                    };
                    if res < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    written += res as usize;
                }
                Ok(())
            })();

            if let Err(e) = write_res {
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to write temporary receipt for {}: {}",
                    path.display(),
                    e
                ));
                continue;
            }

            let chown_res =
                unsafe { libc::fchown(tmp_fd, entry.uid as libc::uid_t, entry.gid as libc::gid_t) };
            if chown_res < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to restore ownership for temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let chmod_res = unsafe { libc::fchmod(tmp_fd, (entry.mode & 0o7777) as libc::mode_t) };
            if chmod_res < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to restore mode for temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let sync_res = unsafe { libc::fsync(tmp_fd) };
            if sync_res != 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to fsync temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            unsafe { libc::close(tmp_fd) };

            let rename_res = unsafe {
                libc::renameat(
                    dir_fd.as_raw_fd(),
                    tmp_cstr.as_ptr(),
                    dir_fd.as_raw_fd(),
                    file_cstr.as_ptr(),
                )
            };
            if rename_res != 0 {
                let err = std::io::Error::last_os_error();
                let _ = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0) };
                errors.push(format!(
                    "Failed to atomically restore receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        } else {
            let unlink_res = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), file_cstr.as_ptr(), 0) };
            if unlink_res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    errors.push(format!(
                        "Failed to remove uncertified receipt {}: {}",
                        path.display(),
                        err
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(())
}

pub(in crate::routes) fn split_git_repo_remote_and_branch(rest: &str) -> (&str, Option<&str>) {
    if let Some(idx) = rest.rfind('#') {
        let before = &rest[..idx];
        let after = &rest[idx + 1..];
        if before.ends_with("?q") || before.ends_with("&q") {
            return (rest, None);
        }
        if before.ends_with("cred") && after.contains('@') {
            return (rest, None);
        }
        (before, Some(after))
    } else {
        (rest, None)
    }
}

pub(in crate::routes) fn sanitize_git_repo_remote(remote: &str) -> String {
    let trimmed = remote.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    static HEX_12_QUERY_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"^\?q#[0-9a-fA-F]{12}$").unwrap());

    // Mask cred#<12-hex> and ?q#<12-hex> so Url::parse does not treat '#' as URL fragment delimiter
    let masked = if trimmed.contains("cred#") || trimmed.contains("?q#") {
        let m1 = regex::Regex::new(r"cred#([0-9a-fA-F]{12})@")
            .unwrap()
            .replace_all(trimmed, "cred__AFTOKEN__$1@")
            .into_owned();
        regex::Regex::new(r"\?q#([0-9a-fA-F]{12})")
            .unwrap()
            .replace_all(&m1, "?q__AFTOKEN__$1")
            .into_owned()
    } else {
        trimmed.to_string()
    };

    if let Ok(mut parsed) = reqwest::Url::parse(&masked) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        if let Some(q) = parsed.query() {
            let full_q = format!("?{q}");
            if !full_q.starts_with("?q__AFTOKEN__") && !HEX_12_QUERY_RE.is_match(&full_q) {
                parsed.set_query(None);
            }
        }
        parsed.set_fragment(None);

        let user = parsed.username().to_string();
        let pass = parsed.password().map(|p| p.to_string());

        if pass.is_some() {
            let _ = parsed.set_password(None);
            if (scheme == "http" || scheme == "https") && !user.starts_with("cred__AFTOKEN__") {
                let _ = parsed.set_username("");
            }
        } else if !user.is_empty()
            && (scheme == "http" || scheme == "https")
            && !user.starts_with("cred__AFTOKEN__")
        {
            let _ = parsed.set_username("");
        }

        let mut out = parsed.to_string();
        if !masked.ends_with('/') && out.ends_with('/') && parsed.path() == "/" {
            out.pop();
        }
        // Unmask
        out = out.replace("cred__AFTOKEN__", "cred#");
        out = out.replace("?q__AFTOKEN__", "?q#");
        out
    } else if trimmed.contains(':') {
        let (without_frag, _) = split_git_repo_remote_and_branch(trimmed);
        let (without_q, query_part) = if let Some((base, q)) = without_frag.split_once('?') {
            let full_q = format!("?{q}");
            if HEX_12_QUERY_RE.is_match(&full_q) {
                (base, format!("?{q}"))
            } else {
                (base, String::new())
            }
        } else {
            (without_frag, String::new())
        };

        if let Some((user_host, path)) = without_q.split_once(':') {
            if let Some((user, host)) = user_host.split_once('@') {
                let clean_user = if let Some((u, _pass)) = user.split_once(':') {
                    u
                } else {
                    user
                };
                format!("{clean_user}@{host}:{path}{query_part}")
            } else {
                format!("{user_host}:{path}{query_part}")
            }
        } else {
            format!("{without_q}{query_part}")
        }
    } else {
        trimmed.to_string()
    }
}

pub fn sanitize_url_or_source_key_for_api(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.contains('|') {
        let parts: Vec<String> = trimmed
            .split('|')
            .map(sanitize_url_or_source_key_for_api)
            .collect();
        return parts.join("|");
    }

    if let Some(rest) = trimmed.strip_prefix("git-repo:") {
        let (remote, branch) = split_git_repo_remote_and_branch(rest);
        let sanitized_remote = sanitize_git_repo_remote(remote);
        return match branch {
            Some(b) => format!("git-repo:{sanitized_remote}#{b}"),
            None => format!("git-repo:{sanitized_remote}"),
        };
    }

    static URL_USERINFO_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/?#@\s]+@").unwrap());
    static SENSITIVE_QUERY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?i)([?&;])([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|jwt[_-]?secret)[A-Za-z0-9_.-]*|\b(?:[A-Za-z0-9]*[_.-])?pass(?:[_.-][A-Za-z0-9]*)*\b)=([^&#|\s]+)"#).unwrap()
    });

    let stripped = URL_USERINFO_RE.replace_all(trimmed, "$1");

    // If reqwest::Url::parse succeeds on a display URL, strip credentials, query string, and fragment.
    if let Ok(mut parsed) = reqwest::Url::parse(&stripped) {
        let scheme = parsed.scheme();
        if (scheme == "http"
            || scheme == "https"
            || scheme == "ssh"
            || scheme == "git"
            || scheme == "ftp")
            && parsed.has_host()
        {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            let mut out = parsed.to_string();
            let base_before = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
            if !trimmed.ends_with('/')
                && out.ends_with('/')
                && !base_before.ends_with('/')
                && parsed.path() == "/"
            {
                out.pop();
            }
            return out;
        }
    }

    // SCP-style remotes: e.g. git@github.com:org/repo.git?token=x#frag or user:pass@host:path?q#frag
    if !trimmed.contains("://") {
        let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let without_q = without_frag.split('?').next().unwrap_or(without_frag);
        if let Some((userinfo, host_path)) = without_q.split_once('@') {
            if host_path.contains(':') || trimmed.starts_with("git@") {
                let clean_user = userinfo.split(':').next().unwrap_or(userinfo);
                return format!("{clean_user}@{host_path}");
            }
        }
    }

    let query_sanitized = SENSITIVE_QUERY_RE.replace_all(&stripped, "$1$2=[REDACTED]");
    let sanitized = af_runner::package_lifecycle::sanitize_lifecycle_field(&query_sanitized);
    URL_USERINFO_RE.replace_all(&sanitized, "$1").into_owned()
}

pub fn sanitize_package_update_record(
    mut record: af_services::workers::PackageUpdateRecord,
) -> af_services::workers::PackageUpdateRecord {
    record.release_url = sanitize_url_or_source_key_for_api(&record.release_url);
    record.source_key = sanitize_url_or_source_key_for_api(&record.source_key);
    record.installed_version = sanitize_url_or_source_key_for_api(&record.installed_version);
    record.latest_version = sanitize_url_or_source_key_for_api(&record.latest_version);
    record.error = sanitize_url_or_source_key_for_api(&af_services::workers::public_update_error(
        &record.error,
    ));
    record
}
