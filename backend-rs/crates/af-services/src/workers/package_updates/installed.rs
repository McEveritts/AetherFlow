use super::*;

pub(in crate::workers) fn should_track_package(pkg: &Package) -> bool {
    if pkg.name == "readarr" {
        return true;
    }
    if pkg.update_source.is_empty() {
        return false;
    }
    match pkg.update_source.as_str() {
        "apt" => !pkg.update_package.is_empty(),
        "github" | "github_release" | "git_tags" | "git" | "git_commit" | "git_head" => {
            !pkg.version_command.is_empty()
                && (!pkg.update_repo.is_empty() || !pkg.update_repo_url.is_empty())
        }
        "pypi" => !pkg.version_command.is_empty(),
        "retired" | "legacy" | "pinned" | "vendor" => true,
        _ => !pkg.version_command.is_empty(),
    }
}

pub(in crate::workers) fn package_is_installed(pkg: &Package) -> bool {
    if pkg.lock_file.trim().is_empty() {
        return false;
    }
    let resolved = resolve_fs_path(&pkg.lock_file);
    let fs_root = af_models::resolve_package_fs_root(None);
    let bound_root = fs_root.as_deref().filter(|root| resolved.starts_with(root));
    af_models::inspect_receipt_file(&resolved, bound_root).unwrap_or(false)
}

pub fn is_package_installed(pkg: &Package) -> bool {
    package_is_installed(pkg) || crate::is_package_installed(&pkg.name)
}

pub async fn probe_package_update(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    let is_installed = package_is_installed(pkg);

    let installed_res = detect_installed_version(pkg).await;
    let installed_failed_early = installed_res.is_err()
        || installed_res
            .as_ref()
            .map(|v| v.trim().is_empty())
            .unwrap_or(false);
    let installed_err_msg = installed_res.as_ref().err().map(|e| e.to_string());

    let latest_res = detect_latest_version(client, github_api_base, pkg).await;

    let observed_at = match &latest_res {
        Ok((_, _, obs)) => obs.clone(),
        Err(_) => String::new(),
    };

    let expected_source_key = canonical_update_source_key(github_api_base, pkg);
    let prev_record = get_package_update_map().get(&pkg.name).cloned();
    let (update_source, _) = effective_update_source_and_apt_package(pkg);
    let mut record = build_package_update_record_for_source(
        github_api_base,
        update_source,
        &pkg.name,
        is_installed,
        installed_res,
        latest_res
            .as_ref()
            .map(|(v, u, _)| (v.clone(), u.clone()))
            .map_err(|e| anyhow::anyhow!("{}", e)),
        prev_record.as_ref(),
        observed_at,
        &expected_source_key,
    );

    let source_matched = prev_record
        .as_ref()
        .map(|r| {
            !r.source_key.trim().is_empty() && r.source_key.trim() == expected_source_key.trim()
        })
        .unwrap_or(false);

    let listenarr_arch_unsupported = pkg.name.eq_ignore_ascii_case("listenarr")
        && af_runner::listenarr_release_asset_suffix_for_arch(env::consts::ARCH).is_err();
    if record.latest_version.is_empty()
        && latest_res.is_err()
        && !listenarr_arch_unsupported
        && (pkg.update_source == "github_release" || pkg.update_source == "github")
        && !pkg.update_repo.is_empty()
    {
        if let Some((cached_v, cached_u, cached_obs)) = get_cached_github_release_stale_for_channel(
            github_api_base,
            &pkg.update_repo,
            &pkg.update_channel,
        ) {
            if tag_allowed_by_channel_for_source(&cached_v, &pkg.update_channel, &pkg.update_source)
            {
                record.latest_version = cached_v;
                if record.release_url.is_empty() {
                    record.release_url = cached_u;
                }
                if prev_record.is_none() || !source_matched {
                    record.checked_at = cached_obs;
                }
            }
        }
    }

    let is_retired = matches!(pkg.update_source.as_str(), "retired" | "legacy" | "pinned")
        || pkg.name == "readarr";
    let is_readarr_404 = pkg.name == "readarr"
        && !record.installed_version.is_empty()
        && match &latest_res {
            Err(e) => {
                let msg = e.to_string();
                msg.contains("404") || msg.contains("not found")
            }
            _ => false,
        };

    let installed_failed = installed_failed_early
        || record
            .error
            .to_ascii_lowercase()
            .contains("installed version");

    if is_retired || is_readarr_404 {
        if record.latest_version.is_empty() {
            if pkg.name == "readarr" {
                record.latest_version = "0.4.18.2805".to_string();
            } else if !record.installed_version.is_empty() {
                record.latest_version = record.installed_version.clone();
            }
        }
        if installed_failed {
            if let Some(ref e) = installed_err_msg {
                record.error = format!("Installed version check failed: {e}");
            } else if record.error.is_empty() {
                record.error =
                    "Installed version check failed: probe returned no output".to_string();
            }
            record.update_available = false;
        } else {
            if !record.installed_version.is_empty() && !record.latest_version.is_empty() {
                record.update_available = record.installed
                    && is_remote_version_newer_for_source(
                        &record.installed_version,
                        &record.latest_version,
                        &pkg.update_source,
                    );
            } else {
                record.update_available = false;
            }
            record.error = String::new();
        }
    }

    let notify = persist_and_cache_package_update(&record);
    (record, notify)
}

pub fn resolve_installed_package_version(
    installed_opt: Option<&str>,
    prev_record: Option<&PackageUpdateRecord>,
) -> (String, bool) {
    if let Some(v) = installed_opt {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return (trimmed.to_string(), false);
        }
    }
    let fallback = prev_record
        .map(|r| r.installed_version.trim().to_string())
        .unwrap_or_default();
    let fell_back = !fallback.is_empty();
    (fallback, fell_back)
}

pub async fn detect_installed_package_version(pkg: &Package) -> anyhow::Result<String> {
    detect_installed_version(pkg).await
}

pub fn open_dir_nofollow_stepwise(dir_path: &Path) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd;
    if !dir_path.is_absolute() {
        return Err(format!("path {:?} is not absolute", dir_path));
    }
    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("failed to open root directory '/': {}", err));
    }
    let mut current_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(root_fd) };

    for comp in dir_path.components() {
        match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                return Err("parent directory traversal ('..') is not permitted".to_string());
            }
            std::path::Component::Normal(name) => {
                use std::os::fd::AsRawFd;
                use std::os::unix::ffi::OsStrExt;
                let c_name = std::ffi::CString::new(name.as_bytes())
                    .map_err(|e| format!("invalid component name {:?}: {}", name, e))?;
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
                        "failed to open dir component {:?} in {:?}: {}",
                        name, dir_path, err
                    ));
                }
                current_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(next_fd) };
            }
            std::path::Component::Prefix(_) => {
                return Err("path prefix is not supported on Unix".to_string());
            }
        }
    }

    Ok(current_fd)
}

pub fn read_receipt_bounded_nofollow(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    if !path.is_absolute() {
        return Err(format!("receipt path {:?} must be absolute", path));
    }

    let parent = match path.parent() {
        Some(p) => p,
        None => return Err(format!("receipt path {:?} has no parent", path)),
    };
    let file_name = match path.file_name() {
        Some(f) => f,
        None => return Err(format!("receipt path {:?} has no file name", path)),
    };

    let parent_fd = match open_dir_nofollow_stepwise(parent) {
        Ok(fd) => fd,
        Err(e) => {
            if e.contains("No such file or directory") {
                return Ok(None);
            }
            return Err(e);
        }
    };

    let c_file_name = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|e| format!("invalid file name {:?}: {}", file_name, e))?;

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let fstatat_res = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_file_name.as_ptr(),
            &mut stat_buf,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    if fstatat_res < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!("fstatat failed for {:?}: {}", path, err));
    }

    if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "receipt {:?} is not a regular file (mode: {:o})",
            path, stat_buf.st_mode
        ));
    }

    if stat_buf.st_size < 0 || stat_buf.st_size > 64 * 1024 {
        return Err(format!(
            "receipt {:?} file size ({}) exceeds 64 KiB limit",
            path, stat_buf.st_size
        ));
    }

    let file_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if file_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("openat failed for {:?}: {}", path, err));
    }
    let owned_file_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(file_fd) };

    let mut opened_stat: libc::stat = unsafe { std::mem::zeroed() };
    let fstat_res = unsafe { libc::fstat(owned_file_fd.as_raw_fd(), &mut opened_stat) };
    if fstat_res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "fstat failed on opened receipt {:?}: {}",
            path, err
        ));
    }
    if (opened_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "opened receipt {:?} is not a regular file (mode: {:o})",
            path, opened_stat.st_mode
        ));
    }
    if opened_stat.st_dev != stat_buf.st_dev || opened_stat.st_ino != stat_buf.st_ino {
        return Err(format!(
            "receipt {:?} changed identity between stat and open",
            path
        ));
    }

    let mut file = std::fs::File::from(owned_file_fd);
    let mut content = String::new();
    let mut reader = (&mut file).take(64 * 1024 + 1);
    reader
        .read_to_string(&mut content)
        .map_err(|e| format!("reading receipt {:?}: {}", path, e))?;

    if content.len() > 64 * 1024 {
        return Err(format!("receipt {:?} content exceeded 64 KiB limit", path));
    }

    Ok(Some(content))
}

pub(in crate::workers) fn read_af_version_receipt(pkg: &Package) -> Option<String> {
    static AF_VER_PATH_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(/[A-Za-z0-9_./-]*/\.(?:af-version|af-components\.json))").unwrap()
    });
    let mut candidate_paths = Vec::new();
    let is_filebot = pkg.name.eq_ignore_ascii_case("filebot");
    let opt_name = if is_filebot {
        "filebot-node"
    } else if pkg.name.eq_ignore_ascii_case("listenarr") {
        "Listenarr"
    } else {
        pkg.name.as_str()
    };
    if let Some(ref root) = resolve_configured_fs_root() {
        candidate_paths.push(root.join(format!("opt/{}/.af-version", opt_name)));
        candidate_paths.push(root.join(format!("opt/{}/.af-components.json", opt_name)));
        candidate_paths.push(root.join(format!("var/lib/{}/.af-version", pkg.name)));
        candidate_paths.push(root.join(format!("var/lib/{}/.af-components.json", pkg.name)));
        for token in &pkg.version_command {
            for cap in AF_VER_PATH_RE.captures_iter(token) {
                if let Some(m) = cap.get(1) {
                    let rel = m.as_str().trim_start_matches('/');
                    candidate_paths.push(root.join(rel));
                }
            }
        }
    }
    candidate_paths.push(resolve_fs_path(&format!("/opt/{}/.af-version", opt_name)));
    candidate_paths.push(resolve_fs_path(&format!(
        "/opt/{}/.af-components.json",
        opt_name
    )));
    candidate_paths.push(resolve_fs_path(&format!(
        "/var/lib/{}/.af-version",
        pkg.name
    )));
    candidate_paths.push(resolve_fs_path(&format!(
        "/var/lib/{}/.af-components.json",
        pkg.name
    )));
    for token in &pkg.version_command {
        for cap in AF_VER_PATH_RE.captures_iter(token) {
            if let Some(m) = cap.get(1) {
                candidate_paths.push(resolve_fs_path(m.as_str()));
            }
        }
    }
    if is_filebot {
        candidate_paths.retain(|p| {
            let s = p.to_string_lossy();
            !s.ends_with("opt/filebot/.af-version")
                && !s.ends_with("opt/filebot/.af-components.json")
        });
    }

    for path in candidate_paths {
        match read_receipt_bounded_nofollow(&path) {
            Ok(Some(contents)) => {
                let version = extract_version(&contents, &pkg.version_regex);
                if version.is_empty() {
                    let t = contents.trim();
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                } else {
                    return Some(version);
                }
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "rejected insecure or invalid receipt");
                continue;
            }
        }
    }
    None
}

pub(in crate::workers) fn resolve_git_dir_for_probe(logical_path: &str) -> Option<PathBuf> {
    let clean = logical_path.trim_start_matches('/');
    let candidates = [
        resolve_configured_fs_root().map(|r| r.join(clean)),
        Some(resolve_fs_path(logical_path)),
    ];
    candidates.into_iter().flatten().find(|p| p.exists())
}

pub(in crate::workers) async fn probe_live_git_version(
    pkg: &Package,
    _budget: Duration,
) -> Option<Result<String, anyhow::Error>> {
    // Cloudplow's checkout is private to root because it also holds rclone configuration.
    if pkg.name == "cloudplow"
        && resolve_configured_fs_root().is_none()
        && af_runner::is_runner_available()
    {
        return Some(af_runner::probe_package_version_via_runner(&pkg.name).await);
    }

    if pkg.name == "piped" || pkg.update_repo.eq_ignore_ascii_case("TeamPiped/Piped") {
        let fe_dir = resolve_git_dir_for_probe("/opt/piped/frontend/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped/.git"));
        let be_dir = resolve_git_dir_for_probe("/opt/piped/backend/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped-backend/.git"));
        let pr_dir = resolve_git_dir_for_probe("/opt/piped/proxy/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped-proxy/.git"));

        if fe_dir.is_some() || be_dir.is_some() || pr_dir.is_some() {
            let (Some(fe), Some(be), Some(pr)) = (fe_dir, be_dir, pr_dir) else {
                return Some(Err(anyhow::anyhow!(
                    "Incomplete or failed live git probe for piped components"
                )));
            };

            let fe_res = af_runner::probe_metadata::resolve_git_head_commit_nofollow(&fe)
                .map_err(|e| anyhow::anyhow!("piped frontend git probe failed: {}", e));
            let be_res = af_runner::probe_metadata::resolve_git_head_commit_nofollow(&be)
                .map_err(|e| anyhow::anyhow!("piped backend git probe failed: {}", e));
            let pr_res = af_runner::probe_metadata::resolve_git_head_commit_nofollow(&pr)
                .map_err(|e| anyhow::anyhow!("piped proxy git probe failed: {}", e));

            match (fe_res, be_res, pr_res) {
                (Ok(fe_sha), Ok(be_sha), Ok(pr_sha)) => Some(Ok(format!(
                    "frontend:{},backend:{},proxy:{}",
                    fe_sha.to_ascii_lowercase(),
                    be_sha.to_ascii_lowercase(),
                    pr_sha.to_ascii_lowercase()
                ))),
                _ => Some(Err(anyhow::anyhow!(
                    "Incomplete or failed live git probe for piped components"
                ))),
            }
        } else {
            None
        }
    } else if pkg.update_source.eq_ignore_ascii_case("git") {
        resolve_git_dir_for_probe(&format!("/opt/{}/source/.git", pkg.name))
            .or_else(|| resolve_git_dir_for_probe(&format!("/opt/{}/.git", pkg.name)))
            .map(|git_dir| {
                af_runner::probe_metadata::resolve_git_head_commit_nofollow(&git_dir)
                    .map_err(|e| anyhow::anyhow!("{}", e))
            })
    } else {
        None
    }
}

pub(in crate::workers) fn is_regular_executable(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.file_type().is_file() && (meta.permissions().mode() & 0o111) != 0 {
            return true;
        }
        if meta.file_type().is_symlink() {
            let path_str = path.to_string_lossy();
            if path_str.starts_with("/bin/")
                || path_str.starts_with("/sbin/")
                || path_str.starts_with("/usr/bin/")
                || path_str.starts_with("/usr/sbin/")
                || path_str.starts_with("/usr/local/bin/")
                || path_str.starts_with("/usr/local/sbin/")
            {
                if let Ok(target_meta) = fs::metadata(path) {
                    if target_meta.file_type().is_file()
                        && (target_meta.permissions().mode() & 0o111) != 0
                    {
                        if let Ok(canonical) = fs::canonicalize(path) {
                            let can_str = canonical.to_string_lossy();
                            if !can_str.starts_with("/tmp")
                                && !can_str.starts_with("/var/tmp")
                                && !can_str.starts_with("/dev/shm")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        meta.file_type().is_file()
    }
}

pub(in crate::workers) fn dir_has_runtime_files(dir_path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir_path) else {
        return false;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let lower = name_str.to_ascii_lowercase();

        if lower == ".af-version" || lower == ".af-components.json" || lower == "." || lower == ".."
        {
            continue;
        }

        if lower.ends_with(".lock")
            || lower.ends_with(".log")
            || lower.ends_with(".tmp")
            || lower.ends_with(".pid")
            || lower.ends_with(".bak")
            || lower.ends_with(".json")
            || lower.ends_with(".txt")
            || lower.ends_with(".conf")
            || lower.ends_with(".ini")
            || lower.ends_with(".yaml")
            || lower.ends_with(".yml")
            || lower.ends_with(".toml")
            || lower.ends_with(".db")
            || lower.ends_with(".sqlite")
        {
            continue;
        }

        if let Ok(meta) = fs::symlink_metadata(&entry_path) {
            if meta.file_type().is_dir() {
                if name_str == "bin" && dir_has_runtime_files(&entry_path) {
                    return true;
                }
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.file_type().is_file() && (meta.permissions().mode() & 0o111) != 0 {
                    return true;
                }
            }
            #[cfg(not(unix))]
            {
                if meta.file_type().is_file() {
                    return true;
                }
            }
        }
    }
    false
}

pub(in crate::workers) fn tokenize_systemd_command(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if in_double => {
                if let Some(&next_c) = chars.peek() {
                    if next_c == '"' || next_c == '\\' || next_c == '$' || next_c == '`' {
                        chars.next();
                        cur.push(next_c);
                        continue;
                    }
                }
                cur.push('\\');
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(cur);
                    cur = String::new();
                }
            }
            c => {
                cur.push(c);
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub fn is_valid_systemd_service_unit(resolved_unit_path: &Path, pkg: &Package) -> bool {
    let content = match read_receipt_bounded_nofollow(resolved_unit_path) {
        Ok(Some(c)) => c,
        _ => return false,
    };

    if content.trim().is_empty() {
        return false;
    }

    let mut exec_commands: Vec<String> = Vec::new();
    let mut working_directory: Option<PathBuf> = None;
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_string();
            continue;
        }

        let Some((raw_key, raw_val)) = trimmed.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let val = raw_val.trim();

        if (key == "ExecStart" || key == "WorkingDirectory") && current_section != "Service" {
            return false;
        }

        if current_section != "Service" {
            continue;
        }

        if key == "WorkingDirectory" {
            if !val.is_empty() {
                working_directory = Some(PathBuf::from(val));
            }
            continue;
        }

        if key == "ExecStart" {
            if val.is_empty() {
                exec_commands.clear();
            } else {
                exec_commands.push(val.to_string());
            }
            continue;
        }
    }

    if exec_commands.is_empty() {
        return false;
    }

    const INTERPRETERS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "env", "python", "python3", "python2", "node", "nodejs",
        "java", "ruby", "perl", "php", "dotnet",
    ];

    for cmd_str in &exec_commands {
        let mut raw = cmd_str.as_str();
        while raw.starts_with(['-', '@', '+', '!']) {
            raw = raw[1..].trim_start();
        }
        if raw.is_empty() {
            return false;
        }

        let tokens = tokenize_systemd_command(raw);
        if tokens.is_empty() {
            return false;
        }

        let exec_bin = &tokens[0];
        let resolved_exec = resolve_fs_path(exec_bin);
        if !is_regular_executable(&resolved_exec) {
            return false;
        }

        let bin_name = Path::new(exec_bin)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(exec_bin)
            .to_ascii_lowercase();

        let is_interpreter = INTERPRETERS.contains(&bin_name.as_str());

        if is_interpreter {
            for arg in &tokens[1..] {
                if arg.starts_with('-') {
                    continue;
                }
                let cand_path = if arg.starts_with('/') {
                    Some(PathBuf::from(arg))
                } else if let Some(ref wd) = working_directory {
                    Some(wd.join(arg))
                } else if arg.contains('.') || arg.contains('/') {
                    Some(PathBuf::from(arg))
                } else {
                    None
                };

                if let Some(p) = cand_path {
                    let resolved_p = resolve_fs_path(&p.to_string_lossy());
                    let is_file = fs::symlink_metadata(&resolved_p)
                        .map(|m| m.file_type().is_file())
                        .unwrap_or(false);
                    if !is_file {
                        return false;
                    }
                    break;
                }
            }

            let mut secondary_evidence = false;

            if pkg.name.eq_ignore_ascii_case("filebot") {
                let resolved_app = resolve_fs_path("/opt/filebot-node/server/app.js");
                if fs::symlink_metadata(&resolved_app)
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false)
                {
                    secondary_evidence = true;
                }
            }

            let candidate_dirs = [
                format!("/opt/{}", pkg.name),
                format!("/opt/{}/bin", pkg.name),
                format!("/var/lib/{}", pkg.name),
                format!("/etc/{}", pkg.name),
            ];
            for dir in &candidate_dirs {
                let resolved_dir = resolve_fs_path(dir);
                if dir_has_runtime_files(&resolved_dir) {
                    secondary_evidence = true;
                    break;
                }
            }

            if !secondary_evidence {
                let bin_paths = [
                    format!("/usr/local/bin/{}", pkg.name),
                    format!("/usr/bin/{}", pkg.name),
                    format!("/opt/{}/{}", pkg.name, pkg.name),
                    format!("/opt/{}/bin/{}", pkg.name, pkg.name),
                ];
                for b in &bin_paths {
                    let resolved_b = resolve_fs_path(b);
                    if is_regular_executable(&resolved_b) {
                        secondary_evidence = true;
                        break;
                    }
                }
            }

            if !secondary_evidence {
                let (update_source, apt_pkg) = effective_update_source_and_apt_package(pkg);
                let non_apt_package_field = matches!(
                    update_source.trim().to_ascii_lowercase().as_str(),
                    "pinned" | "retired" | "vendor" | "pypi"
                );
                if (update_source == "apt"
                    || (!non_apt_package_field && !pkg.update_package.is_empty()))
                    && !apt_pkg.is_empty()
                {
                    let mut cmd = std::process::Command::new("dpkg-query");
                    if let Some(ref root) = resolve_configured_fs_root() {
                        let dpkg_dir = root.join("var/lib/dpkg");
                        if dpkg_dir.exists() {
                            cmd.arg(format!("--admindir={}", dpkg_dir.display()));
                        }
                    }
                    cmd.args(["-W", "-f=${Status}", apt_pkg]);
                    if let Ok(out) = cmd.output() {
                        if out.status.success() {
                            let status_str = String::from_utf8_lossy(&out.stdout);
                            if status_str.trim() == "install ok installed" {
                                secondary_evidence = true;
                            }
                        }
                    }
                }
            }

            if !secondary_evidence {
                return false;
            }
        }
    }

    true
}

pub(in crate::workers) fn has_independent_runtime_evidence(pkg: &Package) -> bool {
    if !is_package_installed(pkg) {
        return false;
    }

    if pkg.name.eq_ignore_ascii_case("filebot") {
        let resolved_app = resolve_fs_path("/opt/filebot-node/server/app.js");
        if fs::symlink_metadata(&resolved_app)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
        {
            return true;
        }
    }

    // 1. Systemd unit file exists and is valid
    let mut unit_paths = vec![
        format!("/etc/systemd/system/{}.service", pkg.name),
        format!("/lib/systemd/system/{}.service", pkg.name),
    ];
    if !pkg.service_name.is_empty() {
        let u_str = if pkg.service_name.ends_with(".service") {
            pkg.service_name.clone()
        } else {
            format!("{}.service", pkg.service_name)
        };
        unit_paths.push(format!("/etc/systemd/system/{}", u_str));
        unit_paths.push(format!("/lib/systemd/system/{}", u_str));
    }
    for u in &unit_paths {
        let resolved = resolve_fs_path(u);
        if is_valid_systemd_service_unit(&resolved, pkg) {
            return true;
        }
    }

    // 2. Binary exists
    let bin_paths = [
        format!("/usr/local/bin/{}", pkg.name),
        format!("/usr/bin/{}", pkg.name),
        format!("/opt/{}/{}", pkg.name, pkg.name),
        format!("/opt/{}/bin/{}", pkg.name, pkg.name),
    ];
    for b in &bin_paths {
        let resolved = resolve_fs_path(b);
        if is_regular_executable(&resolved) {
            return true;
        }
    }
    if let Some(cmd_prog) = pkg.version_command.first() {
        if cmd_prog.starts_with('/') && !cmd_prog.ends_with("/cat") {
            let resolved = resolve_fs_path(cmd_prog);
            if is_regular_executable(&resolved) {
                return true;
            }
        }
    }

    // 3. Install directory contains actual runtime files beyond .af-version and .af-components.json
    let mut candidate_dirs = vec![
        format!("/opt/{}", pkg.name),
        format!("/opt/{}/bin", pkg.name),
        format!("/var/lib/{}", pkg.name),
        format!("/etc/{}", pkg.name),
    ];
    if pkg.name.eq_ignore_ascii_case("listenarr") {
        candidate_dirs.push("/opt/Listenarr".to_string());
    }
    for dir in &candidate_dirs {
        let resolved = resolve_fs_path(dir);
        if dir_has_runtime_files(&resolved) {
            return true;
        }
    }

    false
}

pub(in crate::workers) fn apt_receipt_matches_live_debian_revision(
    update_source: &str,
    receipt_ver: &str,
    live_ver: &str,
) -> bool {
    af_release::lifecycle::apt_receipt_matches_live_debian_revision(
        update_source,
        receipt_ver,
        live_ver,
    )
}

pub async fn probe_installed_package_version_strict(pkg: &Package) -> anyhow::Result<String> {
    let receipt_opt = read_af_version_receipt(pkg);
    let cmd_only_reads_af_ver = pkg
        .version_command
        .first()
        .map(|s| s == "cat")
        .unwrap_or(false)
        && pkg
            .version_command
            .iter()
            .any(|arg| arg.contains(".af-version"));

    if let Some(git_res) = probe_live_git_version(pkg, Duration::from_secs(5)).await {
        match git_res {
            Ok(live_git_ver) => {
                if let Some(ref receipt_ver) = receipt_opt {
                    if !af_release::lifecycle::versions_match_target(receipt_ver, &live_git_ver)
                        && !af_release::lifecycle::versions_match_target(&live_git_ver, receipt_ver)
                    {
                        anyhow::bail!(
                            "Stale or mismatched .af-version receipt ({receipt_ver}) vs live git state ({live_git_ver})"
                        );
                    }
                }
                return Ok(live_git_ver);
            }
            Err(e) => return Err(e),
        }
    }

    let (update_source, _) = effective_update_source_and_apt_package(pkg);
    let has_live_command =
        !cmd_only_reads_af_ver && (!pkg.version_command.is_empty() || update_source == "apt");
    let live_res = if has_live_command {
        Some(run_live_version_command(pkg, Duration::from_secs(10)).await)
    } else {
        None
    };

    match (live_res, receipt_opt) {
        (Some(Ok(live_ver)), Some(receipt_ver)) => {
            if !af_release::lifecycle::versions_match_target(&receipt_ver, &live_ver)
                && !af_release::lifecycle::versions_match_target(&live_ver, &receipt_ver)
                && !apt_receipt_matches_live_debian_revision(
                    &pkg.update_source,
                    &receipt_ver,
                    &live_ver,
                )
            {
                anyhow::bail!(
                    "Stale or mismatched .af-version receipt ({receipt_ver}) vs live runtime ({live_ver})"
                );
            }
            Ok(live_ver)
        }
        (Some(Ok(live_ver)), None) => Ok(live_ver),
        (Some(Err(e)), _) => Err(e),
        (None, Some(receipt_ver)) => {
            if !has_independent_runtime_evidence(pkg) {
                anyhow::bail!(
                    "No independent runtime evidence found alongside .af-version receipt"
                );
            }
            Ok(receipt_ver)
        }
        (None, None) => {
            anyhow::bail!(
                "no installed version probe configured or available for {}",
                pkg.name
            );
        }
    }
}
