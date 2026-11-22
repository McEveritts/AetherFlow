use super::admitted_snapshots::{package_definition, package_service_units};
use super::probe_command::run_bounded_probe_command;
use super::receipt_snapshots::read_receipt_bounded_nofollow;
use af_release::lifecycle;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveRuntimeProbeOutcome {
    Verified(String),
    Failed(String),
    NotConfigured,
}

pub use LiveRuntimeProbeOutcome::Verified as Confirmed;

pub fn has_prerelease_or_build(token: &str) -> bool {
    if let Some(pos) = token.find(['-', '+']) {
        token[pos + 1..]
            .chars()
            .any(|c| c.is_ascii_alphanumeric() || c == '-')
    } else {
        false
    }
}

pub fn has_prerelease_or_build_with_alnum(token: &str) -> bool {
    has_prerelease_or_build(token)
}

pub fn trim_version_token(raw_token: &str) -> &str {
    let mut s = raw_token.trim();
    loop {
        let trimmed_punct = s.trim_end_matches(['.', ',', ';', ':', ')', ']', '"', '\'']);
        if trimmed_punct.len() < s.len() {
            s = trimmed_punct;
            continue;
        }
        if s.ends_with('+') {
            s = s.trim_end_matches('+');
            continue;
        }
        if s.ends_with('-') && !has_prerelease_or_build(s) {
            s = s.trim_end_matches('-');
            continue;
        }
        break;
    }
    s
}

pub fn extract_version_token(raw: &str) -> String {
    static DOTTED_VERSION_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(
        || {
            regex::Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?\d+\.\d+(?:\.\d+)*(?:(?:[-+~:][0-9A-Za-z.+~:-]*[0-9A-Za-z-])|[0-9A-Za-z.+~:-]*[0-9A-Za-z])?)")
            .unwrap()
        },
    );
    static DEFAULT_VERSION_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(
        || {
            regex::Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?[0-9]+(?:(?:[-+~:][0-9A-Za-z.+~:-]*[0-9A-Za-z-])|[0-9A-Za-z.+~:-]*[0-9A-Za-z])?)")
            .unwrap()
        },
    );
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(caps) = DOTTED_VERSION_RE.captures(trimmed) {
        if let Some(m) = caps.get(1) {
            return trim_version_token(m.as_str()).to_string();
        }
    }
    for line in trimmed.lines() {
        let line_trim = line.trim();
        if let Some(caps) = DOTTED_VERSION_RE.captures(line_trim) {
            if let Some(m) = caps.get(1) {
                return trim_version_token(m.as_str()).to_string();
            }
        }
    }
    if let Some(caps) = DEFAULT_VERSION_RE.captures(trimmed) {
        if let Some(m) = caps.get(1) {
            return trim_version_token(m.as_str()).to_string();
        }
        if let Some(m) = caps.get(0) {
            return trim_version_token(m.as_str()).to_string();
        }
    }
    trim_version_token(trimmed).to_string()
}

pub fn probe_live_runtime_version(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> LiveRuntimeProbeOutcome {
    // 0. 3-repo live git probe for piped: check frontend, backend, and proxy sub-repos
    if package_id.eq_ignore_ascii_case("piped") {
        let find_git_dir = |primary_sub: &str, fallback_sub: &str| -> Option<std::path::PathBuf> {
            if let Ok(p) = env_cfg.resolve_path(primary_sub) {
                let git = p.join(".git");
                if git.exists() {
                    return Some(git);
                }
            }
            if let Ok(p) = env_cfg.resolve_path(fallback_sub) {
                let git = p.join(".git");
                if git.exists() {
                    return Some(git);
                }
            }
            None
        };

        let fe_dir = find_git_dir("/opt/piped/frontend", "/opt/piped");
        let be_dir = find_git_dir("/opt/piped/backend", "/opt/piped-backend");
        let pr_dir = find_git_dir("/opt/piped/proxy", "/opt/piped-proxy");

        let any_exists = fe_dir.is_some() || be_dir.is_some() || pr_dir.is_some();
        if any_exists {
            if let (Some(fe), Some(be), Some(pr)) = (fe_dir, be_dir, pr_dir) {
                if let (Ok(fe_hash), Ok(be_hash), Ok(pr_hash)) = (
                    crate::probe_metadata::resolve_git_head_commit_nofollow(&fe),
                    crate::probe_metadata::resolve_git_head_commit_nofollow(&be),
                    crate::probe_metadata::resolve_git_head_commit_nofollow(&pr),
                ) {
                    return LiveRuntimeProbeOutcome::Verified(format!(
                        "frontend:{fe_hash},backend:{be_hash},proxy:{pr_hash}"
                    ));
                } else {
                    return LiveRuntimeProbeOutcome::Failed(
                        "Piped pure-Rust .git/HEAD resolution failed for one or more sub-repos"
                            .into(),
                    );
                }
            } else {
                return LiveRuntimeProbeOutcome::Failed(
                    "Piped partial git checkouts detected: expected frontend, backend, and proxy"
                        .into(),
                );
            }
        } else {
            return LiveRuntimeProbeOutcome::Failed(
                "Piped git repositories missing: expected frontend, backend, and proxy in /opt/piped".into(),
            );
        }
    }

    // 1. version_command from package definition
    let pkg = match package_definition(package_id) {
        Ok(pkg) => pkg,
        Err(e) => {
            return LiveRuntimeProbeOutcome::Failed(format!(
                "Failed to load package definition for live probe: {}",
                e
            ));
        }
    };

    let is_apt = pkg.update_source.eq_ignore_ascii_case("apt");
    let fallback_sandbox_spec = crate::probe_metadata::ProbeSandboxSpec {
        drop_to_path_owner: true,
        fs_root: env_cfg.fs_root.clone(),
        package_user: Some(package_id.to_string()),
    };
    let dpkg_prog = if let Some(root) = &env_cfg.fs_root {
        [
            "usr/bin/dpkg-query",
            "usr/local/bin/dpkg-query",
            "bin/dpkg-query",
        ]
        .into_iter()
        .map(|rel| root.join(rel))
        .find(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dpkg-query".to_string())
    } else if Path::new("/usr/bin/dpkg-query").exists() {
        "/usr/bin/dpkg-query".to_string()
    } else {
        "dpkg-query".to_string()
    };

    if is_apt {
        let apt_pkg = if !pkg.update_package.trim().is_empty() {
            pkg.update_package.trim()
        } else {
            package_id
        };
        let mut dpkg_args: Vec<String> = Vec::new();
        if let Some(root) = &env_cfg.fs_root {
            let dpkg_dir = root.join("var/lib/dpkg");
            if dpkg_dir.exists() {
                dpkg_args.push(format!("--admindir={}", dpkg_dir.display()));
            }
        }
        dpkg_args.push("-W".to_string());
        dpkg_args.push("-f=${db:Status-Status} ${Version}\n".to_string());
        dpkg_args.push(apt_pkg.to_string());

        let mut cmd = std::process::Command::new(&dpkg_prog);
        if let Err(err) = crate::probe_metadata::configure_sandboxed_std_command(
            &mut cmd,
            Path::new(&dpkg_prog),
            &dpkg_args,
            &fallback_sandbox_spec,
        ) {
            return LiveRuntimeProbeOutcome::Failed(format!(
                "Refused unsafe dpkg-query probe for '{}': {}",
                apt_pkg, err
            ));
        }
        cmd.args(&dpkg_args);
        return match run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(ver) =
                    af_release::lifecycle::parse_installed_dpkg_status_version(&stdout)
                {
                    LiveRuntimeProbeOutcome::Verified(ver.to_string())
                } else {
                    LiveRuntimeProbeOutcome::Failed(format!(
                        "Package '{}' APT package '{}' is not in installed dpkg state or has invalid version (output: '{}')",
                        package_id,
                        apt_pkg,
                        stdout.trim()
                    ))
                }
            }
            Ok(output) => LiveRuntimeProbeOutcome::Failed(format!(
                "Package '{}' APT dpkg-query for '{}' exited with status: {}",
                package_id, apt_pkg, output.status
            )),
            Err(e) => LiveRuntimeProbeOutcome::Failed(format!(
                "Package '{}' failed to execute dpkg-query for '{}': {}",
                package_id, apt_pkg, e
            )),
        };
    }

    let is_cat_receipt = pkg.version_command.len() == 2
        && pkg.version_command[0] == "cat"
        && pkg.version_command[1].ends_with("/.af-version");

    if !pkg.version_command.is_empty() && !is_cat_receipt {
        let rebase_static = |raw: &str| {
            env_cfg
                .resolve_path(raw)
                .unwrap_or_else(|_| std::path::PathBuf::from(raw))
        };
        if let Some(static_res) = crate::probe_metadata::extract_static_package_version(
            package_id,
            &pkg.version_command,
            &rebase_static,
        ) {
            return match static_res {
                Ok(ver) if !ver.is_empty() => LiveRuntimeProbeOutcome::Verified(ver),
                Ok(_) => LiveRuntimeProbeOutcome::Failed(
                    "Static version probe returned empty version".into(),
                ),
                Err(e) => LiveRuntimeProbeOutcome::Failed(e),
            };
        }

        let prog = &pkg.version_command[0];
        let args = &pkg.version_command[1..];
        let prog_to_run = if package_id == "rclone" && prog == crate::package_executor::RCLONE_BIN {
            match crate::probe_metadata::rclone_version_program(env_cfg.fs_root.as_deref()) {
                Ok(path) => path.to_string_lossy().into_owned(),
                Err(err) => return LiveRuntimeProbeOutcome::Failed(err),
            }
        } else if let Ok(resolved_prog) = env_cfg.resolve_path(prog) {
            if resolved_prog.exists() {
                resolved_prog.to_string_lossy().to_string()
            } else {
                prog.clone()
            }
        } else if let Some(root) = &env_cfg.fs_root {
            let mut found = None;
            for bin_dir in ["usr/bin", "usr/local/bin", "bin"] {
                let candidate = root.join(bin_dir).join(prog);
                if candidate.exists() {
                    found = Some(candidate.to_string_lossy().to_string());
                    break;
                }
            }
            found.unwrap_or_else(|| prog.clone())
        } else {
            prog.clone()
        };

        let sanitized_args = crate::probe_metadata::sanitize_probe_shell_args(
            std::path::Path::new(&prog_to_run),
            args,
        );
        let mut cmd = std::process::Command::new(&prog_to_run);
        cmd.args(&sanitized_args);
        let sandbox_spec = crate::probe_metadata::ProbeSandboxSpec {
            drop_to_path_owner: true,
            fs_root: env_cfg.fs_root.clone(),
            package_user: Some(package_id.to_string()),
        };
        if let Err(err) = crate::probe_metadata::configure_sandboxed_std_command(
            &mut cmd,
            std::path::Path::new(&prog_to_run),
            &sanitized_args,
            &sandbox_spec,
        ) {
            return LiveRuntimeProbeOutcome::Failed(format!(
                "Refused unsafe version probe command '{}': {}",
                prog_to_run, err
            ));
        }

        match run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
            Ok(output) => {
                if output.status.success() {
                    let combined = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let mut extracted = if !pkg.version_regex.is_empty() {
                        if let Ok(re) = regex::Regex::new(&pkg.version_regex) {
                            re.captures(&combined)
                                .and_then(|cap| {
                                    cap.get(1)
                                        .or_else(|| cap.get(0))
                                        .map(|m| m.as_str().trim().to_string())
                                })
                                .unwrap_or_default()
                        } else {
                            extract_version_token(combined.lines().next().unwrap_or("").trim())
                        }
                    } else {
                        extract_version_token(combined.lines().next().unwrap_or("").trim())
                    };
                    if let Some(stripped) = extracted
                        .strip_prefix('v')
                        .or_else(|| extracted.strip_prefix('V'))
                    {
                        if stripped.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                            extracted = stripped.to_string();
                        }
                    }
                    if !extracted.is_empty() {
                        return LiveRuntimeProbeOutcome::Verified(extracted);
                    } else {
                        return LiveRuntimeProbeOutcome::Failed(
                            "Version command produced no output matching regex".into(),
                        );
                    }
                } else {
                    return LiveRuntimeProbeOutcome::Failed(format!(
                        "Version command exited with status: {}",
                        output.status
                    ));
                }
            }
            Err(e) => {
                return LiveRuntimeProbeOutcome::Failed(format!(
                    "Failed to execute version command '{}': {}",
                    prog_to_run, e
                ));
            }
        }
    }

    // 2. Live git `rev-parse HEAD` in `/opt/<pkg>/source` or `/opt/<pkg>` (e.g. invidious, git packages)
    if !package_id.eq_ignore_ascii_case("piped") {
        let is_git_package = pkg.update_source.eq_ignore_ascii_case("git_tags")
            || pkg.update_source.eq_ignore_ascii_case("git")
            || !pkg.update_repo_url.is_empty();

        let mut candidates = Vec::new();
        for dir_cand in [
            format!("/opt/{}/source", package_id),
            format!("/opt/{}/source", package_id.to_lowercase()),
            format!("/opt/{}", package_id),
            format!("/opt/{}", package_id.to_lowercase()),
        ] {
            if let Ok(resolved) = env_cfg.resolve_path(&dir_cand) {
                let git = resolved.join(".git");
                if git.exists() && !candidates.contains(&resolved) {
                    candidates.push(resolved);
                }
            }
        }
        if let Some(opt_dir) = candidates.into_iter().next() {
            match crate::probe_metadata::resolve_git_head_commit_nofollow(&opt_dir.join(".git")) {
                Ok(hash) if !hash.is_empty() => return LiveRuntimeProbeOutcome::Verified(hash),
                Ok(_) => {
                    return LiveRuntimeProbeOutcome::Failed(
                        "Git HEAD resolved to empty hash".into(),
                    )
                }
                Err(e) => {
                    return LiveRuntimeProbeOutcome::Failed(format!(
                        "Failed to resolve .git/HEAD cleanly: {}",
                        e
                    ))
                }
            }
        } else if is_git_package {
            return LiveRuntimeProbeOutcome::Failed(format!(
                "Package '{}' has git update source, but no valid git checkout exists in /opt",
                package_id
            ));
        }
    }

    // 3. Binary or dpkg version (non-APT packages such as local .deb installs)
    let mut pkg_names = Vec::new();
    if !pkg.update_package.is_empty() {
        pkg_names.push(pkg.update_package.clone());
    }
    pkg_names.push(package_id.to_string());
    pkg_names.push(pkg.name.clone());
    pkg_names.push(pkg.service_name.clone());

    for name in &pkg_names {
        if name.is_empty() {
            continue;
        }
        let mut dpkg_args: Vec<String> = Vec::new();
        if let Some(root) = &env_cfg.fs_root {
            let dpkg_dir = root.join("var/lib/dpkg");
            if dpkg_dir.exists() {
                dpkg_args.push(format!("--admindir={}", dpkg_dir.display()));
            }
        }
        dpkg_args.push("-W".to_string());
        dpkg_args.push("-f=${db:Status-Status} ${Version}\n".to_string());
        dpkg_args.push(name.clone());

        let mut cmd = std::process::Command::new(&dpkg_prog);
        if crate::probe_metadata::configure_sandboxed_std_command(
            &mut cmd,
            Path::new(&dpkg_prog),
            &dpkg_args,
            &fallback_sandbox_spec,
        )
        .is_err()
        {
            continue;
        }
        cmd.args(&dpkg_args);
        if let Ok(output) = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(ver) =
                    af_release::lifecycle::parse_installed_dpkg_status_version(&stdout)
                {
                    return LiveRuntimeProbeOutcome::Verified(ver.to_string());
                }
            }
        }
    }

    // If dpkg-query didn't find the package, check if an executable binary exists on disk
    let mut candidate_progs = Vec::new();
    if !pkg.update_package.is_empty() {
        candidate_progs.push(pkg.update_package.clone());
    }
    candidate_progs.push(package_id.to_string());
    candidate_progs.push(pkg.name.clone());

    static VERSION_TOKEN_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:[0-9]+:)?[0-9]+\.[0-9]+(?:\.[0-9]+)*(?:~[0-9A-Za-z.+~_-]+)?(?:-[0-9A-Za-z.+~_-]+)?(?:\+[0-9A-Za-z.+~_-]+)?|\b[0-9a-f]{7,40}\b)"
        )
        .expect("valid version regex")
    });
    for prog_cand in &candidate_progs {
        let bin_path = if let Some(root) = &env_cfg.fs_root {
            let mut found = None;
            for dir in ["usr/bin", "usr/local/bin", "bin", "opt"] {
                let p = root.join(dir).join(prog_cand);
                if p.is_file() {
                    found = Some(p);
                    break;
                }
            }
            found
        } else {
            let mut found = None;
            for dir in ["/usr/bin", "/usr/local/bin", "/bin"] {
                let p = Path::new(dir).join(prog_cand);
                if p.is_file() {
                    found = Some(p);
                    break;
                }
            }
            found
        };

        if let Some(bin) = bin_path {
            let bin_args = vec!["--version".to_string()];
            let mut cmd = std::process::Command::new(&bin);
            if crate::probe_metadata::configure_sandboxed_std_command(
                &mut cmd,
                &bin,
                &bin_args,
                &fallback_sandbox_spec,
            )
            .is_err()
            {
                continue;
            }
            cmd.args(&bin_args);
            if let Ok(output) = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
                if output.status.success() {
                    let combined = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if let Some(cap) = VERSION_TOKEN_RE.captures(&combined) {
                        if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                            let extracted = trim_version_token(m.as_str()).to_string();
                            if !extracted.is_empty() {
                                return LiveRuntimeProbeOutcome::Verified(extracted);
                            }
                        }
                    }
                }
            }
        }
    }

    LiveRuntimeProbeOutcome::NotConfigured
}

pub fn read_af_version_receipt(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Option<String> {
    if let Some(recipe) = crate::package_executor::get_declarative_recipe(package_id) {
        if let Some(vf) = crate::package_executor::recipe_version_file_logical_path(&recipe) {
            if let Ok(p) = env_cfg.resolve_path(&vf) {
                if let Ok(Some(bytes)) = read_receipt_bounded_nofollow(&p) {
                    if let Ok(raw) = String::from_utf8(bytes) {
                        let t = raw.trim().to_string();
                        if !t.is_empty() {
                            return Some(t);
                        }
                    }
                }
            }
        }
    }
    if package_id.eq_ignore_ascii_case("filebot") {
        for candidate in [
            "/opt/filebot-node/.af-version",
            "/var/lib/filebot/.af-version",
            "/etc/filebot/.af-version",
        ] {
            if let Ok(p) = env_cfg.resolve_path(candidate) {
                if let Ok(Some(bytes)) = read_receipt_bounded_nofollow(&p) {
                    if let Ok(raw) = String::from_utf8(bytes) {
                        let t = raw.trim().to_string();
                        if !t.is_empty() {
                            return Some(t);
                        }
                    }
                }
            }
        }
        return None;
    }
    if package_id.eq_ignore_ascii_case("listenarr") {
        for candidate in [
            "/opt/Listenarr/.af-version",
            "/var/lib/listenarr/.af-version",
            "/etc/listenarr/.af-version",
        ] {
            if let Ok(p) = env_cfg.resolve_path(candidate) {
                if let Ok(Some(bytes)) = read_receipt_bounded_nofollow(&p) {
                    if let Ok(raw) = String::from_utf8(bytes) {
                        let t = raw.trim().to_string();
                        if !t.is_empty() {
                            return Some(t);
                        }
                    }
                }
            }
        }
        return None;
    }
    for prefix in ["/var/lib", "/etc", "/opt"] {
        let candidate = format!("{}/{}/.af-version", prefix, package_id);
        if let Ok(p) = env_cfg.resolve_path(&candidate) {
            if let Ok(Some(bytes)) = read_receipt_bounded_nofollow(&p) {
                if let Ok(raw) = String::from_utf8(bytes) {
                    let t = raw.trim().to_string();
                    if !t.is_empty() {
                        return Some(t);
                    }
                }
            }
        }
    }
    None
}

fn is_regular_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                (meta.permissions().mode() & 0o111) != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        Err(_) => false,
    }
}

fn tokenize_systemd_command(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in cmd.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' && !in_single {
            escaped = true;
        } else if ch == '\'' && !in_double {
            in_single = !in_single;
        } else if ch == '"' && !in_single {
            in_double = !in_double;
        } else if ch.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(current);
                current = String::new();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

pub(super) fn validate_systemd_unit_runtime_evidence(
    content: &str,
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> bool {
    let mut working_dir: Option<PathBuf> = None;
    let mut exec_commands: Vec<String> = Vec::new();
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
        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim();
            if key == "WorkingDirectory" {
                if current_section == "Service" {
                    let v = val.trim().trim_matches('"').trim_matches('\'');
                    if !v.is_empty() {
                        working_dir = Some(PathBuf::from(v));
                    }
                }
                continue;
            }
            if key == "ExecStart" {
                if current_section != "Service" {
                    // ExecStart outside [Service] is invalid in systemd service units. Fail closed immediately.
                    return false;
                }
                let rhs = val.trim();
                if rhs.is_empty() {
                    exec_commands.clear();
                } else {
                    exec_commands.push(rhs.to_string());
                }
                continue;
            }
        }
    }

    if exec_commands.is_empty() {
        return false;
    }

    for cmd in &exec_commands {
        let mut s = cmd.as_str().trim_start();
        while let Some(stripped) = s.strip_prefix(|c| matches!(c, '-' | '@' | '+' | '!' | ':')) {
            s = stripped.trim_start();
        }
        if s.is_empty() {
            return false;
        }
        let tokens = tokenize_systemd_command(s);
        if tokens.is_empty() {
            return false;
        }
        let exec_bin = &tokens[0];
        let resolved_bin = if exec_bin.starts_with('/') {
            let p_cand = env_cfg.resolve_path(exec_bin).ok();
            if let Some(ref p) = p_cand {
                if is_regular_executable(p) {
                    p_cand
                } else if is_regular_executable(Path::new(exec_bin)) {
                    Some(PathBuf::from(exec_bin))
                } else {
                    None
                }
            } else if is_regular_executable(Path::new(exec_bin)) {
                Some(PathBuf::from(exec_bin))
            } else {
                None
            }
        } else {
            let mut found = None;
            for dir in ["/usr/local/bin", "/usr/bin", "/bin"] {
                let full = format!("{}/{}", dir, exec_bin);
                if let Ok(p) = env_cfg.resolve_path(&full) {
                    if is_regular_executable(&p) {
                        found = Some(p);
                        break;
                    }
                }
                if is_regular_executable(Path::new(&full)) {
                    found = Some(PathBuf::from(full));
                    break;
                }
            }
            found
        };

        let Some(bin_path) = resolved_bin else {
            return false;
        };
        if !is_regular_executable(&bin_path) {
            return false;
        }

        let bin_name = Path::new(exec_bin)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(exec_bin)
            .to_ascii_lowercase();

        let is_interpreter = matches!(
            bin_name.as_str(),
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "env"
                | "python"
                | "python2"
                | "python3"
                | "node"
                | "nodejs"
                | "java"
                | "ruby"
                | "perl"
                | "php"
                | "dotnet"
        );

        if is_interpreter {
            let mut script_found = false;
            let mut has_c_flag = false;
            let mut c_command = None;

            let mut idx = 1;
            while idx < tokens.len() {
                let arg = &tokens[idx];
                if arg == "-c" {
                    has_c_flag = true;
                    if idx + 1 < tokens.len() {
                        c_command = Some(&tokens[idx + 1]);
                        idx += 2;
                        continue;
                    }
                } else if arg == "-jar" || arg == "-m" {
                    if idx + 1 < tokens.len() {
                        let target = &tokens[idx + 1];
                        let cand = if target.starts_with('/') {
                            env_cfg.resolve_path(target).ok()
                        } else if let Some(ref wd) = working_dir {
                            wd.join(target)
                                .to_str()
                                .and_then(|s| env_cfg.resolve_path(s).ok())
                        } else {
                            None
                        };
                        if let Some(target_p) = cand {
                            if !std::fs::symlink_metadata(&target_p)
                                .map(|m| m.file_type().is_file())
                                .unwrap_or(false)
                            {
                                return false;
                            }
                            script_found = true;
                        } else {
                            return false;
                        }
                        idx += 2;
                        continue;
                    }
                } else if !arg.starts_with('-') {
                    let cand = if arg.starts_with('/') {
                        env_cfg.resolve_path(arg).ok()
                    } else if let Some(ref wd) = working_dir {
                        wd.join(arg)
                            .to_str()
                            .and_then(|s| env_cfg.resolve_path(s).ok())
                    } else {
                        None
                    };
                    if let Some(target_p) = cand {
                        if !std::fs::symlink_metadata(&target_p)
                            .map(|m| m.file_type().is_file())
                            .unwrap_or(false)
                        {
                            return false;
                        }
                        script_found = true;
                        break;
                    }
                }
                idx += 1;
            }

            if !script_found {
                if has_c_flag {
                    let mut found_file = false;
                    if let Some(cmd_str) = c_command {
                        let c_tokens = tokenize_systemd_command(cmd_str);
                        for tok in &c_tokens {
                            if tok.starts_with('/') {
                                if let Ok(tp) = env_cfg.resolve_path(tok) {
                                    if std::fs::symlink_metadata(&tp)
                                        .map(|m| m.file_type().is_file())
                                        .unwrap_or(false)
                                    {
                                        found_file = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if !found_file {
                        let mut app_has_exec = false;
                        for cand_dir in [
                            format!("/opt/{}", package_id),
                            format!("/opt/{}", package_id.to_lowercase()),
                        ] {
                            if let Ok(ap) = env_cfg.resolve_path(&cand_dir) {
                                if ap.is_dir() {
                                    if let Ok(entries) = std::fs::read_dir(&ap) {
                                        for entry in entries.flatten() {
                                            if is_regular_executable(&entry.path()) {
                                                app_has_exec = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if app_has_exec {
                                break;
                            }
                        }
                        if !app_has_exec {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
        }
    }

    true
}

fn is_executable_regular_file(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                (meta.permissions().mode() & 0o111) != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        Err(_) => false,
    }
}

pub fn has_independent_runtime_evidence(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> bool {
    let lower_id = package_id.to_lowercase();

    // 1. Installed systemd unit file for the package's systemd services or <pkg>.service
    let mut unit_candidates = vec![
        format!("{}.service", package_id),
        format!("{}.service", lower_id),
    ];
    if let Ok(units) = package_service_units(package_id) {
        for u in units {
            if lifecycle::is_activation_unit(&u) {
                continue;
            }
            let u_name = if u.ends_with(".service") {
                u
            } else {
                format!("{}.service", u)
            };
            if !unit_candidates.contains(&u_name) {
                unit_candidates.push(u_name);
            }
        }
    }
    for unit in &unit_candidates {
        for prefix in [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
        ] {
            let unit_path = format!("{}/{}", prefix, unit);
            if let Ok(p) = env_cfg.resolve_path(&unit_path) {
                if let Ok(meta) = std::fs::metadata(&p) {
                    if meta.is_file() {
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            if validate_systemd_unit_runtime_evidence(&content, package_id, env_cfg)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Executable regular file at /usr/local/bin/<pkg>, /usr/bin/<pkg>, /bin/<pkg>, or inside /opt/<pkg>
    for prog in [package_id, &lower_id] {
        for dir in ["/usr/local/bin", "/usr/bin", "/bin"] {
            let bin_path = format!("{}/{}", dir, prog);
            if let Ok(p) = env_cfg.resolve_path(&bin_path) {
                if is_executable_regular_file(&p) {
                    return true;
                }
            }
        }
    }

    // Scan /opt/<pkg> and /opt/<lower_id> for executable regular files (excluding .af-*, *.lock, *.tmp, *.log, *.pid, *.bak)
    let mut opt_names = vec![package_id, lower_id.as_str()];
    if lower_id == "listenarr" {
        opt_names.push("Listenarr");
    }
    for opt_name in opt_names {
        for opt_sub in [
            format!("/opt/{}", opt_name),
            format!("/opt/{}/bin", opt_name),
            format!("/opt/{}/current", opt_name),
            format!("/opt/{}/current/bin", opt_name),
        ] {
            if let Ok(p) = env_cfg.resolve_path(&opt_sub) {
                if p.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(&p) {
                        for entry in entries.flatten() {
                            let fname = entry.file_name();
                            let fname_str = fname.to_string_lossy();
                            if fname_str.starts_with(".af-")
                                || fname_str.ends_with(".lock")
                                || fname_str.ends_with(".tmp")
                                || fname_str.ends_with(".log")
                                || fname_str.ends_with(".pid")
                                || fname_str.ends_with(".bak")
                            {
                                continue;
                            }
                            if is_executable_regular_file(&entry.path()) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. When apt_package is configured, verified dpkg-query "install ok installed" status
    if let Ok(pkg) = package_definition(package_id) {
        let non_apt_package_field = matches!(
            pkg.update_source.trim().to_ascii_lowercase().as_str(),
            "pinned" | "retired" | "vendor" | "pypi"
        );
        if pkg.update_source.eq_ignore_ascii_case("apt")
            || (!non_apt_package_field && !pkg.update_package.is_empty())
        {
            let apt_name = if !pkg.update_package.is_empty() {
                &pkg.update_package
            } else {
                package_id
            };
            let mut cmd = std::process::Command::new("dpkg-query");
            cmd.args(["-W", "-f=${Status}\n", apt_name]);
            if let Ok(output) = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
                if output.status.success() {
                    let out = String::from_utf8_lossy(&output.stdout);
                    if out.trim() == "install ok installed" {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn resolve_verified_installed_version(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Option<String> {
    resolve_verified_installed_version_with_prober(
        package_id,
        env_cfg,
        probe_live_runtime_version,
        read_af_version_receipt,
    )
}

pub fn resolve_verified_installed_version_with_prober<FProbe, FReceipt>(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
    probe_fn: FProbe,
    receipt_fn: FReceipt,
) -> Option<String>
where
    FProbe: Fn(&str, &crate::PackageExecutionEnv) -> LiveRuntimeProbeOutcome,
    FReceipt: Fn(&str, &crate::PackageExecutionEnv) -> Option<String>,
{
    let live_outcome = probe_fn(package_id, env_cfg);
    let receipt_opt = receipt_fn(package_id, env_cfg);

    match live_outcome {
        LiveRuntimeProbeOutcome::Failed(reason) => {
            tracing::warn!(
                package = %package_id,
                reason = %reason,
                "Configured live runtime probe failed; refusing to certify installed version"
            );
            None
        }
        LiveRuntimeProbeOutcome::Verified(live_ver) => {
            if let Some(receipt_ver) = receipt_opt {
                let apt_legacy_compat = package_definition(package_id)
                    .ok()
                    .map(|pkg| {
                        af_release::lifecycle::apt_receipt_matches_live_debian_revision(
                            &pkg.update_source,
                            &receipt_ver,
                            &live_ver,
                        )
                    })
                    .unwrap_or(false);
                if !af_release::lifecycle::versions_match_target(&receipt_ver, &live_ver)
                    && !af_release::lifecycle::versions_match_target(&live_ver, &receipt_ver)
                    && !apt_legacy_compat
                {
                    tracing::warn!(
                        package = %package_id,
                        live = %live_ver,
                        receipt = %receipt_ver,
                        "Live runtime probe disagrees with .af-version receipt; treating as stale receipt"
                    );
                    None
                } else {
                    Some(live_ver)
                }
            } else {
                Some(live_ver)
            }
        }
        LiveRuntimeProbeOutcome::NotConfigured => {
            // Only use .af-version alone when package has independent app-specific runtime evidence on disk
            if let Some(receipt_ver) = receipt_opt {
                if has_independent_runtime_evidence(package_id, env_cfg) {
                    Some(receipt_ver)
                } else {
                    tracing::warn!(
                        package = %package_id,
                        receipt = %receipt_ver,
                        "Refusing to certify package version based on receipt alone: no independent runtime evidence found on disk"
                    );
                    None
                }
            } else {
                None
            }
        }
    }
}
