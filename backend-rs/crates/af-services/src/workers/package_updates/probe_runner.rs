use super::*;

pub(in crate::workers) async fn check_single_package(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    probe_package_update(client, github_api_base, pkg).await
}

#[cfg(test)]
pub(in crate::workers) fn build_package_update_record(
    pkg_name: &str,
    is_installed: bool,
    installed_res: anyhow::Result<String>,
    latest_res: anyhow::Result<(String, String)>,
    prev_record: Option<&PackageUpdateRecord>,
    checked_at: String,
) -> PackageUpdateRecord {
    build_package_update_record_for_source(
        "https://api.github.com",
        "",
        pkg_name,
        is_installed,
        installed_res,
        latest_res,
        prev_record,
        checked_at,
        "",
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::workers) fn build_package_update_record_for_source(
    github_api_base: &str,
    update_source: &str,
    pkg_name: &str,
    is_installed: bool,
    installed_res: anyhow::Result<String>,
    latest_res: anyhow::Result<(String, String)>,
    prev_record: Option<&PackageUpdateRecord>,
    checked_at: String,
    expected_source_key: &str,
) -> PackageUpdateRecord {
    let mut err_parts = Vec::new();
    let (installed_version, installed_fell_back) = match &installed_res {
        Ok(v) if !v.trim().is_empty() => (v.trim().to_string(), false),
        Ok(_) => {
            let (fallback, fell_back) = resolve_installed_package_version(None, prev_record);
            if is_installed && fell_back {
                tracing::warn!(
                    package = pkg_name,
                    "installed version probe returned empty output"
                );
            }
            (fallback, is_installed && fell_back)
        }
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "installed version observation failed");
            let (fallback, fell_back) = resolve_installed_package_version(None, prev_record);
            (fallback, is_installed && fell_back)
        }
    };

    let resolved_expected_key = if !expected_source_key.trim().is_empty() {
        expected_source_key.trim().to_string()
    } else if let Ok(catalog) = crate::get_package_catalog() {
        if let Some(pkg) = catalog
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(pkg_name))
        {
            canonical_update_source_key(github_api_base, pkg)
        } else {
            let synth = Package {
                name: pkg_name.to_string(),
                update_source: update_source.to_string(),
                update_repo: pkg_name.to_string(),
                update_package: pkg_name.to_string(),
                ..Default::default()
            };
            canonical_update_source_key(github_api_base, &synth)
        }
    } else {
        let synth = Package {
            name: pkg_name.to_string(),
            update_source: update_source.to_string(),
            update_repo: pkg_name.to_string(),
            update_package: pkg_name.to_string(),
            ..Default::default()
        };
        canonical_update_source_key(github_api_base, &synth)
    };

    let source_matched = prev_record
        .map(|r| {
            !r.source_key.trim().is_empty() && r.source_key.trim() == resolved_expected_key.trim()
        })
        .unwrap_or(false);

    let current_channel = if let Some((_, ch)) = resolved_expected_key.rsplit_once('|') {
        let ch_clean = ch.trim();
        if ((resolved_expected_key.starts_with("github:")
            || resolved_expected_key.starts_with("git"))
            && resolved_expected_key.matches('|').count() < 2)
            || ch_clean.is_empty()
            || ch_clean.contains('/')
        {
            "stable"
        } else {
            ch_clean
        }
    } else {
        "stable"
    };

    let effective_update_source = if !update_source.trim().is_empty() {
        update_source.trim()
    } else if let Some((src, _)) = resolved_expected_key.split_once(':') {
        src.trim()
    } else {
        ""
    };

    let valid_prev_upstream = if source_matched { prev_record } else { None };

    let mut stale_cache_observed_at: Option<String> = None;
    let mut used_prev_latest = false;

    let listenarr_arch_unsupported = pkg_name.eq_ignore_ascii_case("listenarr")
        && af_runner::listenarr_release_asset_suffix_for_arch(env::consts::ARCH).is_err();

    let (latest_version, release_url) = match &latest_res {
        Ok((v, u)) => (v.clone(), u.clone()),
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "latest version observation failed");
            if listenarr_arch_unsupported {
                err_parts.push(
                    "Package 'listenarr' is unsupported on this host architecture; official Listenarrs/Listenarr releases provide Linux x64 assets only",
                );
                (String::new(), String::new())
            } else {
                err_parts.push("Latest version could not be confirmed");
                let mut prev_ver = valid_prev_upstream
                    .filter(|r| {
                        !r.latest_version.trim().is_empty()
                            && tag_allowed_by_channel_for_source(
                                &r.latest_version,
                                current_channel,
                                effective_update_source,
                            )
                    })
                    .map(|r| r.latest_version.clone())
                    .unwrap_or_default();
                let mut prev_url = if !prev_ver.is_empty() {
                    valid_prev_upstream
                        .map(|r| r.release_url.clone())
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                if !prev_ver.is_empty() {
                    used_prev_latest = true;
                } else {
                    if let Ok(pkgs) = crate::get_package_catalog() {
                        if let Some(pkg) = pkgs.iter().find(|p| p.name == pkg_name) {
                            if (pkg.update_source == "github_release"
                                || pkg.update_source == "github")
                                && !pkg.update_repo.is_empty()
                            {
                                let ch = if !pkg.update_channel.trim().is_empty() {
                                    &pkg.update_channel
                                } else {
                                    current_channel
                                };
                                if let Some((cached_v, cached_u, cached_obs)) =
                                    get_cached_github_release_stale_for_channel(
                                        github_api_base,
                                        &pkg.update_repo,
                                        ch,
                                    )
                                {
                                    if tag_allowed_by_channel_for_source(
                                        &cached_v,
                                        ch,
                                        &pkg.update_source,
                                    ) {
                                        prev_ver = cached_v;
                                        if prev_url.is_empty() {
                                            prev_url = cached_u;
                                        }
                                        stale_cache_observed_at = Some(cached_obs);
                                    }
                                }
                            }
                            if prev_ver.is_empty() && pkg.name == "threadfin" {
                                let fallback = af_runner::resolve_threadfin_target_version();
                                if !fallback.is_empty() {
                                    prev_ver = fallback.clone();
                                    if prev_url.is_empty() {
                                        prev_url = format!("https://github.com/Threadfin/Threadfin/releases/tag/{fallback}");
                                    }
                                }
                            }
                        }
                    }
                    if prev_ver.is_empty() {
                        if let Some((cached_v, cached_u, cached_obs)) =
                            get_cached_github_release_stale_for_channel(
                                github_api_base,
                                pkg_name,
                                current_channel,
                            )
                        {
                            if tag_allowed_by_channel_for_source(
                                &cached_v,
                                current_channel,
                                effective_update_source,
                            ) {
                                prev_ver = cached_v;
                                if prev_url.is_empty() {
                                    prev_url = cached_u;
                                }
                                stale_cache_observed_at = Some(cached_obs);
                            }
                        }
                    }
                }
                (prev_ver, prev_url)
            }
        }
    };

    if installed_res.is_err()
        || installed_res
            .as_ref()
            .map(|v| v.trim().is_empty())
            .unwrap_or(false)
    {
        if is_installed && installed_fell_back && latest_res.is_ok() {
            err_parts.push("Installed version probe returned no output; retaining last known installed version");
        } else {
            err_parts.insert(0, "Installed version could not be confirmed");
        }
    }

    let update_available = if !is_installed {
        false
    } else if latest_res.is_ok() {
        if installed_res.is_ok()
            && !installed_fell_back
            && !installed_version.is_empty()
            && !installed_version.eq_ignore_ascii_case("unknown")
        {
            is_version_newer_for_source(
                &installed_version,
                &latest_version,
                effective_update_source,
            )
        } else {
            // Installed probe failed/fell back; do not claim a confirmed update against fresh upstream
            false
        }
    } else if used_prev_latest {
        // Upstream latest_res failed, but previous latest_version was retained
        if installed_res.is_ok()
            && !installed_fell_back
            && !installed_version.is_empty()
            && !installed_version.eq_ignore_ascii_case("unknown")
        {
            // Fresh installed observation succeeded: recompute availability against retained latest_version!
            is_version_newer_for_source(
                &installed_version,
                &latest_version,
                effective_update_source,
            )
        } else {
            // Installed probe also failed/fell back: preserve previous availability if channel allowed
            valid_prev_upstream
                .filter(|r| {
                    tag_allowed_by_channel_for_source(
                        &r.latest_version,
                        current_channel,
                        effective_update_source,
                    )
                })
                .map(|record| record.update_available)
                .unwrap_or(false)
        }
    } else {
        false
    };

    let checked_at = if latest_res.is_err() {
        if used_prev_latest {
            valid_prev_upstream
                .map(|p| p.checked_at.clone())
                .unwrap_or_default()
        } else {
            stale_cache_observed_at.unwrap_or_default()
        }
    } else {
        checked_at
    };

    PackageUpdateRecord {
        package_id: pkg_name.to_string(),
        installed: is_installed,
        installed_version,
        latest_version,
        update_available,
        checked_at,
        release_url,
        error: err_parts.join("; "),
        source_key: resolved_expected_key,
    }
}

pub(in crate::workers) async fn update_probe_output(
    command: Command,
    budget: Duration,
) -> anyhow::Result<std::process::Output> {
    // The supervisor retains process-tree ownership through cancellation,
    // deadline/output failure and pipe cleanup; a response timeout is not enough.
    af_runner::bounded_command::output(command, budget, 1024 * 1024)
        .await
        .map_err(Into::into)
}

pub(in crate::workers) fn effective_update_source_and_apt_package(pkg: &Package) -> (&str, &str) {
    if af_runner::select_package_engine(&pkg.name) == af_runner::PackageEngineMode::DeclarativeRust
        && matches!(pkg.name.as_str(), "prometheus" | "netdata" | "mergerfs")
    {
        let apt_pkg = if pkg.update_package.is_empty() {
            pkg.name.as_str()
        } else {
            pkg.update_package.as_str()
        };
        return ("apt", apt_pkg);
    }
    let src = pkg.update_source.as_str();
    if src == "github_release" || src == "github" {
        ("github", pkg.update_package.as_str())
    } else {
        (src, pkg.update_package.as_str())
    }
}

pub(in crate::workers) fn resolve_configured_fs_root() -> Option<PathBuf> {
    for env_key in ["AETHERFLOW_FS_ROOT", "AETHERFLOW_INSTALL_ROOT"] {
        if let Ok(root) = env::var(env_key) {
            let trimmed = root.trim();
            if !trimmed.is_empty() && trimmed != "/" {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    None
}

pub(in crate::workers) fn normalize_live_probe_output(
    pkg: &Package,
    update_source: &str,
    combined: &str,
    stdout_str: &str,
) -> anyhow::Result<String> {
    for line in combined.lines() {
        let trimmed_line = line.trim();
        if let Some(manifest) = parse_component_manifest(trimmed_line) {
            return Ok(normalize_component_manifest(&manifest));
        }
    }

    if update_source == "git" {
        return parse_git_head(stdout_str);
    }

    let version = extract_version(combined, &pkg.version_regex);
    if version.is_empty() {
        anyhow::bail!("unable to parse version output");
    }
    Ok(version)
}

pub(in crate::workers) fn resolve_probe_program(raw_prog: &str, fs_root: Option<&Path>) -> PathBuf {
    if raw_prog.starts_with('/') {
        let resolved = resolve_fs_path(raw_prog);
        if resolved.exists() {
            return resolved;
        }
        if raw_prog == "/usr/local/bin/prometheus" {
            let alt = resolve_fs_path("/usr/bin/prometheus");
            if alt.exists() {
                return alt;
            }
            return resolved;
        }
        return PathBuf::from(raw_prog);
    }
    if let Some(root) = fs_root {
        for rel in [
            "usr/local/sbin",
            "usr/local/bin",
            "usr/sbin",
            "usr/bin",
            "sbin",
            "bin",
        ] {
            let candidate = root.join(rel).join(raw_prog);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(raw_prog)
}

pub async fn run_live_version_command(pkg: &Package, budget: Duration) -> anyhow::Result<String> {
    if let Some(git_res) = probe_live_git_version(pkg, budget).await {
        return git_res;
    }
    let (update_source, apt_package) = effective_update_source_and_apt_package(pkg);
    let fs_root = resolve_configured_fs_root();
    match update_source {
        "apt" => {
            if apt_package.is_empty() {
                anyhow::bail!("no apt package configured for {}", pkg.name);
            }
            let dpkg_prog = resolve_probe_program("dpkg-query", fs_root.as_deref());
            let mut command = Command::new(&dpkg_prog);
            let mut dpkg_args: Vec<String> = Vec::new();
            if let Some(ref root) = fs_root {
                let dpkg_dir = root.join("var/lib/dpkg");
                if dpkg_dir.exists() {
                    dpkg_args.push(format!("--admindir={}", dpkg_dir.display()));
                }
            }
            dpkg_args.push("-W".to_string());
            dpkg_args.push("-f=${db:Status-Status} ${Version}\n".to_string());
            dpkg_args.push(apt_package.to_string());
            let sandbox_spec = af_runner::probe_metadata::ProbeSandboxSpec {
                drop_to_path_owner: false,
                fs_root: fs_root.clone(),
                package_user: None,
            };
            af_runner::probe_metadata::configure_sandboxed_tokio_command(
                &mut command,
                &dpkg_prog,
                &dpkg_args,
                &sandbox_spec,
            )
            .map_err(|e| anyhow::anyhow!("probe sandbox validation failed: {}", e))?;
            command.args(&dpkg_args);
            let out = update_probe_output(command, budget).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "dpkg-query exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let stdout = String::from_utf8_lossy(&out.stdout);
            let Some(version) = af_release::lifecycle::parse_installed_dpkg_status_version(&stdout)
            else {
                anyhow::bail!(
                    "installed apt package '{}' for {} is not in installed dpkg state or returned invalid version (output: '{}')",
                    apt_package,
                    pkg.name,
                    stdout.trim()
                );
            };
            Ok(version.to_string())
        }
        _ => {
            if pkg.version_command.is_empty() {
                anyhow::bail!("no version command configured");
            }
            if let Some(static_res) = af_runner::probe_metadata::extract_static_package_version(
                &pkg.name,
                &pkg.version_command,
                &resolve_fs_path,
            ) {
                let raw = static_res.map_err(|e| anyhow::anyhow!("{}", e))?;
                if update_source == "git" {
                    return parse_git_head(&raw);
                }
                let extracted = extract_version(&raw, &pkg.version_regex);
                if !extracted.is_empty() {
                    return Ok(extracted);
                }
                let trimmed = raw.trim();
                if !trimmed.is_empty() && pkg.version_regex.is_empty() {
                    return Ok(trimmed.to_string());
                }
                anyhow::bail!("unable to parse static version output");
            }

            let mut version_command = pkg.version_command.clone();
            if version_command.len() == 3
                && (version_command[0] == "bash" || version_command[0] == "sh")
                && (version_command[1] == "-lc" || version_command[1] == "-c")
            {
                let script = &version_command[2];
                if script.contains(".af-version") {
                    let mut clean = script.as_str();
                    if let Some(pos) = clean.rfind("||") {
                        let rhs = clean[pos + 2..].trim();
                        if rhs.starts_with("cat ") && rhs.contains(".af-version") {
                            clean = clean[..pos].trim();
                        }
                    }
                    if clean.starts_with("if [ -s ")
                        && clean.contains(".af-version")
                        && clean.contains("; else ")
                        && clean.ends_with("; fi")
                    {
                        if let Some(idx1) = clean.find("; else ") {
                            if let Some(idx2) = clean.rfind("; fi") {
                                if idx1 < idx2 {
                                    let mut inner = clean[idx1 + 7..idx2].trim();
                                    if inner.starts_with("bash -lc ") {
                                        inner =
                                            inner[9..].trim().trim_matches('\'').trim_matches('"');
                                    }
                                    clean = inner;
                                }
                            }
                        }
                    }
                    version_command[2] = clean.to_string();
                }
            }
            let prog = if pkg.name == "rclone"
                && version_command[0] == "/opt/AetherFlow/apps/rclone/rclone"
            {
                af_runner::probe_metadata::rclone_version_program(fs_root.as_deref())
                    .map_err(anyhow::Error::msg)?
            } else {
                resolve_probe_program(&version_command[0], fs_root.as_deref())
            };
            let raw_args: Vec<String> = version_command[1..]
                .iter()
                .map(|arg| {
                    if arg.starts_with('/') {
                        let rebased = resolve_fs_path(arg);
                        if rebased.exists() {
                            return rebased.to_string_lossy().into_owned();
                        }
                    }
                    arg.clone()
                })
                .collect();
            let args = af_runner::probe_metadata::sanitize_probe_shell_args(&prog, &raw_args);
            let mut command = Command::new(&prog);
            let sandbox_spec = af_runner::probe_metadata::ProbeSandboxSpec {
                drop_to_path_owner: false,
                fs_root: fs_root.clone(),
                package_user: None,
            };
            if let Err(e) = af_runner::probe_metadata::configure_sandboxed_tokio_command(
                &mut command,
                &prog,
                &args,
                &sandbox_spec,
            ) {
                if fs_root.is_none() && af_runner::is_runner_available() {
                    let raw = af_runner::probe_package_version_via_runner(&pkg.name).await?;
                    return normalize_live_probe_output(pkg, update_source, &raw, &raw);
                }
                anyhow::bail!("probe sandbox validation failed: {}", e);
            }
            command.args(&args);
            let out = update_probe_output(command, budget).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "version command exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let stderr_str = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}\n{}", stdout_str, stderr_str);
            normalize_live_probe_output(pkg, update_source, &combined, &stdout_str)
        }
    }
}

pub(in crate::workers) async fn detect_installed_version(pkg: &Package) -> anyhow::Result<String> {
    probe_installed_package_version_strict(pkg).await
}
