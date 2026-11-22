use super::*;

pub(super) fn read_rclone_env(path: &Path) -> Result<Option<String>, PackageExecutorError> {
    crate::package_lifecycle::read_receipt_bounded_nofollow(path)
        .map_err(PackageExecutorError::ExecutionError)?
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| {
            PackageExecutorError::ExecutionError(format!("invalid UTF-8: {}", path.display()))
        })
}

fn rclone_runtime_owned(owner: &Path) -> Result<bool, PackageExecutorError> {
    Ok(read_rclone_env(owner)?.is_some_and(|content| content.trim_end_matches('\n') == "rclone"))
}

fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn purge_owned_rclone_archives(
    binary: &Path,
    root: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    let parent = binary
        .parent()
        .expect("Rclone executable has a parent directory");
    validate_filesystem_path(parent, root)?;
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("rclone.af-backup.")
            && entry.file_type()?.is_dir()
        {
            let path = entry.path();
            let owner = path.join(".af-archive-owner");
            if fs::symlink_metadata(&owner).is_ok_and(|meta| meta.is_file())
                && rclone_runtime_owned(&owner)?
            {
                fs::remove_dir_all(path)?;
            }
        }
    }
    Ok(())
}

pub(super) fn rclone_unit_path(vars: &HashMap<String, String>, effective_root: &Path) -> PathBuf {
    let dir = effective_root.join("etc/systemd/system");
    let service = dir.join("rclone.service");
    let web = dir.join("rclone-web.service");
    match vars
        .get("SYSTEMD_UNIT")
        .or_else(|| vars.get("SERVICE_NAME"))
        .map(|s| s.trim())
    {
        Some("rclone-web" | "rclone-web.service") => web,
        Some("rclone" | "rclone.service") => service,
        _ if !service.is_file() && web.is_file() => web,
        _ => service,
    }
}

pub fn detect_rclone_exec_start_for_root(effective_root: &Path) -> String {
    let rclone_bin = effective_root.join(RCLONE_BIN.trim_start_matches('/'));
    let help = |command: &str| {
        std::process::Command::new(&rclone_bin)
            .args([command, "--help"])
            .output()
            .ok()
            .map(|output| {
                format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
    };
    let rcd_help = help("rcd");
    let mut args = if rcd_help
        .as_deref()
        .is_none_or(|output| output.contains("--rc-web-gui"))
    {
        let mut flags = vec!["rcd", "--rc-web-gui", "--rc-addr=127.0.0.1:{{APP_PORT}}"];
        for option in ["--rc-web-gui-no-open-browser", "--rc-enable-metrics"] {
            if rcd_help
                .as_deref()
                .is_none_or(|output| output.contains(option))
            {
                flags.push(option);
            }
        }
        flags
    } else {
        let gui_help = help("gui").unwrap_or_default();
        let address_flag = if gui_help.contains("--addr") {
            "--addr=127.0.0.1:{{APP_PORT}}"
        } else {
            "--rc-addr=127.0.0.1:{{APP_PORT}}"
        };
        let mut flags = vec!["gui", address_flag];
        if gui_help.contains("--api-addr") {
            flags.push("--api-addr=127.0.0.1:{{RCLONE_API_PORT}}");
        }
        if gui_help.contains("--rc-enable-metrics") {
            flags.push("--rc-enable-metrics");
        } else if gui_help.contains("--enable-metrics") {
            flags.push("--enable-metrics");
        }
        if gui_help.contains("--no-open-browser") {
            flags.push("--no-open-browser");
        }
        flags
    };
    args.extend([
        "--config=/etc/rclone/rclone.conf",
        "--cache-dir=/var/lib/rclone/cache",
    ]);
    format!("{RCLONE_BIN} {}", args.join(" "))
}

fn rclone_unit_api_port(unit: &str) -> Option<u16> {
    crate::app_metadata::parse_rclone_unit_ports(unit).api_port
}

fn open_confined_package_sqlite(
    fs_root: Option<&Path>,
    lifecycle_job_id: &str,
) -> Option<rusqlite::Connection> {
    for db_path in crate::candidate_package_sqlite_dbs(fs_root) {
        let Ok(meta) = fs::symlink_metadata(&db_path) else {
            continue;
        };
        if !meta.is_file() || meta.file_type().is_symlink() {
            continue;
        }
        let Ok(conn) = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ) else {
            continue;
        };
        let _ = conn.busy_timeout(Duration::from_secs(5));
        if lifecycle_job_id.is_empty() {
            return Some(conn);
        }
        let has_job = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE job_id = ?1)",
                [lifecycle_job_id],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false);
        if has_job {
            return Some(conn);
        }
    }
    None
}

pub(crate) fn resolve_and_reserve_rclone_api_port_with<F>(
    fs_root: Option<&Path>,
    app_port: u16,
    explicit_api_port: Option<&str>,
    lifecycle_job_id: &str,
    lifecycle_action: Option<&str>,
    mut available_port: F,
) -> Result<u16, PackageExecutorError>
where
    F: FnMut(u16) -> bool,
{
    let effective_root = fs_root.unwrap_or(Path::new("/"));
    let invalid_err = || {
        PackageExecutorError::Validation(format!(
            "Rclone RC API port must be between 1 and 65535 and differ from GUI port {app_port}"
        ))
    };

    let mut explicit_pinned: Option<i32> = None;
    if let Some(raw) = explicit_api_port.map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = crate::app_metadata::parse_rclone_port_value(raw)
            .filter(|&p| p != app_port)
            .ok_or_else(invalid_err)?;
        explicit_pinned = Some(parsed as i32);
    } else {
        for logical in [RCLONE_ENV, RCLONE_LEGACY_ENV] {
            if let Some(content) =
                read_rclone_env(&effective_root.join(logical.trim_start_matches('/')))?
            {
                if let Some(env_port) = crate::app_metadata::parse_rclone_env_api_port(&content)
                    .map_err(PackageExecutorError::Validation)?
                {
                    if env_port == app_port {
                        return Err(invalid_err());
                    }
                    explicit_pinned = Some(env_port as i32);
                }
                break;
            }
        }
    }
    let unit_port = explicit_pinned
        .is_none()
        .then(|| {
            crate::app_metadata::extract_rclone_runtime_api_port_for_root(fs_root)
                .filter(|&p| p != app_port)
                .map(i32::from)
        })
        .flatten();

    let preferred = if app_port as i32 == af_models::RCLONE_DEFAULT_RC_API_PORT {
        af_models::RCLONE_ALT_RC_API_PORT
    } else {
        af_models::RCLONE_DEFAULT_RC_API_PORT
    };
    let [start, end] = af_models::MARKETPLACE_FALLBACK_PORT_RANGE;
    let select_fresh = |reserved: &std::collections::BTreeSet<i32>, avail: &mut F| {
        std::iter::once(preferred)
            .chain(start..=end)
            .find(|&p| {
                p != app_port as i32
                    && (1..=65535).contains(&p)
                    && !reserved.contains(&p)
                    && avail(p as u16)
            })
            .ok_or_else(|| {
                PackageExecutorError::Validation(
                    "No supported Rclone RC API port is available".into(),
                )
            })
    };

    if let Some(mut conn) = open_confined_package_sqlite(fs_root, lifecycle_job_id) {
        let chosen = af_db::reserve_lifecycle_port_in_tx(
            &mut conn,
            "rclone",
            lifecycle_job_id,
            lifecycle_action,
            |tx, reserved| {
                if let Some(p) = explicit_pinned {
                    anyhow::ensure!(
                        !reserved.contains(&p),
                        "Rclone RC API port {p} is already reserved by another application"
                    );
                    return Ok(Some(p));
                }
                let saved = match unit_port {
                    Some(p) => Some(p),
                    None => af_db::load_lifecycle_secondary_port(
                        tx,
                        "rclone",
                        af_models::RCLONE_RC_API_PORT_ROLE,
                    )?,
                };
                match saved.filter(|&p| p != app_port as i32 && !reserved.contains(&p)) {
                    Some(p) => Ok(Some(p)),
                    None => select_fresh(reserved, &mut available_port)
                        .map(Some)
                        .map_err(|e| anyhow::anyhow!("{e}")),
                }
            },
        )
        .map_err(|e| PackageExecutorError::Validation(e.to_string()))?
        .ok_or_else(|| {
            PackageExecutorError::Validation("No supported Rclone RC API port is available".into())
        })?;
        Ok(chosen as u16)
    } else if !lifecycle_job_id.is_empty() {
        Err(PackageExecutorError::Validation(
            "Cannot reserve the Rclone RC API port without the active lifecycle database".into(),
        ))
    } else if let Some(p) = explicit_pinned.or(unit_port) {
        Ok(p as u16)
    } else {
        select_fresh(&std::collections::BTreeSet::new(), &mut available_port).map(|p| p as u16)
    }
}

pub(crate) fn resolve_and_reserve_rclone_api_port(
    fs_root: Option<&Path>,
    app_port: u16,
    explicit_api_port: Option<&str>,
    lifecycle_job_id: &str,
    lifecycle_action: Option<&str>,
) -> Result<u16, PackageExecutorError> {
    resolve_and_reserve_rclone_api_port_with(
        fs_root,
        app_port,
        explicit_api_port,
        lifecycle_job_id,
        lifecycle_action,
        |port| port != 0 && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(),
    )
}

pub fn detect_rclone_exec_start() -> String {
    detect_rclone_exec_start_for_root(Path::new("/"))
}

pub fn detect_rclone_separate_api_port_for_root(
    effective_root: &Path,
    vars: &HashMap<String, String>,
    app_port: u16,
) -> Option<u16> {
    // 1. First check if variables explicitly specifies RCLONE_WEB_MODE or RCLONE_MODE:
    // If it is "rcd", return None immediately!
    let is_explicit_rcd = vars
        .get("RCLONE_WEB_MODE")
        .map(|v| v.eq_ignore_ascii_case("rcd"))
        .or_else(|| {
            vars.get("RCLONE_MODE")
                .map(|v| v.eq_ignore_ascii_case("rcd"))
        })
        .unwrap_or(false);
    if is_explicit_rcd {
        return None;
    }

    let unit_override = vars
        .get("SYSTEMD_UNIT")
        .or_else(|| vars.get("SERVICE_NAME"))
        .map(String::as_str);
    if let Some(unit) =
        crate::app_metadata::read_rclone_unit_text_for_root(effective_root, unit_override)
    {
        return rclone_unit_api_port(&unit).filter(|port| *port != app_port);
    }

    // ONLY use variables.get("RCLONE_API_PORT") if variables.get("RCLONE_WEB_MODE") (or RCLONE_MODE) is explicitly "gui"!
    let is_explicit_gui = vars
        .get("RCLONE_WEB_MODE")
        .map(|v| v.eq_ignore_ascii_case("gui"))
        .or_else(|| {
            vars.get("RCLONE_MODE")
                .map(|v| v.eq_ignore_ascii_case("gui"))
        })
        .unwrap_or(false);

    if is_explicit_gui {
        if let Some(p) = vars
            .get("RCLONE_API_PORT")
            .and_then(|v| v.parse::<u16>().ok())
        {
            if p != app_port {
                return Some(p);
            }
        }
    }

    None
}

pub fn detect_rclone_separate_api_port(
    env_cfg: &PackageExecutionEnv,
    vars: &HashMap<String, String>,
    app_port: u16,
) -> Option<u16> {
    let effective_root = env_cfg.fs_root.as_deref().unwrap_or(Path::new("/"));
    detect_rclone_separate_api_port_for_root(effective_root, vars, app_port)
}

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    pub(super) async fn execute_install_rclone_binary(
        &self,
        recipe: &DeclarativePackageRecipe,
        vars: &mut HashMap<String, String>,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        let arch_raw = self.env_cfg.effective_arch();
        let rclone_arch = match arch_raw.as_str() {
            "amd64" | "x86_64" => "amd64",
            "arm64" | "aarch64" => "arm64",
            "armhf" | "armv7l" | "arm" => "arm-v7",
            unsupported => {
                return Err(PackageExecutorError::Validation(format!(
                    "unsupported architecture '{}' for rclone",
                    unsupported
                )));
            }
        };

        let mut target_version: Option<String> = env::var("RCLONE_VERSION")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                env::var("AF_TARGET_VERSION")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            })
            .or_else(|| {
                vars.get("AF_TARGET_VERSION")
                    .cloned()
                    .filter(|v| !v.trim().is_empty())
            })
            .or_else(|| {
                vars.get("VERSION")
                    .cloned()
                    .filter(|v| !v.trim().is_empty() && v != "unknown")
            });

        if target_version.is_none() && self.env_cfg.fs_root.is_some() {
            let out = self
                .runner
                .run_command(
                    "dpkg-query",
                    &[
                        "-W".to_string(),
                        "-f=${Version}".to_string(),
                        "rclone".to_string(),
                    ],
                    &[],
                    cancel,
                )
                .await?;
            if out.success() && !out.stdout.trim().is_empty() {
                let ver = out.stdout.trim().trim_start_matches('v').to_string();
                let clean = ver
                    .split(':')
                    .next_back()
                    .unwrap_or(&ver)
                    .split('-')
                    .next()
                    .unwrap_or(&ver);
                target_version = Some(clean.to_string());
            }
        }

        let resolved_ver = if let Some(ver) = target_version {
            ver
        } else if self.env_cfg.fs_root.is_some() {
            "1.68.1".to_string()
        } else {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent("AetherFlow-PackageExecutor/4.0")
                .build()
                .map_err(|e| PackageExecutorError::StepFailed {
                    step: "install_rclone_binary".to_string(),
                    reason: format!("failed to build HTTP client: {}", e),
                })?;
            let resp = client
                .get("https://api.github.com/repos/rclone/rclone/releases/latest")
                .send()
                .await;
            match resp {
                Ok(res) if res.status().is_success() => {
                    if let Ok(json_val) = res.json::<serde_json::Value>().await {
                        json_val
                            .get("tag_name")
                            .and_then(|t| t.as_str())
                            .map(|t| t.trim_start_matches('v').to_string())
                            .unwrap_or_else(|| "1.68.1".to_string())
                    } else {
                        "1.68.1".to_string()
                    }
                }
                _ => "1.68.1".to_string(),
            }
        };

        let clean_ver = resolved_ver.trim().trim_start_matches('v').to_string();
        vars.insert("VERSION".to_string(), clean_ver.clone());
        vars.insert("TAG".to_string(), format!("v{}", clean_ver));

        if !is_downgrade_allowed() {
            let ver_marker_logical = "/var/lib/rclone/.af-version";
            if let Ok(ver_marker_path) = self.env_cfg.resolve_path(ver_marker_logical) {
                if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                    let existing_ver = existing_raw.trim().trim_start_matches('v');
                    if is_semver_strictly_greater(existing_ver, &clean_ver) {
                        return Err(PackageExecutorError::Validation(format!(
                            "refusing to downgrade rclone from installed version {} to {}",
                            existing_ver, clean_ver
                        )));
                    }
                }
            }
        }

        let tmp_dir = self.env_cfg.temp_dir.clone();
        if let Err(e) = check_filesystem_capacity_and_inodes(&tmp_dir, 512 * 1024 * 1024, 1024) {
            return Err(PackageExecutorError::ExecutionError(e));
        }

        let dest_bin = self.env_cfg.resolve_path(RCLONE_BIN)?;
        let owner = self.env_cfg.resolve_path(RCLONE_BIN_OWNER)?;
        let owned = rclone_runtime_owned(&owner)?;
        if !owned && (owner.exists() || dest_bin.exists()) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to replace an unowned Rclone installation at {}",
                dest_bin.display()
            )));
        }

        let test_archive_mode = vars.contains_key("RCLONE_ARCHIVE_PATH")
            || vars.contains_key("RCLONE_DOWNLOAD_URL")
            || vars.contains_key("RCLONE_SHA256SUMS_URL")
            || vars.contains_key("RCLONE_ARCHIVE_SHA256")
            || vars.contains_key("AF_TEST_RCLONE_DOWNLOAD")
            || env::var("AF_TEST_RCLONE_DOWNLOAD").is_ok();

        let is_mock_runner = self.env_cfg.fs_root.is_some() && !test_archive_mode;
        let bin_bytes = if is_mock_runner {
            let mut binary_bytes = None;
            if let Some(ref cache_dir) = self.env_cfg.artifact_cache_dir {
                let cand = cache_dir.join("rclone");
                if cand.is_file() {
                    binary_bytes = fs::read(&cand).ok();
                }
            }
            binary_bytes.unwrap_or_else(|| {
                let mut data = vec![0x7f, b'E', b'L', b'F'];
                data.resize(2048, 0x90);
                data[4] = 2;
                data[5] = 1;
                data[18] = 62;
                data[19] = 0;
                data
            })
        } else {
            validate_filesystem_path(&tmp_dir, self.env_cfg.fs_root.as_deref())?;
            fs::create_dir_all(&tmp_dir)?;
            let staging_dir = tmp_dir.join(format!("rclone-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&staging_dir)?;
            struct StagingDirGuard(PathBuf);
            impl Drop for StagingDirGuard {
                fn drop(&mut self) {
                    let _ = fs::remove_dir_all(&self.0);
                }
            }
            let _staging_guard = StagingDirGuard(staging_dir.clone());
            let zip_path = staging_dir.join("rclone.zip");

            let archive_filename = format!("rclone-v{}-linux-{}.zip", clean_ver, rclone_arch);

            let zip_bytes: Vec<u8> = if let Some(archive_path) = vars.get("RCLONE_ARCHIVE_PATH") {
                fs::read(archive_path).map_err(|e| {
                    let _ = fs::remove_dir_all(&staging_dir);
                    PackageExecutorError::ExecutionError(format!(
                        "failed to read override rclone archive at {}: {}",
                        archive_path, e
                    ))
                })?
            } else {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(120))
                    .user_agent("AetherFlow-PackageExecutor/4.0")
                    .build()
                    .map_err(|e| {
                        let _ = fs::remove_dir_all(&staging_dir);
                        PackageExecutorError::ExecutionError(format!(
                            "failed to build HTTP client: {}",
                            e
                        ))
                    })?;

                let download_url = vars.get("RCLONE_DOWNLOAD_URL").cloned().unwrap_or_else(|| {
                    format!(
                        "https://downloads.rclone.org/v{}/rclone-v{}-linux-{}.zip",
                        clean_ver, clean_ver, rclone_arch
                    )
                });

                let resp = client.get(&download_url).send().await;
                match resp {
                    Ok(r) if r.status().is_success() => r
                        .bytes()
                        .await
                        .map_err(|e| {
                            let _ = fs::remove_dir_all(&staging_dir);
                            PackageExecutorError::ExecutionError(format!(
                                "failed to read rclone download bytes from {}: {}",
                                download_url, e
                            ))
                        })?
                        .to_vec(),
                    _ => {
                        let github_url = format!(
                                    "https://github.com/rclone/rclone/releases/download/v{}/rclone-v{}-linux-{}.zip",
                                    clean_ver, clean_ver, rclone_arch
                                );
                        let gh_resp = client.get(&github_url).send().await.map_err(|e| {
                            let _ = fs::remove_dir_all(&staging_dir);
                            PackageExecutorError::ExecutionError(format!(
                                "failed to download rclone from fallback {}: {}",
                                github_url, e
                            ))
                        })?;
                        if !gh_resp.status().is_success() {
                            let _ = fs::remove_dir_all(&staging_dir);
                            return Err(PackageExecutorError::ExecutionError(format!(
                                "failed to download rclone archive: HTTP {}",
                                gh_resp.status()
                            )));
                        }
                        gh_resp
                            .bytes()
                            .await
                            .map_err(|e| {
                                let _ = fs::remove_dir_all(&staging_dir);
                                PackageExecutorError::ExecutionError(format!(
                                    "failed to read rclone download bytes: {}",
                                    e
                                ))
                            })?
                            .to_vec()
                    }
                }
            };

            fs::write(&zip_path, &zip_bytes)?;

            let override_sha_opt = vars
                .get("RCLONE_ARCHIVE_SHA256")
                .cloned()
                .or_else(|| env::var("RCLONE_ARCHIVE_SHA256").ok());
            let expected_sha256 = if let Some(override_sha) = override_sha_opt {
                let clean = override_sha.trim().to_ascii_lowercase();
                if clean.len() != 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(PackageExecutorError::ExecutionError(format!(
                        "malformed RCLONE_ARCHIVE_SHA256: '{}'",
                        override_sha
                    )));
                }
                clean
            } else {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(60))
                    .user_agent("AetherFlow-PackageExecutor/4.0")
                    .build()
                    .map_err(|e| {
                        let _ = fs::remove_dir_all(&staging_dir);
                        PackageExecutorError::ExecutionError(format!(
                            "failed to build HTTP client for SHA256SUMS: {}",
                            e
                        ))
                    })?;

                let sums_url_opt = vars
                    .get("RCLONE_SHA256SUMS_URL")
                    .cloned()
                    .or_else(|| env::var("RCLONE_SHA256SUMS_URL").ok());
                let sums_text = if let Some(sums_url) = sums_url_opt {
                    let resp = client.get(&sums_url).send().await.map_err(|e| {
                        let _ = fs::remove_dir_all(&staging_dir);
                        PackageExecutorError::ExecutionError(format!(
                            "failed to fetch SHA256SUMS from {}: {}",
                            sums_url, e
                        ))
                    })?;
                    if !resp.status().is_success() {
                        let _ = fs::remove_dir_all(&staging_dir);
                        return Err(PackageExecutorError::ExecutionError(format!(
                            "failed to fetch SHA256SUMS from {}: HTTP {}",
                            sums_url,
                            resp.status()
                        )));
                    }
                    resp.text().await.map_err(|e| {
                        let _ = fs::remove_dir_all(&staging_dir);
                        PackageExecutorError::ExecutionError(format!(
                            "failed to read SHA256SUMS: {}",
                            e
                        ))
                    })?
                } else {
                    let primary_url =
                        format!("https://downloads.rclone.org/v{}/SHA256SUMS", clean_ver);
                    let resp = client.get(&primary_url).send().await;
                    match resp {
                        Ok(r) if r.status().is_success() => r.text().await.map_err(|e| {
                            let _ = fs::remove_dir_all(&staging_dir);
                            PackageExecutorError::ExecutionError(format!(
                                "failed to read SHA256SUMS text: {}",
                                e
                            ))
                        })?,
                        _ => {
                            let fallback_url = format!(
                                "https://github.com/rclone/rclone/releases/download/v{}/SHA256SUMS",
                                clean_ver
                            );
                            let gh_resp = client.get(&fallback_url).send().await.map_err(|e| {
                                let _ = fs::remove_dir_all(&staging_dir);
                                PackageExecutorError::ExecutionError(format!(
                                    "failed to fetch fallback SHA256SUMS: {}",
                                    e
                                ))
                            })?;
                            if !gh_resp.status().is_success() {
                                let _ = fs::remove_dir_all(&staging_dir);
                                return Err(PackageExecutorError::ExecutionError(format!(
                                    "failed to fetch SHA256SUMS from {} and fallback {}: HTTP {}",
                                    primary_url,
                                    fallback_url,
                                    gh_resp.status()
                                )));
                            }
                            gh_resp.text().await.map_err(|e| {
                                let _ = fs::remove_dir_all(&staging_dir);
                                PackageExecutorError::ExecutionError(format!(
                                    "failed to read SHA256SUMS text: {}",
                                    e
                                ))
                            })?
                        }
                    }
                };

                let mut found_sha = None;
                for line in sums_text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let mut parts = trimmed.split_whitespace();
                    if let (Some(hash), Some(filename)) = (parts.next(), parts.next()) {
                        let clean_fname = filename.trim_start_matches('*');
                        if clean_fname == archive_filename
                            || clean_fname.ends_with(&format!("/{}", archive_filename))
                        {
                            let clean_hash = hash.to_ascii_lowercase();
                            if clean_hash.len() == 64
                                && clean_hash.chars().all(|c| c.is_ascii_hexdigit())
                            {
                                found_sha = Some(clean_hash);
                                break;
                            }
                        }
                    }
                }

                found_sha.ok_or_else(|| {
                    let _ = fs::remove_dir_all(&staging_dir);
                    PackageExecutorError::ExecutionError(format!(
                        "archive '{}' not found in SHA256SUMS or digest is malformed",
                        archive_filename
                    ))
                })?
            };

            let mut hasher = Sha256::new();
            hasher.update(&zip_bytes);
            let actual_sha256 = format!("{:x}", hasher.finalize());

            if actual_sha256 != expected_sha256 {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(PackageExecutorError::ExecutionError(format!(
                    "SHA-256 digest mismatch for archive '{}': expected {}, got {}",
                    archive_filename, expected_sha256, actual_sha256
                )));
            }

            let unzip_out = self
                .runner
                .run_command(
                    "unzip",
                    &[
                        "-qo".to_string(),
                        zip_path.to_string_lossy().to_string(),
                        "-d".to_string(),
                        staging_dir.to_string_lossy().to_string(),
                    ],
                    &[],
                    cancel,
                )
                .await?;
            if !unzip_out.success() {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(PackageExecutorError::ExecutionError(format!(
                    "failed to unzip rclone archive: {}",
                    unzip_out.combined_output()
                )));
            }

            let mut found_bin = None;
            if let Ok(entries) = fs::read_dir(&staging_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        let cand = p.join("rclone");
                        if cand.is_file() {
                            found_bin = Some(cand);
                            break;
                        }
                    } else if p.file_name().map(|n| n == "rclone").unwrap_or(false) {
                        found_bin = Some(p);
                        break;
                    }
                }
            }

            let bin_path = found_bin.ok_or_else(|| {
                let _ = fs::remove_dir_all(&staging_dir);
                PackageExecutorError::ExecutionError(
                    "rclone binary not found in extracted archive".to_string(),
                )
            })?;

            let bin_bytes = fs::read(&bin_path)?;
            if bin_bytes.len() < 4 || bin_bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(PackageExecutorError::ArtifactVerification(
                    "extracted rclone binary failed ELF magic header check".to_string(),
                ));
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755));
            }

            let mut ver_cmd = std::process::Command::new(&bin_path);
            ver_cmd.arg("--version");
            cancel.check(&recipe.package_id)?;
            let version_out = crate::package_lifecycle::run_bounded_probe_command_cancellable(
                &mut ver_cmd,
                std::time::Duration::from_secs(5),
                || cancel.is_cancelled(),
            );
            cancel.check(&recipe.package_id)?;
            let out = match version_out {
                Ok(o) if o.status.success() => o,
                Ok(o) => {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(PackageExecutorError::ExecutionError(format!(
                        "extracted rclone binary failed self-test '--version': status {}",
                        o.status
                    )));
                }
                Err(ref e) if e.contains("cancelled") || cancel.is_cancelled() => {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(PackageExecutorError::Cancelled(recipe.package_id.clone()));
                }
                Err(e) => {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(PackageExecutorError::ExecutionError(format!(
                        "failed to execute extracted rclone binary for self-test '--version': {}",
                        e
                    )));
                }
            };

            let combined_ver = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let first_line = combined_ver.lines().next().unwrap_or("").trim();
            let reported_ver = crate::package_lifecycle::extract_version_token(first_line);
            let clean_reported = reported_ver.trim_start_matches('v');
            if !af_release::lifecycle::versions_match_target(clean_reported, &clean_ver) {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(PackageExecutorError::ExecutionError(format!(
                            "extracted rclone binary self-reported version '{}' does not match target version '{}'",
                            reported_ver, clean_ver
                        )));
            }

            bin_bytes
        };

        cancel.check(&recipe.package_id)?;
        let root = self.env_cfg.fs_root.as_deref();
        // An earlier install under a private umask may have left the
        // managed runtime directories unsearchable by the service user.
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let runtime_dir = dest_bin.parent().expect("managed Rclone binary parent");
            let apps_dir = runtime_dir.parent().expect("managed application directory");
            create_dir_all_0755(runtime_dir)?;
            for path in [apps_dir, runtime_dir] {
                let directory = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                    .open(path)?;
                let mut permissions = directory.metadata()?.permissions();
                let mode = permissions.mode();
                if mode & 0o111 != 0o111 {
                    permissions.set_mode(mode | 0o111);
                    directory.set_permissions(permissions)?;
                }
            }
        }
        if !owned {
            journal.stage_file_mutation(&owner)?;
            write_file_atomic_with_mode_bounded(&owner, b"rclone\n", 0o644, root)?;
        }
        journal.stage_file_mutation(&dest_bin)?;
        write_file_atomic_with_mode_bounded(&dest_bin, &bin_bytes, 0o755, root)?;

        Ok(format!(
            "installed rclone binary {} -> {}",
            dest_bin.display(),
            clean_ver
        ))
    }

    pub(super) fn execute_remove_rclone_files(&self) -> Result<String, PackageExecutorError> {
        if self.env_cfg.delete_data
            && self.is_active_mountpoint("/mnt/remote", &self.env_cfg.resolve_path("/mnt/remote")?)
        {
            return Err(PackageExecutorError::SecurityViolation(
                "Rclone mount at /mnt/remote is still an active mountpoint".to_string(),
            ));
        }
        let owner = self.env_cfg.resolve_path(RCLONE_BIN_OWNER)?;
        if rclone_runtime_owned(&owner)? {
            remove_file_if_present(&self.env_cfg.resolve_path(RCLONE_BIN)?)?;
            remove_file_if_present(&owner)?;
        }
        for marker in ["/var/lib/rclone/.af-version", "/etc/rclone/.af-version"] {
            remove_file_if_present(&self.env_cfg.resolve_path(marker)?)?;
        }
        if self.env_cfg.delete_data {
            for logical in [RCLONE_ENV, RCLONE_LEGACY_ENV, "/etc/rclone/rclone.conf"] {
                remove_file_if_present(&self.env_cfg.resolve_path(logical)?)?;
            }
            let state = self.env_cfg.resolve_path("/var/lib/rclone")?;
            if state.exists() {
                if self.is_active_mountpoint("/var/lib/rclone", &state) {
                    return Err(PackageExecutorError::SecurityViolation(
                        "Rclone state directory is an active mountpoint".to_string(),
                    ));
                }
                fs::remove_dir_all(state)?;
            }
            for binary in [RCLONE_BIN, "/usr/bin/rclone"] {
                purge_owned_rclone_archives(
                    &self.env_cfg.resolve_readonly_path(binary),
                    self.env_cfg.fs_root.as_deref(),
                )?;
            }
        }
        Ok("removed AetherFlow Rclone files".to_string())
    }
}
