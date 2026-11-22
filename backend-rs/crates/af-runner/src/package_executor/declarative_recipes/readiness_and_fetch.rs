use super::*;

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    async fn probe_curl_http(
        &self,
        method: &str,
        target_url: &str,
        creds: Option<&(String, String)>,
        cancel: &CancellationToken,
    ) -> Result<CommandOutput, PackageExecutorError> {
        let mut curl_args = vec![
            "-sSL".to_string(),
            "--max-time".to_string(),
            "5".to_string(),
            "-w".to_string(),
            "\n%{http_code}".to_string(),
        ];
        let mut stdin_bytes = Vec::new();
        if let Some((ref u, ref p)) = creds {
            curl_args.push("-K".to_string());
            curl_args.push("-".to_string());
            let escaped_u = u.replace('\\', "\\\\").replace('"', "\\\"");
            let escaped_p = p.replace('\\', "\\\\").replace('"', "\\\"");
            let config_line = format!("user = \"{}:{}\"\n", escaped_u, escaped_p);
            stdin_bytes.extend_from_slice(config_line.as_bytes());
        }
        if method == "POST" {
            curl_args.push("-X".to_string());
            curl_args.push("POST".to_string());
        }
        curl_args.push(target_url.to_string());
        self.runner
            .run_command_with_stdin("curl", &curl_args, &[], &stdin_bytes, cancel)
            .await
    }

    pub(crate) async fn execute_wait_for_http_ready(
        &self,
        package_id: &str,
        path: &str,
        default_port: i32,
        vars: &HashMap<String, String>,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        fn parse_curl(raw: &str) -> Option<(&str, u16)> {
            let trimmed = raw.trim_end();
            let (body, code_str) = match trimmed.rfind('\n') {
                Some(idx) => (&trimmed[..idx], trimmed[idx + 1..].trim()),
                None => ("", trimmed.trim()),
            };
            if code_str.len() == 3 && code_str.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(code) = code_str.parse::<u16>() {
                    return Some((body, code));
                }
            }
            None
        }

        fn is_mock_curl_output(raw: &str) -> bool {
            let t = raw.trim_start();
            t.starts_with("ok: curl") || t.starts_with("[dry-run] curl")
        }

        let port = vars
            .get("APP_PORT")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(default_port as u16);
        let url = format!("http://127.0.0.1:{}{}", port, path);

        let is_rclone_check = package_id.eq_ignore_ascii_case("rclone");

        let mut rclone_creds: Option<(String, String)> = None;
        if is_rclone_check {
            let effective_root = self.env_cfg.fs_root.as_deref().unwrap_or(Path::new("/"));
            let unit =
                fs::read_to_string(rclone_unit_path(vars, effective_root)).unwrap_or_default();
            let unit_env = unit.lines().rev().find_map(|line| {
                let value = line.trim().strip_prefix("EnvironmentFile=")?.trim();
                let path = value.trim_start_matches('-').trim_matches(['"', '\'']);
                path.starts_with('/').then_some(path)
            });
            let explicit_env = vars.get("RCLONE_ENV_FILE").map(String::as_str);
            let candidates: Vec<&str> = explicit_env
                .or(unit_env)
                .map_or_else(|| vec![RCLONE_ENV, RCLONE_LEGACY_ENV], |path| vec![path]);
            let mut user = None;
            let mut pass = None;
            for candidate in candidates {
                let path = self.env_cfg.resolve_readonly_path(candidate);
                validate_filesystem_path(&path, self.env_cfg.fs_root.as_deref())?;
                if let Some(content) = read_rclone_env(&path)? {
                    let settings = af_models::parse_key_value_env_str(&content);
                    user = settings
                        .get("RCLONE_RC_USER")
                        .or_else(|| settings.get("RCLONE_USER"))
                        .cloned();
                    pass = settings
                        .get("RCLONE_RC_PASS")
                        .or_else(|| settings.get("RCLONE_PASS"))
                        .cloned();
                    break;
                }
            }
            if user.is_none() {
                user = vars
                    .get("MASTER_USER")
                    .cloned()
                    .or_else(|| vars.get("AF_CONFIG_USER").cloned());
            }
            if pass.is_none() {
                pass = vars
                    .get("RCLONE_PASS")
                    .cloned()
                    .or_else(|| vars.get("MASTER_PASS").cloned())
                    .or_else(|| vars.get("AF_CONFIG_PASS").cloned());
            }
            if let (Some(u), Some(p)) = (user, pass) {
                rclone_creds = Some((u, p));
            }
        }

        let max_attempts = env::var("AETHERFLOW_HTTP_READY_MAX_ATTEMPTS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(if self.env_cfg.fs_root.is_some() {
                5
            } else {
                15
            });
        let retry_delay_ms = env::var("AETHERFLOW_HTTP_READY_RETRY_DELAY_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(if self.env_cfg.fs_root.is_some() {
                15
            } else {
                500
            });
        let deadline = Instant::now()
            + Duration::from_secs(if self.env_cfg.fs_root.is_some() {
                5
            } else {
                30
            });
        let mut last_reason = String::new();

        for attempt in 1..=max_attempts {
            cancel.check(package_id)?;
            if attempt > 1 {
                if Instant::now() >= deadline {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(retry_delay_ms)) => {}
                    _ = wait_for_cancellation(cancel) => {
                        return Err(PackageExecutorError::Cancelled(package_id.to_string()));
                    }
                }
            }

            if is_rclone_check {
                let separate_api_port = detect_rclone_separate_api_port(&self.env_cfg, vars, port);

                let rc_port = if let Some(api_port) = separate_api_port {
                    // Split-port GUI mode: requires GUI listener reachability on APP_PORT
                    let gui_url = format!("http://127.0.0.1:{}/", port);
                    let gui_out = self.probe_curl_http("GET", &gui_url, None, cancel).await?;
                    if is_mock_curl_output(&gui_out.stdout) {
                        if self.env_cfg.dry_run {
                            if gui_out.success() {
                                return Ok(format!("verified HTTP readiness at {}", url));
                            }
                        } else {
                            last_reason = format!(
                                "rclone GUI probe returned mock/dry-run response when dry_run is false: {}",
                                gui_out.stdout.trim()
                            );
                            continue;
                        }
                    } else if !gui_out.success() {
                        last_reason = format!(
                            "rclone GUI probe to {} failed: {}",
                            gui_url,
                            gui_out.combined_output()
                        );
                        continue;
                    } else {
                        let Some((_, gui_code)) = parse_curl(&gui_out.stdout) else {
                            last_reason = format!(
                                "rclone GUI listener on {} returned invalid HTTP status: {}",
                                gui_url,
                                gui_out.stdout.trim()
                            );
                            continue;
                        };
                        if !(200..=399).contains(&gui_code) {
                            last_reason = format!(
                                "rclone GUI listener on {} returned HTTP {}",
                                gui_url, gui_code
                            );
                            continue;
                        }
                    }
                    api_port
                } else {
                    port
                };

                let _is_single_port = separate_api_port.is_none();

                // On the RC listener (api_port in split-port mode, or app_port in single-port rcd mode):
                // Verify BOTH /metrics (GET) AND /core/version (POST) on every readiness attempt:

                // 1. /metrics (GET)
                let metrics_url = format!("http://127.0.0.1:{}/metrics", rc_port);
                let unauth_metrics = self
                    .probe_curl_http("GET", &metrics_url, None, cancel)
                    .await?;
                if is_mock_curl_output(&unauth_metrics.stdout) {
                    if self.env_cfg.dry_run {
                        if unauth_metrics.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "RC metrics probe returned mock/dry-run response when dry_run is false: {}",
                            unauth_metrics.stdout.trim()
                        );
                        continue;
                    }
                }
                if !unauth_metrics.success() {
                    last_reason = format!(
                        "RC metrics probe to {} failed: {}",
                        metrics_url,
                        unauth_metrics.combined_output()
                    );
                    continue;
                }
                let Some((_unauth_m_body, unauth_m_code)) = parse_curl(&unauth_metrics.stdout)
                else {
                    last_reason = format!(
                        "RC metrics probe to {} returned invalid HTTP status: {}",
                        metrics_url,
                        unauth_metrics.stdout.trim()
                    );
                    continue;
                };
                if (200..=299).contains(&unauth_m_code) {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "unauthenticated metrics exposure / auth bypass detected on {}",
                            metrics_url
                        ),
                    });
                }
                if unauth_m_code != 401 && unauth_m_code != 403 {
                    last_reason = format!(
                        "unauthenticated RC metrics probe to {} returned unexpected status {} (expected 401 or 403)",
                        metrics_url, unauth_m_code
                    );
                    continue;
                }
                let auth_metrics = self
                    .probe_curl_http("GET", &metrics_url, rclone_creds.as_ref(), cancel)
                    .await?;
                if is_mock_curl_output(&auth_metrics.stdout) {
                    if self.env_cfg.dry_run {
                        if auth_metrics.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "authenticated RC metrics probe returned mock/dry-run response when dry_run is false: {}",
                            auth_metrics.stdout.trim()
                        );
                        continue;
                    }
                }
                if !auth_metrics.success() {
                    last_reason = format!(
                        "authenticated RC metrics probe to {} failed: {}",
                        metrics_url,
                        auth_metrics.combined_output()
                    );
                    continue;
                }
                let Some((_auth_m_body, auth_m_code)) = parse_curl(&auth_metrics.stdout) else {
                    last_reason = format!(
                        "authenticated RC metrics probe to {} returned invalid HTTP status: {}",
                        metrics_url,
                        auth_metrics.stdout.trim()
                    );
                    continue;
                };
                if auth_m_code == 401 || auth_m_code == 403 {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "authenticated RC metrics check failed with HTTP {} on {}",
                            auth_m_code, metrics_url
                        ),
                    });
                }
                if auth_m_code != 200 {
                    last_reason = format!(
                        "authenticated RC metrics check returned HTTP {} on {} (expected 200)",
                        auth_m_code, metrics_url
                    );
                    continue;
                }

                // 2. /core/version (POST)
                let version_url = format!("http://127.0.0.1:{}/core/version", rc_port);
                let unauth_version = self
                    .probe_curl_http("POST", &version_url, None, cancel)
                    .await?;
                if is_mock_curl_output(&unauth_version.stdout) {
                    if self.env_cfg.dry_run {
                        if unauth_version.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "RC API probe returned mock/dry-run response when dry_run is false: {}",
                            unauth_version.stdout.trim()
                        );
                        continue;
                    }
                }
                if !unauth_version.success() {
                    last_reason = format!(
                        "RC API probe to {} failed: {}",
                        version_url,
                        unauth_version.combined_output()
                    );
                    continue;
                }
                let Some((_unauth_v_body, unauth_v_code)) = parse_curl(&unauth_version.stdout)
                else {
                    last_reason = format!(
                        "unauthenticated probe to {} returned invalid HTTP status: {}",
                        version_url,
                        unauth_version.stdout.trim()
                    );
                    continue;
                };
                if (200..=299).contains(&unauth_v_code) {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "RC API listener on {} returned {} without credentials (auth bypass)",
                            version_url, unauth_v_code
                        ),
                    });
                }
                if unauth_v_code != 401 && unauth_v_code != 403 {
                    last_reason = format!(
                        "unauthenticated probe to {} returned unexpected HTTP {}",
                        version_url, unauth_v_code
                    );
                    continue;
                }

                // 3. Authenticated POST /core/version MUST return 200
                let auth_version = self
                    .probe_curl_http("POST", &version_url, rclone_creds.as_ref(), cancel)
                    .await?;
                if is_mock_curl_output(&auth_version.stdout) {
                    if self.env_cfg.dry_run {
                        if auth_version.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "authenticated RC API check returned mock/dry-run response when dry_run is false: {}",
                            auth_version.stdout.trim()
                        );
                        continue;
                    }
                }
                if !auth_version.success() {
                    last_reason = format!(
                        "authenticated RC API probe to {} failed: {}",
                        version_url,
                        auth_version.combined_output()
                    );
                    continue;
                }
                let Some((_auth_v_body, auth_v_code)) = parse_curl(&auth_version.stdout) else {
                    last_reason = format!(
                        "authenticated RC API check returned invalid HTTP status on {}: {}",
                        version_url,
                        auth_version.stdout.trim()
                    );
                    continue;
                };
                if auth_v_code == 401 || auth_v_code == 403 {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "authenticated RC API check failed with HTTP {} on {}",
                            auth_v_code, version_url
                        ),
                    });
                }
                if auth_v_code != 200 {
                    last_reason = format!(
                        "authenticated RC API check returned HTTP {} on {}",
                        auth_v_code, version_url
                    );
                    continue;
                }

                let require_live = env::var("AETHERFLOW_REQUIRE_LIVE_LISTENER")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if require_live {
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], rc_port));
                    match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
                        Ok(_) => {}
                        Err(err) => {
                            last_reason = format!(
                                "RC API listener on 127.0.0.1:{} is not accepting TCP connections: {}",
                                rc_port, err
                            );
                            continue;
                        }
                    }
                }

                if separate_api_port.is_some() {
                    return Ok(format!(
                        "verified HTTP readiness for Rclone GUI at http://127.0.0.1:{}/ and RC API at {}",
                        port, version_url
                    ));
                } else {
                    return Ok(format!("verified HTTP readiness at {}", url));
                }
            } else {
                // Non-rclone probe: never read rclone.env or send Authorization header
                let out = self.probe_curl_http("GET", &url, None, cancel).await?;
                if is_mock_curl_output(&out.stdout) {
                    if self.env_cfg.dry_run {
                        if out.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "application readiness probe returned mock/dry-run response when dry_run is false: {}",
                            out.stdout.trim()
                        );
                        continue;
                    }
                }
                if !out.success() {
                    last_reason = format!(
                        "application readiness check failed for {}: {}",
                        url,
                        out.combined_output()
                    );
                    continue;
                }
                let Some((_body, status_code)) = parse_curl(&out.stdout) else {
                    last_reason = format!(
                        "application readiness probe to {} returned invalid HTTP status: {}",
                        url,
                        out.stdout.trim()
                    );
                    continue;
                };
                if !(200..=399).contains(&status_code) {
                    last_reason = format!(
                        "application readiness check returned HTTP {} on {}",
                        status_code, url
                    );
                    continue;
                }
                let require_live = env::var("AETHERFLOW_REQUIRE_LIVE_LISTENER")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if require_live {
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                    match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
                        Ok(_) => return Ok(format!("verified HTTP readiness at {}", url)),
                        Err(err) => {
                            last_reason = format!(
                                "application listener on 127.0.0.1:{} is not accepting TCP connections: {}",
                                port, err
                            );
                            continue;
                        }
                    }
                }
                return Ok(format!("verified HTTP readiness at {}", url));
            }
        }

        Err(PackageExecutorError::StepFailed {
            step: format!("wait_for_http_ready {}", url),
            reason: last_reason,
        })
    }

    pub(super) fn resolve_explicit_password(&self) -> Option<String> {
        if self.env_cfg.keep_existing_secrets {
            return None;
        }
        self.env_cfg
            .password
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "adminadmin")
            .or_else(|| {
                env::var("AF_PASS")
                    .or_else(|_| env::var("AETHERFLOW_MASTER_PASS"))
                    .or_else(|_| env::var("MASTER_PASS"))
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty() && v != "adminadmin")
            })
    }

    pub(super) fn is_active_mountpoint(&self, logical: &str, resolved: &Path) -> bool {
        let norm_logical = logical.trim().trim_end_matches('/');
        let norm_resolved = resolved.to_string_lossy().trim_end_matches('/').to_string();

        let mut mount_tables = vec![
            self.env_cfg.resolve_readonly_path("/proc/mounts"),
            self.env_cfg.resolve_readonly_path("/proc/self/mountinfo"),
        ];
        if self.env_cfg.fs_root.is_none() {
            mount_tables.push(PathBuf::from("/proc/mounts"));
        }

        for table_path in mount_tables {
            if let Ok(contents) = fs::read_to_string(&table_path) {
                for line in contents.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    let mp_candidates: Vec<&str> = if table_path.ends_with("mountinfo") {
                        fields.get(4).copied().into_iter().collect()
                    } else {
                        fields.get(1).copied().into_iter().collect()
                    };
                    for raw_mp in mp_candidates {
                        let unescaped = raw_mp.replace("\\040", " ");
                        let mp = unescaped.trim_end_matches('/');
                        if !mp.is_empty()
                            && mp != "/"
                            && (mp == norm_logical || mp == norm_resolved)
                        {
                            return true;
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if matches!(
                norm_logical,
                "/mnt/unionfs" | "/mnt/mergerfs" | "/mnt/remote"
            ) || norm_logical.starts_with("/mnt/")
            {
                if let (Ok(meta), Some(parent)) =
                    (fs::symlink_metadata(resolved), resolved.parent())
                {
                    if let Ok(parent_meta) = fs::symlink_metadata(parent) {
                        if meta.dev() != parent_meta.dev() {
                            return true;
                        }
                    }
                }
            }
        }

        if self.env_cfg.fs_root.is_none()
            && cfg!(target_os = "linux")
            && (matches!(
                norm_logical,
                "/mnt/unionfs" | "/mnt/mergerfs" | "/mnt/remote"
            ) || norm_logical.starts_with("/mnt/"))
        {
            if let Ok(status) = std::process::Command::new("mountpoint")
                .arg("-q")
                .arg(resolved)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                if status.success() {
                    return true;
                }
            }
        }

        false
    }

    pub(super) async fn resolve_github_tag(
        &self,
        repo: &str,
        fallback_version: &str,
        strip_v_prefix: bool,
    ) -> String {
        // 1. Honor explicit version override or offline mode in tests/airgapped environments
        if let Ok(override_ver) = env::var("AETHERFLOW_PACKAGE_VERSION_OVERRIDE") {
            let trimmed = override_ver.trim();
            if SAFE_VERSION_TAG.is_match(trimmed) {
                return if strip_v_prefix {
                    trimmed.trim_start_matches('v').to_string()
                } else {
                    trimmed.to_string()
                };
            }
        }
        if self.env_cfg.artifact_cache_dir.is_some() || self.env_cfg.fs_root.is_some() {
            return if strip_v_prefix {
                fallback_version.trim_start_matches('v').to_string()
            } else if fallback_version.starts_with('v') {
                fallback_version.to_string()
            } else {
                format!("v{}", fallback_version)
            };
        }

        // 2. Query GitHub releases/latest API with short timeout
        let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
        if let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("AetherFlow-PackageExecutor/4.0")
            .build()
        {
            if let Ok(resp) = client.get(&api_url).send().await {
                if resp.status().is_success() {
                    if let Ok(json_val) = resp.json::<serde_json::Value>().await {
                        if let Some(tag_str) = json_val.get("tag_name").and_then(|v| v.as_str()) {
                            let clean = tag_str.trim();
                            if SAFE_VERSION_TAG.is_match(clean) {
                                return if strip_v_prefix {
                                    clean.trim_start_matches('v').to_string()
                                } else {
                                    clean.to_string()
                                };
                            }
                        }
                    }
                }
            }
        }

        if strip_v_prefix {
            fallback_version.trim_start_matches('v').to_string()
        } else if fallback_version.starts_with('v') {
            fallback_version.to_string()
        } else {
            format!("v{}", fallback_version)
        }
    }

    pub(in crate::package_executor) async fn fetch_artifact_to_temp(
        &self,
        pkg_id: &str,
        url: &str,
        asset_name: &str,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<PathBuf, PackageExecutorError> {
        let (path, _) = self
            .fetch_artifact_to_temp_with_source(pkg_id, url, asset_name, journal, cancel)
            .await?;
        Ok(path)
    }

    pub(in crate::package_executor) async fn fetch_artifact_to_temp_with_source(
        &self,
        pkg_id: &str,
        url: &str,
        asset_name: &str,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<(PathBuf, Option<String>), PackageExecutorError> {
        cancel.check(pkg_id)?;
        validate_filesystem_path(&self.env_cfg.temp_dir, self.env_cfg.fs_root.as_deref())?;
        fs::create_dir_all(&self.env_cfg.temp_dir)?;
        validate_filesystem_path(&self.env_cfg.temp_dir, self.env_cfg.fs_root.as_deref())?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_dest = self
            .env_cfg
            .temp_dir
            .join(format!("af-{}-{}-{}", pkg_id, nanos, asset_name));
        validate_filesystem_path(&tmp_dest, self.env_cfg.fs_root.as_deref())?;
        journal.track_temp_file(tmp_dest.clone());

        // 1. Check local artifact cache directory first (used by isolated tests and offline staging)
        if let Some(ref cache_dir) = self.env_cfg.artifact_cache_dir {
            validate_filesystem_path(cache_dir, self.env_cfg.fs_root.as_deref())?;
            let mut candidate_names = vec![asset_name];
            if asset_name == "Threadfin_linux_amd64_glibc_2.31_compat" {
                candidate_names.push("Threadfin_linux_amd64_compat");
                candidate_names.push("Threadfin_linux_amd64");
            }
            for cand in candidate_names {
                let cached = cache_dir.join(cand);
                validate_filesystem_path(&cached, self.env_cfg.fs_root.as_deref())?;
                if cached.is_file() {
                    fs::copy(&cached, &tmp_dest)?;
                    return Ok((tmp_dest, Some(cand.to_string())));
                }
            }
        }

        // 2. Support `file://` URLs for local staging tests
        if let Some(local_path) = url.strip_prefix("file://") {
            let src = Path::new(local_path);
            validate_filesystem_path(src, None)?;
            if !src.is_file() {
                return Err(PackageExecutorError::ArtifactVerification(format!(
                    "staged file artifact not found: {}",
                    src.display()
                )));
            }
            fs::copy(src, &tmp_dest)?;
            return Ok((tmp_dest, None));
        }

        // 3. Enforce HTTPS fail-closed on remote downloads
        if !url.starts_with("https://") {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing non-HTTPS artifact download URL: {}",
                url
            )));
        }

        // 4. Perform HTTPS download via reqwest with chunked cancellation checks
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("AetherFlow-PackageExecutor/4.0")
            .build()
            .map_err(|e| PackageExecutorError::StepFailed {
                step: "http_client".to_string(),
                reason: e.to_string(),
            })?;

        let mut resp = tokio::select! {
            _ = wait_for_cancellation(cancel) => {
                return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
            }
            res = client.get(url).send() => {
                res.map_err(|e| PackageExecutorError::StepFailed {
                    step: "download_artifact".to_string(),
                    reason: format!("failed to download {}: {}", url, e),
                })?
            }
        };

        if !resp.status().is_success() {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "HTTP {} when downloading {}",
                resp.status(),
                url
            )));
        }

        let mut f = File::create(&tmp_dest)?;
        loop {
            let next_chunk = tokio::select! {
                _ = wait_for_cancellation(cancel) => {
                    drop(f);
                    let _ = fs::remove_file(&tmp_dest);
                    return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
                }
                chunk_res = resp.chunk() => {
                    chunk_res.map_err(|e| PackageExecutorError::StepFailed {
                        step: "download_artifact_body".to_string(),
                        reason: e.to_string(),
                    })?
                }
            };
            match next_chunk {
                Some(chunk) => {
                    f.write_all(&chunk)?;
                }
                None => break,
            }
        }
        cancel.check(pkg_id)?;
        f.sync_all()?;

        Ok((tmp_dest, None))
    }
}
