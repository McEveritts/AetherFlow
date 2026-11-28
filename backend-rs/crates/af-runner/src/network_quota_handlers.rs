use super::*;

pub(crate) async fn handle_network(
    Json(req): Json<NetworkRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !network::is_allowed_action(&req.action) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "disallowed network action".to_string(),
            }),
        );
    }

    match execute_network_action_local(&req).await {
        Ok(out) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: out,
                error: String::new(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: e.to_string(),
            }),
        ),
    }
}

pub async fn execute_network_action_local(req: &NetworkRunnerRequest) -> anyhow::Result<String> {
    network::execute(req).await
}

pub(crate) fn setdisk_script_candidates_with_root(
    exe_dir: Option<&Path>,
    running_as_root: bool,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("packages/system/setdisk"));
        candidates.push(dir.join("../packages/system/setdisk"));
    }
    candidates.extend([
        PathBuf::from("/opt/AetherFlow/current/packages/system/setdisk"),
        PathBuf::from("/opt/AetherFlow/packages/system/setdisk"),
        PathBuf::from("/usr/local/bin/AetherFlow/system/setdisk"),
    ]);
    if !running_as_root {
        candidates.extend([
            PathBuf::from("packages/system/setdisk"),
            PathBuf::from("../packages/system/setdisk"),
        ]);
    }
    candidates
}

pub fn resolve_setdisk_script_path() -> Option<PathBuf> {
    let running_as_root = runner_is_root();
    if let Ok(explicit) = env::var("AF_SETDISK_PATH") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if is_trusted_runner_target(&p, running_as_root) {
                return Some(p);
            }
        }
    }

    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    setdisk_script_candidates_with_root(exe_dir.as_deref(), running_as_root)
        .into_iter()
        .find(|c| is_trusted_runner_target(c, running_as_root))
}

pub fn parse_quota_size_to_1k_blocks(size_raw: &str) -> Option<(u64, u64)> {
    let trimmed = size_raw.trim().to_uppercase();
    if trimmed == "0" {
        return Some((0, 0));
    }
    let re = Regex::new(r"^([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?)[B]?$").ok()?;
    let caps = re.captures(&trimmed)?;
    let num: f64 = caps.get(1)?.as_str().parse().ok()?;
    let unit = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let bytes: u64 = match unit {
        "" => num as u64,
        "K" => (num * 1024.0) as u64,
        "M" => (num * 1024.0 * 1024.0) as u64,
        "G" => (num * 1024.0 * 1024.0 * 1024.0) as u64,
        "T" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        "P" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        "E" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => return None,
    };
    let blocks_1k = bytes.div_ceil(1024);
    Some((blocks_1k, bytes))
}

pub async fn execute_set_quota_local(username: &str, size: &str) -> anyhow::Result<String> {
    if !quota::valid_username(username) {
        anyhow::bail!("invalid username format");
    }
    if !SAFE_QUOTA_SIZE.is_match(size) {
        anyhow::bail!("invalid size format");
    }

    let dry_run = env::var("AETHERFLOW_QUOTA_DRY_RUN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if dry_run || !cfg!(target_os = "linux") {
        let (_, quota_bytes) = parse_quota_size_to_1k_blocks(size).unwrap_or((0, 0));
        return Ok(json!({
            "username": username,
            "quota": size.trim().to_uppercase(),
            "quota_bytes": quota_bytes,
            "status": "applied"
        })
        .to_string());
    }

    let bin_setdisk_opt = resolve_setdisk_script_path();

    // Legacy setdisk only accepts whole MB/GB/TB. Exact byte requests must
    // use setquota directly rather than failing inside the legacy script.
    if let Some(bin_setdisk) =
        bin_setdisk_opt.filter(|_| Regex::new(r"(?i)^[0-9]+[MGT]B$").unwrap().is_match(size))
    {
        let mut setdisk_cmd = Command::new("bash");
        setdisk_cmd
            .arg(&bin_setdisk)
            .arg("--username")
            .arg(username)
            .arg("--size")
            .arg(size)
            .arg("--json");
        let out = bounded_command::output(setdisk_cmd, Duration::from_secs(20), 64 * 1024).await;
        if let Ok(o) = out {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if o.status.success() {
                return Ok(combined.trim().to_string());
            }
            // Also try positional invocation `<username> <size>` if script variant expects positional args
            let mut positional_cmd = Command::new(&bin_setdisk);
            positional_cmd.arg(username).arg(size);
            if let Ok(o2) =
                bounded_command::output(positional_cmd, Duration::from_secs(20), 64 * 1024).await
            {
                if o2.status.success() {
                    return Ok(String::from_utf8_lossy(&o2.stdout).trim().to_string());
                }
            }
            anyhow::bail!("setdisk failed: {}", combined.trim());
        }
    }

    let (blocks_1k, quota_bytes) = parse_quota_size_to_1k_blocks(size)
        .ok_or_else(|| anyhow::anyhow!("invalid quota size: {:?}", size))?;
    let block_str = blocks_1k.to_string();
    let mut command = Command::new("setquota");
    command.args(["-u", username, &block_str, &block_str, "0", "0", "-a"]);
    let out = bounded_command::output(command, Duration::from_secs(20), 64 * 1024).await?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        anyhow::bail!("setquota failed: {}", combined.trim());
    }

    Ok(json!({
        "username": username,
        "quota": size.trim().to_uppercase(),
        "quota_bytes": quota_bytes,
        "status": "applied"
    })
    .to_string())
}

pub(crate) async fn handle_quota(
    Json(req): Json<QuotaRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !quota::valid_username(&req.username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid username format".to_string(),
            }),
        );
    }
    if !SAFE_QUOTA_SIZE.is_match(&req.size) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid size format".to_string(),
            }),
        );
    }

    match execute_set_quota_local(&req.username, &req.size).await {
        Ok(out) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: out,
                error: String::new(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: e.to_string(),
            }),
        ),
    }
}
