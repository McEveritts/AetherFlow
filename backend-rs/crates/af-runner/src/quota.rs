//! Fixed-path quota usage inspection behind the privileged runner socket.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRequest {
    pub username: String,
    pub user_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub used_bytes: u64,
    pub scanned_roots: Vec<PathBuf>,
}

pub(crate) fn valid_username(username: &str) -> bool {
    (SAFE_USERNAME.is_match(username) || SAFE_USERNAME_REGEX.is_match(username))
        && !username.starts_with(['-', '.'])
        && !username.contains("..")
}

async fn scan_paths(paths: Vec<PathBuf>) -> anyhow::Result<Usage> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for path in paths {
        anyhow::ensure!(path.is_absolute(), "quota storage root must be absolute");
        anyhow::ensure!(
            !path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
            "invalid quota storage root"
        );
        match tokio::fs::symlink_metadata(&path).await {
            Ok(meta) => anyhow::ensure!(
                meta.is_dir() && !meta.is_symlink(),
                "quota storage root must be a directory, not a symlink"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        }
        if roots.iter().any(|root| path.starts_with(root)) {
            continue;
        }
        roots.retain(|root| !root.starts_with(&path));
        roots.push(path);
    }
    let mut used_bytes = 0u64;
    for path in &roots {
        // GNU du does not follow links, fails on unreadable entries, and stays
        // on this filesystem. Timeout drops and kills the child process.
        let mut command = Command::new("du");
        command
            .args([
                "--summarize",
                "--bytes",
                "--no-dereference",
                "--one-file-system",
                "--",
            ])
            .arg(path)
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(20), command.output()).await??;
        anyhow::ensure!(
            output.status.success(),
            "quota usage scan failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let text = std::str::from_utf8(&output.stdout)?;
        let bytes = text
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("quota usage scan returned no count"))?
            .parse::<u64>()?;
        used_bytes = used_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("quota usage overflow"))?;
    }
    Ok(Usage {
        used_bytes,
        scanned_roots: roots,
    })
}

pub async fn inspect(req: &UsageRequest) -> anyhow::Result<Usage> {
    anyhow::ensure!(
        req.user_id > 0 && valid_username(&req.username),
        "invalid quota user"
    );
    let browser_root = env::var("AF_MCBROWSER_ROOT")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| "/var/lib/aetherflow/mcbrowser".into());
    scan_paths(vec![
        Path::new("/home").join(&req.username),
        Path::new(&browser_root).join(format!("user-{}", req.user_id)),
    ])
    .await
}

pub async fn handle(Json(req): Json<UsageRequest>) -> (StatusCode, Json<RunnerResponse>) {
    match inspect(&req).await {
        Ok(usage) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: serde_json::to_string(&usage).unwrap(),
                error: String::new(),
            }),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: error.to_string(),
            }),
        ),
    }
}

pub async fn dispatch(req: &UsageRequest) -> anyhow::Result<Usage> {
    let response = post_runner_json("/v1/quota/usage", req, Duration::from_secs(45)).await?;
    anyhow::ensure!(
        response.success,
        "runner quota usage error: {}",
        response.error
    );
    Ok(serde_json::from_str(&response.output)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn usage_scan_counts_real_files_without_following_symlinks_or_double_counting_roots() {
        let root = env::temp_dir().join(format!("af-quota-scan-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/media"), vec![7; 8192]).unwrap();
        std::os::unix::fs::symlink("/", root.join("outside")).unwrap();
        let only = scan_paths(vec![root.clone()]).await.unwrap();
        assert!(only.used_bytes >= 8192 && only.used_bytes < 1_000_000);
        let duplicate = scan_paths(vec![root.join("nested"), root.clone()])
            .await
            .unwrap();
        assert_eq!(only.used_bytes, duplicate.used_bytes);
        assert!(scan_paths(vec![root.join("outside")]).await.is_err());
        fs::remove_dir_all(root).unwrap();
        for name in ["../root", ".", "-root", "user/other"] {
            assert!(!valid_username(name));
        }
        assert!(valid_username("alice"));
    }
}
