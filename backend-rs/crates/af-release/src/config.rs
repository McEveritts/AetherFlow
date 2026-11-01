//! Configuration, channel taxonomy, environment/conf file parsing, and database path resolution.
//!
//! Preserves exact parity with `deploy/release-manager.conf` and `deploy/release-manager.sh`
//! without sourcing untrusted shell files.

use crate::error::{ReleaseError, ReleaseResult};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

static SAFE_GITHUB_REPO_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$").unwrap());
static SAFE_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$").unwrap());

/// Supported release channels across AetherFlow v4.0 (`stable`, `nightly`, `experimental`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseChannel {
    #[default]
    Stable,
    Nightly,
    Experimental,
}

impl ReleaseChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            ReleaseChannel::Stable => "stable",
            ReleaseChannel::Nightly => "nightly",
            ReleaseChannel::Experimental => "experimental",
        }
    }
}

impl fmt::Display for ReleaseChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReleaseChannel {
    type Err = ReleaseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "stable" => Ok(ReleaseChannel::Stable),
            "nightly" => Ok(ReleaseChannel::Nightly),
            "experimental" => Ok(ReleaseChannel::Experimental),
            other => Err(ReleaseError::Config(format!(
                "invalid release channel {:?} (expected stable, nightly, or experimental)",
                other
            ))),
        }
    }
}

/// Top-level release manager subcommands matching `deploy/release-manager.sh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseCommand {
    #[default]
    Deploy,
    Rollback,
    Cleanup,
    MigrateSystemd,
}

impl ReleaseCommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            ReleaseCommand::Deploy => "deploy",
            ReleaseCommand::Rollback => "rollback",
            ReleaseCommand::Cleanup => "cleanup",
            ReleaseCommand::MigrateSystemd => "migrate-systemd",
        }
    }
}

impl fmt::Display for ReleaseCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReleaseCommand {
    type Err = ReleaseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "deploy" => Ok(ReleaseCommand::Deploy),
            "rollback" => Ok(ReleaseCommand::Rollback),
            "cleanup" => Ok(ReleaseCommand::Cleanup),
            "migrate-systemd" | "migrate_systemd" => Ok(ReleaseCommand::MigrateSystemd),
            other => Err(ReleaseError::Config(format!(
                "invalid release command {:?} (expected deploy, rollback, cleanup, or migrate-systemd)",
                other
            ))),
        }
    }
}

/// Execution options for a release command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseOptions {
    pub command: ReleaseCommand,
    pub channel: ReleaseChannel,
    pub dry_run: bool,
    pub offline: bool,
    pub from_source: bool,
}

impl Default for ReleaseOptions {
    fn default() -> Self {
        Self {
            command: ReleaseCommand::Deploy,
            channel: ReleaseChannel::Stable,
            dry_run: false,
            offline: false,
            from_source: false,
        }
    }
}

impl ReleaseOptions {
    /// Parses CLI-style arguments matching `release-manager.sh` invocation syntax:
    /// `deploy|rollback|cleanup|migrate-systemd [--channel stable|nightly|experimental] [--from-source] [--dry-run] [--offline]`
    pub fn parse_args<I, S>(args: I, default_channel: ReleaseChannel) -> ReleaseResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut iter = args.into_iter().peekable();
        let mut opts = Self {
            command: ReleaseCommand::Deploy,
            channel: default_channel,
            dry_run: false,
            offline: false,
            from_source: false,
        };

        if let Some(first) = iter.peek() {
            let token = first.as_ref().trim();
            if !token.starts_with('-') {
                opts.command = ReleaseCommand::from_str(token)?;
                let _ = iter.next();
            }
        }

        while let Some(arg_raw) = iter.next() {
            let arg = arg_raw.as_ref().trim();
            match arg {
                "--dry-run" => opts.dry_run = true,
                "--offline" => opts.offline = true,
                "--from-source" => opts.from_source = true,
                "--channel" => {
                    let next = iter
                        .next()
                        .ok_or_else(|| ReleaseError::Config("--channel requires a value".into()))?;
                    opts.channel = ReleaseChannel::from_str(next.as_ref())?;
                }
                "stable" | "nightly" | "experimental" => {
                    opts.channel = ReleaseChannel::from_str(arg)?;
                }
                "" => {}
                other => {
                    return Err(ReleaseError::Config(format!(
                        "unrecognized argument {:?}",
                        other
                    )));
                }
            }
        }

        opts.validate()?;
        Ok(opts)
    }

    /// Validates option combinations before touching the filesystem.
    pub fn validate(&self) -> ReleaseResult<()> {
        if self.offline && !self.dry_run {
            return Err(ReleaseError::Config(
                "--offline is only valid with --dry-run; refusing to deploy a placeholder binary"
                    .to_string(),
            ));
        }
        if self.from_source && self.dry_run {
            return Err(ReleaseError::Unsupported(
                "[DRY-RUN] Refusing --from-source. Use a published artifact, or --offline for a placeholder."
                    .to_string(),
            ));
        }
        if self.from_source {
            return Err(ReleaseError::Unsupported(
                "--from-source is not supported by the native Rust release engine (af-release enforces signed/checksum-verified pre-built single-binary artifacts; use deploy/release-manager.sh --from-source if an emergency source build is required)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Complete typed configuration for the release engine, matching `deploy/release-manager.conf`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseConfig {
    /// Root directory where isolated release directories (`/opt/AetherFlow/releases/<epoch>`) are extracted.
    pub releases_dir: PathBuf,
    /// Atomic symlink pointing to the live release (`/opt/AetherFlow/current`).
    pub current_link: PathBuf,
    /// Source repository root (`/opt/AetherFlow`).
    pub repo_dir: PathBuf,
    /// Legacy `/opt/AetherFlow` root inspected during Stage 0 migration.
    pub legacy_opt_root: PathBuf,
    /// Dry-run isolated root (`/tmp/aetherflow-dryrun`).
    pub dry_run_root: PathBuf,
    /// GitHub repository (`McEveritts/AetherFlow`).
    pub github_repo: String,
    /// Default release channel (`stable`).
    pub release_channel: ReleaseChannel,
    /// Tarball artifact filename (`aetherflow-linux-amd64.tar.gz`).
    pub artifact_name: String,
    /// SHA-256 manifest filename (`SHA256SUMS`).
    pub checksum_name: String,
    /// Fallback git branch (`master`).
    pub git_branch: String,
    /// Fallback git remote (`origin`).
    pub git_remote: String,
    /// Deep readiness endpoint (`http://127.0.0.1:8080/health/ready`).
    pub health_endpoint: String,
    /// Number of readiness poll retries (`10`).
    pub health_retries: u32,
    /// Readiness poll interval (`3s`).
    pub health_interval: Duration,
    /// Number of releases to retain during Stage 5 housekeeping (`3`).
    pub max_releases: usize,
    /// Structured JSONL deployment log path (`/var/log/aetherflow/deploy.log`).
    pub log_file: PathBuf,
    /// FHS state directory (`/var/lib/aetherflow`).
    pub data_dir: PathBuf,
    /// FHS environment directory (`/etc/aetherflow`).
    pub env_dir: PathBuf,
    /// FHS environment file (`/etc/aetherflow/aetherflow.env`).
    pub env_file: PathBuf,
    /// SQLite database filename (`aetherflow.sqlite`).
    pub sqlite_db: String,
    /// Lock acquisition timeout for SQLite snapshots (`30s`).
    pub snapshot_timeout: Duration,
    /// Packaged systemd unit source directory (`deploy/systemd`).
    pub systemd_units_src: PathBuf,
    /// Systemd unit installation destination (`/etc/systemd/system`).
    pub systemd_units_dst: PathBuf,
    /// Optional explicit override from `AF_DB_PATH`.
    pub af_db_path_override: Option<PathBuf>,
    /// Original host `env_file` preserved across `--dry-run` path rewrites so live DB resolution still works.
    pub host_env_file: PathBuf,
    /// Original host `data_dir` preserved across `--dry-run` path rewrites.
    pub host_data_dir: PathBuf,
    /// Optional path to the executing `release-manager.sh` to stage into new releases for backward compatibility.
    pub stage_script_path: Option<PathBuf>,
    /// Optional path to `release-manager.conf` to stage into new releases.
    pub stage_conf_path: Option<PathBuf>,
}

impl Default for ReleaseConfig {
    fn default() -> Self {
        let data_dir = PathBuf::from("/var/lib/aetherflow");
        let env_file = PathBuf::from("/etc/aetherflow/aetherflow.env");
        Self {
            releases_dir: PathBuf::from("/opt/AetherFlow/releases"),
            current_link: PathBuf::from("/opt/AetherFlow/current"),
            repo_dir: PathBuf::from("/opt/AetherFlow"),
            legacy_opt_root: PathBuf::from("/opt/AetherFlow"),
            dry_run_root: PathBuf::from("/tmp/aetherflow-dryrun"),
            github_repo: "McEveritts/AetherFlow".to_string(),
            release_channel: ReleaseChannel::Stable,
            artifact_name: "aetherflow-linux-amd64.tar.gz".to_string(),
            checksum_name: "SHA256SUMS".to_string(),
            git_branch: "master".to_string(),
            git_remote: "origin".to_string(),
            health_endpoint: "http://127.0.0.1:8080/health/ready".to_string(),
            health_retries: 10,
            health_interval: Duration::from_secs(3),
            max_releases: 3,
            log_file: PathBuf::from("/var/log/aetherflow/deploy.log"),
            data_dir: data_dir.clone(),
            env_dir: PathBuf::from("/etc/aetherflow"),
            env_file: env_file.clone(),
            sqlite_db: "aetherflow.sqlite".to_string(),
            snapshot_timeout: Duration::from_secs(30),
            systemd_units_src: PathBuf::from("/opt/AetherFlow/deploy/systemd"),
            systemd_units_dst: PathBuf::from("/etc/systemd/system"),
            af_db_path_override: None,
            host_env_file: env_file,
            host_data_dir: data_dir,
            stage_script_path: None,
            stage_conf_path: None,
        }
    }
}

impl ReleaseConfig {
    /// Creates an isolated configuration rooted inside `root` (ideal for tests and dry-run sandboxes).
    pub fn for_root(root: impl AsRef<Path>) -> Self {
        let r = root.as_ref();
        let data_dir = r.join("var/lib/aetherflow");
        let env_dir = r.join("etc/aetherflow");
        let env_file = env_dir.join("aetherflow.env");
        Self {
            releases_dir: r.join("opt/AetherFlow/releases"),
            current_link: r.join("opt/AetherFlow/current"),
            repo_dir: r.join("opt/AetherFlow"),
            legacy_opt_root: r.join("opt/AetherFlow"),
            dry_run_root: r.join("tmp/aetherflow-dryrun"),
            log_file: r.join("var/log/aetherflow/deploy.log"),
            data_dir: data_dir.clone(),
            env_dir,
            env_file: env_file.clone(),
            systemd_units_src: r.join("opt/AetherFlow/deploy/systemd"),
            systemd_units_dst: r.join("etc/systemd/system"),
            host_env_file: env_file,
            host_data_dir: data_dir,
            ..Self::default()
        }
    }

    /// Loads configuration from an optional `release-manager.conf` file and an environment map
    /// (where runtime environment variables take precedence over config file defaults).
    pub fn load_with_env(
        conf_path: Option<&Path>,
        env_map: &HashMap<String, String>,
    ) -> ReleaseResult<Self> {
        let mut file_vars = HashMap::new();
        if let Some(p) = conf_path {
            if p.is_file() {
                file_vars = parse_conf_file(p)?;
            } else {
                return Err(ReleaseError::Config(format!(
                    "configuration file not found: {}",
                    p.display()
                )));
            }
        }

        let get_var = |key: &str| -> Option<String> {
            env_map
                .get(key)
                .filter(|v| !v.trim().is_empty())
                .cloned()
                .or_else(|| file_vars.get(key).filter(|v| !v.trim().is_empty()).cloned())
        };

        let mut cfg = Self::default();
        if let Some(p) = conf_path {
            cfg.stage_conf_path = Some(p.to_path_buf());
            if let Some(parent) = p.parent() {
                let candidate_script = parent.join("release-manager.sh");
                if candidate_script.is_file() {
                    cfg.stage_script_path = Some(candidate_script);
                }
                cfg.systemd_units_src = parent.join("systemd");
            }
        }

        if let Some(v) = get_var("RELEASES_DIR") {
            cfg.releases_dir = PathBuf::from(v);
        }
        if let Some(v) = get_var("CURRENT_LINK") {
            cfg.current_link = PathBuf::from(v);
        }
        if let Some(v) = get_var("REPO_DIR") {
            cfg.repo_dir = PathBuf::from(v);
        }
        if let Some(v) = get_var("LEGACY_OPT_ROOT") {
            cfg.legacy_opt_root = PathBuf::from(v);
        }
        if let Some(v) = get_var("DRY_RUN_ROOT") {
            cfg.dry_run_root = PathBuf::from(v);
        }
        if let Some(v) = get_var("GITHUB_REPO") {
            cfg.github_repo = v;
        }
        if let Some(v) = get_var("RELEASE_CHANNEL") {
            cfg.release_channel = ReleaseChannel::from_str(&v)?;
        }
        if let Some(v) = get_var("ARTIFACT_NAME") {
            cfg.artifact_name = v;
        }
        if let Some(v) = get_var("CHECKSUM_NAME") {
            cfg.checksum_name = v;
        }
        if let Some(v) = get_var("GIT_BRANCH") {
            cfg.git_branch = v;
        }
        if let Some(v) = get_var("GIT_REMOTE") {
            cfg.git_remote = v;
        }
        if let Some(v) = get_var("HEALTH_ENDPOINT") {
            cfg.health_endpoint = v;
        }
        if let Some(v) = get_var("HEALTH_RETRIES") {
            cfg.health_retries = v.parse::<u32>().map_err(|_| {
                ReleaseError::Config(format!("invalid HEALTH_RETRIES value: {:?}", v))
            })?;
        }
        if let Some(v) = get_var("HEALTH_INTERVAL") {
            let secs = v.parse::<u64>().map_err(|_| {
                ReleaseError::Config(format!("invalid HEALTH_INTERVAL value: {:?}", v))
            })?;
            cfg.health_interval = Duration::from_secs(secs);
        }
        if let Some(v) = get_var("MAX_RELEASES") {
            cfg.max_releases = v.parse::<usize>().map_err(|_| {
                ReleaseError::Config(format!("invalid MAX_RELEASES value: {:?}", v))
            })?;
        }
        if let Some(v) = get_var("LOG_FILE") {
            cfg.log_file = PathBuf::from(v);
        }
        if let Some(v) = get_var("DATA_DIR") {
            cfg.data_dir = PathBuf::from(v);
        }
        if let Some(v) = get_var("ENV_DIR") {
            cfg.env_dir = PathBuf::from(v);
        }
        if let Some(v) = get_var("ENV_FILE") {
            cfg.env_file = PathBuf::from(v);
        }
        if let Some(v) = get_var("SQLITE_DB") {
            cfg.sqlite_db = v;
        }
        if let Some(v) = get_var("SNAPSHOT_TIMEOUT") {
            let secs = v.parse::<u64>().map_err(|_| {
                ReleaseError::Config(format!("invalid SNAPSHOT_TIMEOUT value: {:?}", v))
            })?;
            cfg.snapshot_timeout = Duration::from_secs(secs);
        }
        if let Some(v) = get_var("SYSTEMD_UNITS_SRC") {
            cfg.systemd_units_src = PathBuf::from(v);
        }
        if let Some(v) = get_var("SYSTEMD_UNITS_DST") {
            cfg.systemd_units_dst = PathBuf::from(v);
        }
        if let Some(v) = env_map.get("AF_DB_PATH").filter(|s| !s.trim().is_empty()) {
            cfg.af_db_path_override = Some(PathBuf::from(v.trim()));
        }

        cfg.host_env_file = cfg.env_file.clone();
        cfg.host_data_dir = cfg.data_dir.clone();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Loads configuration from `conf_path` and process environment `std::env::vars()`.
    pub fn load_from_process_env(conf_path: Option<&Path>) -> ReleaseResult<Self> {
        let env_map: HashMap<String, String> = env::vars().collect();
        Self::load_with_env(conf_path, &env_map)
    }

    /// Returns a copy of this configuration with write paths redirected under `dry_run_root`,
    /// while preserving `host_env_file` and `host_data_dir` for live database resolution.
    pub fn with_dry_run(&self, dry_run: bool) -> Self {
        let mut out = self.clone();
        out.host_env_file = self.host_env_file.clone();
        out.host_data_dir = self.host_data_dir.clone();
        if dry_run {
            out.releases_dir = self.dry_run_root.join("releases");
            out.current_link = self.dry_run_root.join("current");
            out.repo_dir = self.dry_run_root.join("repo");
            out.data_dir = self.dry_run_root.join("data");
            out.env_dir = self.dry_run_root.join("etc");
            out.env_file = self.dry_run_root.join("etc/aetherflow.env");
            out.log_file = self.dry_run_root.join("deploy.log");
        }
        out
    }

    /// Validates all configured paths, filenames, and parameters against traversal or injection.
    pub fn validate(&self) -> ReleaseResult<()> {
        validate_no_parent_traversal(&self.releases_dir, "releases_dir")?;
        validate_no_parent_traversal(&self.current_link, "current_link")?;
        validate_no_parent_traversal(&self.repo_dir, "repo_dir")?;
        validate_no_parent_traversal(&self.dry_run_root, "dry_run_root")?;
        validate_no_parent_traversal(&self.data_dir, "data_dir")?;
        validate_no_parent_traversal(&self.env_dir, "env_dir")?;
        validate_no_parent_traversal(&self.env_file, "env_file")?;
        validate_no_parent_traversal(&self.log_file, "log_file")?;
        validate_no_parent_traversal(&self.systemd_units_dst, "systemd_units_dst")?;

        if !SAFE_GITHUB_REPO_RE.is_match(&self.github_repo) {
            return Err(ReleaseError::Config(format!(
                "invalid GITHUB_REPO format: {:?}",
                self.github_repo
            )));
        }
        if !SAFE_FILENAME_RE.is_match(&self.artifact_name) || self.artifact_name.contains("..") {
            return Err(ReleaseError::Config(format!(
                "invalid ARTIFACT_NAME: {:?}",
                self.artifact_name
            )));
        }
        if !SAFE_FILENAME_RE.is_match(&self.checksum_name) || self.checksum_name.contains("..") {
            return Err(ReleaseError::Config(format!(
                "invalid CHECKSUM_NAME: {:?}",
                self.checksum_name
            )));
        }
        if !SAFE_FILENAME_RE.is_match(&self.sqlite_db) || self.sqlite_db.contains("..") {
            return Err(ReleaseError::Config(format!(
                "invalid SQLITE_DB filename: {:?}",
                self.sqlite_db
            )));
        }
        if self.max_releases == 0 {
            return Err(ReleaseError::Config(
                "MAX_RELEASES must be at least 1".to_string(),
            ));
        }
        if self.health_retries == 0 {
            return Err(ReleaseError::Config(
                "HEALTH_RETRIES must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Rejects empty paths, NUL bytes, or `..` parent traversal segments in critical configuration paths.
pub fn validate_no_parent_traversal(path: &Path, label: &str) -> ReleaseResult<()> {
    let raw = path.to_string_lossy();
    if raw.trim().is_empty() {
        return Err(ReleaseError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} must not be empty", label),
        });
    }
    if raw.contains('\0') {
        return Err(ReleaseError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} contains NUL byte", label),
        });
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} must not contain parent traversal ('..')", label),
            });
        }
    }
    Ok(())
}

/// Parses `release-manager.conf` style `KEY="${KEY:-default}"` or `KEY="value"` assignments
/// safely without executing a shell.
pub fn parse_conf_file(path: &Path) -> ReleaseResult<HashMap<String, String>> {
    let content = fs::read_to_string(path)
        .map_err(|e| ReleaseError::io(format!("reading config file {}", path.display()), e))?;
    Ok(parse_conf_str(&content, path.parent()))
}

/// Parses `release-manager.conf` text content into key-value defaults.
pub fn parse_conf_str(content: &str, script_dir: Option<&Path>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let script_dir_str = script_dir
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/opt/AetherFlow/deploy".to_string());

    for raw_line in content.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export") {
            if rest.starts_with(char::is_whitespace) {
                line = rest.trim_start();
            }
        }
        let Some((key_raw, val_raw)) = line.split_once('=') else {
            continue;
        };
        let key = key_raw.trim();
        if key.is_empty() {
            continue;
        }
        let mut val = val_raw.trim().to_string();
        if (val.starts_with('"') && val.ends_with('"'))
            || (val.starts_with('\'') && val.ends_with('\''))
        {
            val = val[1..val.len() - 1].to_string();
        }
        // Unwrap `${KEY:-default}` shell default syntax
        let prefix = format!("${{{}:-", key);
        if val.starts_with(&prefix) && val.ends_with('}') {
            val = val[prefix.len()..val.len() - 1].to_string();
        }
        val = val.replace("${SCRIPT_DIR}", &script_dir_str);
        if !val.is_empty() {
            map.insert(key.to_string(), val);
        }
    }
    map
}

/// Parses a single key from an environment file (`/etc/aetherflow/aetherflow.env`) using the exact
/// rules of `read_env_file_value` in `deploy/release-manager.sh`:
/// - Last non-empty assignment wins.
/// - Comments (`#...`) and blank lines are ignored.
/// - Optional leading `export ` is stripped.
/// - Matching surrounding double or single quotes are stripped.
/// - The file is parsed as data and never sourced.
pub fn read_env_file_value(path: &Path, key: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    read_env_str_value(&content, key)
}

/// Parses a single key from environment file content.
pub fn read_env_str_value(content: &str, key: &str) -> Option<String> {
    let mut found: Option<String> = None;
    let prefix = format!("{}=", key);

    for raw_line in content.lines() {
        let line = raw_line.trim_end_matches('\r').trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut body = line;
        if let Some(after_export) = body.strip_prefix("export") {
            if after_export.starts_with(char::is_whitespace) {
                body = after_export.trim_start();
            }
        }
        let Some(mut val) = body.strip_prefix(&prefix) else {
            continue;
        };
        if val.len() >= 2
            && ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
        {
            val = &val[1..val.len() - 1];
        }
        if !val.is_empty() {
            found = Some(val.to_string());
        }
    }

    found
}

/// Parses `systemctl show -p Environment aetherflow-api` output using POSIX shell-like tokenization.
///
/// `systemctl show -p Environment` prints one or more `Environment=K=V K2="V2"` lines.
/// Last non-empty assignment for `key` wins.
pub fn read_systemd_environment_value(key: &str, blob: &str) -> Option<String> {
    if blob.trim().is_empty() {
        return None;
    }
    let mut chunks = Vec::new();
    for raw_line in blob.lines() {
        let mut line = raw_line.trim();
        if let Some(stripped) = line.strip_prefix("Environment=") {
            line = stripped;
        }
        if !line.is_empty() {
            chunks.push(line);
        }
    }
    let joined = chunks.join(" ");
    let tokens = posix_shlex_split(&joined)?;
    let mut found: Option<String> = None;
    for token in tokens {
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        if name == key && !value.is_empty() {
            found = Some(value.to_string());
        }
    }
    found
}

/// Minimal POSIX-compatible lexer (`shlex.split(..., posix=True)`) for systemd `Environment=` blobs.
fn posix_shlex_split(input: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            Some('"') => {
                if ch == '"' {
                    quote = None;
                } else if ch == '\\' {
                    let next = chars.next()?;
                    current.push(next);
                } else {
                    current.push(ch);
                }
            }
            Some(_) => unreachable!(),
            None => {
                if ch.is_whitespace() {
                    if in_token {
                        tokens.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                } else if ch == '\'' || ch == '"' {
                    in_token = true;
                    quote = Some(ch);
                } else if ch == '\\' {
                    in_token = true;
                    let next = chars.next()?;
                    current.push(next);
                } else {
                    in_token = true;
                    current.push(ch);
                }
            }
        }
    }

    if quote.is_some() {
        return None;
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}

/// Identifies which configuration layer resolved the live SQLite database path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbPathSource {
    /// Resolved from explicit `AF_DB_PATH` environment variable.
    AfDbPathEnv,
    /// Resolved from `DB_PATH` or `AETHERFLOW_DB_PATH` in the environment file.
    EnvFile { path: PathBuf, key: String },
    /// Resolved from `systemctl show -p Environment aetherflow-api`.
    SystemdUnit { unit: String, key: String },
    /// Fallback to `${DATA_DIR}/${SQLITE_DB}`.
    DataDirDefault,
}

impl fmt::Display for DbPathSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbPathSource::AfDbPathEnv => write!(f, "AF_DB_PATH"),
            DbPathSource::EnvFile { path, key } => {
                write!(f, "env-file:{}:{}", path.display(), key)
            }
            DbPathSource::SystemdUnit { unit, key } => write!(f, "systemd:{}:{}", unit, key),
            DbPathSource::DataDirDefault => write!(f, "DATA_DIR"),
        }
    }
}

/// Resolved live database location and provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDbPath {
    pub path: PathBuf,
    pub source: DbPathSource,
}

/// Resolves the live SQLite database path with the exact precedence of `resolve_db_path` in `release-manager.sh`:
/// 1. `AF_DB_PATH` override
/// 2. `DB_PATH` from `host_env_file`
/// 3. `AETHERFLOW_DB_PATH` from `host_env_file`
/// 4. `DB_PATH` from `systemctl show -p Environment aetherflow-api`
/// 5. `AETHERFLOW_DB_PATH` from `systemctl show -p Environment aetherflow-api`
/// 6. `${host_data_dir}/${sqlite_db}`
pub fn resolve_db_path(
    config: &ReleaseConfig,
    systemd_env_blob: Option<&str>,
) -> ResolvedDbPath {
    if let Some(ref explicit) = config.af_db_path_override {
        if !explicit.as_os_str().is_empty() {
            return ResolvedDbPath {
                path: explicit.clone(),
                source: DbPathSource::AfDbPathEnv,
            };
        }
    }

    for key in ["DB_PATH", "AETHERFLOW_DB_PATH"] {
        if let Some(val) = read_env_file_value(&config.host_env_file, key) {
            return ResolvedDbPath {
                path: PathBuf::from(val),
                source: DbPathSource::EnvFile {
                    path: config.host_env_file.clone(),
                    key: key.to_string(),
                },
            };
        }
    }

    if let Some(blob) = systemd_env_blob {
        for key in ["DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = read_systemd_environment_value(key, blob) {
                return ResolvedDbPath {
                    path: PathBuf::from(val),
                    source: DbPathSource::SystemdUnit {
                        unit: "aetherflow-api".to_string(),
                        key: key.to_string(),
                    },
                };
            }
        }
    }

    ResolvedDbPath {
        path: config.host_data_dir.join(&config.sqlite_db),
        source: DbPathSource::DataDirDefault,
    }
}
