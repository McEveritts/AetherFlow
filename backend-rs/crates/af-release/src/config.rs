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

/// Supported release channels across AetherFlow v4.0 (`stable`, `nightly`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseChannel {
    #[default]
    Stable,
    #[serde(alias = "experimental")]
    Nightly,
}

impl ReleaseChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            ReleaseChannel::Stable => "stable",
            ReleaseChannel::Nightly => "nightly",
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
            "nightly" | "experimental" => Ok(ReleaseChannel::Nightly),
            other => Err(ReleaseError::Config(format!(
                "invalid release channel {:?} (expected stable or nightly)",
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
    /// `deploy|rollback|cleanup|migrate-systemd [--channel stable|nightly] [--from-source] [--dry-run] [--offline]`
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
                "--from-source is not supported by the native Rust release engine (af-release enforces signed/checksum-verified pre-built release artifacts with external frontend assets; use deploy/release-manager.sh --from-source if an emergency source build is required)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

fn default_cli_bin_dir() -> PathBuf {
    PathBuf::from("/usr/local/bin")
}

/// Maps a Rust `std::env::consts::ARCH` architecture identifier to the canonical
/// AetherFlow release tarball filename, defaulting to `aetherflow-linux-amd64.tar.gz`.
pub fn default_release_asset_for_arch(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "aetherflow-linux-amd64.tar.gz",
        "aarch64" => "aetherflow-linux-arm64.tar.gz",
        "arm" => "aetherflow-linux-armv7.tar.gz",
        _ => "aetherflow-linux-amd64.tar.gz",
    }
}

/// Redacted secret wrapper for GitHub tokens loaded from process env or `/etc/aetherflow/aetherflow.env`.
/// Backed by [`af_models::secret_zeroize::SecretString`] so `Debug` renders `"[REDACTED]"`,
/// equality is constant-time, the value is never serialized into `.conf` or JSON, and its
/// full `0..capacity` backing storage is volatile-zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedSecret(af_models::secret_zeroize::SecretString);

impl RedactedSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(af_models::secret_zeroize::SecretString::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseConfig {
    pub releases_dir: PathBuf,
    pub current_link: PathBuf,
    pub repo_dir: PathBuf,
    pub legacy_opt_root: PathBuf,
    pub dry_run_root: PathBuf,
    pub github_repo: String,
    pub release_channel: ReleaseChannel,
    pub artifact_name: String,
    pub checksum_name: String,
    pub git_branch: String,
    pub git_remote: String,
    pub health_endpoint: String,
    pub health_retries: u32,
    pub health_interval: Duration,
    pub max_releases: usize,
    pub log_file: PathBuf,
    pub data_dir: PathBuf,
    pub env_dir: PathBuf,
    pub env_file: PathBuf,
    pub sqlite_db: String,
    pub snapshot_timeout: Duration,
    pub systemd_units_src: PathBuf,
    pub systemd_units_dst: PathBuf,
    pub af_db_path_override: Option<PathBuf>,
    pub host_env_file: PathBuf,
    pub host_data_dir: PathBuf,
    pub stage_script_path: Option<PathBuf>,
    pub stage_conf_path: Option<PathBuf>,
    #[serde(default)]
    pub isolated_root: Option<PathBuf>,
    #[serde(default = "default_cli_bin_dir")]
    pub cli_bin_dir: PathBuf,
    #[serde(skip)]
    pub github_auth_token: Option<RedactedSecret>,
    #[serde(skip)]
    pub skip_provenance_verify: bool,
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
            artifact_name: default_release_asset_for_arch(std::env::consts::ARCH).to_string(),
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
            isolated_root: None,
            cli_bin_dir: default_cli_bin_dir(),
            github_auth_token: None,
            skip_provenance_verify: false,
        }
    }
}

pub fn escape_conf_value(raw_val: &str) -> String {
    let mut escaped = String::with_capacity(raw_val.len() + 8);
    for ch in raw_val.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '$' => escaped.push_str("\\$"),
            '`' => escaped.push_str("\\`"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other_ch => escaped.push(other_ch),
        }
    }
    escaped
}

pub fn decode_quoted_or_raw_conf_value(
    raw_val: &str,
    key: &str,
    line_no: usize,
) -> ReleaseResult<(String, bool)> {
    let trimmed = raw_val.trim();
    if trimmed.starts_with('"') || trimmed.ends_with('"') {
        if trimmed.len() < 2 || !trimmed.starts_with('"') || !trimmed.ends_with('"') {
            return Err(ReleaseError::Config(format!(
                "unbalanced double quotes for key {} at line {}",
                key, line_no
            )));
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        let default_prefix = format!("${{{}:-", key);
        let (target_slice, is_default_fallback) =
            if inner.starts_with(&default_prefix) && inner.ends_with('}') {
                (&inner[default_prefix.len()..inner.len() - 1], true)
            } else {
                (inner, false)
            };

        let mut decoded = String::with_capacity(target_slice.len());
        let mut chars = target_slice.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '"' {
                return Err(ReleaseError::Config(format!(
                    "unescaped double quote inside value for key {} at line {}",
                    key, line_no
                )));
            }
            if ch == '`' {
                return Err(ReleaseError::Config(format!(
                    "unescaped backtick command substitution for key {} at line {}",
                    key, line_no
                )));
            }
            if ch == '$' && chars.peek() == Some(&'(') {
                return Err(ReleaseError::Config(format!(
                    "unescaped command substitution '$(' for key {} at line {}",
                    key, line_no
                )));
            }
            if ch == '\\' {
                let Some(next_ch) = chars.next() else {
                    return Err(ReleaseError::Config(format!(
                        "dangling escape backslash for key {} at line {}",
                        key, line_no
                    )));
                };
                match next_ch {
                    '\\' => decoded.push('\\'),
                    '"' => decoded.push('"'),
                    '$' => decoded.push('$'),
                    '`' => decoded.push('`'),
                    'n' => decoded.push('\n'),
                    'r' => decoded.push('\r'),
                    't' => decoded.push('\t'),
                    other_ch => {
                        decoded.push('\\');
                        decoded.push(other_ch);
                    }
                }
            } else {
                decoded.push(ch);
            }
        }
        return Ok((decoded, is_default_fallback));
    }

    if trimmed.starts_with('\'') || trimmed.ends_with('\'') {
        if trimmed.len() < 2 || !trimmed.starts_with('\'') || !trimmed.ends_with('\'') {
            return Err(ReleaseError::Config(format!(
                "unbalanced single quotes for key {} at line {}",
                key, line_no
            )));
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        if inner.contains('\'') {
            return Err(ReleaseError::Config(format!(
                "unescaped single quote inside value for key {} at line {}",
                key, line_no
            )));
        }
        return Ok((inner.to_string(), false));
    }

    if trimmed.contains("$(") || trimmed.contains('`') {
        return Err(ReleaseError::Config(format!(
            "unescaped command substitution in value for key {} at line {}",
            key, line_no
        )));
    }

    let default_prefix = format!("${{{}:-", key);
    if trimmed.starts_with(&default_prefix) && trimmed.ends_with('}') {
        let inner_default = &trimmed[default_prefix.len()..trimmed.len() - 1];
        return Ok((inner_default.to_string(), true));
    }

    Ok((trimmed.to_string(), false))
}

impl ReleaseConfig {
    pub fn for_root(root: impl AsRef<Path>) -> Self {
        let root_path = root.as_ref();
        let data_dir = root_path.join("var/lib/aetherflow");
        let env_dir = root_path.join("etc/aetherflow");
        let env_file = env_dir.join("aetherflow.env");
        Self {
            releases_dir: root_path.join("opt/AetherFlow/releases"),
            current_link: root_path.join("opt/AetherFlow/current"),
            repo_dir: root_path.join("opt/AetherFlow"),
            legacy_opt_root: root_path.join("opt/AetherFlow"),
            dry_run_root: root_path.join("tmp/aetherflow-dryrun"),
            log_file: root_path.join("var/log/aetherflow/deploy.log"),
            data_dir: data_dir.clone(),
            env_dir,
            env_file: env_file.clone(),
            systemd_units_src: root_path.join("opt/AetherFlow/deploy/systemd"),
            systemd_units_dst: root_path.join("etc/systemd/system"),
            host_env_file: env_file,
            host_data_dir: data_dir,
            isolated_root: Some(root_path.to_path_buf()),
            cli_bin_dir: root_path.join("usr/local/bin"),
            ..Self::default()
        }
    }

    pub fn load_with_env(
        conf_path: Option<&Path>,
        env_map: &HashMap<String, String>,
    ) -> ReleaseResult<Self> {
        Self::load_for_root_with_env(None, conf_path, env_map)
    }

    pub fn load_for_root_with_env(
        explicit_root: Option<&Path>,
        conf_path: Option<&Path>,
        env_map: &HashMap<String, String>,
    ) -> ReleaseResult<Self> {
        let env_root = env_map
            .get("AETHERFLOW_RELEASE_ROOT")
            .map(|raw_val| raw_val.trim())
            .filter(|trimmed| !trimmed.is_empty())
            .map(PathBuf::from);

        let mut effective_root: Option<PathBuf> = match (
            explicit_root.filter(|root_val| !root_val.as_os_str().is_empty()),
            env_root,
        ) {
            (Some(exp), Some(env_r)) => {
                if normalize_root_cmp(exp) != normalize_root_cmp(&env_r) {
                    return Err(ReleaseError::Config(format!(
                        "conflicting isolated release roots: --root='{}' vs AETHERFLOW_RELEASE_ROOT='{}'",
                        exp.display(),
                        env_r.display()
                    )));
                }
                Some(exp.to_path_buf())
            }
            (Some(exp), None) => Some(exp.to_path_buf()),
            (None, Some(env_r)) => Some(env_r),
            (None, None) => None,
        };

        let mut parsed_entries: HashMap<String, ParsedConfEntry> = HashMap::new();
        if let Some(conf_file_path) = conf_path {
            parsed_entries = parse_conf_file_entries(conf_file_path, effective_root.as_deref())?;
        }

        if let Some(conf_root_entry) = parsed_entries.get("AETHERFLOW_RELEASE_ROOT") {
            let trimmed_conf_root = conf_root_entry.value.trim();
            if !trimmed_conf_root.is_empty() {
                let conf_root_path = PathBuf::from(trimmed_conf_root);
                if let Some(ref existing_root) = effective_root {
                    if normalize_root_cmp(existing_root) != normalize_root_cmp(&conf_root_path) {
                        return Err(ReleaseError::Config(format!(
                            "conflicting isolated release roots: '{}' vs config AETHERFLOW_RELEASE_ROOT='{}'",
                            existing_root.display(),
                            conf_root_path.display()
                        )));
                    }
                } else {
                    effective_root = Some(conf_root_path);
                }
            }
        }

        if let Some(ref root) = effective_root {
            validate_no_parent_traversal(root, "isolated release root")?;
        }

        let get_var = |key: &str, is_path_key: bool| -> Option<String> {
            if let Some(env_val) = env_map
                .get(key)
                .map(|raw_val| raw_val.trim())
                .filter(|trimmed| !trimmed.is_empty())
            {
                return Some(env_val.to_string());
            }
            if let Some(entry) = parsed_entries.get(key) {
                let trimmed = entry.value.trim();
                if !trimmed.is_empty() {
                    if is_path_key && entry.is_default_fallback {
                        if let Some(ref root) = effective_root {
                            if !path_is_within_root(Path::new(trimmed), root) {
                                return None;
                            }
                        }
                    }
                    return Some(trimmed.to_string());
                }
            }
            None
        };

        let mut cfg = if let Some(ref root) = effective_root {
            Self::for_root(root)
        } else {
            Self::default()
        };

        if let Some(conf_file_path) = conf_path {
            cfg.stage_conf_path = Some(conf_file_path.to_path_buf());
            if let Some(parent) = conf_file_path.parent() {
                let candidate_script = parent.join("release-manager.sh");
                if candidate_script.is_file() {
                    cfg.stage_script_path = Some(candidate_script);
                }
                let candidate_units = parent.join("systemd");
                if effective_root
                    .as_ref()
                    .map(|root| path_is_within_root(&candidate_units, root))
                    .unwrap_or(true)
                {
                    cfg.systemd_units_src = candidate_units;
                }
            }
        }

        if let Some(val) = get_var("RELEASES_DIR", true) {
            cfg.releases_dir = PathBuf::from(val);
        }
        if let Some(val) = get_var("CURRENT_LINK", true) {
            cfg.current_link = PathBuf::from(val);
        }
        if let Some(val) = get_var("REPO_DIR", true) {
            cfg.repo_dir = PathBuf::from(val);
        }
        if let Some(val) = get_var("LEGACY_OPT_ROOT", true) {
            cfg.legacy_opt_root = PathBuf::from(val);
        }
        if let Some(val) = get_var("DRY_RUN_ROOT", true) {
            cfg.dry_run_root = PathBuf::from(val);
        }
        if let Some(val) = get_var("GITHUB_REPO", false) {
            cfg.github_repo = val;
        }
        if let Some(val) = get_var("RELEASE_CHANNEL", false) {
            cfg.release_channel = ReleaseChannel::from_str(&val)?;
        }
        if let Some(val) =
            get_var("ARTIFACT_NAME", false).or_else(|| get_var("RELEASE_ASSET_NAME", false))
        {
            cfg.artifact_name = val;
        }
        if let Some(val) = get_var("CHECKSUM_NAME", false) {
            cfg.checksum_name = val;
        }
        if let Some(val) = get_var("GIT_BRANCH", false) {
            cfg.git_branch = val;
        }
        if let Some(val) = get_var("GIT_REMOTE", false) {
            cfg.git_remote = val;
        }
        if let Some(val) = get_var("HEALTH_ENDPOINT", false) {
            cfg.health_endpoint = val;
        }
        if let Some(val) = get_var("HEALTH_RETRIES", false) {
            cfg.health_retries = val.parse::<u32>().map_err(|_| {
                ReleaseError::Config(format!("invalid HEALTH_RETRIES value: {:?}", val))
            })?;
        }
        if let Some(val) = get_var("HEALTH_INTERVAL", false) {
            let secs = val.parse::<u64>().map_err(|_| {
                ReleaseError::Config(format!("invalid HEALTH_INTERVAL value: {:?}", val))
            })?;
            cfg.health_interval = Duration::from_secs(secs);
        }
        if let Some(val) = get_var("MAX_RELEASES", false) {
            cfg.max_releases = val.parse::<usize>().map_err(|_| {
                ReleaseError::Config(format!("invalid MAX_RELEASES value: {:?}", val))
            })?;
        }
        if let Some(val) = get_var("LOG_FILE", true) {
            cfg.log_file = PathBuf::from(val);
        }
        if let Some(val) = get_var("DATA_DIR", true) {
            cfg.data_dir = PathBuf::from(val);
        }
        if let Some(val) = get_var("ENV_DIR", true) {
            cfg.env_dir = PathBuf::from(val);
        }
        if let Some(val) = get_var("ENV_FILE", true) {
            cfg.env_file = PathBuf::from(val);
        }
        if let Some(val) = get_var("SQLITE_DB", false) {
            cfg.sqlite_db = val;
        }
        if let Some(val) = get_var("SNAPSHOT_TIMEOUT", false) {
            let secs = val.parse::<u64>().map_err(|_| {
                ReleaseError::Config(format!("invalid SNAPSHOT_TIMEOUT value: {:?}", val))
            })?;
            cfg.snapshot_timeout = Duration::from_secs(secs);
        }
        if let Some(val) = get_var("SYSTEMD_UNITS_SRC", true) {
            cfg.systemd_units_src = PathBuf::from(val);
        }
        if let Some(val) = get_var("SYSTEMD_UNITS_DST", true) {
            cfg.systemd_units_dst = PathBuf::from(val);
        }
        if let Some(val) = get_var("CLI_BIN_DIR", true) {
            cfg.cli_bin_dir = PathBuf::from(val);
        }

        let mut db_env_overrides: Vec<(&str, PathBuf)> = Vec::new();
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = env_map
                .get(key)
                .map(|raw_val| raw_val.trim())
                .filter(|trimmed| !trimmed.is_empty())
            {
                db_env_overrides.push((key, PathBuf::from(val)));
            }
        }
        if db_env_overrides.is_empty() {
            for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
                if let Some(val) = get_var(key, true) {
                    db_env_overrides.push((key, PathBuf::from(val)));
                }
            }
        }
        if let Some((first_key, first_path)) = db_env_overrides.first() {
            let first_norm = normalize_root_cmp(first_path);
            for (other_key, other_path) in db_env_overrides.iter().skip(1) {
                if normalize_root_cmp(other_path) != first_norm {
                    return Err(ReleaseError::Config(format!(
                        "conflicting database path environment overrides: {}='{}' vs {}='{}'",
                        first_key,
                        first_path.display(),
                        other_key,
                        other_path.display()
                    )));
                }
            }
            cfg.af_db_path_override = Some(first_path.clone());
        }

        cfg.host_env_file = cfg.env_file.clone();
        cfg.host_data_dir = cfg.data_dir.clone();
        cfg.isolated_root = effective_root.clone();

        // Unified secret and runtime override loading from `cfg.env_file` (`/etc/aetherflow/aetherflow.env`):
        // - Non-secret runtime settings (e.g., `HEALTH_ENDPOINT`):
        //   process env > explicit --config > cfg.env_file (unless AETHERFLOW_SKIP_ENV_FILES=1)
        //   > default-fallback --config > compiled default.
        // - Secret GitHub tokens (`AF_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`):
        //   process env > cfg.env_file ONLY (strictly forbidden in `--config`, enforced by `ALLOWED_CONF_KEYS`).
        // - Security-critical `AETHERFLOW_SKIP_PROVENANCE_VERIFY`:
        //   process env > trusted root `cfg.env_file` ONLY (NEVER resolved from `--config`).
        let (env_file_content, env_file_trusted_root) =
            load_env_file_if_enabled_with_trust(&cfg.env_file, env_map, effective_root.as_deref());

        let resolve_health_endpoint = || -> Option<String> {
            let key = "HEALTH_ENDPOINT";
            if let Some(env_val) = env_map
                .get(key)
                .map(|raw_val| raw_val.trim())
                .filter(|trimmed| !trimmed.is_empty())
            {
                return Some(env_val.to_string());
            }
            if let Some(entry) = parsed_entries.get(key) {
                let trimmed = entry.value.trim();
                if !entry.is_default_fallback && !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
            if let Some(ref content) = env_file_content {
                if let Some(val) = read_env_str_value(content.expose_secret(), key) {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            if let Some(entry) = parsed_entries.get(key) {
                let trimmed = entry.value.trim();
                if entry.is_default_fallback && !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
            None
        };

        if let Some(val) = resolve_health_endpoint() {
            cfg.health_endpoint = val;
        }

        let github_token_keys = ["AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"];
        let resolved_token = github_token_keys
            .iter()
            .find_map(|key| {
                env_map
                    .get(*key)
                    .map(|raw| raw.trim())
                    .filter(|trimmed| !trimmed.is_empty())
                    .map(str::to_string)
            })
            .or_else(|| {
                env_file_content.as_ref().and_then(|content| {
                    github_token_keys.iter().find_map(|key| {
                        read_env_str_value(content.expose_secret(), key)
                            .map(|val| val.trim().to_string())
                            .filter(|trimmed| !trimmed.is_empty())
                    })
                })
            });
        cfg.github_auth_token = resolved_token.map(RedactedSecret::new);

        let skip_prov_val = env_map
            .get("AETHERFLOW_SKIP_PROVENANCE_VERIFY")
            .map(|raw| raw.trim().to_string())
            .filter(|trimmed| !trimmed.is_empty())
            .or_else(|| {
                if env_file_trusted_root {
                    env_file_content.as_ref().and_then(|content| {
                        read_env_str_value(
                            content.expose_secret(),
                            "AETHERFLOW_SKIP_PROVENANCE_VERIFY",
                        )
                        .map(|val| val.trim().to_string())
                        .filter(|trimmed| !trimmed.is_empty())
                    })
                } else {
                    None
                }
            });
        cfg.skip_provenance_verify = skip_prov_val.as_deref() == Some("1");

        cfg.validate()?;

        if let Some(ref root) = effective_root {
            cfg.validate_within_root(root)?;
        }

        let _ = try_resolve_db_path(&cfg, None)?;

        Ok(cfg)
    }

    pub fn github_auth_token_str(&self) -> Option<&str> {
        self.github_auth_token.as_ref().map(RedactedSecret::as_str)
    }

    pub fn load_from_process_env(conf_path: Option<&Path>) -> ReleaseResult<Self> {
        Self::load_for_root_from_process_env(None, conf_path)
    }

    pub fn load_for_root_from_process_env(
        explicit_root: Option<&Path>,
        conf_path: Option<&Path>,
    ) -> ReleaseResult<Self> {
        let env_map: HashMap<String, String> = env::vars().collect();
        Self::load_for_root_with_env(explicit_root, conf_path, &env_map)
    }

    pub fn validate_within_root(&self, root: &Path) -> ReleaseResult<()> {
        validate_no_parent_traversal(root, "isolated release root")?;
        let checked_paths: [(&str, &Path); 12] = [
            ("releases_dir", &self.releases_dir),
            ("current_link", &self.current_link),
            ("repo_dir", &self.repo_dir),
            ("legacy_opt_root", &self.legacy_opt_root),
            ("dry_run_root", &self.dry_run_root),
            ("log_file", &self.log_file),
            ("data_dir", &self.data_dir),
            ("env_dir", &self.env_dir),
            ("env_file", &self.env_file),
            ("systemd_units_src", &self.systemd_units_src),
            ("systemd_units_dst", &self.systemd_units_dst),
            ("cli_bin_dir", &self.cli_bin_dir),
        ];
        for (label, path) in checked_paths {
            if !path_is_within_root(path, root) {
                return Err(ReleaseError::Config(format!(
                    "configured {} '{}' escapes isolated release root '{}'",
                    label,
                    path.display(),
                    root.display()
                )));
            }
        }
        if let Some(ref db_override) = self.af_db_path_override {
            if !path_is_within_root(db_override, root) {
                return Err(ReleaseError::Config(format!(
                    "configured AF_DB_PATH '{}' escapes isolated release root '{}'",
                    db_override.display(),
                    root.display()
                )));
            }
        }
        Ok(())
    }

    pub fn to_serialized_conf_string(&self) -> String {
        let mut lines = vec![
            "# Auto-generated validated AetherFlow release configuration".to_string(),
            format!(
                "RELEASES_DIR=\"{}\"",
                escape_conf_value(&self.releases_dir.to_string_lossy())
            ),
            format!(
                "CURRENT_LINK=\"{}\"",
                escape_conf_value(&self.current_link.to_string_lossy())
            ),
            format!(
                "REPO_DIR=\"{}\"",
                escape_conf_value(&self.repo_dir.to_string_lossy())
            ),
            format!(
                "LEGACY_OPT_ROOT=\"{}\"",
                escape_conf_value(&self.legacy_opt_root.to_string_lossy())
            ),
            format!(
                "DRY_RUN_ROOT=\"{}\"",
                escape_conf_value(&self.dry_run_root.to_string_lossy())
            ),
            format!("GITHUB_REPO=\"{}\"", escape_conf_value(&self.github_repo)),
            format!(
                "RELEASE_CHANNEL=\"{}\"",
                escape_conf_value(self.release_channel.as_str())
            ),
            format!(
                "ARTIFACT_NAME=\"{}\"",
                escape_conf_value(&self.artifact_name)
            ),
            format!(
                "CHECKSUM_NAME=\"{}\"",
                escape_conf_value(&self.checksum_name)
            ),
            format!("GIT_BRANCH=\"{}\"", escape_conf_value(&self.git_branch)),
            format!("GIT_REMOTE=\"{}\"", escape_conf_value(&self.git_remote)),
            format!(
                "HEALTH_ENDPOINT=\"{}\"",
                escape_conf_value(&self.health_endpoint)
            ),
            format!("HEALTH_RETRIES=\"{}\"", self.health_retries),
            format!("HEALTH_INTERVAL=\"{}\"", self.health_interval.as_secs()),
            format!("MAX_RELEASES=\"{}\"", self.max_releases),
            format!(
                "LOG_FILE=\"{}\"",
                escape_conf_value(&self.log_file.to_string_lossy())
            ),
            format!(
                "DATA_DIR=\"{}\"",
                escape_conf_value(&self.data_dir.to_string_lossy())
            ),
            format!(
                "ENV_DIR=\"{}\"",
                escape_conf_value(&self.env_dir.to_string_lossy())
            ),
            format!(
                "ENV_FILE=\"{}\"",
                escape_conf_value(&self.env_file.to_string_lossy())
            ),
            format!("SQLITE_DB=\"{}\"", escape_conf_value(&self.sqlite_db)),
            format!("SNAPSHOT_TIMEOUT=\"{}\"", self.snapshot_timeout.as_secs()),
            format!(
                "SYSTEMD_UNITS_SRC=\"{}\"",
                escape_conf_value(&self.systemd_units_src.to_string_lossy())
            ),
            format!(
                "SYSTEMD_UNITS_DST=\"{}\"",
                escape_conf_value(&self.systemd_units_dst.to_string_lossy())
            ),
            format!(
                "CLI_BIN_DIR=\"{}\"",
                escape_conf_value(&self.cli_bin_dir.to_string_lossy())
            ),
        ];
        if let Some(ref root_path) = self.isolated_root {
            lines.push(format!(
                "AETHERFLOW_RELEASE_ROOT=\"{}\"",
                escape_conf_value(&root_path.to_string_lossy())
            ));
        }
        if let Some(ref db_override) = self.af_db_path_override {
            lines.push(format!(
                "AF_DB_PATH=\"{}\"",
                escape_conf_value(&db_override.to_string_lossy())
            ));
        }
        lines.push(String::new());
        lines.join("\n")
    }

    pub fn write_protected_config_file(&self, path: &Path) -> ReleaseResult<()> {
        self.validate()?;
        validate_no_parent_traversal(path, "serialized release config file")?;
        let serialized = self.to_serialized_conf_string();
        crate::fs_security::atomic_write_bytes_with_mode(path, serialized.as_bytes(), 0o600)
    }

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
            out.cli_bin_dir = self.dry_run_root.join("usr/local/bin");
        }
        out
    }

    pub fn is_dry_run_config(&self) -> bool {
        self.data_dir == self.dry_run_root.join("data")
            && self.releases_dir == self.dry_run_root.join("releases")
    }

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
        validate_no_parent_traversal(&self.cli_bin_dir, "cli_bin_dir")?;
        if let Some(ref db_override) = self.af_db_path_override {
            validate_no_parent_traversal(db_override, "af_db_path_override")?;
        }
        if let Some(ref root_path) = self.isolated_root {
            validate_no_parent_traversal(root_path, "isolated_root")?;
        }

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

fn normalize_root_cmp(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    if raw.len() > 1 {
        raw.trim_end_matches('/').to_string()
    } else {
        raw
    }
}

pub fn path_is_within_root(path: &Path, root: &Path) -> bool {
    let Ok(norm_path) = af_models::normalize_lexical_path(path, "path") else {
        return false;
    };
    let Ok(norm_root) = af_models::normalize_lexical_path(root, "root") else {
        return false;
    };
    if norm_path.strip_prefix(&norm_root).is_ok() {
        return true;
    }
    let cmp_path = normalize_root_cmp(&norm_path);
    let cmp_root = normalize_root_cmp(&norm_root);
    if cmp_path == cmp_root {
        return true;
    }
    let prefix = format!("{}/", cmp_root.trim_end_matches('/'));
    cmp_path.starts_with(&prefix)
}

#[derive(Debug, Clone)]
pub struct ParsedConfEntry {
    pub value: String,
    pub is_default_fallback: bool,
}

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

/// Exact 31-key allowlist permitted inside `release-manager.conf` (`--config`), aligned 1:1 with
/// `deploy/release-manager.sh:398-405` (`PIPE-01`). Secret tokens (`AF_GITHUB_TOKEN`, `GITHUB_TOKEN`,
/// `GH_TOKEN`) and security bypass flags (`AETHERFLOW_SKIP_PROVENANCE_VERIFY`) are strictly excluded.
pub const ALLOWED_CONF_KEYS: [&str; 31] = [
    "RELEASES_DIR",
    "CURRENT_LINK",
    "REPO_DIR",
    "LEGACY_OPT_ROOT",
    "DRY_RUN_ROOT",
    "GITHUB_REPO",
    "RELEASE_CHANNEL",
    "ARTIFACT_NAME",
    "RELEASE_ASSET_NAME",
    "CHECKSUM_NAME",
    "GIT_BRANCH",
    "GIT_REMOTE",
    "NODE_HEAP_MB",
    "HEALTH_ENDPOINT",
    "HEALTH_RETRIES",
    "HEALTH_INTERVAL",
    "MAX_RELEASES",
    "LOG_FILE",
    "DATA_DIR",
    "ENV_DIR",
    "ENV_FILE",
    "SQLITE_DB",
    "SNAPSHOT_TIMEOUT",
    "SYSTEMD_UNITS_SRC",
    "SYSTEMD_UNITS_DST",
    "CLI_BIN_DIR",
    "TRANSCODE_SHIM_PATH",
    "AETHERFLOW_RELEASE_ROOT",
    "AF_DB_PATH",
    "DB_PATH",
    "AETHERFLOW_DB_PATH",
];

const MAX_CONF_FILE_BYTES: u64 = 64 * 1024;

#[cfg(unix)]
fn open_conf_file_via_openat(path: &Path, isolated_root: Option<&Path>) -> ReleaseResult<fs::File> {
    use std::ffi::{CString, OsStr, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::Component;

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| ReleaseError::io("resolving working directory for --config", err))?
            .join(path)
    };
    let leaf = abs_path
        .file_name()
        .ok_or_else(|| ReleaseError::PathValidation {
            path: path.to_path_buf(),
            reason: "configuration path has no filename".to_string(),
        })?;
    let parent = abs_path
        .parent()
        .ok_or_else(|| ReleaseError::PathValidation {
            path: path.to_path_buf(),
            reason: "configuration path has no parent directory".to_string(),
        })?;
    let is_root = unsafe { libc::geteuid() == 0 };

    // Anchor traversal at `isolated_root` when `path` lies inside it (matching release-manager.sh
    // so host OS symlinks above an isolated staging root such as /var/run -> /run do not cause
    // false rejections), otherwise anchor at `/`.
    let (anchor_path, rel_parent): (PathBuf, PathBuf) = match isolated_root {
        Some(root) if parent.starts_with(root) => (
            root.to_path_buf(),
            parent
                .strip_prefix(root)
                .unwrap_or(Path::new(""))
                .to_path_buf(),
        ),
        _ => (
            PathBuf::from("/"),
            parent.strip_prefix("/").unwrap_or(parent).to_path_buf(),
        ),
    };

    let anchor_c = CString::new(anchor_path.as_os_str().as_bytes()).map_err(|_| {
        ReleaseError::PathValidation {
            path: anchor_path.clone(),
            reason: "configuration anchor path contains NUL byte".to_string(),
        }
    })?;
    let anchor_fd = unsafe {
        libc::open(
            anchor_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if anchor_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(if err.raw_os_error() == Some(libc::ENOENT) {
            ReleaseError::Config(format!("configuration file not found: {}", path.display()))
        } else {
            ReleaseError::io(
                format!("opening configuration root {}", anchor_path.display()),
                err,
            )
        });
    }
    let mut cur_dir = unsafe { fs::File::from_raw_fd(anchor_fd) };
    let mut cur_path = anchor_path;

    let open_child_dir_nofollow =
        |dir: &fs::File, name: &OsStr, disp: &Path| -> ReleaseResult<fs::File> {
            let name_c =
                CString::new(name.as_bytes()).map_err(|_| ReleaseError::PathValidation {
                    path: disp.to_path_buf(),
                    reason: "configuration ancestor contains NUL byte".to_string(),
                })?;
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(match err.raw_os_error() {
                    Some(libc::ENOENT) => ReleaseError::Config(format!(
                        "configuration file not found: {}",
                        path.display()
                    )),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => ReleaseError::PathValidation {
                        path: disp.to_path_buf(),
                        reason: "refusing symlinked or non-directory configuration ancestor"
                            .to_string(),
                    },
                    _ => ReleaseError::io(
                        format!("opening configuration ancestor {}", disp.display()),
                        err,
                    ),
                });
            }
            Ok(unsafe { fs::File::from_raw_fd(fd) })
        };

    for comp in rel_parent.components() {
        match comp {
            Component::CurDir | Component::RootDir | Component::Prefix(_) => continue,
            Component::ParentDir => {
                return Err(ReleaseError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "refusing parent traversal in configuration path".to_string(),
                });
            }
            Component::Normal(part) => {
                let nxt = cur_path.join(part);
                let part_c =
                    CString::new(part.as_bytes()).map_err(|_| ReleaseError::PathValidation {
                        path: nxt.clone(),
                        reason: "configuration ancestor contains NUL byte".to_string(),
                    })?;
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe {
                    libc::fstatat(
                        cur_dir.as_raw_fd(),
                        part_c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    let err = std::io::Error::last_os_error();
                    return Err(if err.raw_os_error() == Some(libc::ENOENT) {
                        ReleaseError::Config(format!(
                            "configuration file not found: {}",
                            path.display()
                        ))
                    } else {
                        ReleaseError::io(
                            format!("inspecting configuration ancestor {}", nxt.display()),
                            err,
                        )
                    });
                }
                if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                    let is_managed_current = part == OsStr::new("current")
                        && cur_path.file_name() == Some(OsStr::new("AetherFlow"))
                        && cur_path.parent().and_then(Path::file_name) == Some(OsStr::new("opt"));
                    if !is_managed_current {
                        return Err(ReleaseError::PathValidation {
                            path: nxt,
                            reason: "refusing symlinked configuration ancestor directory"
                                .to_string(),
                        });
                    }
                    if is_root && st.st_uid != 0 {
                        return Err(ReleaseError::PathValidation {
                            path: nxt,
                            reason: "refusing non-root-owned current release symlink".to_string(),
                        });
                    }
                    let mut buf = vec![0u8; 4096];
                    let n = unsafe {
                        libc::readlinkat(
                            cur_dir.as_raw_fd(),
                            part_c.as_ptr(),
                            buf.as_mut_ptr() as *mut libc::c_char,
                            buf.len(),
                        )
                    };
                    if n <= 0 || (n as usize) >= buf.len() {
                        return Err(ReleaseError::io(
                            format!("reading current release symlink {}", nxt.display()),
                            std::io::Error::last_os_error(),
                        ));
                    }
                    buf.truncate(n as usize);
                    let raw_target = PathBuf::from(OsString::from_vec(buf));
                    if raw_target
                        .components()
                        .any(|c| matches!(c, Component::ParentDir))
                    {
                        return Err(ReleaseError::PathValidation {
                            path: nxt,
                            reason: "refusing parent traversal in current release symlink"
                                .to_string(),
                        });
                    }
                    let resolved_target = if raw_target.is_absolute() {
                        raw_target
                    } else {
                        cur_path.join(raw_target)
                    };
                    let expected_releases = cur_path.join("releases");
                    if resolved_target.parent() != Some(expected_releases.as_path()) {
                        return Err(ReleaseError::PathValidation {
                            path: nxt,
                            reason: "refusing current release symlink outside releases/"
                                .to_string(),
                        });
                    }
                    let epoch_name = resolved_target.file_name().ok_or_else(|| {
                        ReleaseError::PathValidation {
                            path: nxt.clone(),
                            reason: "invalid current release symlink target".to_string(),
                        }
                    })?;
                    let releases_dir = open_child_dir_nofollow(
                        &cur_dir,
                        OsStr::new("releases"),
                        &expected_releases,
                    )?;
                    let epoch_dir =
                        open_child_dir_nofollow(&releases_dir, epoch_name, &resolved_target)?;
                    if is_root {
                        for (dfd, disp) in [
                            (releases_dir.as_raw_fd(), &expected_releases),
                            (epoch_dir.as_raw_fd(), &resolved_target),
                        ] {
                            let mut hst: libc::stat = unsafe { std::mem::zeroed() };
                            if unsafe { libc::fstat(dfd, &mut hst) } != 0
                                || hst.st_uid != 0
                                || (hst.st_mode & 0o022) != 0
                            {
                                return Err(ReleaseError::PathValidation {
                                    path: disp.clone(),
                                    reason: "refusing untrusted release directory ownership/mode"
                                        .to_string(),
                                });
                            }
                        }
                    }
                    cur_dir = epoch_dir;
                    cur_path = resolved_target;
                    continue;
                }
                cur_dir = open_child_dir_nofollow(&cur_dir, part, &nxt)?;
                cur_path = nxt;
            }
        }
    }

    let leaf_c = CString::new(leaf.as_bytes()).map_err(|_| ReleaseError::PathValidation {
        path: path.to_path_buf(),
        reason: "configuration filename contains NUL byte".to_string(),
    })?;
    let leaf_fd = unsafe {
        libc::openat(
            cur_dir.as_raw_fd(),
            leaf_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if leaf_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ENOENT) => {
                ReleaseError::Config(format!("configuration file not found: {}", path.display()))
            }
            Some(libc::ELOOP) => ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing symlinked configuration file".to_string(),
            },
            _ => ReleaseError::io(format!("opening config file {}", path.display()), err),
        });
    }
    Ok(unsafe { fs::File::from_raw_fd(leaf_fd) })
}

fn read_conf_file_secure(path: &Path, isolated_root: Option<&Path>) -> ReleaseResult<String> {
    use std::io::Read;

    validate_no_parent_traversal(path, "configuration file")?;

    #[cfg(unix)]
    let file = {
        use std::os::unix::io::AsRawFd;

        let opened = open_conf_file_via_openat(path, isolated_root)?;

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(opened.as_raw_fd(), &mut st) } != 0 {
            return Err(ReleaseError::io(
                format!("fstat config file {}", path.display()),
                std::io::Error::last_os_error(),
            ));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "configuration path is not a regular file".to_string(),
            });
        }
        if (st.st_mode & 0o002) != 0 {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "refusing world-writable configuration file (mode {:04o})",
                    st.st_mode & 0o777
                ),
            });
        }
        if unsafe { libc::geteuid() } == 0 {
            if st.st_uid != 0 {
                return Err(ReleaseError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "refusing non-root-owned configuration file (uid={}) while running as root",
                        st.st_uid
                    ),
                });
            }
            if (st.st_mode & 0o022) != 0 {
                return Err(ReleaseError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "refusing group/world-writable configuration file (mode {:04o}) while running as root",
                        st.st_mode & 0o777
                    ),
                });
            }
        }
        if st.st_size < 0 || (st.st_size as u64) > MAX_CONF_FILE_BYTES {
            return Err(ReleaseError::Config(format!(
                "configuration file {} exceeds maximum size ({} bytes)",
                path.display(),
                MAX_CONF_FILE_BYTES
            )));
        }
        opened
    };

    #[cfg(not(unix))]
    let file = {
        let _ = isolated_root;
        let meta = fs::symlink_metadata(path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                ReleaseError::Config(format!("configuration file not found: {}", path.display()))
            } else {
                ReleaseError::io(format!("inspecting config file {}", path.display()), err)
            }
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "configuration path must be a regular non-symlink file".to_string(),
            });
        }
        fs::File::open(path).map_err(|err| {
            ReleaseError::io(format!("opening config file {}", path.display()), err)
        })?
    };

    let mut raw = Vec::new();
    file.take(MAX_CONF_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|err| ReleaseError::io(format!("reading config file {}", path.display()), err))?;
    if (raw.len() as u64) > MAX_CONF_FILE_BYTES {
        return Err(ReleaseError::Config(format!(
            "configuration file {} exceeds maximum size ({} bytes)",
            path.display(),
            MAX_CONF_FILE_BYTES
        )));
    }
    String::from_utf8(raw).map_err(|err| {
        ReleaseError::Config(format!(
            "configuration file {} is not valid UTF-8: {}",
            path.display(),
            err
        ))
    })
}

fn parse_conf_file_entries(
    path: &Path,
    isolated_root: Option<&Path>,
) -> ReleaseResult<HashMap<String, ParsedConfEntry>> {
    let content = read_conf_file_secure(path, isolated_root)?;
    try_parse_conf_entries(&content, path.parent())
}

pub fn try_parse_conf_entries(
    content: &str,
    script_dir: Option<&Path>,
) -> ReleaseResult<HashMap<String, ParsedConfEntry>> {
    let mut map = HashMap::new();
    let script_dir_str = script_dir
        .map(|dir_path| dir_path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/opt/AetherFlow/deploy".to_string());

    for (line_idx, raw_line) in content.lines().enumerate() {
        let line_no = line_idx + 1;
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains('\0') {
            return Err(ReleaseError::Config(format!(
                "invalid NUL byte in configuration at line {}",
                line_no
            )));
        }
        if let Some(rest) = line.strip_prefix("export") {
            if rest.starts_with(char::is_whitespace) {
                line = rest.trim_start();
            }
        }
        let Some((key_raw, val_raw)) = line.split_once('=') else {
            return Err(ReleaseError::Config(format!(
                "malformed configuration line {} (expected KEY=VALUE): {:?}",
                line_no, raw_line
            )));
        };
        let key = key_raw.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            || key
                .chars()
                .next()
                .map(|ch| ch.is_ascii_digit())
                .unwrap_or(true)
        {
            return Err(ReleaseError::Config(format!(
                "invalid configuration key {:?} at line {}",
                key, line_no
            )));
        }
        if !ALLOWED_CONF_KEYS.contains(&key) {
            return Err(ReleaseError::Config(format!(
                "disallowed configuration key {:?} at line {} (not in release-manager.conf allowlist)",
                key, line_no
            )));
        }

        let (mut val, is_default_fallback) =
            decode_quoted_or_raw_conf_value(val_raw, key, line_no)?;
        if is_default_fallback || val_raw.contains("${SCRIPT_DIR}") {
            val = val.replace("${SCRIPT_DIR}", &script_dir_str);
        }
        if !val.is_empty() {
            map.insert(
                key.to_string(),
                ParsedConfEntry {
                    value: val,
                    is_default_fallback,
                },
            );
        }
    }
    Ok(map)
}

pub fn parse_conf_file(path: &Path) -> ReleaseResult<HashMap<String, String>> {
    let entries = parse_conf_file_entries(path, None)?;
    Ok(entries
        .into_iter()
        .map(|(entry_key, entry_val)| (entry_key, entry_val.value))
        .collect())
}

pub fn parse_conf_str(content: &str, script_dir: Option<&Path>) -> HashMap<String, String> {
    if let Ok(parsed) = try_parse_conf_entries(content, script_dir) {
        return parsed
            .into_iter()
            .map(|(entry_key, entry_val)| (entry_key, entry_val.value))
            .collect();
    }
    let mut map = HashMap::new();
    let script_dir_str = script_dir
        .map(|dir_path| dir_path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/opt/AetherFlow/deploy".to_string());

    for (line_idx, raw_line) in content.lines().enumerate() {
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
        if key.is_empty() || !ALLOWED_CONF_KEYS.contains(&key) {
            continue;
        }
        if let Ok((mut val, is_default_fallback)) =
            decode_quoted_or_raw_conf_value(val_raw, key, line_idx + 1)
        {
            if is_default_fallback || val_raw.contains("${SCRIPT_DIR}") {
                val = val.replace("${SCRIPT_DIR}", &script_dir_str);
            }
            if !val.is_empty() {
                map.insert(key.to_string(), val);
            }
        }
    }
    map
}

fn load_env_file_if_enabled_with_trust(
    path: &Path,
    env_map: &HashMap<String, String>,
    isolated_root: Option<&Path>,
) -> (Option<af_models::secret_zeroize::SecretString>, bool) {
    use std::io::Read;

    if env_map.get("AETHERFLOW_SKIP_ENV_FILES").map(|v| v.trim()) == Some("1") {
        return (None, false);
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let Ok(file) = crate::fs_security::open_regular_file_nofollow_anchored(path, isolated_root)
        else {
            return (None, false);
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0
            || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        {
            return (None, false);
        }

        let parent_trusted = isolated_root.is_some()
            || path
                .parent()
                .is_some_and(|p| crate::fs_security::is_trusted_root_path_dir(p, false));
        let trusted = parent_trusted
            && st.st_nlink == 1
            && (st.st_mode & 0o022) == 0
            && (st.st_uid == 0
                || (isolated_root.is_some() && st.st_uid == unsafe { libc::geteuid() }));

        let mut raw = Vec::new();
        let read_res = file.take(MAX_CONF_FILE_BYTES + 1).read_to_end(&mut raw);
        if read_res.is_err() || (raw.len() as u64) > MAX_CONF_FILE_BYTES {
            let _wipe = af_models::secret_zeroize::SecretBytes::new(raw);
            return (None, false);
        }
        match String::from_utf8(raw) {
            Ok(content) => (
                Some(af_models::secret_zeroize::SecretString::new(content)),
                trusted,
            ),
            Err(err) => {
                let _wipe = af_models::secret_zeroize::SecretBytes::new(err.into_bytes());
                (None, false)
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = isolated_root;
        let Ok(meta) = fs::symlink_metadata(path) else {
            return (None, false);
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            return (None, false);
        }
        (
            fs::read_to_string(path)
                .ok()
                .map(af_models::secret_zeroize::SecretString::new),
            false,
        )
    }
}

#[cfg(test)]
pub(crate) fn is_trusted_root_env_file(path: &Path, isolated_root: Option<&Path>) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (meta.mode() & 0o022) != 0 {
            return false;
        }
        if isolated_root.is_none()
            && !path
                .parent()
                .is_some_and(|p| crate::fs_security::is_trusted_root_path_dir(p, false))
        {
            return false;
        }
        let uid = meta.uid();
        if uid == 0 {
            return true;
        }
        if isolated_root.is_some() {
            return uid == unsafe { libc::geteuid() };
        }
        false
    }
    #[cfg(not(unix))]
    {
        let _ = isolated_root;
        false
    }
}

fn read_env_file_secure(
    path: &Path,
    anchor_root: Option<&Path>,
) -> Option<af_models::secret_zeroize::SecretString> {
    use std::io::Read;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let file =
            crate::fs_security::open_regular_file_nofollow_anchored(path, anchor_root).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0
            || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        {
            return None;
        }
        let mut raw = Vec::new();
        let read_res = file.take(MAX_CONF_FILE_BYTES + 1).read_to_end(&mut raw);
        if read_res.is_err() || (raw.len() as u64) > MAX_CONF_FILE_BYTES {
            let _wipe = af_models::secret_zeroize::SecretBytes::new(raw);
            return None;
        }
        match String::from_utf8(raw) {
            Ok(content) => Some(af_models::secret_zeroize::SecretString::new(content)),
            Err(err) => {
                let _wipe = af_models::secret_zeroize::SecretBytes::new(err.into_bytes());
                None
            }
        }
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(path).ok()?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return None;
        }
        fs::read_to_string(path)
            .ok()
            .map(af_models::secret_zeroize::SecretString::new)
    }
}

pub fn read_env_file_value(path: &Path, key: &str) -> Option<String> {
    let content = read_env_file_secure(path, None)?;
    read_env_str_value(content.expose_secret(), key)
}

pub fn read_env_str_value(content: &str, key: &str) -> Option<String> {
    let mut found: Option<String> = None;
    let prefix = format!("{}=", key);

    for (line_idx, raw_line) in content.lines().enumerate() {
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
        let Some(val_raw) = body.strip_prefix(&prefix) else {
            continue;
        };
        if let Ok((decoded, _)) = decode_quoted_or_raw_conf_value(val_raw, key, line_idx + 1) {
            if !decoded.is_empty() {
                found = Some(decoded);
            }
        }
    }

    found
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbPathSource {
    AfDbPathEnv,
    EnvFile { path: PathBuf, key: String },
    SystemdUnit { unit: String, key: String },
    DataDirDefault,
}

impl fmt::Display for DbPathSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbPathSource::AfDbPathEnv => write!(formatter, "AF_DB_PATH"),
            DbPathSource::EnvFile { path, key } => {
                write!(formatter, "env-file:{}:{}", path.display(), key)
            }
            DbPathSource::SystemdUnit { unit, key } => {
                write!(formatter, "systemd:{}:{}", unit, key)
            }
            DbPathSource::DataDirDefault => write!(formatter, "DATA_DIR"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDbPath {
    pub path: PathBuf,
    pub source: DbPathSource,
}

pub fn try_resolve_db_path(
    config: &ReleaseConfig,
    systemd_env_blob: Option<&str>,
) -> ReleaseResult<ResolvedDbPath> {
    let ensure_within_isolated = |candidate: &Path, label: &str| -> ReleaseResult<PathBuf> {
        validate_no_parent_traversal(candidate, label)?;
        if let Some(ref root_path) = config.isolated_root {
            if !path_is_within_root(candidate, root_path) {
                return Err(ReleaseError::Config(format!(
                    "resolved database path '{}' ({}) escapes isolated release root '{}'",
                    candidate.display(),
                    label,
                    root_path.display()
                )));
            }
        }
        Ok(candidate.to_path_buf())
    };

    if let Some(ref explicit) = config.af_db_path_override {
        if !explicit.as_os_str().is_empty() {
            let validated = ensure_within_isolated(explicit, "AF_DB_PATH")?;
            return Ok(ResolvedDbPath {
                path: validated,
                source: DbPathSource::AfDbPathEnv,
            });
        }
    }

    let mut env_file_candidates: Vec<(&str, PathBuf)> = Vec::new();
    let skip_host_env = config.isolated_root.is_none()
        && normalize_root_cmp(&config.host_env_file) == "/etc/aetherflow/aetherflow.env"
        && std::env::var("AETHERFLOW_SKIP_ENV_FILES")
            .ok()
            .as_deref()
            .map(str::trim)
            == Some("1");
    if !skip_host_env {
        if let Some(content) =
            read_env_file_secure(&config.host_env_file, config.isolated_root.as_deref())
        {
            for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
                if let Some(val) = read_env_str_value(content.expose_secret(), key) {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() {
                        env_file_candidates.push((key, PathBuf::from(trimmed)));
                    }
                }
            }
        }
    }
    if let Some((first_key, first_path)) = env_file_candidates.first() {
        if config.isolated_root.is_some() {
            let first_norm = normalize_root_cmp(first_path);
            for (other_key, other_path) in env_file_candidates.iter().skip(1) {
                if normalize_root_cmp(other_path) != first_norm {
                    return Err(ReleaseError::Config(format!(
                        "conflicting database path entries in {}: {}='{}' vs {}='{}'",
                        config.host_env_file.display(),
                        first_key,
                        first_path.display(),
                        other_key,
                        other_path.display()
                    )));
                }
            }
        }
        let validated = ensure_within_isolated(first_path, first_key)?;
        return Ok(ResolvedDbPath {
            path: validated,
            source: DbPathSource::EnvFile {
                path: config.host_env_file.clone(),
                key: (*first_key).to_string(),
            },
        });
    }

    if config.isolated_root.is_none() {
        let custom_data_dir_active =
            normalize_root_cmp(&config.host_data_dir) != "/var/lib/aetherflow";
        if let Some(blob) = systemd_env_blob {
            for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
                if let Some(val) = read_systemd_environment_value(key, blob) {
                    let candidate = PathBuf::from(val.trim());
                    let is_legacy_unit_default = normalize_root_cmp(&candidate)
                        == "/var/lib/aetherflow/aetherflow.sqlite"
                        && key != "AF_DB_PATH";
                    if !(custom_data_dir_active && is_legacy_unit_default) {
                        let validated = ensure_within_isolated(&candidate, key)?;
                        return Ok(ResolvedDbPath {
                            path: validated,
                            source: DbPathSource::SystemdUnit {
                                unit: "aetherflow-api".to_string(),
                                key: key.to_string(),
                            },
                        });
                    }
                }
            }
        }
    }

    let fallback_db = config.host_data_dir.join(&config.sqlite_db);
    let validated_fallback = ensure_within_isolated(&fallback_db, "DATA_DIR")?;
    Ok(ResolvedDbPath {
        path: validated_fallback,
        source: DbPathSource::DataDirDefault,
    })
}

pub fn resolve_db_path(config: &ReleaseConfig, systemd_env_blob: Option<&str>) -> ResolvedDbPath {
    match try_resolve_db_path(config, systemd_env_blob) {
        Ok(resolved) => resolved,
        Err(_) => ResolvedDbPath {
            path: config.host_data_dir.join(&config.sqlite_db),
            source: DbPathSource::DataDirDefault,
        },
    }
}

#[cfg(test)]
mod pipe01_pipe15_config_tests {
    use super::*;

    #[test]
    fn pipe01_allowlist_has_exact_31_keys_and_forbids_provenance_bypass_and_secrets() {
        assert_eq!(ALLOWED_CONF_KEYS.len(), 31);

        // Every one of the 31 allowlisted keys must parse cleanly.
        let all_allowed = ALLOWED_CONF_KEYS
            .iter()
            .map(|k| format!("{k}=\"value\""))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = try_parse_conf_entries(&all_allowed, None).unwrap();
        assert_eq!(parsed.len(), 31);

        // Forbidden security/secret/arbitrary keys must be rejected by --config parser.
        for forbidden in [
            "AETHERFLOW_SKIP_PROVENANCE_VERIFY=1\n",
            "AF_GITHUB_TOKEN=placeholder\n",
            "GITHUB_TOKEN=placeholder\n",
            "GH_TOKEN=placeholder\n",
            "JWT_SECRET=placeholder\n",
            "ARBITRARY_INJECTED_KEY=1\n",
        ] {
            let err = try_parse_conf_entries(forbidden, None).unwrap_err();
            assert!(
                matches!(&err, ReleaseError::Config(msg) if msg.contains("disallowed configuration key")),
                "expected disallowed key rejection for {forbidden:?}, got: {err:?}"
            );
            // parse_conf_str fallback must also never admit forbidden keys.
            assert!(
                parse_conf_str(forbidden, None).is_empty(),
                "parse_conf_str must drop disallowed key {forbidden:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn pipe01_conf_loader_uses_o_nofollow_rejects_symlinks_fifos_and_world_writable_files() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root =
            std::env::temp_dir().join(format!("af-pipe01-conf-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let empty_env = HashMap::new();

        // 1. Symlinked --config file is rejected via O_NOFOLLOW.
        let real_conf = root.join("real.conf");
        fs::write(&real_conf, "RELEASE_CHANNEL=nightly\n").unwrap();
        fs::set_permissions(&real_conf, fs::Permissions::from_mode(0o644)).unwrap();
        let sym_conf = root.join("sym.conf");
        symlink(&real_conf, &sym_conf).unwrap();
        let sym_err =
            ReleaseConfig::load_for_root_with_env(Some(&root), Some(&sym_conf), &empty_env)
                .unwrap_err();
        assert!(matches!(sym_err, ReleaseError::PathValidation { .. }));

        // 2. FIFO passed as --config fails immediately without blocking (O_NONBLOCK + S_IFREG).
        let fifo_conf = root.join("fifo.conf");
        let fifo_c = CString::new(fifo_conf.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let fifo_err =
            ReleaseConfig::load_for_root_with_env(Some(&root), Some(&fifo_conf), &empty_env)
                .unwrap_err();
        assert!(matches!(fifo_err, ReleaseError::PathValidation { .. }));

        // 3. World-writable --config is rejected.
        let ww_conf = root.join("world-writable.conf");
        fs::write(&ww_conf, "RELEASE_CHANNEL=nightly\n").unwrap();
        fs::set_permissions(&ww_conf, fs::Permissions::from_mode(0o666)).unwrap();
        let ww_err = ReleaseConfig::load_for_root_with_env(Some(&root), Some(&ww_conf), &empty_env)
            .unwrap_err();
        assert!(matches!(ww_err, ReleaseError::PathValidation { .. }));

        // 4. --config attempting to set AETHERFLOW_SKIP_PROVENANCE_VERIFY or AF_GITHUB_TOKEN is rejected.
        let bad_prov_conf = root.join("bad-prov.conf");
        fs::write(&bad_prov_conf, "AETHERFLOW_SKIP_PROVENANCE_VERIFY=1\n").unwrap();
        fs::set_permissions(&bad_prov_conf, fs::Permissions::from_mode(0o600)).unwrap();
        let prov_err =
            ReleaseConfig::load_for_root_with_env(Some(&root), Some(&bad_prov_conf), &empty_env)
                .unwrap_err();
        assert!(matches!(prov_err, ReleaseError::Config(_)));

        // 5. Directory passed as --config is rejected as non-regular.
        let dir_conf = root.join("dir-conf");
        fs::create_dir(&dir_conf).unwrap();
        let dir_err =
            ReleaseConfig::load_for_root_with_env(Some(&root), Some(&dir_conf), &empty_env)
                .unwrap_err();
        assert!(matches!(dir_err, ReleaseError::PathValidation { .. }));

        // 6. Valid regular non-world-writable config loads cleanly and keeps skip_provenance_verify=false.
        let loaded =
            ReleaseConfig::load_for_root_with_env(Some(&root), Some(&real_conf), &empty_env)
                .unwrap();
        assert_eq!(loaded.release_channel, ReleaseChannel::Nightly);
        assert!(!loaded.skip_provenance_verify);
        assert_eq!(loaded.github_auth_token_str(), None);

        // 7. is_trusted_root_env_file rejects symlinks and group/world-writable files.
        assert!(!is_trusted_root_env_file(&sym_conf, Some(&root)));
        assert!(!is_trusted_root_env_file(&ww_conf, Some(&root)));
        assert!(is_trusted_root_env_file(&bad_prov_conf, Some(&root)));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pipe15_with_dry_run_unifies_cli_bin_dir_with_release_manager_sh() {
        let cfg = ReleaseConfig::default();
        let dry = cfg.with_dry_run(true);
        assert_eq!(dry.cli_bin_dir, cfg.dry_run_root.join("usr/local/bin"));
    }
}
