//! Resumable bare-metal provisioning foundation (`STATE_VERSION=2`) for AetherFlow (`af-cli`).
//!
//! # Scope & Architectural Boundaries
//! - Implements persisted resumable step states (`/install/.aetherflow.state` with `# STATE_VERSION=2`),
//!   atomic key-value configuration persistence (`/install/.aetherflow.conf`), PID lockfile acquisition
//!   (`/var/run/aetherflow-setup.lock`), preflight verification (`os-release`, privilege check, FHS layout),
//!   SHA-256 sidecar config overlays (`<target>.aetherflow-sha256` + `<target>.user-backup.<ts>`), and
//!   explicit `--repair` / `--resume` / `--fresh` / `--dry-run` step orchestration.
//! - Reuses verified Rust primitives (`af-release` FHS layout paths, `af-runner` systemd sandbox drop-in
//!   rendering, and `af-host` path/symlink/SHA-256 helpers).
//! - **Does NOT claim full replacement of `setup/AetherFlow-Setup`**: interactive prompts (`whiptail`),
//!   distro-specific `apt-get` repository bootstrap, kernel BBR/tuned sysctl scripts, and TLS certificate
//!   generation remain owned by the shell bootstrap (`setup/AetherFlow-Setup` & `setup/modules/*.sh`).
//! - **Never accepts or executes arbitrary privileged commands or raw shell step strings.**

use crate::error::{CliError, CliResult};
use af_host::{compute_file_sha256, reject_if_symlink, reject_symlink_chain, validate_no_parent_traversal};
use af_runner::render_systemd_sandbox_dropin;
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// State file format version matching `setup/modules/06-state.sh` (`# STATE_VERSION=2`).
pub const PROVISION_STATE_VERSION: u32 = 2;

/// Header comment written at line 1 of `/install/.aetherflow.state`.
pub const STATE_VERSION_HEADER: &str = "# STATE_VERSION=2";

/// Validates that `path` has no parent traversal (`..`) and that no existing ancestor or leaf
/// component is a symbolic link.
pub fn ensure_no_symlink_ancestors(path: &Path, context: &str) -> CliResult<()> {
    validate_no_parent_traversal(path, context)?;
    reject_if_symlink(path, context)?;
    Ok(())
}

/// Ensures `dir` and all of its ancestors under `fs_root` contain no symlinks, creates `dir`
/// if missing, re-verifies no symlink was introduced, and applies `unix_mode` on Unix.
fn ensure_dir_no_symlinks(
    fs_root: &Path,
    dir: &Path,
    unix_mode: u32,
    context: &str,
) -> CliResult<()> {
    ensure_no_symlink_ancestors(dir, context)?;
    reject_symlink_chain(fs_root, dir)?;
    fs::create_dir_all(dir)
        .map_err(|e| CliError::io(format!("creating {} ({})", dir.display(), context), e))?;
    reject_symlink_chain(fs_root, dir)?;
    reject_if_symlink(dir, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(unix_mode))
            .map_err(|error| CliError::io(format!("setting permissions on {}", dir.display()), error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = unix_mode;
    }
    Ok(())
}

/// Opens a new file exclusively (`O_CREAT | O_EXCL` via `create_new(true)`) with `unix_mode`
/// applied at inode creation time on Unix so private state/secret files (`0o600`) are never
/// world- or group-readable even momentarily before `chmod`.
fn open_exclusive_private_file(path: &Path, unix_mode: u32, context: &str) -> CliResult<File> {
    ensure_no_symlink_ancestors(path, context)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(unix_mode);
    }
    let file = opts.open(path).map_err(|e| {
        CliError::io(
            format!("creating exclusive file {} ({})", path.display(), context),
            e,
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(unix_mode))
            .map_err(|error| CliError::io(format!("setting permissions on {}", path.display()), error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = unix_mode;
    }
    Ok(file)
}

/// Atomically writes `contents` to `target_path` by creating a uniquely named sibling temporary
/// file with `create_new(true)` and `unix_mode`, flushing via `sync_all()`, and renaming into place.
fn write_file_atomic_exclusive(
    target_path: &Path,
    contents: &[u8],
    unix_mode: u32,
    context: &str,
) -> CliResult<()> {
    ensure_no_symlink_ancestors(target_path, context)?;
    let parent = target_path.parent().ok_or_else(|| {
        CliError::Validation(format!(
            "{} path '{}' has no parent directory",
            context,
            target_path.display()
        ))
    })?;
    if !parent.as_os_str().is_empty() {
        ensure_no_symlink_ancestors(parent, context)?;
        fs::create_dir_all(parent).map_err(|e| {
            CliError::io(
                format!("creating parent dir {} ({})", parent.display(), context),
                e,
            )
        })?;
        ensure_no_symlink_ancestors(parent, context)?;
    }

    let file_name = target_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "artifact".to_string());
    let tmp_name = format!(
        ".af-tmp-{}-{}-{}",
        file_name,
        std::process::id(),
        Uuid::new_v4()
    );
    let tmp_path = parent.join(tmp_name);

    let write_res = (|| -> CliResult<()> {
        let mut f = open_exclusive_private_file(&tmp_path, unix_mode, context)?;
        f.write_all(contents).map_err(|e| {
            CliError::io(
                format!("writing temporary file {} ({})", tmp_path.display(), context),
                e,
            )
        })?;
        f.sync_all().map_err(|e| {
            CliError::io(
                format!("syncing temporary file {} ({})", tmp_path.display(), context),
                e,
            )
        })?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = ensure_no_symlink_ancestors(target_path, context) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    fs::rename(&tmp_path, target_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        CliError::io(
            format!(
                "renaming {} -> {} ({})",
                tmp_path.display(),
                target_path.display(),
                context
            ),
            e,
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(target_path, fs::Permissions::from_mode(unix_mode));
    }

    Ok(())
}

/// Canonical ordered 39 setup step IDs from `setup/modules/06-state.sh` (`ALL_STEPS`).
pub const CANONICAL_ALL_STEPS: &[&str] = &[
    "bashrc",
    "intro",
    "checkroot",
    "logcheck",
    "checkkernel",
    "hostname",
    "locale",
    "ssdpblock",
    "askcontinue",
    "askpartition",
    "ask10g",
    "askdashtheme",
    "adduser",
    "askffmpeg",
    "askvsftpd",
    "denyhosts",
    "askbbr",
    "repos",
    "updates",
    "depends",
    "syscommands",
    "skel",
    "lshell",
    "ffmpeg",
    "apachesudo",
    "install_go",
    "install_node",
    "build_modern",
    "apacheconf",
    "fix_cert",
    "makedirs",
    "installftpd",
    "ftpdconfig",
    "boot",
    "firewall",
    "harden_perms",
    "perms",
    "bbr",
    "bcm",
];

static SAFE_STEP_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z][a-z0-9_]{1,31}$").unwrap());
static SAFE_CONF_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$").unwrap());

/// Execution ownership tier for each canonical provisioning step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionStepTier {
    /// Bounded, idempotent Rust-native step executable directly by `af provision run/repair`.
    RustNativeFoundation,
    /// Retained in `setup/AetherFlow-Setup` (`setup/modules/*.sh`); tracked in `.aetherflow.state`
    /// and inspectable/resettable for `--repair`, but never executed as raw shell by `af-cli`.
    RetainedShellBootstrap,
}

/// Metadata describing one of the 39 canonical provisioning steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionStepDescriptor {
    pub index: usize,
    pub step_id: &'static str,
    pub tier: ProvisionStepTier,
    pub summary: &'static str,
}

/// Returns the descriptor table for all 39 canonical `ALL_STEPS`.
pub fn canonical_step_catalog() -> Vec<ProvisionStepDescriptor> {
    CANONICAL_ALL_STEPS
        .iter()
        .enumerate()
        .map(|(idx, &step_id)| {
            let (tier, summary) = match step_id {
                "checkroot" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Verify root/operator execution context and lockfile readiness",
                ),
                "logcheck" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Initialize /install directory and structured install log file",
                ),
                "checkkernel" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Verify Linux OS release compatibility (Ubuntu 20.04+, Debian 11+, Kali)",
                ),
                "makedirs" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Create canonical bare-metal FHS directories (/opt/aetherflow, /etc/aetherflow, /var/lib/aetherflow, /var/log/aetherflow)",
                ),
                "harden_perms" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Enforce 0750/0600 permissions on /install, /etc/aetherflow, /var/lib/aetherflow, and state/secret files",
                ),
                "boot" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Verify and stage systemd service drop-in & unit directory layout (/etc/systemd/system)",
                ),
                _ => (
                    ProvisionStepTier::RetainedShellBootstrap,
                    "Retained interactive/distro shell bootstrap step in setup/AetherFlow-Setup",
                ),
            };
            ProvisionStepDescriptor {
                index: idx + 1,
                step_id,
                tier,
                summary,
            }
        })
        .collect()
}

/// Returns `true` if `step_id` is in the 39 canonical `ALL_STEPS`.
pub fn is_canonical_step(step_id: &str) -> bool {
    CANONICAL_ALL_STEPS.contains(&step_id)
}

/// Validates a step identifier against injection and verifies membership in `CANONICAL_ALL_STEPS`.
pub fn validate_step_id(step_id: &str) -> CliResult<String> {
    let trimmed = step_id.trim();
    if !SAFE_STEP_ID_RE.is_match(trimmed) {
        return Err(CliError::Validation(format!(
            "invalid provisioning step identifier {:?} (arbitrary commands or shell expressions are forbidden)",
            step_id
        )));
    }
    if !is_canonical_step(trimmed) {
        return Err(CliError::Validation(format!(
            "unknown provisioning step {:?} (run 'af provision list-steps' for the 39 canonical step IDs)",
            trimmed
        )));
    }
    Ok(trimmed.to_string())
}

/// Filesystem layout for provisioning state, config, lockfile, and FHS directories,
/// parameterized by `fs_root` so all unit tests run in isolated temp directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionPaths {
    pub fs_root: PathBuf,
    pub install_dir: PathBuf,
    pub state_file: PathBuf,
    pub config_file: PathBuf,
    pub install_log: PathBuf,
    pub lock_file: PathBuf,
    pub os_release_file: PathBuf,
    pub opt_aetherflow: PathBuf,
    pub opt_releases: PathBuf,
    pub etc_aetherflow: PathBuf,
    pub etc_legacy_aetherflow: PathBuf,
    pub var_lib_aetherflow: PathBuf,
    pub var_lib_backups: PathBuf,
    pub var_log_aetherflow: PathBuf,
    pub etc_systemd_system: PathBuf,
}

impl ProvisionPaths {
    /// Resolves canonical provisioning paths rooted at `fs_root` (`/` on production hosts).
    pub fn for_root(fs_root: impl Into<PathBuf>) -> CliResult<Self> {
        let root = fs_root.into();
        ensure_no_symlink_ancestors(&root, "provision fs_root")?;

        Ok(Self {
            install_dir: root.join("install"),
            state_file: root.join("install/.aetherflow.state"),
            config_file: root.join("install/.aetherflow.conf"),
            install_log: root.join("install/.aetherflow.install.log"),
            lock_file: root.join("run/aetherflow-setup.lock"),
            os_release_file: root.join("etc/os-release"),
            opt_aetherflow: root.join("opt/AetherFlow"),
            opt_releases: root.join("opt/AetherFlow/releases"),
            etc_aetherflow: root.join("etc/aetherflow"),
            etc_legacy_aetherflow: root.join("etc/AetherFlow"),
            var_lib_aetherflow: root.join("var/lib/aetherflow"),
            var_lib_backups: root.join("var/lib/aetherflow/backups"),
            var_log_aetherflow: root.join("var/log/aetherflow"),
            etc_systemd_system: root.join("etc/systemd/system"),
            fs_root: root,
        })
    }
}

/// Persisted state store compatible with `setup/modules/06-state.sh` (`/install/.aetherflow.state`
/// `# STATE_VERSION=2` and `/install/.aetherflow.conf`).
#[derive(Debug, Clone)]
pub struct ProvisionStateStore {
    paths: ProvisionPaths,
}

/// Snapshot of current provisioning state on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionStatusReport {
    pub state_file: PathBuf,
    pub config_file: PathBuf,
    pub state_exists: bool,
    pub state_version: Option<u32>,
    pub version_compatible: bool,
    pub completed_steps: Vec<String>,
    pub pending_steps: Vec<String>,
    pub completed_count: usize,
    pub total_canonical_steps: usize,
    pub saved_config: BTreeMap<String, String>,
    pub lock_file_present: bool,
}

impl ProvisionStateStore {
    pub fn new(paths: ProvisionPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &ProvisionPaths {
        &self.paths
    }

    /// Initializes `/install/.aetherflow.state` (with `# STATE_VERSION=2`), `/install/.aetherflow.conf`,
    /// and `/install/.aetherflow.install.log` if they do not exist.
    /// If `fresh` is `true` or an older incompatible `# STATE_VERSION=` header is detected, resets
    /// the state file to `# STATE_VERSION=2`.
    pub fn ensure_initialized(&self, fresh: bool) -> CliResult<()> {
        ensure_dir_no_symlinks(
            &self.paths.fs_root,
            &self.paths.install_dir,
            0o750,
            "provision install dir",
        )?;

        ensure_no_symlink_ancestors(&self.paths.state_file, "provision state file")?;
        ensure_no_symlink_ancestors(&self.paths.config_file, "provision config file")?;
        ensure_no_symlink_ancestors(&self.paths.install_log, "provision install log")?;

        let needs_reset = if fresh || !self.paths.state_file.exists() {
            true
        } else {
            let raw = fs::read_to_string(&self.paths.state_file).map_err(|e| {
                CliError::io(
                    format!("reading state file {}", self.paths.state_file.display()),
                    e,
                )
            })?;
            let first_line = raw.lines().next().unwrap_or("").trim();
            first_line != STATE_VERSION_HEADER
        };

        if needs_reset {
            self.write_completed_steps_atomic(&[])?;
        }

        if fresh || !self.paths.config_file.exists() {
            self.write_config_map_atomic(&BTreeMap::new())?;
        }

        if !self.paths.install_log.exists() {
            let init_line = format!(
                "# AetherFlow Provisioning Log initialized at {}\n",
                Utc::now().to_rfc3339()
            );
            write_file_atomic_exclusive(
                &self.paths.install_log,
                init_line.as_bytes(),
                0o600,
                "provision install log",
            )?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.paths.state_file, fs::Permissions::from_mode(0o600));
            let _ = fs::set_permissions(&self.paths.config_file, fs::Permissions::from_mode(0o600));
            let _ = fs::set_permissions(&self.paths.install_log, fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Reads the state file and returns `(Option<state_version>, completed_steps)`.
    pub fn read_state(&self) -> CliResult<(Option<u32>, Vec<String>)> {
        ensure_no_symlink_ancestors(&self.paths.state_file, "provision state file")?;
        if !self.paths.state_file.exists() {
            return Ok((None, Vec::new()));
        }
        let raw = fs::read_to_string(&self.paths.state_file).map_err(|e| {
            CliError::io(
                format!("reading state file {}", self.paths.state_file.display()),
                e,
            )
        })?;

        let mut version: Option<u32> = None;
        let mut completed = Vec::new();
        let mut seen = HashSet::new();

        for (idx, raw_line) in raw.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if idx == 0 && line.starts_with("# STATE_VERSION=") {
                let ver_str = line.trim_start_matches("# STATE_VERSION=").trim();
                version = ver_str.parse::<u32>().ok();
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            if SAFE_STEP_ID_RE.is_match(line) && seen.insert(line.to_string()) {
                completed.push(line.to_string());
            }
        }

        Ok((version, completed))
    }

    /// Returns `true` if `step_id` is recorded as completed in `/install/.aetherflow.state`
    /// with a valid `# STATE_VERSION=2` header.
    pub fn is_step_done(&self, step_id: &str) -> CliResult<bool> {
        let _ = validate_step_id(step_id)?;
        let (ver, steps) = self.read_state()?;
        if ver != Some(PROVISION_STATE_VERSION) {
            return Ok(false);
        }
        Ok(steps.iter().any(|s| s == step_id))
    }

    /// Marks `step_id` as completed in `/install/.aetherflow.state` idempotently and atomically.
    pub fn mark_step_done(&self, step_id: &str) -> CliResult<()> {
        let clean = validate_step_id(step_id)?;
        self.ensure_initialized(false)?;
        let (_, mut steps) = self.read_state()?;
        if !steps.iter().any(|s| s == &clean) {
            steps.push(clean.clone());
            self.write_completed_steps_atomic(&steps)?;
        }
        self.append_log(&format!("[STATE] Step '{}' marked DONE", clean))?;
        Ok(())
    }

    /// Clears completion markers for the specified `repair_steps` so they will be re-executed,
    /// matching `_clear_step_done` in `setup/modules/06-state.sh`.
    pub fn clear_steps_for_repair(&self, repair_steps: &[String]) -> CliResult<Vec<String>> {
        let mut validated = Vec::new();
        for s in repair_steps {
            validated.push(validate_step_id(s)?);
        }
        ensure_no_symlink_ancestors(&self.paths.state_file, "provision state file")?;
        if !self.paths.state_file.exists() {
            return Ok(Vec::new());
        }
        let (ver, current_steps) = self.read_state()?;
        if ver != Some(PROVISION_STATE_VERSION) {
            self.write_completed_steps_atomic(&[])?;
            self.append_log("[REPAIR] Reset incompatible state version to empty v2 state")?;
            return Ok(Vec::new());
        }
        let clear_set: HashSet<&str> = validated.iter().map(|s| s.as_str()).collect();
        let mut removed = Vec::new();
        let mut remaining = Vec::new();
        for step in current_steps {
            if clear_set.contains(step.as_str()) {
                removed.push(step);
            } else {
                remaining.push(step);
            }
        }
        self.write_completed_steps_atomic(&remaining)?;
        for s in &removed {
            self.append_log(&format!("[REPAIR] Cleared completion state for step '{}'", s))?;
        }
        Ok(removed)

    /// Atomically writes `# STATE_VERSION=2` followed by `steps` to `/install/.aetherflow.state`
    /// using an exclusive `0o600` sibling temporary file.
    fn write_completed_steps_atomic(&self, steps: &[String]) -> CliResult<()> {
        ensure_dir_no_symlinks(
            &self.paths.fs_root,
            &self.paths.install_dir,
            0o750,
            "provision install dir",
        )?;

        let mut body = String::from(STATE_VERSION_HEADER);
        body.push('\n');
        for step in steps {
            body.push_str(step);
            body.push('\n');
        }

        write_file_atomic_exclusive(
            &self.paths.state_file,
            body.as_bytes(),
            0o600,
            "provision state file",
        )
    }

    /// Reads `/install/.aetherflow.conf` key-value pairs.
    pub fn read_config_map(&self) -> CliResult<BTreeMap<String, String>> {
        ensure_no_symlink_ancestors(&self.paths.config_file, "provision config file")?;
        if !self.paths.config_file.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read_to_string(&self.paths.config_file).map_err(|e| {
            CliError::io(
                format!("reading config file {}", self.paths.config_file.display()),
                e,
            )
        })?;

        let mut map = BTreeMap::new();
        for raw_line in raw.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                if SAFE_CONF_KEY_RE.is_match(key) {
                    map.insert(key.to_string(), v.trim().to_string());
                }
            }
        }
        Ok(map)
    }

    /// Atomically saves a configuration `key=value` entry in `/install/.aetherflow.conf`,
    /// matching `_save_config` in `setup/modules/06-state.sh`.
    pub fn save_config_value(&self, key: &str, value: &str) -> CliResult<()> {
        let clean_key = key.trim();
        if !SAFE_CONF_KEY_RE.is_match(clean_key) {
            return Err(CliError::Validation(format!(
                "invalid config key {:?} in .aetherflow.conf",
                key
            )));
        }
        if value.contains('\n') || value.contains('\r') || value.contains('\0') {
            return Err(CliError::Validation(
                "config value must not contain newlines or NUL bytes".to_string(),
            ));
        }
        self.ensure_initialized(false)?;
        let mut map = self.read_config_map()?;
        map.insert(clean_key.to_string(), value.to_string());
        self.write_config_map_atomic(&map)
    }

    fn write_config_map_atomic(&self, map: &BTreeMap<String, String>) -> CliResult<()> {
        ensure_dir_no_symlinks(
            &self.paths.fs_root,
            &self.paths.install_dir,
            0o750,
            "provision install dir",
        )?;

        let mut out = String::new();
        for (k, v) in map {
            out.push_str(k);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }

        write_file_atomic_exclusive(
            &self.paths.config_file,
            out.as_bytes(),
            0o600,
            "provision config file",
        )
    }

    /// Appends a timestamped entry to `/install/.aetherflow.install.log` with `0o600` private mode.
    pub fn append_log(&self, message: &str) -> CliResult<()> {
        ensure_dir_no_symlinks(
            &self.paths.fs_root,
            &self.paths.install_dir,
            0o750,
            "provision install dir",
        )?;
        ensure_no_symlink_ancestors(&self.paths.install_log, "provision install log")?;

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.paths.install_log).map_err(|e| {
            CliError::io(
                format!("opening install log {}", self.paths.install_log.display()),
                e,
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        writeln!(f, "[{}] {}", Utc::now().to_rfc3339(), message).map_err(|e| {
            CliError::io(
                format!("writing install log {}", self.paths.install_log.display()),
                e,
            )
        })?;
        Ok(())
    }

    /// Removes `/install/.aetherflow.state` and `/install/.aetherflow.conf`.
    pub fn reset_state(&self) -> CliResult<()> {
        ensure_no_symlink_ancestors(&self.paths.state_file, "provision state file")?;
        if self.paths.state_file.exists() {
            fs::remove_file(&self.paths.state_file).map_err(|e| {
                CliError::io(
                    format!("removing state file {}", self.paths.state_file.display()),
                    e,
                )
            })?;
        }
        ensure_no_symlink_ancestors(&self.paths.config_file, "provision config file")?;
        if self.paths.config_file.exists() {
            fs::remove_file(&self.paths.config_file).map_err(|e| {
                CliError::io(
                    format!("removing config file {}", self.paths.config_file.display()),
                    e,
                )
            })?;
        }
        Ok(())
    }

    /// Builds a structured [`ProvisionStatusReport`] of current completion and configuration state.
    pub fn inspect_status(&self) -> CliResult<ProvisionStatusReport> {
        ensure_no_symlink_ancestors(&self.paths.state_file, "provision state file")?;
        ensure_no_symlink_ancestors(&self.paths.config_file, "provision config file")?;
        let state_exists = self.paths.state_file.exists();
        let (state_version, raw_completed_steps) = self.read_state()?;
        let version_compatible = state_version == Some(PROVISION_STATE_VERSION);
        let completed_steps = if version_compatible {
            raw_completed_steps
        } else {
            Vec::new()
        };
        let done_set: HashSet<&str> = completed_steps.iter().map(|s| s.as_str()).collect();
        let pending_steps: Vec<String> = CANONICAL_ALL_STEPS
            .iter()
            .filter(|&&s| !done_set.contains(s))
            .map(|&s| s.to_string())
            .collect();
        let saved_config = self.read_config_map()?;

        Ok(ProvisionStatusReport {
            state_file: self.paths.state_file.clone(),
            config_file: self.paths.config_file.clone(),
            state_exists,
            state_version,
            version_compatible,
            completed_count: completed_steps.len(),
            total_canonical_steps: CANONICAL_ALL_STEPS.len(),
            completed_steps,
            pending_steps,
            saved_config,
            lock_file_present: self.paths.lock_file.exists(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PID Lockfile Guard (`/run/aetherflow-setup.lock`)
// ─────────────────────────────────────────────────────────────────────────────

/// RAII crash-safe PID lockfile guard compatible with `_acquire_lock` / `_release_lock`
/// in `setup/modules/06-state.sh`.
#[derive(Debug)]
pub struct ProvisionLockGuard {
    lock_path: PathBuf,
    owner_pid: u32,
    _serialization_guard: af_release::ReleaseLockGuard,
}

impl ProvisionLockGuard {
    /// Atomically acquires `lock_path` using an exclusive temporary lockfile + hard-link/create_new
    /// publish and stale-PID crash recovery.
    pub fn acquire(lock_path: impl Into<PathBuf>) -> CliResult<Self> {
        let lock_path = lock_path.into();
        ensure_no_symlink_ancestors(&lock_path, "provision lockfile")?;

        let parent = lock_path.parent().ok_or_else(|| {
            CliError::Validation(format!(
                "lockfile path '{}' has no parent directory",
                lock_path.display()
            ))
        })?;
        if !parent.as_os_str().is_empty() {
            ensure_no_symlink_ancestors(parent, "provision lockfile parent")?;
            fs::create_dir_all(parent).map_err(|e| {
                CliError::io(format!("creating lockfile dir {}", parent.display()), e)
            })?;
            ensure_no_symlink_ancestors(parent, "provision lockfile parent")?;
        }

        let guard_path = parent.join(format!(
            ".{}.rust-guard",
            lock_path.file_name().unwrap_or_default().to_string_lossy()
        ));
        ensure_no_symlink_ancestors(&guard_path, "provision serialization guard")?;
        let serialization_guard = af_release::ReleaseLockGuard::acquire(
            &guard_path, std::time::Duration::ZERO,
        ).map_err(|error| CliError::PreflightOrIntegrity(format!(
            "another provisioning operation holds {}: {}", guard_path.display(), error
        )))?;

        let my_pid = std::process::id();
        let pid_payload = format!("{}\n", my_pid);
        let tmp_lock = parent.join(format!(
            ".af-lock-tmp-{}-{}",
            my_pid,
            Uuid::new_v4()
        ));

        let mut tmp_file = open_exclusive_private_file(&tmp_lock, 0o600, "temporary lockfile")?;
        if let Err(e) = tmp_file
            .write_all(pid_payload.as_bytes())
            .and_then(|()| tmp_file.sync_all())
        {
            let _ = fs::remove_file(&tmp_lock);
            return Err(CliError::io(
                format!("writing temporary lockfile {}", tmp_lock.display()),
                e,
            ));
        }
        drop(tmp_file);

        for _attempt in 0..3 {
            ensure_no_symlink_ancestors(&lock_path, "provision lockfile")?;
            let link_res = fs::hard_link(&tmp_lock, &lock_path).or_else(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    Err(err)
                } else {
                    // Fallback for filesystems that disallow hard links: exclusive `create_new(true)`
                    let mut options = OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
                    }
                    let mut f = options.open(&lock_path)?;
                    f.write_all(pid_payload.as_bytes())?;
                    f.sync_all()
                }
            });

            match link_res {
                Ok(()) => {
                    let _ = fs::remove_file(&tmp_lock);
                    return Ok(Self {
                        lock_path,
                        owner_pid: my_pid,
                        _serialization_guard: serialization_guard,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Err(sym_err) = ensure_no_symlink_ancestors(&lock_path, "provision lockfile") {
                        let _ = fs::remove_file(&tmp_lock);
                        return Err(sym_err);
                    }
                    let raw_pid = fs::read_to_string(&lock_path).unwrap_or_default();
                    if let Ok(existing_pid) = raw_pid.trim().parse::<u32>() {
                        if is_pid_alive(existing_pid) {
                            let _ = fs::remove_file(&tmp_lock);
                            return Err(CliError::PreflightOrIntegrity(format!(
                                "another AetherFlow setup/provision process is running (PID {} in {})",
                                existing_pid,
                                lock_path.display()
                            )));
                        }
                    }
                    // Stale lockfile from crashed/non-running PID or corrupt PID file: remove and retry
                    let _ = fs::remove_file(&lock_path);
                }
                Err(err) => {
                    let _ = fs::remove_file(&tmp_lock);
                    return Err(CliError::io(
                        format!("acquiring lockfile {}", lock_path.display()),
                        err,
                    ));
                }
            }
        }

        let _ = fs::remove_file(&tmp_lock);
        Err(CliError::PreflightOrIntegrity(format!(
            "failed to acquire provisioning lockfile {} due to concurrent contention",
            lock_path.display()
        )))
    }
}

impl Drop for ProvisionLockGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.lock_path) {
            if !meta.file_type().is_symlink() {
                if let Ok(raw) = fs::read_to_string(&self.lock_path) {
                    if raw.trim().parse::<u32>().ok() == Some(self.owner_pid) {
                        let _ = fs::remove_file(&self.lock_path);
                    }
                }
            }
        }
    }
}

fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if pid == 0 {
            return false;
        }
        if pid == std::process::id() {
            return true;
        }
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(stat_raw) = fs::read_to_string(&stat_path) {
            // In `/proc/<pid>/stat`, state character follows the last `)` of `comm`
            if let Some(rparen) = stat_raw.rfind(')') {
                let after = stat_raw[rparen + 1..].trim_start();
                if after.starts_with('Z') || after.starts_with('X') {
                    return false;
                }
                return true;
            }
        }
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        pid == std::process::id()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Safe Configuration Overlay (`_safe_overlay_config` parity)
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome classification when overlaying a managed configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOverlayOutcome {
    /// Target did not exist and was newly installed with its `.aetherflow-sha256` sidecar.
    InstalledNew,
    /// Target already matched the incoming source SHA-256; no disk writes were needed.
    UnchangedIdentical,
    /// Target matched the previous `.aetherflow-sha256` sidecar (unmodified by user) and was cleanly updated.
    UpdatedUnmodifiedStock,
    /// Target was modified by the operator, so `<target>.user-backup.<ts>` was saved before applying the new config.
    BackedUpUserModifiedAndUpdated,
}

/// Receipt returned by [`safe_overlay_config_file`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigOverlayReceipt {
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    pub sidecar_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub sha256: String,
    pub outcome: ConfigOverlayOutcome,
    pub dry_run: bool,
}

/// Safely overlays `source_path` onto `target_path`, matching `_safe_overlay_config` in `setup/modules/06-state.sh`:
/// 1. Rejects symlinks on `source_path`, `target_path`, `<target_path>.aetherflow-sha256`, and all ancestor directories.
/// 2. Computes SHA-256 of `source_path`.
/// 3. If `target_path` exists:
///    - If `target_sha == source_sha`, returns `UnchangedIdentical` (ensuring `.aetherflow-sha256` exists).
///    - If `force == false` and `target_sha != previous_sidecar_sha`, preserves the operator's customized file
///      at `<target_path>.user-backup.<timestamp>` before writing the new config.
/// 4. Atomically writes `target_path` using an exclusive unique sibling temporary file and records `source_sha`
///    in `<target_path>.aetherflow-sha256`.
pub fn safe_overlay_config_file(
    source_path: &Path,
    target_path: &Path,
    force: bool,
    dry_run: bool,
) -> CliResult<ConfigOverlayReceipt> {
    ensure_no_symlink_ancestors(source_path, "overlay source_path")?;
    ensure_no_symlink_ancestors(target_path, "overlay target_path")?;

    if !source_path.is_file() {
        return Err(CliError::Validation(format!(
            "overlay source file does not exist: {}",
            source_path.display()
        )));
    }

    let mut sidecar_os = target_path.as_os_str().to_os_string();
    sidecar_os.push(".aetherflow-sha256");
    let sidecar_path = PathBuf::from(sidecar_os);
    ensure_no_symlink_ancestors(&sidecar_path, "overlay sha256 sidecar")?;

    let (new_sha, _) = compute_file_sha256(source_path)?;
    let mut backup_path: Option<PathBuf> = None;

    let outcome = if !target_path.exists() {
        ConfigOverlayOutcome::InstalledNew
    } else {
        let (current_sha, _) = compute_file_sha256(target_path)?;
        if current_sha.eq_ignore_ascii_case(&new_sha) {
            if !dry_run && !sidecar_path.exists() {
                let sidecar_body = format!("{}\n", new_sha);
                write_file_atomic_exclusive(
                    &sidecar_path,
                    sidecar_body.as_bytes(),
                    0o640,
                    "overlay sha256 sidecar",
                )?;
            }
            return Ok(ConfigOverlayReceipt {
                source_path: source_path.to_path_buf(),
                target_path: target_path.to_path_buf(),
                sidecar_path,
                backup_path: None,
                sha256: new_sha,
                outcome: ConfigOverlayOutcome::UnchangedIdentical,
                dry_run,
            });
        }

        let prev_stock_sha = if sidecar_path.is_file() {
            fs::read_to_string(&sidecar_path)
                .ok()
                .map(|s| s.trim().to_ascii_lowercase())
        } else {
            None
        };

        let is_unmodified_stock = prev_stock_sha
            .as_deref()
            .map(|prev| prev.eq_ignore_ascii_case(&current_sha))
            .unwrap_or(false);

        if force || is_unmodified_stock {
            ConfigOverlayOutcome::UpdatedUnmodifiedStock
        } else {
            let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let mut bak_os = target_path.as_os_str().to_os_string();
            bak_os.push(format!(".user-backup.{}", ts));
            let bak = PathBuf::from(bak_os);
            ensure_no_symlink_ancestors(&bak, "overlay user backup file")?;
            backup_path = Some(bak);
            ConfigOverlayOutcome::BackedUpUserModifiedAndUpdated
        }
    };

    if !dry_run {
        let source_bytes = fs::read(source_path).map_err(|e| {
            CliError::io(
                format!("reading overlay source {}", source_path.display()),
                e,
            )
        })?;

        if let Some(ref bak) = backup_path {
            let existing_bytes = fs::read(target_path).map_err(|e| {
                CliError::io(
                    format!("reading user-modified config {}", target_path.display()),
                    e,
                )
            })?;
            write_file_atomic_exclusive(
                bak,
                &existing_bytes,
                0o600,
                "overlay user backup file",
            )?;
        }

        write_file_atomic_exclusive(target_path, &source_bytes, 0o640, "overlay target file")?;

        let sidecar_body = format!("{}\n", new_sha);
        write_file_atomic_exclusive(
            &sidecar_path,
            sidecar_body.as_bytes(),
            0o640,
            "overlay sha256 sidecar",
        )?;
    }

    Ok(ConfigOverlayReceipt {
        source_path: source_path.to_path_buf(),
        target_path: target_path.to_path_buf(),
        sidecar_path,
        backup_path,
        sha256: new_sha,
        outcome,
        dry_run,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Preflight Verification (`os-release`, privileges, systemd, FHS paths)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed operating system metadata from `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsReleaseInfo {
    pub distro_id: String,
    pub version_id: String,
    pub pretty_name: String,
    pub codename: Option<String>,
    pub supported: bool,
    pub support_reason: String,
}

/// Parses an `/etc/os-release` content string and evaluates compatibility against
/// `setup/modules/00-core.sh` (`check_kernel`: Ubuntu >= 20.04, Debian >= 11, Kali).
pub fn parse_and_validate_os_release(content: &str) -> OsReleaseInfo {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let clean_val = v.trim().trim_matches('"').trim_matches('\'').to_string();
            fields.insert(k.trim().to_ascii_uppercase(), clean_val);
        }
    }

    let distro_id = fields
        .get("ID")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
        .to_ascii_lowercase();
    let version_id = fields.get("VERSION_ID").cloned().unwrap_or_default();
    let pretty_name = fields
        .get("PRETTY_NAME")
        .cloned()
        .unwrap_or_else(|| format!("{} {}", distro_id, version_id));
    let codename = fields
        .get("VERSION_CODENAME")
        .or_else(|| fields.get("UBUNTU_CODENAME"))
        .cloned();

    let major_version = version_id
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let (supported, support_reason) = match distro_id.as_str() {
        "ubuntu" => {
            if major_version >= 20 {
                (
                    true,
                    format!("Ubuntu {} (>= 20.04 LTS supported)", version_id),
                )
            } else {
                (
                    false,
                    format!(
                        "Ubuntu {} is older than minimum required 20.04 LTS",
                        version_id
                    ),
                )
            }
        }
        "debian" => {
            if major_version >= 11 {
                (
                    true,
                    format!("Debian {} (>= 11 Bullseye supported)", version_id),
                )
            } else {
                (
                    false,
                    format!(
                        "Debian {} is older than minimum required Debian 11",
                        version_id
                    ),
                )
            }
        }
        "kali" => (true, format!("Kali Rolling ({}) supported", version_id)),
        other => (
            false,
            format!(
                "unsupported distribution {:?} (supported: Ubuntu 20.04+, Debian 11+, Kali)",
                other
            ),
        ),
    };

    OsReleaseInfo {
        distro_id,
        version_id,
        pretty_name,
        codename,
        supported,
        support_reason,
    }
}

/// Comprehensive preflight check report returned by `af provision preflight`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionPreflightReport {
    pub passed: bool,
    pub fs_root: PathBuf,
    pub is_effective_root: bool,
    pub root_check_passed: bool,
    pub os_release: Option<OsReleaseInfo>,
    pub os_check_passed: bool,
    pub lock_contended: bool,
    pub systemd_dir_present: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Returns `true` if the current process has effective UID 0 on Unix.
pub fn is_effective_root_user() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Runs non-destructive provisioning preflight checks against `paths`.
pub fn run_provision_preflight(
    paths: &ProvisionPaths,
    os_release_override: Option<&Path>,
    require_root: bool,
) -> CliResult<ProvisionPreflightReport> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    ensure_no_symlink_ancestors(&paths.fs_root, "provision fs_root")?;

    let is_root = is_effective_root_user();
    let root_check_passed = !require_root || is_root;
    if !root_check_passed {
        errors.push(
            "effective UID is not 0 (root); bare-metal provisioning requires root privileges or --no-root-check / --root <isolated_dir>".to_string(),
        );
    }

    let os_rel_path = os_release_override.unwrap_or(&paths.os_release_file);
    ensure_no_symlink_ancestors(os_rel_path, "os-release file")?;
    let (os_release, os_check_passed) = if os_rel_path.is_file() {
        let raw = fs::read_to_string(os_rel_path).map_err(|e| {
            CliError::io(format!("reading os-release {}", os_rel_path.display()), e)
        })?;
        let parsed = parse_and_validate_os_release(&raw);
        let ok = parsed.supported;
        if !ok {
            errors.push(parsed.support_reason.clone());
        }
        (Some(parsed), ok)
    } else {
        warnings.push(format!(
            "os-release file not found at {} (skipping distro gate in isolated root)",
            os_rel_path.display()
        ));
        (None, true)
    };

    ensure_no_symlink_ancestors(&paths.lock_file, "provision lockfile")?;
    let mut lock_contended = false;
    if paths.lock_file.exists() {
        let raw_pid = fs::read_to_string(&paths.lock_file).unwrap_or_default();
        if let Ok(pid) = raw_pid.trim().parse::<u32>() {
            if is_pid_alive(pid) {
                lock_contended = true;
                errors.push(format!(
                    "setup lockfile {} is held by active PID {}",
                    paths.lock_file.display(),
                    pid
                ));
            }
        }
    }

    let systemd_dir_present = paths.etc_systemd_system.is_dir();
    if !systemd_dir_present {
        warnings.push(format!(
            "systemd unit directory {} does not exist yet (will be created by 'makedirs'/'boot')",
            paths.etc_systemd_system.display()
        ));
    }

    let passed = errors.is_empty();
    Ok(ProvisionPreflightReport {
        passed,
        fs_root: paths.fs_root.clone(),
        is_effective_root: is_root,
        root_check_passed,
        os_release,
        os_check_passed,
        lock_contended,
        systemd_dir_present,
        warnings,
        errors,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Resumable Step Execution & Repair Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Execution outcome for an individual provisioning step during `af provision run` or `repair`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepExecutionStatus {
    /// Step was already recorded as completed in `.aetherflow.state` and skipped (`--resume`).
    SkippedAlreadyDone,
    /// Step was validated in `--dry-run` mode without mutating disk state.
    DryRunPlanned,
    /// Step executed and was persisted as completed in `.aetherflow.state`.
    Completed,
    /// Step is a `RetainedShellBootstrap` step that must be run via `setup/AetherFlow-Setup`.
    DeferredToShellBootstrap,
}

/// Detailed record for a single step processed during a provisioning run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepExecutionRecord {
    pub step_id: String,
    pub tier: ProvisionStepTier,
    pub status: StepExecutionStatus,
    pub detail: String,
}

/// Summary report returned by [`execute_provision_steps`] (`af provision run` / `repair`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionRunReport {
    pub mode: String,
    pub dry_run: bool,
    pub fresh: bool,
    pub cleared_for_repair: Vec<String>,
    pub records: Vec<StepExecutionRecord>,
    pub completed_steps_after: Vec<String>,
}

/// Executes or resumes a bounded list of provisioning steps (or the default Rust-native foundation
/// steps when `requested_steps` is empty).
///
/// If `is_repair` is `true`, first clears completion state for `requested_steps` so they are
/// guaranteed to re-run.
pub fn execute_provision_steps(
    store: &ProvisionStateStore,
    requested_steps: &[String],
    fresh: bool,
    is_repair: bool,
    require_root: bool,
    dry_run: bool,
) -> CliResult<ProvisionRunReport> {
    let paths = store.paths();
    ensure_no_symlink_ancestors(&paths.fs_root, "provision fs_root")?;

    // Enforce root privilege unless running against an isolated non-root test directory or dry-run
    if require_root && !dry_run && paths.fs_root == Path::new("/") && !is_effective_root_user() {
        return Err(CliError::PrivilegeRequired(
            "provisioning live '/' root requires root privileges (UID 0)".to_string(),
        ));
    }

    // Default to the 6 Rust-native foundation steps when no explicit step list is passed
    let target_steps: Vec<String> = if requested_steps.is_empty() {
        vec![
            "checkroot".to_string(),
            "logcheck".to_string(),
            "checkkernel".to_string(),
            "makedirs".to_string(),
            "boot".to_string(),
            "harden_perms".to_string(),
        ]
    } else {
        let mut out = Vec::with_capacity(requested_steps.len());
        for s in requested_steps {
            out.push(validate_step_id(s)?);
        }
        out
    };

    let _lock = if !dry_run {
        Some(ProvisionLockGuard::acquire(&paths.lock_file)?)
    } else {
        None
    };

    if !dry_run {
        store.ensure_initialized(fresh)?;
    }

    let cleared_for_repair = if is_repair && !dry_run {
        store.clear_steps_for_repair(&target_steps)?
    } else if is_repair {
        target_steps.clone()
    } else {
        Vec::new()
    };

    let catalog_map: BTreeMap<&str, ProvisionStepDescriptor> = canonical_step_catalog()
        .into_iter()
        .map(|d| (d.step_id, d))
        .collect();

    let mut records = Vec::with_capacity(target_steps.len());

    for step_id in &target_steps {
        let desc = catalog_map.get(step_id.as_str()).ok_or_else(|| {
            CliError::Validation(format!("unknown canonical step {:?}", step_id))
        })?;

        if !dry_run && !is_repair && store.is_step_done(step_id)? {
            records.push(StepExecutionRecord {
                step_id: step_id.clone(),
                tier: desc.tier,
                status: StepExecutionStatus::SkippedAlreadyDone,
                detail: "already recorded in .aetherflow.state (# STATE_VERSION=2)".to_string(),
            });
            continue;
        }

        match desc.tier {
            ProvisionStepTier::RetainedShellBootstrap => {
                records.push(StepExecutionRecord {
                    step_id: step_id.clone(),
                    tier: desc.tier,
                    status: StepExecutionStatus::DeferredToShellBootstrap,
                    detail: format!(
                        "step '{}' is owned by setup/AetherFlow-Setup shell bootstrap; state marker ready for shell resume/repair",
                        step_id
                    ),
                });
            }
            ProvisionStepTier::RustNativeFoundation => {
                if dry_run {
                    records.push(StepExecutionRecord {
                        step_id: step_id.clone(),
                        tier: desc.tier,
                        status: StepExecutionStatus::DryRunPlanned,
                        detail: format!("would execute Rust-native foundation step: {}", desc.summary),
                    });
                    continue;
                }

                let detail = execute_single_rust_step(store, step_id, require_root)?;
                store.mark_step_done(step_id)?;
                records.push(StepExecutionRecord {
                    step_id: step_id.clone(),
                    tier: desc.tier,
                    status: StepExecutionStatus::Completed,
                    detail,
                });
            }
        }
    }

    let (_, completed_steps_after) = if dry_run {
        store.read_state().unwrap_or((Some(PROVISION_STATE_VERSION), Vec::new()))
    } else {
        store.read_state()?
    };

    Ok(ProvisionRunReport {
        mode: if is_repair {
            "repair".to_string()
        } else {
            "run".to_string()
        },
        dry_run,
        fresh,
        cleared_for_repair,
        records,
        completed_steps_after,
    })
}

fn execute_single_rust_step(
    store: &ProvisionStateStore,
    step_id: &str,
    require_root: bool,
) -> CliResult<String> {
    let paths = store.paths();
    match step_id {
        "checkroot" => {
            if require_root && paths.fs_root == Path::new("/") && !is_effective_root_user() {
                return Err(CliError::PrivilegeRequired(
                    "checkroot failed: effective UID is not 0".to_string(),
                ));
            }
            Ok("verified operator privilege and lockfile ownership".to_string())
        }
        "logcheck" => {
            store.ensure_initialized(false)?;
            store.save_config_value("PROVISION_ENGINE", "af-cli-v4")?;
            Ok(format!(
                "initialized state and log under {}",
                paths.install_dir.display()
            ))
        }
        "checkkernel" => {
            ensure_no_symlink_ancestors(&paths.os_release_file, "os-release file")?;
            if paths.os_release_file.is_file() {
                let raw = fs::read_to_string(&paths.os_release_file).map_err(|e| {
                    CliError::io(
                        format!("reading {}", paths.os_release_file.display()),
                        e,
                    )
                })?;
                let info = parse_and_validate_os_release(&raw);
                if !info.supported {
                    return Err(CliError::PreflightOrIntegrity(info.support_reason));
                }
                store.save_config_value("DISTRO_ID", &info.distro_id)?;
                store.save_config_value("DISTRO_VERSION_ID", &info.version_id)?;
                Ok(info.support_reason)
            } else {
                Ok("no /etc/os-release in isolated root; skipped kernel/distro rejection".to_string())
            }
        }
        "makedirs" => {
            let dirs = [
                &paths.install_dir,
                &paths.etc_aetherflow,
                &paths.etc_legacy_aetherflow,
                &paths.var_lib_aetherflow,
                &paths.var_lib_backups,
                &paths.var_log_aetherflow,
            ];
            for dir in dirs {
                ensure_dir_no_symlinks(&paths.fs_root, dir, 0o750, "FHS directory")?;
            }
            for dir in [&paths.opt_aetherflow, &paths.opt_releases, &paths.etc_systemd_system] {
                ensure_dir_no_symlinks(&paths.fs_root, dir, 0o755, "executable or shared FHS directory")?;
            }
            Ok("created canonical bare-metal FHS directories".to_string())
        }
        "boot" => {
            ensure_dir_no_symlinks(
                &paths.fs_root,
                &paths.etc_systemd_system,
                0o755,
                "systemd unit dir",
            )?;
            // Render a baseline systemd sandbox drop-in template using af-runner's canonical helper
            // and overlay it safely with a .aetherflow-sha256 sidecar.
            let dropin_dir = paths
                .etc_systemd_system
                .join("aetherflow-api.service.d");
            ensure_dir_no_symlinks(&paths.fs_root, &dropin_dir, 0o755, "systemd dropin dir")?;
            let rw_paths = vec!["/var/lib/aetherflow".to_string(), "/var/log/aetherflow".to_string()];
            let rendered = render_systemd_sandbox_dropin("native", "aetherflow-api.service", &rw_paths);
            let staging_src = paths.install_dir.join(format!(
                ".staging-aetherflow-api-sandbox-{}-{}.conf",
                std::process::id(),
                Uuid::new_v4()
            ));
            write_file_atomic_exclusive(
                &staging_src,
                rendered.as_bytes(),
                0o600,
                "staging sandbox drop-in",
            )?;
            let target_dropin = dropin_dir.join("10-aetherflow-sandbox.conf");
            let overlay_res = safe_overlay_config_file(&staging_src, &target_dropin, false, false);
            let _ = fs::remove_file(&staging_src);
            let overlay = overlay_res?;
            Ok(format!(
                "staged systemd sandbox drop-in at {} ({:?})",
                overlay.target_path.display(),
                overlay.outcome
            ))
        }
        "harden_perms" => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for (dir, mode) in [
                    (&paths.install_dir, 0o750u32),
                    (&paths.etc_aetherflow, 0o750u32),
                    (&paths.var_lib_aetherflow, 0o750u32),
                    (&paths.var_lib_backups, 0o750u32),
                    (&paths.var_log_aetherflow, 0o750u32),
                ] {
                    if dir.is_dir() {
                        ensure_no_symlink_ancestors(dir, "harden_perms directory")?;
                        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode));
                    }
                }
                for (file, mode) in [
                    (&paths.state_file, 0o600u32),
                    (&paths.config_file, 0o600u32),
                    (&paths.install_log, 0o600u32),
                ] {
                    if file.is_file() {
                        ensure_no_symlink_ancestors(file, "harden_perms file")?;
                        let _ = fs::set_permissions(file, fs::Permissions::from_mode(mode));
                    }
                }
            }
            // Write a deterministic sha256 verification stamp of the state header
            let mut hasher = Sha256::new();
            hasher.update(STATE_VERSION_HEADER.as_bytes());
            let stamp = hex::encode(hasher.finalize());
            store.save_config_value("HARDEN_PERMS_STAMP", &stamp[..16])?;
            Ok("applied directory and state file permission hardening".to_string())
        }
        other => Err(CliError::Unsupported {
            operation: format!("provision step {}", other),
            reason: "step is retained in setup/AetherFlow-Setup shell bootstrap".to_string(),
        }),
    }
}
