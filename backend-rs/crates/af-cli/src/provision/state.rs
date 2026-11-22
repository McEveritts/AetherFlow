use super::fs_helpers::{
    enforce_root_private_file_perms, ensure_install_dir_secure, ensure_no_symlink_ancestors,
    parse_config_map, quote_posix_single, write_file_atomic_exclusive,
};
use super::{
    is_canonical_step, validate_step_id, ProvisionPaths, CANONICAL_ALL_STEPS,
    PROVISION_STATE_VERSION, SAFE_CONF_KEY_RE, SAFE_STEP_ID_RE, STATE_VERSION_HEADER,
};
use crate::error::{CliError, CliResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

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
        ensure_install_dir_secure(&self.paths.fs_root, &self.paths.install_dir)?;

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
            enforce_root_private_file_perms(&self.paths.state_file);
            enforce_root_private_file_perms(&self.paths.config_file);
            enforce_root_private_file_perms(&self.paths.install_log);
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
            self.append_log(&format!(
                "[REPAIR] Cleared completion state for step '{}'",
                s
            ))?;
        }
        Ok(removed)
    }

    /// Atomically writes `# STATE_VERSION=2` followed by `steps` to `/install/.aetherflow.state`
    /// using an exclusive `0o600` sibling temporary file.
    fn write_completed_steps_atomic(&self, steps: &[String]) -> CliResult<()> {
        ensure_install_dir_secure(&self.paths.fs_root, &self.paths.install_dir)?;

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
        )?;
        #[cfg(unix)]
        enforce_root_private_file_perms(&self.paths.state_file);
        Ok(())
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

        Ok(parse_config_map(&raw))
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
        if clean_key.eq_ignore_ascii_case("passwd") {
            return Err(CliError::Validation(
                "refusing to persist plaintext 'passwd' in .aetherflow.conf".to_string(),
            ));
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
        ensure_install_dir_secure(&self.paths.fs_root, &self.paths.install_dir)?;

        let mut out = String::new();
        for (k, v) in map {
            if k.eq_ignore_ascii_case("passwd") {
                continue;
            }
            out.push_str(k);
            out.push('=');
            out.push_str(&quote_posix_single(v)?);
            out.push('\n');
        }

        write_file_atomic_exclusive(
            &self.paths.config_file,
            out.as_bytes(),
            0o600,
            "provision config file",
        )?;
        #[cfg(unix)]
        enforce_root_private_file_perms(&self.paths.config_file);
        Ok(())
    }

    /// Appends a timestamped entry to `/install/.aetherflow.install.log` with `0o600` private mode.
    pub fn append_log(&self, message: &str) -> CliResult<()> {
        ensure_install_dir_secure(&self.paths.fs_root, &self.paths.install_dir)?;
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
            // Keep historical markers on disk, but count only steps in the current installer.
            raw_completed_steps
                .into_iter()
                .filter(|step| is_canonical_step(step))
                .collect::<Vec<_>>()
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
