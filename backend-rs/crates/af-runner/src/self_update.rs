use af_release::{RecoveryState, ReleaseConfig, ReleasePhase};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;

pub const UPDATE_UNIT: &str = "aetherflow-self-update.service";
const DESCRIPTION_PREFIX: &str = "AetherFlow self-update:";
const ENV_HANDOFF_DIRECTORY: &str = "/run/aetherflow-self-update";
static LAUNCH_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const FORWARDED_ENVIRONMENT: &[&str] = &[
    "AF_DB_PATH",
    "DB_PATH",
    "RELEASES_DIR",
    "CURRENT_LINK",
    "REPO_DIR",
    "LEGACY_OPT_ROOT",
    "GITHUB_REPO",
    "ARTIFACT_NAME",
    "CHECKSUM_NAME",
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
    "AF_GITHUB_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub state: String,
    pub operation_id: Option<String>,
    pub phase: Option<String>,
    pub error: Option<String>,
    pub selected_version: Option<String>,
    pub runner_version: String,
}

#[derive(Debug)]
pub enum LaunchError {
    Busy(String),
    Failed(String),
}

#[derive(Debug, Default)]
struct UnitState {
    loaded: bool,
    active: String,
    sub: String,
    result: String,
    operation_id: Option<String>,
    previous_operation_id: Option<String>,
}

impl UnitState {
    fn parse(text: &str) -> Self {
        let fields: HashMap<_, _> = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        let field = |key| fields.get(key).copied().unwrap_or_default().to_string();
        let identity = fields
            .get("Description")
            .and_then(|description| description.strip_prefix(DESCRIPTION_PREFIX));
        let operation_id = identity
            .and_then(|identity| identity.split(';').next())
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .map(|id| id.to_string());
        let previous_operation_id = identity
            .and_then(|identity| identity.split_once(";previous="))
            .map(|(_, previous)| previous.to_string());
        Self {
            loaded: fields
                .get("LoadState")
                .is_some_and(|state| *state != "not-found"),
            active: field("ActiveState"),
            sub: field("SubState"),
            result: field("Result"),
            operation_id,
            previous_operation_id,
        }
    }

    fn running(&self) -> bool {
        matches!(self.active.as_str(), "activating" | "deactivating")
            || (self.active == "active" && self.sub != "exited")
    }
}

fn checked_output(command: &mut Command) -> Result<Output, LaunchError> {
    let output = command
        .output()
        .map_err(|error| LaunchError::Failed(error.to_string()))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(LaunchError::Failed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

fn unit_state() -> Result<UnitState, LaunchError> {
    let output = Command::new("systemctl")
        .args([
            "show",
            UPDATE_UNIT,
            "--property=LoadState,ActiveState,SubState,Result,Description",
        ])
        .output()
        .map_err(|error| LaunchError::Failed(error.to_string()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let state = UnitState::parse(&text);
    if !output.status.success() && !text.contains("LoadState=not-found") {
        return Err(LaunchError::Failed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(state)
}

fn load_config() -> Result<(ReleaseConfig, Option<PathBuf>), LaunchError> {
    let path = af_release::resolve_release_manager_conf();
    let config = ReleaseConfig::load_from_process_env(path.as_deref())
        .map_err(|error| LaunchError::Failed(error.to_string()))?;
    Ok((config, path))
}

fn trusted_path(path: &Path) -> Result<PathBuf, LaunchError> {
    let resolved =
        fs::canonicalize(path).map_err(|error| LaunchError::Failed(error.to_string()))?;
    if !resolved.is_file() {
        return Err(LaunchError::Failed(
            "update executable/configuration is not a file".to_string(),
        ));
    }
    validate_root_ownership(&resolved)?;
    Ok(resolved)
}

fn validate_root_ownership(path: &Path) -> Result<(), LaunchError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for ancestor in path.ancestors() {
            let metadata =
                fs::metadata(ancestor).map_err(|error| LaunchError::Failed(error.to_string()))?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(LaunchError::Failed(format!(
                    "untrusted updater path: {}",
                    ancestor.display()
                )));
            }
        }
    }
    Ok(())
}

fn encode_environment_file(environment: &[(&str, String)]) -> String {
    environment
        .iter()
        .map(|(name, value)| {
            format!(
                "{name}=\"{}\"\n",
                value.replace('\\', "\\\\").replace('"', "\\\"")
            )
        })
        .collect()
}

fn write_environment_handoff() -> Result<PathBuf, LaunchError> {
    let directory = Path::new(ENV_HANDOFF_DIRECTORY);
    af_release::fs_security::create_dir_all_no_symlinks(directory, 0o700)
        .map_err(|error| LaunchError::Failed(error.to_string()))?;
    validate_root_ownership(directory)?;
    let mut environment = Vec::new();
    for name in FORWARDED_ENVIRONMENT {
        if let Some(value) = env::var_os(name) {
            let value = value.into_string().map_err(|_| {
                LaunchError::Failed(format!("updater environment variable {name} is not UTF-8"))
            })?;
            environment.push((*name, value));
        }
    }
    let path = directory.join("environment");
    af_release::fs_security::atomic_write_bytes_with_mode(
        &path,
        encode_environment_file(&environment).as_bytes(),
        0o600,
    )
    .map_err(|error| LaunchError::Failed(error.to_string()))?;
    Ok(path)
}

fn systemd_arguments(
    request: &af_release::admin::ValidatedSelfUpdateRequest,
    executable: &Path,
    script: Option<&Path>,
    config: Option<&Path>,
    env_file: &Path,
    operation_id: &str,
    previous_operation_id: Option<&str>,
    environment_file: &Path,
) -> Vec<OsString> {
    let description = match previous_operation_id {
        Some(previous) => format!("{DESCRIPTION_PREFIX}{operation_id};previous={previous}"),
        None => format!("{DESCRIPTION_PREFIX}{operation_id}"),
    };
    let mut arguments: Vec<OsString> = [
        format!("--unit={UPDATE_UNIT}"),
        "--service-type=exec".to_string(),
        format!("--property=Description={description}"),
        "--property=RemainAfterExit=yes".to_string(),
        "--property=WorkingDirectory=/".to_string(),
        "--property=KillMode=control-group".to_string(),
        "--property=RuntimeMaxSec=1800".to_string(),
        "--property=UMask=0077".to_string(),
        "--property=StandardOutput=journal".to_string(),
        "--property=StandardError=journal".to_string(),
        format!("--property=EnvironmentFile=-{}", env_file.display()),
        format!("--property=EnvironmentFile={}", environment_file.display()),
        format!("--setenv=AETHERFLOW_UPDATE_OPERATION_ID={operation_id}"),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    arguments.push("--".into());
    arguments.push(executable.as_os_str().to_owned());
    if let Some(script) = script {
        arguments.push(script.as_os_str().to_owned());
    } else {
        arguments.push("release".into());
    }
    arguments.push(request.command.as_str().into());
    if script.is_none() {
        arguments.push("--local".into());
    }
    arguments.push("--channel".into());
    arguments.push(request.channel.as_str().into());
    if script.is_none() {
        if let Some(config) = config {
            arguments.push("--config".into());
            arguments.push(config.as_os_str().to_owned());
        }
    }
    arguments
}

pub fn launch(
    request: &af_release::admin::ValidatedSelfUpdateRequest,
) -> Result<String, LaunchError> {
    let _guard = LAUNCH_MUTEX
        .lock()
        .map_err(|error| LaunchError::Failed(error.to_string()))?;
    let current_unit = unit_state()?;
    if current_unit.running() {
        return Err(LaunchError::Busy(
            "update_in_progress: an updater is already running".to_string(),
        ));
    }
    let (config, config_path) = load_config()?;
    let recovery = RecoveryState::load(&config.releases_dir)
        .map_err(|error| LaunchError::Failed(error.to_string()))?;
    if request.command == af_release::ReleaseCommand::Deploy
        && recovery
            .as_ref()
            .is_some_and(RecoveryState::has_unhealthy_or_interrupted_post_swap_deploy)
    {
        return Err(LaunchError::Busy(
            "recovery_required: run an explicit rollback before updating".to_string(),
        ));
    }
    let use_bash = env::var("AETHERFLOW_RELEASE_ENGINE")
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("bash");
    let custom = env::var("AETHERFLOW_RELEASE_MANAGER_SCRIPT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let script = if use_bash || custom.is_some() {
        let path = custom
            .map(PathBuf::from)
            .or_else(super::resolve_release_manager_script)
            .ok_or_else(|| LaunchError::Failed("release-manager.sh not found".to_string()))?;
        Some(trusted_path(&path)?)
    } else {
        None
    };
    let executable = if script.is_some() {
        trusted_path(Path::new("/bin/bash"))?
    } else {
        let running = env::current_exe().map_err(|error| LaunchError::Failed(error.to_string()))?;
        let parent = running
            .parent()
            .ok_or_else(|| LaunchError::Failed("missing running release directory".to_string()))?;
        trusted_path(&parent.join("af"))?
    };
    let config_path = config_path.as_deref().map(trusted_path).transpose()?;
    if current_unit.loaded {
        checked_output(Command::new("systemctl").args(["stop", UPDATE_UNIT]))?;
        let _ = Command::new("systemctl")
            .args(["reset-failed", UPDATE_UNIT])
            .output();
    }
    let operation_id = uuid::Uuid::new_v4().to_string();
    let environment_file = write_environment_handoff()?;
    let arguments = systemd_arguments(
        request,
        &executable,
        script.as_deref(),
        config_path.as_deref(),
        &config.env_file,
        &operation_id,
        recovery.as_ref().map(|state| state.operation_id.as_str()),
        &environment_file,
    );
    let result = checked_output(Command::new("systemd-run").args(arguments));
    let _ = fs::remove_file(environment_file);
    result?;
    Ok(operation_id)
}

fn merge_status(unit: &UnitState, recovery: Option<&RecoveryState>) -> UpdateStatus {
    let recovery = recovery.filter(|state| {
        !(unit.active == "active"
            && unit.sub == "exited"
            && unit.result == "success"
            && unit.operation_id.is_some()
            && unit.previous_operation_id.as_deref() == Some(state.operation_id.as_str())
            && !state.has_unhealthy_or_interrupted_post_swap_deploy())
    });
    let phase = recovery
        .filter(|state| {
            !unit.running() || unit.operation_id.as_deref() == Some(state.operation_id.as_str())
        })
        .and_then(|state| serde_json::to_value(state.phase).ok())
        .and_then(|phase| phase.as_str().map(str::to_string));
    let error = recovery.and_then(|state| state.last_error.clone());
    let (state, phase, error) = if unit.running() {
        (
            "running",
            phase
                .filter(|phase| phase != "complete" && phase != "failed")
                .or_else(|| Some("starting".to_string())),
            None,
        )
    } else if recovery.is_some_and(RecoveryState::is_unfinished) {
        (
            "interrupted",
            phase,
            Some("The updater stopped before completing; recovery is required.".to_string()),
        )
    } else if unit.active == "failed" || (!unit.result.is_empty() && unit.result != "success") {
        (
            "failed",
            phase,
            Some(error.unwrap_or_else(|| format!("Updater service failed: {}", unit.result))),
        )
    } else if recovery
        .is_some_and(|state| state.phase == ReleasePhase::Failed || state.last_error.is_some())
    {
        (
            "failed",
            phase,
            error.or_else(|| Some("The previous deployment failed.".to_string())),
        )
    } else if unit.active == "active" && unit.sub == "exited" {
        ("complete", Some("complete".to_string()), None)
    } else if recovery.is_some() {
        ("complete", phase, None)
    } else {
        ("idle", phase, None)
    };
    UpdateStatus {
        state: state.to_string(),
        operation_id: if !unit.running() && recovery.is_some_and(RecoveryState::is_unfinished) {
            recovery.map(|state| state.operation_id.clone())
        } else {
            unit.operation_id
                .clone()
                .or_else(|| recovery.map(|state| state.operation_id.clone()))
        },
        phase,
        error,
        selected_version: None,
        runner_version: af_release::runtime::runtime_identity().version.clone(),
    }
}

pub fn status() -> Result<UpdateStatus, LaunchError> {
    let unit = unit_state()?;
    let (config, _) = load_config()?;
    let recovery = RecoveryState::load(&config.releases_dir)
        .map_err(|error| LaunchError::Failed(error.to_string()))?;
    let mut status = merge_status(&unit, recovery.as_ref());
    status.selected_version = fs::read_to_string(config.current_link.join(".version"))
        .ok()
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty());
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> af_release::admin::ValidatedSelfUpdateRequest {
        af_release::validate_self_update_request(&af_models::SelfUpdateRequest {
            command: "deploy".to_string(),
            channel: "nightly".to_string(),
        })
        .unwrap()
    }

    #[test]
    fn native_launch_is_a_separate_service_and_never_recurses_to_runner() {
        let args = systemd_arguments(
            &request(),
            Path::new("/trusted/release/af"),
            None,
            Some(Path::new("/trusted/config")),
            Path::new("/etc/aetherflow/aetherflow.env"),
            "launch-id",
            None,
            Path::new("/trusted/forwarded.env"),
        );
        let args: Vec<_> = args
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--service-type=exec".to_string()));
        assert!(args.contains(&"--property=RemainAfterExit=yes".to_string()));
        assert!(args.contains(&"--property=EnvironmentFile=/trusted/forwarded.env".to_string()));
        assert!(!args.iter().any(|argument| argument.contains("GH_TOKEN")));
        let start = args.iter().position(|argument| argument == "--").unwrap();
        assert_eq!(
            &args[start + 1..],
            [
                "/trusted/release/af",
                "release",
                "deploy",
                "--local",
                "--channel",
                "nightly",
                "--config",
                "/trusted/config"
            ]
        );
        assert!(!args
            .iter()
            .any(|argument| argument.contains("PartOf=") || argument == "--scope"));
    }

    #[test]
    fn bash_compatibility_also_runs_in_independent_service() {
        let args = systemd_arguments(
            &request(),
            Path::new("/bin/bash"),
            Some(Path::new("/trusted/script with spaces")),
            None,
            Path::new("/etc/aetherflow/aetherflow.env"),
            "launch-id",
            None,
            Path::new("/trusted/forwarded.env"),
        );
        let args: Vec<_> = args
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        let start = args.iter().position(|argument| argument == "--").unwrap();
        assert_eq!(
            &args[start + 1..],
            [
                "/bin/bash",
                "/trusted/script with spaces",
                "deploy",
                "--channel",
                "nightly"
            ]
        );
        assert!(!args.iter().any(|argument| argument == "-c"));
    }

    #[test]
    fn running_launcher_never_reports_previous_completed_operation_as_complete() {
        let unit = UnitState {
            active: "active".into(),
            sub: "running".into(),
            ..Default::default()
        };
        let mut recovery = RecoveryState::new(
            af_release::ReleaseCommand::Deploy,
            af_release::ReleaseChannel::Nightly,
            false,
        );
        recovery.phase = ReleasePhase::Complete;
        let status = merge_status(&unit, Some(&recovery));
        assert_eq!(status.state, "running");
        assert_eq!(status.phase.as_deref(), Some("starting"));
    }

    #[test]
    fn interrupted_and_failed_updates_are_not_success() {
        let recovery = RecoveryState::new(
            af_release::ReleaseCommand::Deploy,
            af_release::ReleaseChannel::Nightly,
            false,
        );
        assert_eq!(
            merge_status(&UnitState::default(), Some(&recovery)).state,
            "interrupted"
        );
        let failed = UnitState {
            active: "failed".into(),
            result: "exit-code".into(),
            ..Default::default()
        };
        assert_eq!(merge_status(&failed, None).state, "failed");
        let old_success = UnitState {
            active: "active".into(),
            sub: "exited".into(),
            ..Default::default()
        };
        assert_eq!(
            merge_status(&old_success, Some(&recovery)).state,
            "interrupted"
        );
    }

    #[test]
    fn unit_identity_is_stable_and_terminal_success_is_not_busy() {
        let id = uuid::Uuid::new_v4().to_string();
        let unit = UnitState::parse(&format!("LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nDescription={DESCRIPTION_PREFIX}{id}\n"));
        assert!(!unit.running());
        let status = merge_status(&unit, None);
        assert_eq!(status.state, "complete");
        assert_eq!(status.operation_id.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn successful_new_unit_supersedes_only_its_recorded_pre_swap_journal() {
        let mut recovery = RecoveryState::new(
            af_release::ReleaseCommand::Deploy,
            af_release::ReleaseChannel::Nightly,
            false,
        );
        recovery.phase = ReleasePhase::Stage1Scaffold;
        let operation_id = uuid::Uuid::new_v4().to_string();
        let unit = UnitState::parse(&format!(
            "ActiveState=active\nSubState=exited\nResult=success\nDescription={DESCRIPTION_PREFIX}{operation_id};previous={}\n",
            recovery.operation_id,
        ));
        let status = merge_status(&unit, Some(&recovery));
        assert_eq!(status.state, "complete");
        assert_eq!(status.operation_id.as_deref(), Some(operation_id.as_str()));
        recovery.phase = ReleasePhase::Stage2SymlinkSwap;
        assert_eq!(merge_status(&unit, Some(&recovery)).state, "interrupted");
        recovery.phase = ReleasePhase::Stage1Scaffold;
        recovery.operation_id = uuid::Uuid::new_v4().to_string();
        assert_eq!(merge_status(&unit, Some(&recovery)).state, "interrupted");
    }

    #[test]
    fn environment_file_quotes_values_without_shell_expansion() {
        assert_eq!(
            encode_environment_file(&[("GH_TOKEN", "a\\b\"c\n$d".to_string())]),
            "GH_TOKEN=\"a\\\\b\\\"c\n$d\"\n"
        );
    }

    #[test]
    #[ignore = "requires an isolated systemd manager; run explicitly in Linux CI"]
    fn updater_survives_caller_restart() {
        for bash in [false, true] {
            let root =
                env::temp_dir().join(format!("af-self-update-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            af_release::fs_security::set_dir_mode(&root, 0o700).unwrap();
            let environment_file = root.join("forwarded.env");
            af_release::fs_security::atomic_write_bytes_with_mode(
                &environment_file,
                encode_environment_file(&[("GH_TOKEN", "fixture-token".to_string())]).as_bytes(),
                0o600,
            )
            .unwrap();
            let executable = if bash {
                PathBuf::from("/bin/bash")
            } else {
                root.join("af")
            };
            let script = bash.then(|| root.join("release.sh"));
            let arguments = systemd_arguments(
                &request(),
                &executable,
                script.as_deref(),
                None,
                Path::new("/nonexistent/af-self-update-test.env"),
                &uuid::Uuid::new_v4().to_string(),
                None,
                &environment_file,
            );
            let arguments: Vec<_> = arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect();
            let harness = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../tests/self_update_systemd_smoke.py");
            let mut command = Command::new("python3");
            command
                .arg(harness)
                .arg("--arguments-json")
                .arg(serde_json::to_string(&arguments).unwrap())
                .arg("--root")
                .arg(&root);
            if bash {
                command.arg("--bash");
            }
            let output = command.output().unwrap();
            fs::remove_dir_all(&root).unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
}
