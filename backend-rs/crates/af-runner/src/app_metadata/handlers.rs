use super::extractors_services::extract_app_runtime_meta_local;
use crate::*;

pub(crate) const DISPATCHARR_ADMIN_SCRIPT: &str = r#"import os
from django.contrib.auth import get_user_model
from django.db import transaction

with transaction.atomic():
    user, _ = get_user_model().objects.get_or_create(username=os.environ["AF_ADMIN_USER"])
    user.email = os.environ["AF_ADMIN_EMAIL"]
    user.user_level = 10
    user.is_staff = True
    user.is_superuser = True
    user.is_active = True
    user.set_password(os.environ["AF_ADMIN_PASS"])
    user.save()
"#;

#[derive(Deserialize)]
pub(crate) struct DispatcharrCredentialsRequest {
    pub(crate) username: String,
    pub(crate) password: String,
}

pub(crate) fn dispatcharr_credentials_command(username: &str, password: &str) -> Command {
    let mut command = Command::new("runuser");
    command
        .args([
            "-u", "dispatcharr", "--", "/bin/bash", "-ec",
            "set -a; source /etc/dispatcharr/dispatcharr.env; set +a; cd /opt/dispatcharr; exec /opt/dispatcharr/env/bin/python manage.py shell",
        ])
        .env("AF_ADMIN_USER", username)
        .env("AF_ADMIN_PASS", password)
        .env("AF_ADMIN_EMAIL", format!("{}@localhost", username))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    command
}

pub(crate) async fn handle_dispatcharr_credentials(
    Json(req): Json<DispatcharrCredentialsRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let username = req.username.trim();
    if username.is_empty()
        || req.password.is_empty()
        || username.len() > 256
        || req.password.len() > 4096
        || username.contains('\0')
        || req.password.contains('\0')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid Dispatcharr credentials".to_string(),
            }),
        );
    }
    if !Path::new("/opt/dispatcharr/manage.py").is_file() {
        return (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: "Dispatcharr is not installed".to_string(),
                error: String::new(),
            }),
        );
    }
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        use tokio::io::AsyncWriteExt;
        let mut child = dispatcharr_credentials_command(username, &req.password).spawn()?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("missing stdin"))?;
        input.write_all(DISPATCHARR_ADMIN_SCRIPT.as_bytes()).await?;
        drop(input);
        child.wait().await
    })
    .await;
    let success = matches!(result, Ok(Ok(status)) if status.success());
    (
        if success {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        },
        Json(RunnerResponse {
            success,
            output: String::new(),
            error: if success {
                String::new()
            } else {
                "Dispatcharr credential sync failed".to_string()
            },
        }),
    )
}

pub(crate) async fn handle_app_meta(
    Json(req): Json<AppMetaRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_SCRIPT_NAME.is_match(&req.app_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid application identifier".to_string(),
            }),
        );
    }
    let meta = extract_app_runtime_meta_local(&req.app_name);
    let output = serde_json::to_string(&meta)
        .unwrap_or_else(|_| "{\"api_key\":\"\",\"configured_port\":0}".to_string());

    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output,
            error: String::new(),
        }),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVersionProbeRunnerRequest {
    pub package_id: String,
}

pub(crate) async fn handle_package_version_probe(
    Json(req): Json<PackageVersionProbeRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_SCRIPT_NAME.is_match(&req.package_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".to_string(),
            }),
        );
    }
    let pkg_id = req.package_id;
    let outcome = tokio::task::spawn_blocking(move || {
        let env_cfg = package_executor::PackageExecutionEnv::default();
        package_lifecycle::probe_live_runtime_version(&pkg_id, &env_cfg)
    })
    .await;

    match outcome {
        Ok(package_lifecycle::LiveRuntimeProbeOutcome::Verified(ver)) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: ver,
                error: String::new(),
            }),
        ),
        Ok(package_lifecycle::LiveRuntimeProbeOutcome::Failed(err)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err,
            }),
        ),
        Ok(package_lifecycle::LiveRuntimeProbeOutcome::NotConfigured) => (
            StatusCode::NOT_FOUND,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "no live version probe configured".to_string(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: format!("probe task failed: {}", e),
            }),
        ),
    }
}

pub async fn probe_package_version_via_runner(package_id: &str) -> anyhow::Result<String> {
    let req = PackageVersionProbeRunnerRequest {
        package_id: package_id.to_string(),
    };
    let result =
        post_runner_json("/v1/package/probe-version", &req, Duration::from_secs(12)).await?;
    if !result.success {
        anyhow::bail!(
            "{}",
            if result.error.is_empty() {
                "runner version probe failed".to_string()
            } else {
                result.error
            }
        );
    }
    Ok(result.output)
}
