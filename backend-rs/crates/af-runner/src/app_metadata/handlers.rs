use super::extractors_services::extract_app_runtime_meta_local;
use crate::*;
use af_models::secret_zeroize::SecretString;

pub(crate) const DISPATCHARR_ADMIN_SCRIPT: &str = r#"import json
import sys
from django.contrib.auth import get_user_model
from django.db import transaction

payload = json.load(sys.stdin)
username = payload["username"]
password = payload["password"]
email = payload.get("email") or f"{username}@localhost"

with transaction.atomic():
    user, _ = get_user_model().objects.get_or_create(username=username)
    user.email = email
    user.user_level = 10
    user.is_staff = True
    user.is_superuser = True
    user.is_active = True
    user.set_password(password)
    user.save()
"#;

#[derive(Deserialize)]
pub(crate) struct DispatcharrCredentialsRequest {
    pub(crate) username: String,
    pub(crate) password: String,
}

impl Drop for DispatcharrCredentialsRequest {
    fn drop(&mut self) {
        let mut wiped = SecretString::new(std::mem::take(&mut self.password));
        wiped.zeroize();
    }
}

pub(crate) fn dispatcharr_credentials_command() -> Command {
    let mut command = Command::new("runuser");
    command
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("HOME", "/opt/dispatcharr")
        .env("USER", "dispatcharr")
        .env("LOGNAME", "dispatcharr")
        .env("LANG", "C.UTF-8")
        .env("PYTHONNOUSERSITE", "1")
        .args([
            "-u",
            "dispatcharr",
            "--",
            "/bin/bash",
            "-ec",
            "set -a; source /etc/dispatcharr/dispatcharr.env; set +a; cd /opt/dispatcharr; exec /opt/dispatcharr/env/bin/python -E manage.py shell -c \"$1\"",
            "af-dispatcharr-sync",
            DISPATCHARR_ADMIN_SCRIPT,
        ]);
    command
}

#[derive(Serialize)]
struct DispatcharrCredentialsStdinPayload<'a> {
    username: &'a str,
    password: &'a str,
    email: &'a str,
}

pub(crate) fn dispatcharr_credentials_stdin_payload(
    username: &str,
    password: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    let email = format!("{username}@localhost");
    let payload = DispatcharrCredentialsStdinPayload {
        username,
        password,
        email: &email,
    };
    let capacity = username
        .len()
        .saturating_mul(2)
        .saturating_add(password.len().saturating_mul(2))
        .saturating_add(email.len().saturating_mul(2))
        .saturating_add(64);
    let mut buf = Vec::with_capacity(capacity);
    if let Err(err) = serde_json::to_writer(&mut buf, &payload) {
        drop(af_models::secret_zeroize::SecretBytes::new(buf));
        return Err(err);
    }
    Ok(buf)
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
    let Ok(payload) = dispatcharr_credentials_stdin_payload(username, &req.password) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "Dispatcharr credential sync failed".to_string(),
            }),
        );
    };
    let result = bounded_command::output_with_stdin(
        dispatcharr_credentials_command(),
        payload,
        Duration::from_secs(20),
        64 * 1024,
    )
    .await;
    let success = matches!(result, Ok(out) if out.status.success());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcharr_stdin_payload_encodes_literals_without_env_exposure() {
        let username = "user'\"$`\\";
        let password = "p'\"\\$(touch /tmp/not-executed)\npassword";
        let payload = dispatcharr_credentials_stdin_payload(username, password).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded["username"].as_str(), Some(username));
        assert_eq!(decoded["password"].as_str(), Some(password));
        assert_eq!(
            decoded["email"].as_str(),
            Some(format!("{username}@localhost").as_str())
        );

        let command = dispatcharr_credentials_command();
        let std_cmd = command.as_std();
        let envs: HashMap<_, _> = std_cmd.get_envs().collect();
        assert_eq!(envs.len(), 6);
        assert!(!envs.contains_key(std::ffi::OsStr::new("AF_ADMIN_PASS")));
        assert!(!envs.contains_key(std::ffi::OsStr::new("AF_ADMIN_USER")));
        assert!(!envs.contains_key(std::ffi::OsStr::new("AF_ADMIN_EMAIL")));
        assert!(!envs.contains_key(std::ffi::OsStr::new("JWT_SECRET")));
        assert!(!envs.contains_key(std::ffi::OsStr::new("AES_MASTER_KEY")));
        assert!(DISPATCHARR_ADMIN_SCRIPT.contains("json.load(sys.stdin)"));
        assert!(!DISPATCHARR_ADMIN_SCRIPT.contains("AF_ADMIN_PASS"));
    }

    #[tokio::test]
    async fn dispatcharr_script_parses_stdin_json_via_output_with_stdin() {
        let username = "admin'\"$`\\";
        let password = "s3cr3t\"'$(id)\nline2";
        let payload = dispatcharr_credentials_stdin_payload(username, password).unwrap();
        let mut cmd = Command::new("/usr/bin/python3");
        cmd.args([
            "-c",
            "import json, sys; p = json.load(sys.stdin); print(json.dumps([p['username'], p['password'], p['email']]))",
        ]);
        let out = bounded_command::output_with_stdin(cmd, payload, Duration::from_secs(5), 4096)
            .await
            .unwrap();
        assert!(out.status.success());
        let parsed: Vec<String> = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            parsed,
            vec![username, password, &format!("{username}@localhost")]
        );
    }
}
