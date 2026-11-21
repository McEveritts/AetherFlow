use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Internal opt-in marker emitted on stderr by `packages/common.sh`'s `wait_for_service_ready`
/// (when `AF_EMIT_READINESS_RECORD=1`) after a successful application readiness probe.
/// Consumed internally by `af-runner` and never forwarded to user-facing log streams.
pub(crate) const AF_READINESS_PROBE_PREFIX: &str = "__AF_READINESS_PROBE__=";

/// Maximum deduplicated readiness probes retained per managed service unit.
const MAX_RECORDED_PROBES_PER_UNIT: usize = 4;

/// Query parameter names that may carry secrets and must never be accepted in a readiness record.
const FORBIDDEN_QUERY_PARAM_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_token",
    "auth",
];

/// Timing policy for post-install legacy systemd sandbox activation and readiness checks.
#[derive(Debug, Clone)]
pub(crate) struct LegacyReadinessConfig {
    pub systemctl_timeout: Duration,
    pub readiness_timeout: Duration,
    pub poll_interval: Duration,
    pub non_http_settle: Duration,
    pub http_connect_timeout: Duration,
    pub http_request_timeout: Duration,
}

impl Default for LegacyReadinessConfig {
    fn default() -> Self {
        Self {
            systemctl_timeout: Duration::from_secs(45),
            readiness_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(250),
            non_http_settle: Duration::from_millis(250),
            http_connect_timeout: Duration::from_secs(2),
            http_request_timeout: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
impl LegacyReadinessConfig {
    pub(crate) fn from_test_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(ms) = env::var("AETHERFLOW_TEST_READINESS_TIMEOUT_MS") {
            if let Ok(v) = ms.trim().parse::<u64>() {
                cfg.readiness_timeout = Duration::from_millis(v.max(50));
            }
        }
        if let Ok(ms) = env::var("AETHERFLOW_TEST_POLL_INTERVAL_MS") {
            if let Ok(v) = ms.trim().parse::<u64>() {
                cfg.poll_interval = Duration::from_millis(v.max(10));
            }
        }
        if let Ok(ms) = env::var("AETHERFLOW_TEST_NON_HTTP_SETTLE_MS") {
            if let Ok(v) = ms.trim().parse::<u64>() {
                cfg.non_http_settle = Duration::from_millis(v);
            }
        }
        cfg
    }
}

/// Snapshot of systemd unit state inspected via `systemctl show`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SystemdUnitState {
    pub load_state: String,
    pub unit_type: String,
    pub active_state: String,
    pub sub_state: String,
    pub remain_after_exit: bool,
    pub result: String,
}

impl SystemdUnitState {
    pub(crate) fn parse_show_output(raw: &str) -> Self {
        let mut state = Self::default();
        for line in raw.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            let val = value.trim();
            match key.trim() {
                "LoadState" => state.load_state = val.to_ascii_lowercase(),
                "Type" => state.unit_type = val.to_ascii_lowercase(),
                "ActiveState" => state.active_state = val.to_ascii_lowercase(),
                "SubState" => state.sub_state = val.to_ascii_lowercase(),
                "RemainAfterExit" => {
                    state.remain_after_exit = matches!(
                        val.to_ascii_lowercase().as_str(),
                        "yes" | "true" | "1" | "on"
                    );
                }
                "Result" => state.result = val.to_ascii_lowercase(),
                _ => {}
            }
        }
        state
    }

    pub(crate) fn is_missing_or_masked(&self) -> bool {
        matches!(self.load_state.as_str(), "not-found" | "masked")
    }

    pub(crate) fn is_oneshot(&self) -> bool {
        self.unit_type == "oneshot"
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.active_state == "failed" || self.sub_state == "failed"
    }

    pub(crate) fn is_crash_looping(&self) -> bool {
        self.sub_state == "auto-restart"
    }

    pub(crate) fn is_running_or_activating(&self) -> bool {
        matches!(
            self.active_state.as_str(),
            "active" | "activating" | "reloading"
        )
    }

    pub(crate) fn is_inactive_dead(&self) -> bool {
        self.active_state == "inactive" && (self.sub_state.is_empty() || self.sub_state == "dead")
    }

    pub(crate) fn is_active_healthy(&self) -> bool {
        self.active_state == "active"
            && !matches!(
                self.sub_state.as_str(),
                "dead"
                    | "failed"
                    | "stop-sigterm"
                    | "stop-sigkill"
                    | "final-sigterm"
                    | "final-sigkill"
                    | "auto-restart"
            )
            && (self.result.is_empty() || self.result == "success")
    }

    pub(crate) fn is_oneshot_healthy_after_restart(&self) -> bool {
        !self.is_failed()
            && (self.result.is_empty() || self.result == "success")
            && (!self.remain_after_exit || self.active_state == "active")
    }

    pub(crate) fn summary(&self) -> String {
        format!(
            "ActiveState={}, SubState={}, Result={}",
            if self.active_state.is_empty() {
                "unknown"
            } else {
                &self.active_state
            },
            if self.sub_state.is_empty() {
                "unknown"
            } else {
                &self.sub_state
            },
            if self.result.is_empty() {
                "none"
            } else {
                &self.result
            }
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReadinessProbeRecord {
    unit: String,
    url: String,
    #[serde(default)]
    accept_auth: bool,
    #[serde(default)]
    accept_409: bool,
}

/// Validated, credential-free readiness probe emitted by `packages/common.sh`'s
/// `wait_for_service_ready` for a managed service unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedReadinessProbe {
    pub unit: String,
    pub url: String,
    pub accept_auth: bool,
    pub accept_409: bool,
    pub accept_invalid_certs: bool,
}

/// Returns `true` only when `url` targets a strict loopback host (`127.0.0.0/8`, `::1`, or `localhost`).
fn is_strict_loopback_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(v6) = inner.parse::<Ipv6Addr>() {
            return v6.is_loopback();
        }
    }
    false
}

/// Parses and validates an opt-in internal readiness record emitted by `wait_for_service_ready`.
/// Enforces managed unit identity (`managed_units`), rejects embedded credentials or secret
/// query parameters, and restricts TLS certificate relaxation strictly to loopback HTTPS.
pub(crate) fn parse_readiness_probe_record(
    line: &str,
    managed_units: &[String],
) -> Option<RecordedReadinessProbe> {
    let trimmed = line.trim();
    let json_slice = trimmed.strip_prefix(AF_READINESS_PROBE_PREFIX)?;
    let raw: RawReadinessProbeRecord = serde_json::from_str(json_slice.trim()).ok()?;

    let raw_unit = raw.unit.trim();
    if raw_unit.is_empty() || raw_unit.contains("..") {
        return None;
    }
    let unit = normalize_unit_filename(raw_unit);
    if !unit.ends_with(".service") || !SAFE_SERVICE_NAME.is_match(&unit) {
        return None;
    }
    // Enforce exact managed unit identity: ignore exempt, foreign, or non-service units.
    if !managed_units.iter().any(|u| u == &unit) {
        return None;
    }

    let raw_url = raw.url.trim();
    if raw_url.is_empty()
        || raw_url
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return None;
    }

    let parsed = reqwest::Url::parse(raw_url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    // Never accept or store credentials in readiness probe URLs.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    if parsed.fragment().is_some() {
        return None;
    }
    if parsed.host_str().is_none() || parsed.port_or_known_default().is_none() {
        return None;
    }
    for (key, _) in parsed.query_pairs() {
        let lower_key = key.to_ascii_lowercase();
        if FORBIDDEN_QUERY_PARAM_KEYS.contains(&lower_key.as_str()) {
            return None;
        }
    }

    let accept_invalid_certs = parsed.scheme() == "https" && is_strict_loopback_url(&parsed);

    Some(RecordedReadinessProbe {
        unit,
        url: parsed.to_string(),
        accept_auth: raw.accept_auth,
        accept_409: raw.accept_409,
        accept_invalid_certs,
    })
}

/// Records a validated readiness probe for its managed unit, deduplicating by canonical URL
/// and enforcing a strict per-unit bound.
pub(crate) fn record_readiness_probe(
    probes_by_unit: &mut HashMap<String, Vec<RecordedReadinessProbe>>,
    probe: RecordedReadinessProbe,
) {
    let entries = probes_by_unit.entry(probe.unit.clone()).or_default();
    if let Some(existing) = entries.iter_mut().find(|p| p.url == probe.url) {
        existing.accept_auth = probe.accept_auth;
        existing.accept_409 = probe.accept_409;
        existing.accept_invalid_certs = probe.accept_invalid_certs;
        return;
    }
    if entries.len() < MAX_RECORDED_PROBES_PER_UNIT {
        entries.push(probe);
    }
}

/// Evaluates whether an HTTP status code from a direct, non-redirect-following probe satisfies
/// the recorded `wait_for_service_ready` contract:
/// - `200..=399` always counts as ready (matching `curl -fsS` without `-L`, preserving redirected
///   resources without following redirects to untrusted targets).
/// - `401` / `403` counts as ready only when `accept_auth` was recorded by the readiness contract.
/// - `409` counts as ready only when `accept_409` was recorded (e.g., Transmission RPC CSRF).
pub(crate) fn is_ready_http_status(status: u16, accept_auth: bool, accept_409: bool) -> bool {
    (200..=399).contains(&status)
        || (accept_auth && matches!(status, 401 | 403))
        || (accept_409 && status == 409)
}

/// Runs a command via `runner` with both cooperative cancellation and a hard wall-clock timeout,
/// signalling child cancellation on timeout so process groups are reaped cleanly.
pub(crate) async fn run_command_bounded<R: CommandRunner>(
    runner: &R,
    program: &str,
    args: &[String],
    env_vars: &[(String, String)],
    cancel: &CancellationToken,
    timeout: Duration,
) -> Result<CommandOutput, PackageExecutorError> {
    if cancel.is_cancelled() {
        return Err(PackageExecutorError::Cancelled(program.to_string()));
    }

    let scoped_cancel = CancellationToken::new();
    let cmd_fut = runner.run_command(program, args, env_vars, &scoped_cancel);
    tokio::pin!(cmd_fut);

    tokio::select! {
        biased;
        res = &mut cmd_fut => res,
        _ = wait_for_cancellation(cancel) => {
            scoped_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(4), &mut cmd_fut).await;
            Err(PackageExecutorError::Cancelled(program.to_string()))
        }
        _ = tokio::time::sleep(timeout) => {
            scoped_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(4), &mut cmd_fut).await;
            Err(PackageExecutorError::ExecutionError(format!(
                "{} {} timed out after {}s",
                program,
                args.join(" "),
                timeout.as_secs()
            )))
        }
    }
}

pub(crate) async fn run_systemctl_bounded<R: CommandRunner>(
    runner: &R,
    args: &[&str],
    cancel: &CancellationToken,
    timeout: Duration,
) -> Result<CommandOutput, PackageExecutorError> {
    let owned_args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let out = run_command_bounded(runner, "systemctl", &owned_args, &[], cancel, timeout).await?;
    if !out.success() {
        let detail = out.combined_output();
        return Err(PackageExecutorError::ExecutionError(if detail.is_empty() {
            format!(
                "systemctl {} exited with status {}",
                args.join(" "),
                out.exit_code
            )
        } else {
            format!("systemctl {} failed: {}", args.join(" "), detail)
        }));
    }
    Ok(out)
}

async fn query_systemd_unit_state<R: CommandRunner>(
    runner: &R,
    unit: &str,
    cancel: &CancellationToken,
    timeout: Duration,
) -> Result<SystemdUnitState, PackageExecutorError> {
    let out = run_systemctl_bounded(
        runner,
        &[
            "show",
            "--property=LoadState,Type,ActiveState,SubState,RemainAfterExit,Result",
            "--",
            unit,
        ],
        cancel,
        timeout,
    )
    .await?;
    Ok(SystemdUnitState::parse_show_output(&out.stdout))
}

async fn wait_for_restarted_oneshot_unit<R: CommandRunner>(
    pkg_id: &str,
    unit: &str,
    initial_state: SystemdUnitState,
    runner: &R,
    cancel: &CancellationToken,
    config: &LegacyReadinessConfig,
) -> Result<String, PackageExecutorError> {
    let deadline = Instant::now() + config.readiness_timeout;
    let state_timeout = config.systemctl_timeout.min(Duration::from_secs(10));
    let mut state = initial_state;

    while state.active_state == "activating" {
        cancel.check(pkg_id)?;
        let now = Instant::now();
        if now >= deadline {
            return Err(PackageExecutorError::ExecutionError(format!(
                "oneshot service {} did not finish activating within {}s after post-install sandbox restart ({})",
                unit,
                config.readiness_timeout.as_secs(),
                state.summary()
            )));
        }
        let sleep_for = config
            .poll_interval
            .min(deadline.saturating_duration_since(now));
        tokio::select! {
            biased;
            _ = wait_for_cancellation(cancel) => {
                return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }
        state = query_systemd_unit_state(runner, unit, cancel, state_timeout).await?;
    }

    if !state.is_oneshot_healthy_after_restart() {
        return Err(PackageExecutorError::ExecutionError(format!(
            "oneshot service {} failed after post-install sandbox restart ({})",
            unit,
            state.summary()
        )));
    }
    Ok(format!(
        "[INFO] Verified post-sandbox activation for oneshot unit {} ({})",
        unit,
        state.summary()
    ))
}

async fn wait_for_restarted_http_service<R: CommandRunner>(
    pkg_id: &str,
    probe: &RecordedReadinessProbe,
    runner: &R,
    cancel: &CancellationToken,
    config: &LegacyReadinessConfig,
) -> Result<String, PackageExecutorError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(config.http_connect_timeout)
        .timeout(config.http_request_timeout)
        .danger_accept_invalid_certs(probe.accept_invalid_certs)
        .build()
        .map_err(|err| {
            PackageExecutorError::ExecutionError(format!(
                "failed to build readiness HTTP client for {}: {}",
                probe.unit, err
            ))
        })?;

    let deadline = Instant::now() + config.readiness_timeout;
    let state_timeout = config.systemctl_timeout.min(Duration::from_secs(10));
    let mut last_reason = "no HTTP response received".to_string();

    loop {
        cancel.check(pkg_id)?;
        let state = query_systemd_unit_state(runner, &probe.unit, cancel, state_timeout).await?;
        if state.is_failed() {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} failed after post-install sandbox restart ({})",
                probe.unit,
                state.summary()
            )));
        }
        if state.is_crash_looping() {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} entered crash-loop ({}) after post-install sandbox restart",
                probe.unit,
                state.summary()
            )));
        }
        if state.is_inactive_dead() {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} became inactive after post-install sandbox restart ({})",
                probe.unit,
                state.summary()
            )));
        }

        if state.is_active_healthy() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(PackageExecutorError::ExecutionError(format!(
                    "service {} did not become HTTP-ready within {:?} after post-install sandbox restart (last error: {})",
                    probe.unit,
                    config.readiness_timeout,
                    last_reason
                )));
            }
            let probe_res = tokio::select! {
                biased;
                _ = wait_for_cancellation(cancel) => {
                    return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
                }
                res = tokio::time::timeout(remaining, client.get(&probe.url).send()) => res,
            };
            match probe_res {
                Ok(Ok(resp)) => {
                    let code = resp.status().as_u16();
                    if is_ready_http_status(code, probe.accept_auth, probe.accept_409) {
                        let post_state =
                            query_systemd_unit_state(runner, &probe.unit, cancel, state_timeout)
                                .await?;
                        if !post_state.is_active_healthy() {
                            return Err(PackageExecutorError::ExecutionError(format!(
                                "service {} did not remain active after HTTP {} ({})",
                                probe.unit,
                                code,
                                post_state.summary()
                            )));
                        }
                        return Ok(format!(
                            "[INFO] Verified post-sandbox readiness for {} (HTTP {})",
                            probe.unit, code
                        ));
                    }
                    last_reason = format!("HTTP {code}");
                }
                Ok(Err(err)) => {
                    last_reason = format!("HTTP probe failed: {}", err.without_url());
                }
                Err(_) => {
                    last_reason = "HTTP probe timed out".to_string();
                }
            }
        } else {
            last_reason = format!("unit {} not yet active ({})", probe.unit, state.summary());
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} did not become HTTP-ready within {:?} after post-install sandbox restart (last error: {})",
                probe.unit,
                config.readiness_timeout,
                last_reason
            )));
        }
        let sleep_for = config
            .poll_interval
            .min(deadline.saturating_duration_since(now));
        tokio::select! {
            biased;
            _ = wait_for_cancellation(cancel) => {
                return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }
    }
}

async fn wait_for_restarted_systemd_unit<R: CommandRunner>(
    pkg_id: &str,
    unit: &str,
    runner: &R,
    cancel: &CancellationToken,
    config: &LegacyReadinessConfig,
) -> Result<String, PackageExecutorError> {
    let deadline = Instant::now() + config.readiness_timeout;
    let state_timeout = config.systemctl_timeout.min(Duration::from_secs(10));
    let mut last_reason = format!("unit {} has not reached active state", unit);

    loop {
        cancel.check(pkg_id)?;
        let state = query_systemd_unit_state(runner, unit, cancel, state_timeout).await?;
        if state.is_failed() {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} failed after post-install sandbox restart ({})",
                unit,
                state.summary()
            )));
        }
        if state.is_crash_looping() {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} entered crash-loop ({}) after post-install sandbox restart",
                unit,
                state.summary()
            )));
        }
        if state.is_inactive_dead() {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} became inactive after post-install sandbox restart ({})",
                unit,
                state.summary()
            )));
        }

        if state.is_active_healthy() {
            if !config.non_http_settle.is_zero() {
                let now = Instant::now();
                let settle_for = config
                    .non_http_settle
                    .min(deadline.saturating_duration_since(now));
                if !settle_for.is_zero() {
                    tokio::select! {
                        biased;
                        _ = wait_for_cancellation(cancel) => {
                            return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
                        }
                        _ = tokio::time::sleep(settle_for) => {}
                    }
                }
                let post_state =
                    query_systemd_unit_state(runner, unit, cancel, state_timeout).await?;
                if post_state.is_active_healthy() {
                    return Ok(format!(
                        "[INFO] Verified post-sandbox readiness for {} ({}/{})",
                        unit, post_state.active_state, post_state.sub_state
                    ));
                }
                if post_state.is_failed()
                    || post_state.is_crash_looping()
                    || post_state.is_inactive_dead()
                {
                    return Err(PackageExecutorError::ExecutionError(format!(
                        "service {} did not remain active after post-install sandbox restart ({})",
                        unit,
                        post_state.summary()
                    )));
                }
                last_reason = format!(
                    "unit {} did not remain active ({})",
                    unit,
                    post_state.summary()
                );
            } else {
                return Ok(format!(
                    "[INFO] Verified post-sandbox readiness for {} ({}/{})",
                    unit, state.active_state, state.sub_state
                ));
            }
        } else {
            last_reason = format!("unit {} not yet active ({})", unit, state.summary());
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} did not become active within {}s after post-install sandbox restart (last state: {})",
                unit,
                config.readiness_timeout.as_secs(),
                last_reason
            )));
        }
        let sleep_for = config
            .poll_interval
            .min(deadline.saturating_duration_since(now));
        tokio::select! {
            biased;
            _ = wait_for_cancellation(cancel) => {
                return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }
    }
}

/// Snapshot of both sandbox drop-in files for a single systemd unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxDropinSnapshot {
    pub aether: Option<Vec<u8>>,
    pub canonical: Option<Vec<u8>>,
}

/// Captures exact drop-in file bytes for each managed sandboxed unit so post-install
/// activation detects whether the drop-in changed after the legacy installer exited.
pub(crate) fn snapshot_sandbox_dropin_bytes(
    systemd_root: &Path,
    units: &[String],
) -> Result<HashMap<String, SandboxDropinSnapshot>, PackageExecutorError> {
    const MAX_SANDBOX_DROPIN_BYTES: usize = 64 * 1024;
    units
        .iter()
        .map(|unit| {
            let dir = systemd_root.join(format!("{unit}.d"));
            let read = |name| {
                crate::probe_metadata::read_regular_nofollow(
                    &dir.join(name),
                    MAX_SANDBOX_DROPIN_BYTES,
                )
                .map_err(PackageExecutorError::ExecutionError)
            };
            let snapshot = SandboxDropinSnapshot {
                aether: read("aetherflow-sandbox.conf")?,
                canonical: read("10-aetherflow-sandbox.conf")?,
            };
            Ok((unit.clone(), snapshot))
        })
        .collect()
}

/// Reloads systemd, restarts only changed active managed service units, and verifies
/// post-restart readiness:
/// - Units with explicit opt-in probe records emitted by `wait_for_service_ready` are verified
///   against those exact validated URLs and HTTP status semantics.
/// - Units without an explicit application probe (including non-HTTP daemons and older scripts)
///   are verified via bounded systemd state checks without inferring HTTP from a numeric port.
/// - Inactive, missing/masked, and `Type=oneshot` semantics are preserved.
pub(crate) async fn activate_and_verify_legacy_sandbox<R: CommandRunner>(
    pkg_id: &str,
    units_needing_restart: &[String],
    recorded_probes: &HashMap<String, Vec<RecordedReadinessProbe>>,
    runner: &R,
    cancel: &CancellationToken,
    config: &LegacyReadinessConfig,
) -> Result<Vec<String>, PackageExecutorError> {
    cancel.check(pkg_id)?;
    run_systemctl_bounded(runner, &["daemon-reload"], cancel, config.systemctl_timeout).await?;

    if units_needing_restart.is_empty() {
        return Ok(Vec::new());
    }

    let state_timeout = config.systemctl_timeout.min(Duration::from_secs(10));
    let mut restarted_daemons: Vec<String> = Vec::new();
    let mut verified_notes: Vec<String> = Vec::new();

    for unit in units_needing_restart {
        cancel.check(pkg_id)?;
        if !unit.ends_with(".service") {
            continue;
        }
        let before = query_systemd_unit_state(runner, unit, cancel, state_timeout).await?;
        if before.is_missing_or_masked() {
            continue;
        }
        if before.is_failed() {
            return Err(PackageExecutorError::ExecutionError(format!(
                "service {} is in failed state before post-install sandbox activation ({})",
                unit,
                before.summary()
            )));
        }
        if !before.is_running_or_activating() {
            // Preserve inactive semantics (including idle socket-activated services and
            // timer-driven Type=oneshot units such as recyclarr.service).
            continue;
        }

        run_systemctl_bounded(
            runner,
            &["try-restart", "--", unit],
            cancel,
            config.systemctl_timeout,
        )
        .await?;

        let after = query_systemd_unit_state(runner, unit, cancel, state_timeout).await?;
        if before.is_oneshot() || after.is_oneshot() {
            let note = wait_for_restarted_oneshot_unit(pkg_id, unit, after, runner, cancel, config)
                .await?;
            verified_notes.push(note);
        } else {
            restarted_daemons.push(unit.clone());
        }
    }

    for unit in &restarted_daemons {
        if let Some(probes) = recorded_probes.get(unit).filter(|list| !list.is_empty()) {
            for probe in probes {
                let note =
                    wait_for_restarted_http_service(pkg_id, probe, runner, cancel, config).await?;
                verified_notes.push(note);
            }
        } else {
            let note =
                wait_for_restarted_systemd_unit(pkg_id, unit, runner, cancel, config).await?;
            verified_notes.push(note);
        }
    }

    Ok(verified_notes)
}

/// Restores any journaled managed sandbox drop-in mutations, removes newly-empty drop-in
/// directories for `sandbox_units`, and reloads systemd when `live_sandbox` is active.
/// Returns `Ok(true)` if drop-in mutations were restored, `Ok(false)` if the journal was empty,
/// or `Err(summary)` if any restoration or reload step failed.
pub(crate) async fn rollback_legacy_sandbox<R: CommandRunner>(
    sandbox_journal: &mut RollbackJournal,
    sandbox_units: &[String],
    systemd_root: &Path,
    live_sandbox: bool,
    runner: &R,
) -> Result<bool, String> {
    if sandbox_journal.is_empty() {
        return Ok(false);
    }
    let _notes = sandbox_journal.rollback(runner).await;
    let mut errors = Vec::new();
    if let Some(err) = sandbox_journal.incomplete_rollback_error.take() {
        errors.push(err);
    }
    for unit in sandbox_units {
        let dropin_dir = systemd_root.join(format!("{unit}.d"));
        if let Ok(mut entries) = fs::read_dir(&dropin_dir) {
            if entries.next().is_none() {
                let _ = fs::remove_dir(&dropin_dir);
            }
        }
    }
    if live_sandbox {
        let noop_cancel = CancellationToken::new();
        if let Err(err) = run_systemctl_bounded(
            runner,
            &["daemon-reload"],
            &noop_cancel,
            Duration::from_secs(30),
        )
        .await
        {
            errors.push(format!(
                "sandbox drop-in restoration daemon-reload failed: {err}"
            ));
        }
    }
    if errors.is_empty() {
        Ok(true)
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    type ScriptedHandler = Box<
        dyn Fn(&str, &[String], &CancellationToken) -> Result<CommandOutput, PackageExecutorError>
            + Send
            + Sync,
    >;

    struct ScriptedRunner {
        calls: StdMutex<Vec<(String, Vec<String>)>>,
        handler: ScriptedHandler,
    }

    impl ScriptedRunner {
        fn new<F>(handler: F) -> Self
        where
            F: Fn(
                    &str,
                    &[String],
                    &CancellationToken,
                ) -> Result<CommandOutput, PackageExecutorError>
                + Send
                + Sync
                + 'static,
        {
            Self {
                calls: StdMutex::new(Vec::new()),
                handler: Box::new(handler),
            }
        }

        fn recorded_calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for ScriptedRunner {
        fn run_command<'a>(
            &'a self,
            program: &'a str,
            args: &'a [String],
            _env_vars: &'a [(String, String)],
            cancel: &'a CancellationToken,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                    + Send
                    + 'a,
            >,
        > {
            let prog = program.to_string();
            let owned_args = args.to_vec();
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap()
                    .push((prog.clone(), owned_args.clone()));
                (self.handler)(&prog, &owned_args, cancel)
            })
        }
    }

    fn show_output(
        load: &str,
        unit_type: &str,
        active: &str,
        sub: &str,
        remain: &str,
        result: &str,
    ) -> CommandOutput {
        CommandOutput {
            exit_code: 0,
            stdout: format!(
                "LoadState={load}\nType={unit_type}\nActiveState={active}\nSubState={sub}\nRemainAfterExit={remain}\nResult={result}\n"
            ),
            stderr: String::new(),
        }
    }

    fn fast_config() -> LegacyReadinessConfig {
        LegacyReadinessConfig {
            systemctl_timeout: Duration::from_secs(5),
            readiness_timeout: Duration::from_millis(800),
            poll_interval: Duration::from_millis(25),
            non_http_settle: Duration::from_millis(60),
            http_connect_timeout: Duration::from_millis(250),
            http_request_timeout: Duration::from_millis(400),
        }
    }

    async fn spawn_http_server(
        expected_target: &'static str,
        status_line: &'static str,
        extra_headers: &'static str,
    ) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                hits_clone.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    use tokio::io::AsyncBufReadExt;
                    let mut request_line = String::new();
                    let mut reader = tokio::io::BufReader::new(&mut sock);
                    let _ = reader.read_line(&mut request_line).await;
                    let status_line =
                        if request_line.split_whitespace().nth(1) == Some(expected_target) {
                            status_line
                        } else {
                            "404 Not Found"
                        };
                    let response = format!(
                        "HTTP/1.1 {status_line}\r\n{extra_headers}Content-Length: 2\r\nConnection: close\r\n\r\nok"
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                });
            }
        });
        (port, hits)
    }

    #[test]
    fn parse_readiness_probe_record_validates_identity_urls_and_rejects_credentials() {
        let managed = vec!["filebot.service".to_string(), "sonarr.service".to_string()];

        // Valid FileBot record (normalizes bare unit name)
        let fb = parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"filebot","url":"http://127.0.0.1:5452/","accept_auth":true,"accept_409":false}"#,
            &managed,
        )
        .expect("filebot record should parse");
        assert_eq!(fb.unit, "filebot.service");
        assert_eq!(fb.url, "http://127.0.0.1:5452/");
        assert!(fb.accept_auth);
        assert!(!fb.accept_409);
        assert!(!fb.accept_invalid_certs);

        // Custom retained IPv6 address + alternate path + safe query
        let custom = parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"sonarr.service","url":"http://[::1]:8989/sonarr/api?mode=version","accept_auth":false,"accept_409":false}"#,
            &managed,
        )
        .expect("custom IPv6/path record should parse");
        assert_eq!(custom.url, "http://[::1]:8989/sonarr/api?mode=version");
        assert!(!custom.accept_invalid_certs);

        // Loopback HTTPS relaxes cert check; non-loopback HTTPS does NOT
        let lb_https = parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"filebot.service","url":"https://127.0.0.1:5452/","accept_auth":true,"accept_409":false}"#,
            &managed,
        )
        .expect("loopback https should parse");
        assert!(lb_https.accept_invalid_certs);

        let lan_https = parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"filebot.service","url":"https://192.168.1.50:5452/","accept_auth":true,"accept_409":false}"#,
            &managed,
        )
        .expect("lan https should parse");
        assert!(!lan_https.accept_invalid_certs);

        // Rejects foreign/unmanaged unit identity
        assert!(parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"node_exporter.service","url":"http://127.0.0.1:9100/metrics","accept_auth":false,"accept_409":false}"#,
            &managed,
        )
        .is_none());

        // Rejects timer/socket units
        assert!(parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"filebot.timer","url":"http://127.0.0.1:5452/","accept_auth":false,"accept_409":false}"#,
            &managed,
        )
        .is_none());

        // Rejects embedded userinfo credentials
        assert!(parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"filebot.service","url":"http://admin:secret@127.0.0.1:5452/","accept_auth":true,"accept_409":false}"#,
            &managed,
        )
        .is_none());

        // Rejects secret query parameters
        assert!(parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"sonarr.service","url":"http://127.0.0.1:8989/ping?apikey=secret123","accept_auth":false,"accept_409":false}"#,
            &managed,
        )
        .is_none());

        // Rejects non-http(s) scheme
        assert!(parse_readiness_probe_record(
            r#"__AF_READINESS_PROBE__={"unit":"filebot.service","url":"file:///etc/passwd","accept_auth":false,"accept_409":false}"#,
            &managed,
        )
        .is_none());
    }

    #[test]
    fn http_status_semantics_preserve_auth_conflict_and_redirects() {
        assert!(is_ready_http_status(200, false, false));
        assert!(is_ready_http_status(204, false, false));
        assert!(is_ready_http_status(301, false, false));
        assert!(is_ready_http_status(302, false, false));
        assert!(is_ready_http_status(307, false, false));
        assert!(is_ready_http_status(308, false, false));

        assert!(!is_ready_http_status(401, false, false));
        assert!(!is_ready_http_status(403, false, false));
        assert!(is_ready_http_status(401, true, false));
        assert!(is_ready_http_status(403, true, false));

        assert!(!is_ready_http_status(409, true, false));
        assert!(is_ready_http_status(409, true, true));

        assert!(!is_ready_http_status(404, true, true));
        assert!(!is_ready_http_status(500, true, true));
        assert!(!is_ready_http_status(503, true, true));
    }

    #[tokio::test]
    async fn filebot_delayed_listener_after_try_restart_succeeds_with_auth_401() {
        // Reserve an ephemeral port, then release it and bind it only AFTER a delay following try-restart.
        let probe_sock = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe_sock.local_addr().unwrap().port();
        drop(probe_sock);

        let restarted = Arc::new(AtomicBool::new(false));
        let restarted_flag = restarted.clone();
        let runner = ScriptedRunner::new(move |_prog, args, _cancel| {
            let cmd = args.first().map(String::as_str).unwrap_or("");
            match cmd {
                "daemon-reload" => Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }),
                "try-restart" => {
                    restarted_flag.store(true, Ordering::SeqCst);
                    // Simulate Type=simple returning immediately while FileBot takes 220ms to bind.
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(220)).await;
                        let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await else {
                            return;
                        };
                        loop {
                            let Ok((mut sock, _)) = listener.accept().await else {
                                break;
                            };
                            tokio::spawn(async move {
                                let mut buf = [0u8; 1024];
                                let _ = sock.read(&mut buf).await;
                                let resp = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"FileBot\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let _ = sock.write_all(resp).await;
                            });
                        }
                    });
                    Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
                "show" => Ok(show_output(
                    "loaded", "simple", "active", "running", "no", "success",
                )),
                _ => Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }),
            }
        });

        let mut probes = HashMap::new();
        record_readiness_probe(
            &mut probes,
            RecordedReadinessProbe {
                unit: "filebot.service".to_string(),
                url: format!("http://127.0.0.1:{port}/"),
                accept_auth: true,
                accept_409: false,
                accept_invalid_certs: false,
            },
        );

        let cancel = CancellationToken::new();
        let notes = activate_and_verify_legacy_sandbox(
            "filebot",
            &["filebot.service".to_string()],
            &probes,
            &runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect("delayed FileBot 401 listener must be observed and pass");

        assert!(restarted.load(Ordering::SeqCst));
        assert!(
            notes
                .iter()
                .any(|n| n.contains("filebot.service") && n.contains("HTTP 401")),
            "expected HTTP 401 verification note, got: {notes:?}"
        );
    }

    #[tokio::test]
    async fn redirected_resource_succeeds_without_following_external_location() {
        let (port, hits) = spawn_http_server(
            "/",
            "302 Found",
            "Location: http://127.0.0.1:1/should-never-be-followed\r\n",
        )
        .await;

        let runner =
            ScriptedRunner::new(
                |_prog, args, _cancel| match args.first().map(String::as_str) {
                    Some("show") => Ok(show_output(
                        "loaded", "simple", "active", "running", "no", "success",
                    )),
                    _ => Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    }),
                },
            );

        let mut probes = HashMap::new();
        record_readiness_probe(
            &mut probes,
            RecordedReadinessProbe {
                unit: "duplicati.service".to_string(),
                url: format!("http://127.0.0.1:{port}/"),
                accept_auth: false,
                accept_409: false,
                accept_invalid_certs: false,
            },
        );

        let cancel = CancellationToken::new();
        let notes = activate_and_verify_legacy_sandbox(
            "duplicati",
            &["duplicati.service".to_string()],
            &probes,
            &runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect("302 redirect must succeed directly without following external target");

        assert!(hits.load(Ordering::SeqCst) >= 1);
        assert!(notes.iter().any(|n| n.contains("HTTP 302")));
    }

    #[tokio::test]
    async fn unauthenticated_401_fails_when_accept_auth_is_false() {
        let (port, _hits) = spawn_http_server("/ping", "401 Unauthorized", "").await;

        let runner =
            ScriptedRunner::new(
                |_prog, args, _cancel| match args.first().map(String::as_str) {
                    Some("show") => Ok(show_output(
                        "loaded", "simple", "active", "running", "no", "success",
                    )),
                    _ => Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    }),
                },
            );

        let mut probes = HashMap::new();
        record_readiness_probe(
            &mut probes,
            RecordedReadinessProbe {
                unit: "sonarr.service".to_string(),
                url: format!("http://127.0.0.1:{port}/ping"),
                accept_auth: false,
                accept_409: false,
                accept_invalid_certs: false,
            },
        );

        let cancel = CancellationToken::new();
        let mut cfg = fast_config();
        cfg.readiness_timeout = Duration::from_millis(200);
        let err = activate_and_verify_legacy_sandbox(
            "sonarr",
            &["sonarr.service".to_string()],
            &probes,
            &runner,
            &cancel,
            &cfg,
        )
        .await
        .expect_err("401 must fail when accept_auth=false");

        assert!(err.to_string().contains("HTTP 401"), "{err}");
    }

    #[tokio::test]
    async fn service_dying_or_crash_looping_after_restart_fails_immediately() {
        for (active, sub, result, expect_substr) in [
            (
                "failed",
                "failed",
                "exit-code",
                "failed after post-install sandbox restart",
            ),
            ("activating", "auto-restart", "exit-code", "crash-loop"),
            ("inactive", "dead", "success", "became inactive"),
        ] {
            let states = StdMutex::new(VecDeque::from(vec![
                show_output("loaded", "simple", "active", "running", "no", "success"),
                show_output("loaded", "simple", "active", "running", "no", "success"),
                show_output("loaded", "simple", active, sub, "no", result),
            ]));
            let runner = ScriptedRunner::new(move |_prog, args, _cancel| {
                if args.first().map(String::as_str) == Some("show") {
                    let mut q = states.lock().unwrap();
                    let next = q.pop_front().unwrap_or_else(|| {
                        show_output("loaded", "simple", active, sub, "no", result)
                    });
                    Ok(next)
                } else {
                    Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            });

            let mut probes = HashMap::new();
            record_readiness_probe(
                &mut probes,
                RecordedReadinessProbe {
                    unit: "filebot.service".to_string(),
                    url: "http://127.0.0.1:1/".to_string(),
                    accept_auth: true,
                    accept_409: false,
                    accept_invalid_certs: false,
                },
            );

            let cancel = CancellationToken::new();
            let err = activate_and_verify_legacy_sandbox(
                "filebot",
                &["filebot.service".to_string()],
                &probes,
                &runner,
                &cancel,
                &fast_config(),
            )
            .await
            .expect_err("dying service must fail closed");
            assert!(
                err.to_string().contains(expect_substr),
                "expected '{expect_substr}' in '{err}'"
            );
        }
    }

    #[tokio::test]
    async fn restarted_unit_without_record_uses_bounded_systemd_check_not_http_inference() {
        // Even if a package has a numeric port (e.g. quasselcore 4242 or an old script that
        // emitted no readiness record), we must NOT infer HTTP and must verify systemd state.
        let runner =
            ScriptedRunner::new(
                |_prog, args, _cancel| match args.first().map(String::as_str) {
                    Some("show") => Ok(show_output(
                        "loaded", "simple", "active", "running", "no", "success",
                    )),
                    _ => Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    }),
                },
            );

        let probes = HashMap::new();
        let cancel = CancellationToken::new();
        let notes = activate_and_verify_legacy_sandbox(
            "quassel",
            &["quasselcore.service".to_string()],
            &probes,
            &runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect("restarted unit without probe record should verify systemd state");

        assert!(notes
            .iter()
            .any(|n| n.contains("quasselcore.service") && n.contains("active/running")));
    }

    #[tokio::test]
    async fn preserves_inactive_oneshot_and_socket_timer_semantics() {
        // 1. Inactive unit is NOT restarted and succeeds
        let inactive_runner = ScriptedRunner::new(|_prog, args, _cancel| {
            if args.first().map(String::as_str) == Some("show") {
                Ok(show_output(
                    "loaded", "simple", "inactive", "dead", "no", "success",
                ))
            } else {
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        });
        let cancel = CancellationToken::new();
        activate_and_verify_legacy_sandbox(
            "librespeed",
            &[
                "librespeed.service".to_string(),
                "librespeed.socket".to_string(),
                "recyclarr.timer".to_string(),
            ],
            &HashMap::new(),
            &inactive_runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect("inactive unit and socket/timer units must not fail");
        assert!(
            inactive_runner
                .recorded_calls()
                .iter()
                .all(|(_, args)| args.first().map(String::as_str) != Some("try-restart")),
            "must not try-restart inactive or socket/timer units: {:?}",
            inactive_runner.recorded_calls()
        );

        // 2. Active Type=oneshot (RemainAfterExit=no) exits cleanly to inactive/dead/success -> OK
        let oneshot_states = StdMutex::new(VecDeque::from(vec![
            show_output("loaded", "oneshot", "active", "exited", "no", "success"),
            show_output("loaded", "oneshot", "inactive", "dead", "no", "success"),
        ]));
        let oneshot_runner = ScriptedRunner::new(move |_prog, args, _cancel| {
            if args.first().map(String::as_str) == Some("show") {
                Ok(oneshot_states.lock().unwrap().pop_front().unwrap())
            } else {
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        });
        let notes = activate_and_verify_legacy_sandbox(
            "recyclarr",
            &["recyclarr.service".to_string()],
            &HashMap::new(),
            &oneshot_runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect("clean oneshot restart must pass");
        assert!(notes
            .iter()
            .any(|n| n.contains("oneshot unit recyclarr.service")));

        // 3. Failing oneshot fails closed
        let failing_oneshot_states = StdMutex::new(VecDeque::from(vec![
            show_output("loaded", "oneshot", "active", "exited", "no", "success"),
            show_output("loaded", "oneshot", "failed", "failed", "no", "exit-code"),
        ]));
        let failing_oneshot_runner = ScriptedRunner::new(move |_prog, args, _cancel| {
            if args.first().map(String::as_str) == Some("show") {
                Ok(failing_oneshot_states.lock().unwrap().pop_front().unwrap())
            } else {
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        });
        let err = activate_and_verify_legacy_sandbox(
            "recyclarr",
            &["recyclarr.service".to_string()],
            &HashMap::new(),
            &failing_oneshot_runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect_err("failing oneshot must fail closed");
        assert!(
            err.to_string()
                .contains("oneshot service recyclarr.service failed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn cancellation_aborts_http_readiness_probe_promptly() {
        // Unreachable port so probe retries until cancelled
        let probe_sock = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe_sock.local_addr().unwrap().port();
        drop(probe_sock);

        let runner =
            ScriptedRunner::new(
                |_prog, args, _cancel| match args.first().map(String::as_str) {
                    Some("show") => Ok(show_output(
                        "loaded", "simple", "active", "running", "no", "success",
                    )),
                    _ => Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    }),
                },
            );

        let mut probes = HashMap::new();
        record_readiness_probe(
            &mut probes,
            RecordedReadinessProbe {
                unit: "filebot.service".to_string(),
                url: format!("http://127.0.0.1:{port}/"),
                accept_auth: true,
                accept_409: false,
                accept_invalid_certs: false,
            },
        );

        let cancel = CancellationToken::new();
        let cancel_trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            cancel_trigger.cancel();
        });

        let mut cfg = fast_config();
        cfg.readiness_timeout = Duration::from_secs(10);
        let started = Instant::now();
        let err = activate_and_verify_legacy_sandbox(
            "filebot",
            &["filebot.service".to_string()],
            &probes,
            &runner,
            &cancel,
            &cfg,
        )
        .await
        .expect_err("cancelled probe must return Cancelled");

        assert!(matches!(err, PackageExecutorError::Cancelled(_)), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn rollback_legacy_sandbox_restores_dropins_and_reloads_systemd() {
        let tmp =
            std::env::temp_dir().join(format!("af-legacy-sandbox-rb-{}", uuid::Uuid::new_v4()));
        let systemd_root = tmp.join("etc/systemd/system");
        let dropin_dir = systemd_root.join("filebot.service.d");
        fs::create_dir_all(&dropin_dir).unwrap();
        let canonical = dropin_dir.join("10-aetherflow-sandbox.conf");
        let companion = dropin_dir.join("aetherflow-sandbox.conf");
        fs::write(&canonical, "[Service]\n# prior\n").unwrap();

        let mut journal = RollbackJournal::new(Some(tmp.clone()));
        journal.stage_file_mutation(&canonical).unwrap();
        journal.stage_file_mutation(&companion).unwrap();
        fs::write(&canonical, "[Service]\n# new\n").unwrap();
        fs::write(&companion, "[Service]\n# new\n").unwrap();

        let runner = ScriptedRunner::new(|_prog, _args, _cancel| {
            Ok(CommandOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        });

        let restored = rollback_legacy_sandbox(
            &mut journal,
            &["filebot.service".to_string()],
            &systemd_root,
            true,
            &runner,
        )
        .await
        .expect("drop-in rollback should succeed");

        assert!(restored);
        assert_eq!(
            fs::read_to_string(&canonical).unwrap(),
            "[Service]\n# prior\n"
        );
        assert!(!companion.exists());
        assert!(runner
            .recorded_calls()
            .iter()
            .any(|(prog, args)| prog == "systemctl" && args == &vec!["daemon-reload".to_string()]));

        // Also verify daemon-reload error during rollback is surfaced, never swallowed.
        let mut failing_journal = RollbackJournal::new(Some(tmp.clone()));
        failing_journal.stage_file_mutation(&canonical).unwrap();
        fs::write(&canonical, "[Service]\n# broken\n").unwrap();
        let failing_runner = ScriptedRunner::new(|_prog, _args, _cancel| {
            Ok(CommandOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: "dbus unavailable".to_string(),
            })
        });
        let err = rollback_legacy_sandbox(
            &mut failing_journal,
            &["filebot.service".to_string()],
            &systemd_root,
            true,
            &failing_runner,
        )
        .await
        .expect_err("daemon-reload failure during rollback must be returned");
        assert!(err.contains("daemon-reload"), "{err}");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn transmission_409_and_custom_alternate_path_are_preserved() {
        let (port_409, _) = spawn_http_server("/transmission/rpc", "409 Conflict", "").await;
        let target = "/custom/sab/api?mode=version";
        let (port_200, _) = spawn_http_server(target, "200 OK", "").await;

        let runner =
            ScriptedRunner::new(
                |_prog, args, _cancel| match args.first().map(String::as_str) {
                    Some("show") => Ok(show_output(
                        "loaded", "simple", "active", "running", "no", "success",
                    )),
                    _ => Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    }),
                },
            );

        let mut probes = HashMap::new();
        record_readiness_probe(
            &mut probes,
            RecordedReadinessProbe {
                unit: "transmission-daemon.service".to_string(),
                url: format!("http://127.0.0.1:{port_409}/transmission/rpc"),
                accept_auth: true,
                accept_409: true,
                accept_invalid_certs: false,
            },
        );
        record_readiness_probe(
            &mut probes,
            RecordedReadinessProbe {
                unit: "sabnzbd.service".to_string(),
                url: format!("http://127.0.0.1:{port_200}{target}"),
                accept_auth: true,
                accept_409: false,
                accept_invalid_certs: false,
            },
        );

        let cancel = CancellationToken::new();
        let notes = activate_and_verify_legacy_sandbox(
            "transmission",
            &[
                "transmission-daemon.service".to_string(),
                "sabnzbd.service".to_string(),
            ],
            &probes,
            &runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect("409 for transmission and custom alternate path for sabnzbd must succeed");
        assert!(notes.iter().any(|n| n.contains("HTTP 409")));
        assert!(notes
            .iter()
            .any(|n| n.contains("sabnzbd.service (HTTP 200)")));
        assert!(notes.iter().all(|n| !n.contains(target)));
    }

    #[tokio::test]
    async fn post_http_crash_fails_closed() {
        let (port, _) = spawn_http_server("/", "200 OK", "").await;
        let states = StdMutex::new(VecDeque::from(vec![
            show_output("loaded", "simple", "active", "running", "no", "success"), // before
            show_output("loaded", "simple", "active", "running", "no", "success"), // after try-restart
            show_output("loaded", "simple", "active", "running", "no", "success"), // pre-probe
            show_output("loaded", "simple", "failed", "failed", "no", "exit-code"), // post-probe!
        ]));
        let runner = ScriptedRunner::new(move |_prog, args, _cancel| {
            if args.first().map(String::as_str) == Some("show") {
                let next = states.lock().unwrap().pop_front().unwrap_or_else(|| {
                    show_output("loaded", "simple", "failed", "failed", "no", "exit-code")
                });
                Ok(next)
            } else {
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        });

        let mut probes = HashMap::new();
        record_readiness_probe(
            &mut probes,
            RecordedReadinessProbe {
                unit: "filebot.service".to_string(),
                url: format!("http://127.0.0.1:{port}/"),
                accept_auth: true,
                accept_409: false,
                accept_invalid_certs: false,
            },
        );

        let cancel = CancellationToken::new();
        let err = activate_and_verify_legacy_sandbox(
            "filebot",
            &["filebot.service".to_string()],
            &probes,
            &runner,
            &cancel,
            &fast_config(),
        )
        .await
        .expect_err("service dying immediately after HTTP 200 must fail closed");
        assert!(err.to_string().contains("did not remain active"), "{err}");
    }
}
