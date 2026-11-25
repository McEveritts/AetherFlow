use crate::cli::{ClusterCliCommand, GlobalOptions};
use crate::client::RunnerClientTransport;
use crate::error::{CliError, CliResponseEnvelope, CliResult};
use af_db::peers::{
    get_active_peer_grant_for_link, get_peer_link, get_peer_link_by_name, get_peer_received_grant,
    get_transcode_worker, list_peer_exports_for_link, list_peer_grants_for_link, list_peer_links,
    list_peer_mounts_for_link, list_transcode_jobs_for_link, AccessMap, PeerExport, PeerGrant,
    PeerLink, PeerMount, PeerReceivedGrant, TranscodeJob, TranscodeWorker,
};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_AUDIT_ENTRIES: usize = 20;
const MAX_TRANSCODE_JOBS: usize = 10;
const REDACTED_MARKER: &str = "[REDACTED]";

static SECRET_KV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(\b(?:PrivateKey|PresharedKey|X-AF-(?:Link|Grant)-Token|Authorization|inbound_token_hash|token_hash|link_token|grant_token|auth_token|api_token|access_token|refresh_token|credential_id|private_key|secret|password)\b\s*[:=]\s*(?:Bearer\s+)?)\S+",
    )
    .expect("constant secret kv redaction regex")
});

static BEARER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(\bBearer\s+)\S+").expect("constant bearer redaction regex"));

static PAIRING_STRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bafpair1:[A-Za-z0-9_=-]+").expect("constant pairing string redaction regex")
});

static HEX_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{64,}\b").expect("constant long hex digest redaction regex")
});

static WG_KEY_B64_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z0-9+/]{43}=").expect("constant wireguard base64 key redaction regex")
});

/// Projects internal durable `peer_links.state` values to canonical public lifecycle states,
/// matching `af-api/src/peers/mod.rs:122-132`.
pub(crate) fn public_link_state(state: &str) -> &'static str {
    match state {
        "pending" | "pending_owned" => "pending",
        "active" | "active_unowned" => "active",
        "down" | "down_unowned" => "down",
        "revoked" | "revoked_unowned" | "revoking" | "revoking_unowned" => "revoked",
        _ => "unknown",
    }
}

/// Affirmative durable WireGuard peer ownership predicate (fail-closed allowlist),
/// matching `af-api/src/peers/mod.rs:85-90`.
pub(crate) fn is_wg_peer_owned(state: &str) -> bool {
    matches!(
        state,
        "pending_owned" | "active" | "down" | "revoked" | "revoking"
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkHealthSummary {
    pub id: String,
    pub name: String,
    pub state: String,
    pub internal_state: String,
    pub wg_peer_owned: bool,
    pub tunnel_ip: String,
    pub endpoint: String,
    pub wg_port: u16,
    pub peer_version: Option<String>,
    pub peer_protocol: Option<i64>,
    pub capabilities: Vec<String>,
    pub rtt_ms: Option<f64>,
    pub last_ok_at: Option<String>,
    pub last_error: Option<String>,
    pub consecutive_failures: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardHandshakeSummary {
    pub available: bool,
    pub interface: String,
    pub interface_state: String,
    pub service_state: String,
    pub peer_found: bool,
    pub present_live: bool,
    pub persistent: bool,
    pub active: bool,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub latest_handshake: Option<String>,
    pub latest_handshake_epoch: Option<i64>,
    pub handshake_age_secs: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Access THIS server grants TO the peer (`peer_grants`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundGrantSummary {
    pub id: String,
    pub run_as_user_id: i64,
    pub access: AccessMap,
    pub active: bool,
    pub created_by: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// Access the PEER grants TO this server (`peer_received_grants`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundGrantSummary {
    pub grant_id: String,
    pub access: AccessMap,
    pub active: bool,
    pub created_by: String,
    pub created_at: String,
    pub generation: i64,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAccessSummary {
    pub inbound: Option<InboundGrantSummary>,
    pub outbound: Option<OutboundGrantSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDiagnosticEntry {
    pub id: String,
    pub path: String,
    pub writable: bool,
    pub squash_uid: Option<u32>,
    pub squash_gid: Option<u32>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelProbeSummary {
    pub ok: bool,
    pub timed_out: bool,
    pub checked_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountDiagnosticEntry {
    pub id: String,
    pub remote_path: String,
    pub mount_path: String,
    pub unit_name: String,
    pub writable: bool,
    pub purpose: String,
    pub state: String,
    pub last_error: Option<String>,
    pub live_exists: Option<bool>,
    pub live_active: Option<bool>,
    pub live_unit_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_error: Option<String>,
    pub probe: Option<SentinelProbeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_skipped_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeJobSummary {
    pub id: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub exit_code: Option<i32>,
    pub request_id: Option<String>,
    pub ran_locally: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeWorkerDiagnostic {
    pub configured: bool,
    pub enabled: bool,
    pub weight: Option<i64>,
    pub max_jobs: Option<i64>,
    pub ffmpeg_version: Option<String>,
    pub encoders: Vec<String>,
    pub render_node: Option<String>,
    pub parity_ok: bool,
    pub parity_error: Option<String>,
    pub recent_jobs: Vec<TranscodeJobSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditDiagnosticEntry {
    pub id: i64,
    pub username: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub detail: String,
    pub ip_address: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterDiagnoseReport {
    pub db_path: PathBuf,
    pub link: LinkHealthSummary,
    pub wireguard: WireGuardHandshakeSummary,
    pub grants: GrantAccessSummary,
    pub exports: Vec<ExportDiagnosticEntry>,
    pub mounts: Vec<MountDiagnosticEntry>,
    pub transcode_worker: TranscodeWorkerDiagnostic,
    pub audit: Vec<AuditDiagnosticEntry>,
}

pub(crate) fn execute_cluster_command(
    global: &GlobalOptions,
    cmd: &ClusterCliCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    match cmd {
        ClusterCliCommand::Diagnose { link, db_path } => {
            let resolved_db = resolve_cluster_db_path(global, db_path.as_deref())?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "cluster",
                    "diagnose",
                    format!(
                        "[DRY-RUN] Would diagnose peer link '{}' from {} via runner socket {}",
                        link,
                        resolved_db.display(),
                        global.socket_path.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "link": link,
                        "db_path": resolved_db,
                        "socket_path": global.socket_path,
                    })),
                ));
            }

            let report = build_cluster_diagnose_report(link, &resolved_db, transport)?;
            let human = render_diagnose_report_human(&report);
            let data = serde_json::to_value(&report).map_err(|err| {
                CliError::Execution(format!("failed serializing diagnose report: {err}"))
            })?;
            Ok(CliResponseEnvelope::success(
                "cluster",
                "diagnose",
                human,
                Some(data),
            ))
        }
    }
}

pub(crate) fn resolve_cluster_db_path(
    global: &GlobalOptions,
    explicit_db: Option<&Path>,
) -> CliResult<PathBuf> {
    let isolated_root =
        af_models::try_resolve_isolated_root_with_env(global.root.as_deref(), |key| {
            std::env::var(key).ok()
        })
        .map_err(CliError::Validation)?;

    if let Some(explicit) = explicit_db {
        if explicit.as_os_str().is_empty() || explicit.to_string_lossy().trim().is_empty() {
            return Err(CliError::Validation(
                "--db path must not be empty".to_string(),
            ));
        }
        if let Some(ref root) = isolated_root {
            return af_models::validate_path_within_isolated_root(explicit, root, "--db")
                .map_err(CliError::Validation);
        }
        return Ok(explicit.to_path_buf());
    }

    af_models::try_resolve_active_db_path_from_env(
        global.root.as_deref(),
        "/var/lib/aetherflow/aetherflow.sqlite",
    )
    .map_err(CliError::Validation)
}

fn open_readonly_db(db_path: &Path) -> CliResult<Connection> {
    if !db_path.exists() {
        return Err(CliError::Execution(format!(
            "SQLite database not found at {}",
            db_path.display()
        )));
    }
    if !db_path.is_file() {
        return Err(CliError::Validation(format!(
            "SQLite database path is not a regular file: {}",
            db_path.display()
        )));
    }
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| {
        CliError::Execution(format!(
            "failed to open SQLite database '{}' read-only: {}",
            db_path.display(),
            err
        ))
    })?;
    let _ = conn.busy_timeout(Duration::from_secs(3));
    Ok(conn)
}

fn table_exists(conn: &Connection, table_name: &str) -> CliResult<bool> {
    let exists: i64 = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table_name],
            |row| row.get(0),
        )
        .map_err(|err| {
            CliError::Execution(format!(
                "failed checking SQLite schema for table '{}': {}",
                table_name, err
            ))
        })?;
    Ok(exists != 0)
}

fn find_peer_link(conn: &Connection, selector: &str) -> CliResult<PeerLink> {
    let trimmed = selector.trim();
    if trimmed.is_empty() {
        return Err(CliError::Validation(
            "peer link selector must not be empty".to_string(),
        ));
    }

    if let Some(link) = get_peer_link(conn, trimmed)
        .map_err(|err| CliError::Execution(format!("failed querying peer_links by id: {err}")))?
    {
        return Ok(link);
    }

    if let Some(link) = get_peer_link_by_name(conn, trimmed)
        .map_err(|err| CliError::Execution(format!("failed querying peer_links by name: {err}")))?
    {
        return Ok(link);
    }

    let all_links = list_peer_links(conn)
        .map_err(|err| CliError::Execution(format!("failed listing peer_links: {err}")))?;
    if let Some(link) = all_links
        .into_iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(trimmed))
    {
        return Ok(link);
    }

    Err(CliError::Execution(format!(
        "peer link {:?} not found",
        trimmed
    )))
}

fn parse_string_list_json(raw: Option<&str>) -> Vec<String> {
    let Some(text) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Vec::new();
    };
    if let Ok(parsed) = serde_json::from_str::<Vec<String>>(text) {
        return parsed;
    }
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) fn redact_diagnostic_secrets(input: &str, exact_secrets: &[String]) -> String {
    let mut out = input.to_string();
    for secret in exact_secrets {
        let trimmed = secret.trim();
        if trimmed.len() >= 8 {
            out = out.replace(trimmed, REDACTED_MARKER);
        }
    }
    out = PAIRING_STRING_RE
        .replace_all(&out, REDACTED_MARKER)
        .into_owned();
    out = SECRET_KV_RE
        .replace_all(&out, format!("$1{REDACTED_MARKER}"))
        .into_owned();
    out = BEARER_RE
        .replace_all(&out, format!("$1{REDACTED_MARKER}"))
        .into_owned();
    out = HEX_SECRET_RE
        .replace_all(&out, REDACTED_MARKER)
        .into_owned();
    out = WG_KEY_B64_RE
        .replace_all(&out, REDACTED_MARKER)
        .into_owned();
    out
}

fn redact_optional(value: Option<&str>, exact_secrets: &[String]) -> Option<String> {
    value.map(|s| redact_diagnostic_secrets(s, exact_secrets))
}

fn collect_exact_secrets(
    link: &PeerLink,
    grants: &[PeerGrant],
    received_grant: Option<&PeerReceivedGrant>,
) -> Vec<String> {
    let mut secrets = Vec::new();
    if let Some(ref hash) = link.inbound_token_hash {
        if !hash.trim().is_empty() {
            secrets.push(hash.clone());
        }
    }
    for grant in grants {
        if let Some(ref hash) = grant.token_hash {
            if !hash.trim().is_empty() {
                secrets.push(hash.clone());
            }
        }
    }
    if let Some(received) = received_grant {
        if let Some(ref cid) = received.credential_id {
            if !cid.trim().is_empty() && cid != &link.id {
                secrets.push(cid.clone());
            }
        }
    }
    secrets
}

fn build_wireguard_summary(
    link: &PeerLink,
    transport: &dyn RunnerClientTransport,
    exact_secrets: &[String],
) -> WireGuardHandshakeSummary {
    match transport.query_peer_network_status() {
        Ok(status) => {
            let matched = status
                .peers
                .iter()
                .find(|peer| peer.public_key == link.wg_pubkey);
            match matched {
                Some(peer) => WireGuardHandshakeSummary {
                    available: true,
                    interface: status.interface,
                    interface_state: status.state,
                    service_state: status.service_state,
                    peer_found: true,
                    present_live: peer.present_live,
                    persistent: peer.persistent,
                    active: peer.active,
                    endpoint: (!peer.endpoint.trim().is_empty()).then(|| peer.endpoint.clone()),
                    allowed_ips: (!peer.allowed_ips.trim().is_empty())
                        .then(|| peer.allowed_ips.clone()),
                    latest_handshake: (!peer.latest_handshake.trim().is_empty())
                        .then(|| peer.latest_handshake.clone()),
                    latest_handshake_epoch: (peer.latest_handshake_epoch > 0)
                        .then_some(peer.latest_handshake_epoch),
                    handshake_age_secs: peer.handshake_age_secs,
                    rx_bytes: peer.transfer_rx.trim().parse::<u64>().ok(),
                    tx_bytes: peer.transfer_tx.trim().parse::<u64>().ok(),
                    error: redact_optional(status.error.as_deref(), exact_secrets),
                },
                None => WireGuardHandshakeSummary {
                    available: true,
                    interface: status.interface,
                    interface_state: status.state,
                    service_state: status.service_state,
                    peer_found: false,
                    present_live: false,
                    persistent: false,
                    active: false,
                    endpoint: None,
                    allowed_ips: None,
                    latest_handshake: None,
                    latest_handshake_epoch: None,
                    handshake_age_secs: None,
                    rx_bytes: None,
                    tx_bytes: None,
                    error: redact_optional(status.error.as_deref(), exact_secrets),
                },
            }
        }
        Err(err) => WireGuardHandshakeSummary {
            available: false,
            interface: "afpeer0".to_string(),
            interface_state: "unavailable".to_string(),
            service_state: "unknown".to_string(),
            peer_found: false,
            present_live: false,
            persistent: false,
            active: false,
            endpoint: None,
            allowed_ips: None,
            latest_handshake: None,
            latest_handshake_epoch: None,
            handshake_age_secs: None,
            rx_bytes: None,
            tx_bytes: None,
            error: Some(redact_diagnostic_secrets(&err.to_string(), exact_secrets)),
        },
    }
}

fn build_mount_diagnostics(
    mounts: Vec<PeerMount>,
    transport: &dyn RunnerClientTransport,
    exact_secrets: &[String],
) -> Vec<MountDiagnosticEntry> {
    mounts
        .into_iter()
        .map(|mount| {
            if mount.purpose != "media" {
                let safe_purpose = redact_diagnostic_secrets(&mount.purpose, exact_secrets);
                return MountDiagnosticEntry {
                    id: mount.id,
                    remote_path: mount.remote_path,
                    mount_path: mount.mount_path,
                    unit_name: mount.unit_name,
                    writable: mount.writable,
                    purpose: mount.purpose,
                    state: mount.state,
                    last_error: redact_optional(mount.last_error.as_deref(), exact_secrets),
                    live_exists: None,
                    live_active: None,
                    live_unit_state: None,
                    live_error: None,
                    probe: None,
                    probe_skipped_reason: Some(format!(
                        "non-media mount purpose '{safe_purpose}' is not managed by /v1/peer-storage live mount/sentinel probes"
                    )),
                };
            }

            let (live_exists, live_active, live_unit_state, live_error) =
                match transport.query_peer_mount_status(&mount.mount_path) {
                    Ok(state) => (
                        Some(state.exists),
                        Some(state.active),
                        Some(state.unit_state),
                        None,
                    ),
                    Err(err) => (
                        None,
                        None,
                        None,
                        Some(redact_diagnostic_secrets(&err.to_string(), exact_secrets)),
                    ),
                };

            let default_sentinel_path = format!(
                "{}/{}",
                mount.mount_path.trim_end_matches('/'),
                af_runner::PEER_SENTINEL_FILE_NAME
            );
            let probe = match transport.probe_peer_mount_sentinel(&mount.mount_path, None) {
                Ok(probed) => SentinelProbeSummary {
                    ok: probed.healthy,
                    timed_out: probed.timed_out,
                    checked_path: if probed.sentinel_path.trim().is_empty() {
                        default_sentinel_path
                    } else {
                        probed.sentinel_path
                    },
                    error: redact_optional(probed.error.as_deref(), exact_secrets),
                },
                Err(err) => SentinelProbeSummary {
                    ok: false,
                    timed_out: false,
                    checked_path: default_sentinel_path,
                    error: Some(redact_diagnostic_secrets(&err.to_string(), exact_secrets)),
                },
            };

            MountDiagnosticEntry {
                id: mount.id,
                remote_path: mount.remote_path,
                mount_path: mount.mount_path,
                unit_name: mount.unit_name,
                writable: mount.writable,
                purpose: mount.purpose,
                state: mount.state,
                last_error: redact_optional(mount.last_error.as_deref(), exact_secrets),
                live_exists,
                live_active,
                live_unit_state,
                live_error,
                probe: Some(probe),
                probe_skipped_reason: None,
            }
        })
        .collect()
}

fn build_transcode_summary(
    worker: Option<TranscodeWorker>,
    jobs: Vec<TranscodeJob>,
    exact_secrets: &[String],
) -> TranscodeWorkerDiagnostic {
    let recent_jobs = jobs
        .into_iter()
        .map(|job| TranscodeJobSummary {
            id: job.id,
            started_at: job.started_at,
            ended_at: job.ended_at,
            exit_code: job.exit_code,
            request_id: job.request_id,
            ran_locally: job.ran_locally,
        })
        .collect();

    match worker {
        Some(w) => TranscodeWorkerDiagnostic {
            configured: true,
            enabled: w.enabled,
            weight: Some(w.weight),
            max_jobs: Some(w.max_jobs),
            ffmpeg_version: w.ffmpeg_version,
            encoders: parse_string_list_json(w.encoders.as_deref()),
            render_node: w.render_node,
            parity_ok: w.parity_ok,
            parity_error: redact_optional(w.parity_error.as_deref(), exact_secrets),
            recent_jobs,
        },
        None => TranscodeWorkerDiagnostic {
            configured: false,
            enabled: false,
            weight: None,
            max_jobs: None,
            ffmpeg_version: None,
            encoders: Vec::new(),
            render_node: None,
            parity_ok: false,
            parity_error: None,
            recent_jobs,
        },
    }
}

fn table_has_column(conn: &Connection, table_name: &str, col_name: &str) -> bool {
    let sql = format!("PRAGMA table_info({table_name})");
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return false;
    };
    let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(1)) else {
        return false;
    };
    for name in rows.flatten() {
        if name == col_name {
            return true;
        }
    }
    false
}

fn query_link_audit_entries(
    conn: &Connection,
    link: &PeerLink,
    grants: &[PeerGrant],
    received_grant: Option<&PeerReceivedGrant>,
    exact_secrets: &[String],
) -> CliResult<Vec<AuditDiagnosticEntry>> {
    let table_name = if table_exists(conn, "admin_audit_log")? {
        "admin_audit_log"
    } else if table_exists(conn, "audit_logs")? {
        "audit_logs"
    } else {
        return Ok(Vec::new());
    };

    let detail_col = if table_has_column(conn, table_name, "detail") {
        "detail"
    } else if table_has_column(conn, table_name, "details") {
        "details"
    } else {
        return Ok(Vec::new());
    };
    let has_target_type = table_has_column(conn, table_name, "target_type");
    let has_target_id = table_has_column(conn, table_name, "target_id");
    let has_ip_address = table_has_column(conn, table_name, "ip_address");
    let has_created_at = table_has_column(conn, table_name, "created_at");

    let target_type_expr = if has_target_type {
        "COALESCE(target_type, '')"
    } else {
        "''"
    };
    let target_id_expr = if has_target_id {
        "COALESCE(target_id, '')"
    } else {
        "''"
    };
    let ip_expr = if has_ip_address {
        "COALESCE(ip_address, '')"
    } else {
        "''"
    };
    let created_expr = if has_created_at {
        "COALESCE(CAST(created_at AS TEXT), '')"
    } else {
        "''"
    };

    let peer_username = format!("peer-{}", link.name);
    let mut grant_ids: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for g in grants {
        if !g.id.trim().is_empty() && seen.insert(g.id.clone()) {
            grant_ids.push(g.id.clone());
        }
    }
    if let Some(received) = received_grant {
        if !received.grant_id.trim().is_empty() && seen.insert(received.grant_id.clone()) {
            grant_ids.push(received.grant_id.clone());
        }
    }

    let mut params: Vec<rusqlite::types::Value> = vec![
        rusqlite::types::Value::Text(link.id.clone()),
        rusqlite::types::Value::Text(peer_username),
        rusqlite::types::Value::Text(link.name.clone()),
    ];

    let mut predicates: Vec<String> = vec![
        "username = ?2".to_string(),
        format!("instr(COALESCE({detail_col}, ''), ?1) > 0"),
        format!("instr(COALESCE({detail_col}, ''), ?3) > 0"),
    ];
    if has_target_id {
        predicates.push("target_id = ?1".to_string());
    }

    for gid in grant_ids {
        params.push(rusqlite::types::Value::Text(gid));
        let idx = params.len();
        if has_target_id {
            predicates.push(format!("target_id = ?{idx}"));
        }
        predicates.push(format!("instr(COALESCE({detail_col}, ''), ?{idx}) > 0"));
    }

    params.push(rusqlite::types::Value::Integer(MAX_AUDIT_ENTRIES as i64));
    let limit_idx = params.len();

    let sql = format!(
        "SELECT id, COALESCE(username, ''), COALESCE(action, ''), {target_type_expr}, \
         {target_id_expr}, COALESCE({detail_col}, ''), {ip_expr}, {created_expr} \
         FROM {table_name} \
         WHERE {} \
         ORDER BY id DESC \
         LIMIT ?{limit_idx}",
        predicates.join(" OR ")
    );

    let mut stmt = conn.prepare(&sql).map_err(|err| {
        CliError::Execution(format!(
            "failed preparing audit query on {table_name}: {err}"
        ))
    })?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|err| {
            CliError::Execution(format!(
                "failed querying audit entries from {table_name}: {err}"
            ))
        })?;

    let mut entries = Vec::new();
    for row in rows {
        let (id, username, action, target_type, target_id, detail, ip_address, created_at) =
            row.map_err(|err| CliError::Execution(format!("failed decoding audit row: {err}")))?;
        entries.push(AuditDiagnosticEntry {
            id,
            username: redact_diagnostic_secrets(&username, exact_secrets),
            action: redact_diagnostic_secrets(&action, exact_secrets),
            target_type: redact_diagnostic_secrets(&target_type, exact_secrets),
            target_id: redact_diagnostic_secrets(&target_id, exact_secrets),
            detail: redact_diagnostic_secrets(&detail, exact_secrets),
            ip_address: redact_diagnostic_secrets(&ip_address, exact_secrets),
            created_at,
        });
    }
    Ok(entries)
}

pub(crate) fn build_cluster_diagnose_report(
    link_selector: &str,
    db_path: &Path,
    transport: &dyn RunnerClientTransport,
) -> CliResult<ClusterDiagnoseReport> {
    let conn = open_readonly_db(db_path)?;
    if !table_exists(&conn, "peer_links")? {
        return Err(CliError::Execution(format!(
            "peer_links table not found in {} (peer clustering schema not initialized)",
            db_path.display()
        )));
    }

    let link = find_peer_link(&conn, link_selector)?;

    let all_inbound_grants = if table_exists(&conn, "peer_grants")? {
        list_peer_grants_for_link(&conn, &link.id)
            .map_err(|err| CliError::Execution(format!("failed querying peer_grants: {err}")))?
    } else {
        Vec::new()
    };

    let inbound_grant = if table_exists(&conn, "peer_grants")? {
        get_active_peer_grant_for_link(&conn, &link.id)
            .map_err(|err| {
                CliError::Execution(format!("failed querying active peer_grant: {err}"))
            })?
            .or_else(|| all_inbound_grants.last().cloned())
    } else {
        None
    };

    let outbound_grant = if table_exists(&conn, "peer_received_grants")? {
        get_peer_received_grant(&conn, &link.id).map_err(|err| {
            CliError::Execution(format!("failed querying peer_received_grants: {err}"))
        })?
    } else {
        None
    };

    let exact_secrets = collect_exact_secrets(&link, &all_inbound_grants, outbound_grant.as_ref());

    let exports: Vec<ExportDiagnosticEntry> = if table_exists(&conn, "peer_exports")? {
        list_peer_exports_for_link(&conn, &link.id)
            .map_err(|err| CliError::Execution(format!("failed querying peer_exports: {err}")))?
            .into_iter()
            .map(|e: PeerExport| ExportDiagnosticEntry {
                id: e.id,
                path: e.path,
                writable: e.writable,
                squash_uid: e.squash_uid,
                squash_gid: e.squash_gid,
                created_at: e.created_at,
            })
            .collect()
    } else {
        Vec::new()
    };

    let raw_mounts = if table_exists(&conn, "peer_mounts")? {
        list_peer_mounts_for_link(&conn, &link.id)
            .map_err(|err| CliError::Execution(format!("failed querying peer_mounts: {err}")))?
    } else {
        Vec::new()
    };

    let worker = if table_exists(&conn, "transcode_workers")? {
        get_transcode_worker(&conn, &link.id).map_err(|err| {
            CliError::Execution(format!("failed querying transcode_workers: {err}"))
        })?
    } else {
        None
    };

    let recent_jobs = if table_exists(&conn, "transcode_jobs")? {
        list_transcode_jobs_for_link(&conn, &link.id, MAX_TRANSCODE_JOBS)
            .map_err(|err| CliError::Execution(format!("failed querying transcode_jobs: {err}")))?
    } else {
        Vec::new()
    };

    let audit = query_link_audit_entries(
        &conn,
        &link,
        &all_inbound_grants,
        outbound_grant.as_ref(),
        &exact_secrets,
    )?;

    let wireguard = build_wireguard_summary(&link, transport, &exact_secrets);
    let mounts = build_mount_diagnostics(raw_mounts, transport, &exact_secrets);
    let transcode_worker = build_transcode_summary(worker, recent_jobs, &exact_secrets);

    let public_state = public_link_state(&link.state).to_string();
    let wg_peer_owned = is_wg_peer_owned(&link.state);
    let link_summary = LinkHealthSummary {
        id: link.id,
        name: link.name,
        state: public_state,
        internal_state: link.state,
        wg_peer_owned,
        tunnel_ip: link.tunnel_ip,
        endpoint: link.endpoint,
        wg_port: link.wg_port,
        peer_version: link.peer_version,
        peer_protocol: link.peer_protocol,
        capabilities: parse_string_list_json(link.capabilities.as_deref()),
        rtt_ms: link.rtt_ms,
        last_ok_at: link.last_ok_at,
        last_error: redact_optional(link.last_error.as_deref(), &exact_secrets),
        consecutive_failures: link.consecutive_failures,
        created_at: link.created_at,
        updated_at: link.updated_at,
    };

    let grants = GrantAccessSummary {
        inbound: inbound_grant.map(|g| InboundGrantSummary {
            id: g.id,
            run_as_user_id: g.run_as_user_id,
            access: g.access,
            active: g.revoked_at.is_none() && g.token_hash.is_some(),
            created_by: g.created_by,
            created_at: g.created_at,
            revoked_at: g.revoked_at,
        }),
        outbound: outbound_grant.map(|g| OutboundGrantSummary {
            grant_id: g.grant_id,
            access: g.access,
            active: g.revoked_at.is_none(),
            created_by: g.created_by,
            created_at: g.created_at,
            generation: g.generation,
            revoked_at: g.revoked_at,
        }),
    };

    Ok(ClusterDiagnoseReport {
        db_path: db_path.to_path_buf(),
        link: link_summary,
        wireguard,
        grants,
        exports,
        mounts,
        transcode_worker,
        audit,
    })
}

fn format_access_map(access: &AccessMap) -> String {
    let entries = [
        ("services", access.services.as_str()),
        ("marketplace", access.marketplace.as_str()),
        ("settings", access.settings.as_str()),
        ("files", access.files.as_str()),
        ("users", access.users.as_str()),
        ("network", access.network.as_str()),
        ("updates", access.updates.as_str()),
        ("transcoding", access.transcoding.as_str()),
    ];
    entries
        .iter()
        .map(|(area, level)| format!("{area}={level}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn render_diagnose_report_human(report: &ClusterDiagnoseReport) -> String {
    let mut lines: Vec<String> = Vec::new();
    let link = &report.link;

    lines.push(format!(
        "=== Peer Link Diagnostics: {} ({}) ===",
        link.name, link.id
    ));
    lines.push(format!("Database: {}", report.db_path.display()));
    lines.push(String::new());

    lines.push("[Link Health]".to_string());
    lines.push(format!(
        "  State:                {} (internal: {}, wg_peer_owned: {})",
        link.state, link.internal_state, link.wg_peer_owned
    ));
    lines.push(format!("  Tunnel IP:            {}", link.tunnel_ip));
    lines.push(format!(
        "  Endpoint:             {}:{}",
        link.endpoint, link.wg_port
    ));
    lines.push(format!(
        "  Peer Version:         {}",
        link.peer_version.as_deref().unwrap_or("unknown")
    ));
    lines.push(format!(
        "  Peer Protocol:        {}",
        link.peer_protocol
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    lines.push(format!(
        "  Capabilities:         {}",
        if link.capabilities.is_empty() {
            "none".to_string()
        } else {
            link.capabilities.join(", ")
        }
    ));
    lines.push(format!(
        "  RTT:                  {}",
        link.rtt_ms
            .map(|ms| format!("{ms:.2} ms"))
            .unwrap_or_else(|| "n/a".to_string())
    ));
    lines.push(format!(
        "  Last OK:              {}",
        link.last_ok_at.as_deref().unwrap_or("never")
    ));
    lines.push(format!(
        "  Consecutive Failures: {}",
        link.consecutive_failures
    ));
    if let Some(ref err) = link.last_error {
        lines.push(format!("  Last Error:           {err}"));
    }
    lines.push(String::new());

    lines.push(format!("[WireGuard ({})]", report.wireguard.interface));
    if !report.wireguard.available {
        lines.push("  Status:               unavailable (runner unreachable)".to_string());
        if let Some(ref err) = report.wireguard.error {
            lines.push(format!("  Runner Error:         {err}"));
        }
    } else {
        lines.push(format!(
            "  Interface State:      {} (service: {})",
            report.wireguard.interface_state, report.wireguard.service_state
        ));
        lines.push(format!(
            "  Peer Live:            {} (persistent: {}, active: {})",
            report.wireguard.present_live, report.wireguard.persistent, report.wireguard.active
        ));
        lines.push(format!(
            "  Latest Handshake:     {}",
            report
                .wireguard
                .latest_handshake
                .as_deref()
                .unwrap_or("none")
        ));
        lines.push(format!(
            "  Handshake Age:        {}",
            report
                .wireguard
                .handshake_age_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "n/a".to_string())
        ));
        lines.push(format!(
            "  Transfer:             rx={} bytes, tx={} bytes",
            report
                .wireguard
                .rx_bytes
                .map(|b| b.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            report
                .wireguard
                .tx_bytes
                .map(|b| b.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ));
        if let Some(ref err) = report.wireguard.error {
            lines.push(format!("  Warning:              {err}"));
        }
    }
    lines.push(String::new());

    lines.push("[Grants]".to_string());
    match &report.grants.inbound {
        Some(g) => {
            let status = if g.active {
                "active".to_string()
            } else if let Some(ref rev) = g.revoked_at {
                format!("revoked at {rev}")
            } else {
                "inactive".to_string()
            };
            lines.push(format!(
                "  Inbound grant (this server -> peer):  {} ({}, run_as_user_id={}, created_by={}, created_at={})",
                g.id, status, g.run_as_user_id, g.created_by, g.created_at
            ));
            lines.push(format!(
                "    Access:                             {}",
                format_access_map(&g.access)
            ));
        }
        None => lines.push("  Inbound grant (this server -> peer):  none".to_string()),
    }
    match &report.grants.outbound {
        Some(g) => {
            let status = if g.active {
                "active".to_string()
            } else if let Some(ref rev) = g.revoked_at {
                format!("revoked at {rev}")
            } else {
                "inactive".to_string()
            };
            lines.push(format!(
                "  Outbound grant (peer -> this server): {} ({}, gen={}, created_by={})",
                if g.grant_id.is_empty() {
                    "(revoked)"
                } else {
                    g.grant_id.as_str()
                },
                status,
                g.generation,
                g.created_by
            ));
            lines.push(format!(
                "    Access:                             {}",
                format_access_map(&g.access)
            ));
        }
        None => lines.push("  Outbound grant (peer -> this server): none".to_string()),
    }
    lines.push(String::new());

    lines.push(format!("[Exports ({})]", report.exports.len()));
    if report.exports.is_empty() {
        lines.push("  (none)".to_string());
    } else {
        for export in &report.exports {
            let mode = if export.writable { "rw" } else { "ro" };
            let squash = match (export.squash_uid, export.squash_gid) {
                (Some(uid), Some(gid)) => format!(" squash={uid}:{gid}"),
                _ => String::new(),
            };
            lines.push(format!(
                "  - {} [{}] ({}{})",
                export.path, export.id, mode, squash
            ));
        }
    }
    lines.push(String::new());

    lines.push(format!("[Mounts ({})]", report.mounts.len()));
    if report.mounts.is_empty() {
        lines.push("  (none)".to_string());
    } else {
        for mount in &report.mounts {
            let mode = if mount.writable { "rw" } else { "ro" };
            let live_desc = match (
                &mount.live_unit_state,
                &mount.live_error,
                &mount.probe_skipped_reason,
            ) {
                (Some(unit_state), None, _) => format!(
                    "unit={} (exists={}, active={})",
                    unit_state,
                    mount.live_exists.unwrap_or(false),
                    mount.live_active.unwrap_or(false)
                ),
                (_, Some(err), _) => format!("runner_error={err}"),
                (None, None, Some(_)) => format!("skipped ({} mount)", mount.purpose),
                _ => "unavailable".to_string(),
            };
            let probe_desc = match &mount.probe {
                Some(probe) if probe.ok => format!("ok ({})", probe.checked_path),
                Some(probe) => {
                    let err = probe.error.as_deref().unwrap_or(if probe.timed_out {
                        "timed out"
                    } else {
                        "failed"
                    });
                    format!("failed ({}: {})", probe.checked_path, err)
                }
                None => match &mount.probe_skipped_reason {
                    Some(reason) => format!("skipped ({reason})"),
                    None => "skipped".to_string(),
                },
            };
            lines.push(format!(
                "  - {} -> {} [{}, {}, db_state={}]",
                mount.remote_path, mount.mount_path, mount.purpose, mode, mount.state
            ));
            lines.push(format!(
                "    Unit: {} | Live: {} | Sentinel: {}",
                mount.unit_name, live_desc, probe_desc
            ));
            if let Some(ref err) = mount.last_error {
                lines.push(format!("    DB Last Error: {err}"));
            }
        }
    }
    lines.push(String::new());

    lines.push("[Transcode Worker]".to_string());
    let tw = &report.transcode_worker;
    if !tw.configured {
        lines.push("  Configured:           no".to_string());
    } else {
        lines.push(format!(
            "  Enabled:              {} (weight={}, max_jobs={})",
            tw.enabled,
            tw.weight.unwrap_or(1),
            tw.max_jobs.unwrap_or(2)
        ));
        lines.push(format!(
            "  FFmpeg Version:       {}",
            tw.ffmpeg_version.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "  Encoders:             {}",
            if tw.encoders.is_empty() {
                "none".to_string()
            } else {
                tw.encoders.join(", ")
            }
        ));
        lines.push(format!(
            "  Render Node:          {}",
            tw.render_node.as_deref().unwrap_or("none")
        ));
        lines.push(format!("  Parity OK:            {}", tw.parity_ok));
        if let Some(ref err) = tw.parity_error {
            lines.push(format!("  Parity Error:         {err}"));
        }
    }
    lines.push(format!("  Recent Jobs ({}):", tw.recent_jobs.len()));
    if tw.recent_jobs.is_empty() {
        lines.push("    (none)".to_string());
    } else {
        for job in &tw.recent_jobs {
            let loc = if job.ran_locally { "local" } else { "remote" };
            let exit = job
                .exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "running".to_string());
            lines.push(format!(
                "    - {} [{}] started={} ended={} exit={}",
                job.id,
                loc,
                job.started_at,
                job.ended_at.as_deref().unwrap_or("-"),
                exit
            ));
        }
    }
    lines.push(String::new());

    lines.push(format!(
        "[Audit Trail (last {} entries)]",
        report.audit.len()
    ));
    if report.audit.is_empty() {
        lines.push("  (none)".to_string());
    } else {
        for entry in &report.audit {
            lines.push(format!(
                "  - #{} [{}] {} {} ({}:{}) {}",
                entry.id,
                entry.created_at,
                entry.username,
                entry.action,
                entry.target_type,
                entry.target_id,
                entry.detail
            ));
        }
    }

    lines.join("\n")
}
