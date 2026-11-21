//! Durable worker-side command execution receipts, confined `0600` ACK outbox,
//! lease-generation reattachment, startup legacy reconciliation, and fail-closed backpressure.

use super::{
    truncate_diagnostic_utf8, truncate_utf8, PendingWorkerCommand, WorkerCommandAck,
    WORKER_COMMAND_STATUS_EXECUTED, WORKER_COMMAND_STATUS_FAILED, WORKER_COMMAND_STATUS_UNKNOWN,
};
use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::env;
#[cfg(not(unix))]
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

const MAX_WORKER_ACK_OUTBOX_ENTRIES: usize = 256;
const MAX_WORKER_ACK_OUTBOX_BYTES: usize = 512 * 1024;
const MAX_WORKER_COMMAND_RECEIPTS: usize = 256;
const MAX_WORKER_COMMAND_RECEIPTS_BYTES: usize = 512 * 1024;
const MAX_RECEIPT_RESULT_MESSAGE_BYTES: usize = 1024;
const MAX_RECEIPT_RESULT_MESSAGE_JSON_BYTES: usize = 1280;
const RECEIPT_INTENT_COMPLETION_HEADROOM_BYTES: usize = 1536;
const OUTBOX_INTENT_COMPLETION_HEADROOM_BYTES: usize = 1536;

/// Resolves the durable `0600` worker command-ack outbox file path.
pub fn resolve_worker_ack_outbox_path(state_path: &Path) -> std::path::PathBuf {
    if let Ok(explicit) = env::var("CLUSTER_WORKER_ACK_OUTBOX_FILE") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    state_path
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/aetherflow"))
        .join("cluster_worker_ack_outbox.json")
}

/// Resolves the durable confined `0600` worker command execution receipt ledger path.
pub fn resolve_worker_command_receipts_path(outbox_path: &Path) -> std::path::PathBuf {
    if let Ok(explicit) = env::var("CLUSTER_WORKER_COMMAND_RECEIPTS_FILE") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    outbox_path
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/aetherflow"))
        .join("cluster_worker_command_receipts.json")
}

fn validate_worker_ack_outbox(acks: &[WorkerCommandAck]) -> anyhow::Result<()> {
    anyhow::ensure!(
        acks.len() <= MAX_WORKER_ACK_OUTBOX_ENTRIES,
        "worker ack outbox exceeds maximum entry limit ({} > {})",
        acks.len(),
        MAX_WORKER_ACK_OUTBOX_ENTRIES
    );
    let mut seen = std::collections::HashSet::with_capacity(acks.len());
    for ack in acks {
        let clean_id = ack.id.trim();
        anyhow::ensure!(
            !clean_id.is_empty(),
            "worker ack outbox contains an entry with empty command id"
        );
        anyhow::ensure!(
            seen.insert(clean_id),
            "worker ack outbox contains duplicate command id '{}'",
            truncate_diagnostic_utf8(clean_id, 64)
        );
        anyhow::ensure!(
            WorkerCommandReceiptPhase::from_ack_status(&ack.status).is_some(),
            "worker ack outbox contains unsupported status '{}' for '{}'",
            truncate_diagnostic_utf8(&ack.status, 64),
            truncate_diagnostic_utf8(clean_id, 64)
        );
        anyhow::ensure!(
            !matches!(ack.lease_generation, Some(g) if g <= 0),
            "worker ack outbox contains non-positive lease_generation for '{}'",
            truncate_diagnostic_utf8(clean_id, 64)
        );
    }
    Ok(())
}

fn serialize_worker_ack_outbox_bounded(acks: &[WorkerCommandAck]) -> anyhow::Result<Vec<u8>> {
    validate_worker_ack_outbox(acks)?;
    let pretty = serde_json::to_vec_pretty(acks)?;
    if pretty.len() <= MAX_WORKER_ACK_OUTBOX_BYTES {
        return Ok(pretty);
    }
    let compact = serde_json::to_vec(acks)?;
    anyhow::ensure!(
        compact.len() <= MAX_WORKER_ACK_OUTBOX_BYTES,
        "worker ack outbox exceeds maximum byte bound ({} > {} bytes)",
        compact.len(),
        MAX_WORKER_ACK_OUTBOX_BYTES
    );
    Ok(compact)
}

/// Atomically persists bounded unconfirmed worker command acks (`0600`, confined `O_NOFOLLOW`),
/// failing closed instead of silently dropping unconfirmed entries or writing oversized files.
pub fn persist_worker_ack_outbox_atomic(
    path: &Path,
    acks: &[WorkerCommandAck],
) -> anyhow::Result<()> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        anyhow::bail!("worker ack outbox path must have a parent directory");
    };
    let Some(file_name) = path.file_name() else {
        anyhow::bail!("worker ack outbox path must have a filename");
    };

    let payload = serialize_worker_ack_outbox_bounded(acks)?;

    #[cfg(unix)]
    {
        let dir = af_runner::job_receipts::ReceiptDirectory::open_confined(parent, true, 0o700)
            .context("opening confined worker ack outbox directory")?;
        dir.write_regular_atomic(file_name, &payload, 0o600)
            .context("atomically persisting confined 0600 worker ack outbox")?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;
        std::fs::create_dir_all(parent).context("creating worker ack outbox parent directory")?;
        let tmp_name = format!(
            ".cluster_worker_ack_outbox.{}.tmp",
            uuid::Uuid::new_v4().simple()
        );
        let tmp_path = parent.join(tmp_name);
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        if let Err(err) = tmp_file
            .write_all(&payload)
            .and_then(|_| tmp_file.sync_all())
        {
            drop(tmp_file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err).context("writing worker ack outbox temp file");
        }
        drop(tmp_file);
        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err).context("atomically activating worker ack outbox file");
        }
        Ok(())
    }
}

/// Strictly loads persisted unconfirmed worker command acks using confined `O_NOFOLLOW` I/O.
/// Missing files return `Ok(Vec::new())`; symlinks, hardlinks, non-regular files, oversized files,
/// malformed JSON, or invalid entries fail closed with `Err`.
pub fn load_worker_ack_outbox_strict(path: &Path) -> anyhow::Result<Vec<WorkerCommandAck>> {
    let raw_opt = {
        #[cfg(unix)]
        {
            let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
                anyhow::bail!("worker ack outbox path must have a parent directory");
            };
            let Some(file_name) = path.file_name() else {
                anyhow::bail!("worker ack outbox path must have a filename");
            };
            let Some(dir) = af_runner::job_receipts::ReceiptDirectory::open_existing(parent)
                .context("opening confined worker ack outbox directory")?
            else {
                return Ok(Vec::new());
            };
            dir.read_regular_bounded(file_name, MAX_WORKER_ACK_OUTBOX_BYTES)
                .context("reading confined worker ack outbox")?
        }
        #[cfg(not(unix))]
        {
            match std::fs::File::open(path) {
                Ok(file) => {
                    let mut buf = Vec::new();
                    file.take((MAX_WORKER_ACK_OUTBOX_BYTES as u64) + 1)
                        .read_to_end(&mut buf)?;
                    if buf.len() > MAX_WORKER_ACK_OUTBOX_BYTES {
                        anyhow::bail!("worker ack outbox exceeds maximum size");
                    }
                    Some(buf)
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(err.into()),
            }
        }
    };

    let Some(raw) = raw_opt else {
        return Ok(Vec::new());
    };
    let parsed: Vec<WorkerCommandAck> =
        serde_json::from_slice(&raw).context("parsing worker ack outbox JSON")?;
    validate_worker_ack_outbox(&parsed)?;
    Ok(parsed)
}

/// Loads persisted unconfirmed worker command acks safely using confined `O_NOFOLLOW` I/O.
pub fn load_worker_ack_outbox_nofollow(path: &Path) -> Vec<WorkerCommandAck> {
    load_worker_ack_outbox_strict(path).unwrap_or_default()
}

/// Appends or updates an unconfirmed ack and durably persists the `0600` outbox before updating
/// memory. Fails closed rather than dropping existing unconfirmed entries when saturated.
pub fn enqueue_worker_ack_outbox_entry(
    outbox_path: &Path,
    pending: &mut Vec<WorkerCommandAck>,
    ack: WorkerCommandAck,
) -> anyhow::Result<()> {
    let mut next = pending.clone();
    if let Some(existing) = next.iter_mut().find(|a| a.id == ack.id) {
        *existing = ack;
    } else {
        anyhow::ensure!(
            next.len() < MAX_WORKER_ACK_OUTBOX_ENTRIES,
            "worker ack outbox saturated at {} unconfirmed entries",
            MAX_WORKER_ACK_OUTBOX_ENTRIES
        );
        next.push(ack);
    }
    persist_worker_ack_outbox_atomic(outbox_path, &next)?;
    *pending = next;
    Ok(())
}

/// Evicts ONLY those ack entries whose command IDs appear in `confirmed_command_ids`.
pub fn evict_confirmed_acks_from_outbox(
    outbox_path: &Path,
    pending: &mut Vec<WorkerCommandAck>,
    confirmed_ids: &[String],
) -> anyhow::Result<()> {
    if confirmed_ids.is_empty() {
        return Ok(());
    }
    let mut next = pending.clone();
    next.retain(|ack| !confirmed_ids.iter().any(|cid| cid == &ack.id));
    if next.len() != pending.len() {
        persist_worker_ack_outbox_atomic(outbox_path, &next)?;
        *pending = next;
    }
    Ok(())
}

/// Durable worker-side command execution phase.
///
/// Recovery contract and limits:
/// - `Intent` is persisted (`0600`, confined `O_NOFOLLOW`, `flock`, `fsync`) before admitting any
///   non-idempotent host mutation (`restart_service`, `start_service`, `stop_service`,
///   `reload_service`, `systemctl`).
/// - If a worker crashes or restarts after persisting `Intent` and before persisting a final
///   outcome, startup recovery transitions `Intent` to `Unknown` rather than guessing `Executed`
///   or `Failed` or replaying the mutation.
/// - Terminal receipts (`Executed`, `Failed`, `Unknown`) are persisted before ACK and reattached
///   to freshly observed higher `lease_generation` values without rerunning the side effect.
/// - Storage is bounded to `MAX_WORKER_COMMAND_RECEIPTS` (256) entries and
///   `MAX_WORKER_COMMAND_RECEIPTS_BYTES` (512 KiB); only master-confirmed terminal receipts are
///   recycled. When saturated by unconfirmed outcomes or active intents, new dispatches fail
///   closed with backpressure while existing commands, reattachments, and ACKs continue to drain.
///   Loss or deletion of the worker state directory removes local intent/outcome history.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerCommandReceiptPhase {
    Intent,
    Executed,
    Failed,
    Unknown,
}

impl WorkerCommandReceiptPhase {
    #[inline]
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Intent)
    }

    pub fn as_ack_status(self) -> Option<&'static str> {
        match self {
            Self::Intent => None,
            Self::Executed => Some(WORKER_COMMAND_STATUS_EXECUTED),
            Self::Failed => Some(WORKER_COMMAND_STATUS_FAILED),
            Self::Unknown => Some(WORKER_COMMAND_STATUS_UNKNOWN),
        }
    }

    fn from_ack_status(status: &str) -> Option<Self> {
        match status.trim().to_ascii_lowercase().as_str() {
            WORKER_COMMAND_STATUS_EXECUTED => Some(Self::Executed),
            WORKER_COMMAND_STATUS_FAILED => Some(Self::Failed),
            WORKER_COMMAND_STATUS_UNKNOWN => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Durable confined worker-side execution receipt (`cluster_worker_command_receipts.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerCommandReceipt {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub phase: WorkerCommandReceiptPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
    #[serde(default)]
    pub ack_confirmed: bool,
    #[serde(default)]
    pub updated_at: String,
}

impl WorkerCommandReceipt {
    pub fn to_ack(&self) -> Option<WorkerCommandAck> {
        let status = self.phase.as_ack_status()?;
        Some(WorkerCommandAck {
            id: self.id.clone(),
            status: status.to_string(),
            result_message: self.result_message.clone(),
            lease_generation: self.lease_generation,
        })
    }

    fn matches_identity(&self, identity: &WorkerCommandIdentity) -> bool {
        if let Some(ref recorded_node) = self.node_id {
            if recorded_node != &identity.node_id {
                return false;
            }
        }
        if let Some(ref recorded_type) = self.cmd_type {
            if recorded_type != &identity.cmd_type {
                return false;
            }
        }
        if let Some(ref recorded_target) = self.target {
            if recorded_target != &identity.target {
                return false;
            }
        }
        if self.cmd_type.is_some() && self.action != identity.action {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerCommandIdentity {
    node_id: String,
    cmd_type: String,
    target: String,
    action: Option<String>,
}

fn extract_command_lease_generation(cmd: &PendingWorkerCommand) -> Option<i64> {
    (cmd.lease_generation > 0)
        .then_some(cmd.lease_generation)
        .or_else(|| {
            cmd.params
                .get("lease_generation")
                .and_then(|s| s.parse::<i64>().ok())
                .filter(|&g| g > 0)
        })
}

fn resolve_service_action(cmd: &PendingWorkerCommand) -> Option<&'static str> {
    match cmd.cmd_type.trim() {
        "restart_service" => Some("restart"),
        "start_service" => Some("start"),
        "stop_service" => Some("stop"),
        "reload_service" => Some("reload"),
        "systemctl" => match cmd.params.get("action").map(|s| s.trim()) {
            Some("restart") => Some("restart"),
            Some("start") => Some("start"),
            Some("stop") => Some("stop"),
            Some("reload") => Some("reload"),
            _ => Some("restart"),
        },
        _ => None,
    }
}

fn resolve_command_target(cmd: &PendingWorkerCommand) -> String {
    cmd.params
        .get("service")
        .or_else(|| cmd.params.get("target"))
        .or_else(|| cmd.params.get("package"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

impl WorkerCommandIdentity {
    fn from_command(node_id: &str, cmd: &PendingWorkerCommand) -> Self {
        Self {
            node_id: node_id.trim().to_string(),
            cmd_type: cmd.cmd_type.trim().to_string(),
            target: resolve_command_target(cmd),
            action: resolve_service_action(cmd).map(str::to_string),
        }
    }
}

fn truncate_receipt_result_message(input: &str) -> String {
    let mut s = truncate_utf8(input, MAX_RECEIPT_RESULT_MESSAGE_BYTES);
    while serde_json::to_string(s)
        .map(|encoded| encoded.len())
        .unwrap_or(usize::MAX)
        > MAX_RECEIPT_RESULT_MESSAGE_JSON_BYTES
    {
        let Some((last_idx, _)) = s.char_indices().next_back() else {
            return String::new();
        };
        s = &s[..last_idx];
    }
    s.to_string()
}

fn build_interrupted_intent_unknown_message(receipt: &WorkerCommandReceipt) -> String {
    let op = receipt
        .action
        .as_deref()
        .or(receipt.cmd_type.as_deref())
        .unwrap_or("service command");
    let target = receipt
        .target
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown target");
    truncate_receipt_result_message(&format!(
        "worker restarted after persisting execution intent for {op} {target} before a final outcome was recorded; mutation may have occurred — inspect service state before retrying"
    ))
}

#[inline]
fn is_recyclable_receipt(receipt: &WorkerCommandReceipt) -> bool {
    receipt.ack_confirmed && receipt.phase.is_terminal()
}

fn recycle_confirmed_worker_command_receipts(
    receipts: &mut Vec<WorkerCommandReceipt>,
    max_entries: usize,
) -> usize {
    let mut recycled = 0;
    while receipts.len() > max_entries {
        if let Some(pos) = receipts.iter().position(is_recyclable_receipt) {
            receipts.remove(pos);
            recycled += 1;
        } else {
            break;
        }
    }
    recycled
}

fn validate_worker_command_receipts(receipts: &[WorkerCommandReceipt]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::with_capacity(receipts.len());
    for receipt in receipts {
        let clean_id = receipt.id.trim();
        anyhow::ensure!(
            !clean_id.is_empty(),
            "worker command receipts contain an entry with empty command id"
        );
        anyhow::ensure!(
            seen.insert(clean_id),
            "worker command receipts contain duplicate command id '{}'",
            truncate_diagnostic_utf8(clean_id, 64)
        );
        anyhow::ensure!(
            !matches!(receipt.lease_generation, Some(g) if g <= 0),
            "worker command receipts contain non-positive lease_generation for '{}'",
            truncate_diagnostic_utf8(clean_id, 64)
        );
        anyhow::ensure!(
            !(receipt.phase == WorkerCommandReceiptPhase::Intent && receipt.ack_confirmed),
            "worker command receipts contain confirmed intent for '{}'",
            truncate_diagnostic_utf8(clean_id, 64)
        );
    }
    Ok(())
}

fn prepare_receipts_for_persistence(
    receipts: &mut Vec<WorkerCommandReceipt>,
) -> anyhow::Result<Vec<u8>> {
    validate_worker_command_receipts(receipts)?;
    recycle_confirmed_worker_command_receipts(receipts, MAX_WORKER_COMMAND_RECEIPTS);
    anyhow::ensure!(
        receipts.len() <= MAX_WORKER_COMMAND_RECEIPTS,
        "worker command receipt ledger saturated: {} unconfirmed/intent receipts exceed limit {}",
        receipts.len(),
        MAX_WORKER_COMMAND_RECEIPTS
    );

    let mut payload = serde_json::to_vec_pretty(receipts)?;
    while payload.len() > MAX_WORKER_COMMAND_RECEIPTS_BYTES {
        if let Some(pos) = receipts.iter().position(is_recyclable_receipt) {
            receipts.remove(pos);
            payload = serde_json::to_vec_pretty(receipts)?;
        } else {
            break;
        }
    }
    if payload.len() > MAX_WORKER_COMMAND_RECEIPTS_BYTES {
        payload = serde_json::to_vec(receipts)?;
    }
    anyhow::ensure!(
        payload.len() <= MAX_WORKER_COMMAND_RECEIPTS_BYTES,
        "worker command receipt ledger exceeds maximum byte bound ({} > {} bytes) with no confirmed receipts available to recycle",
        payload.len(),
        MAX_WORKER_COMMAND_RECEIPTS_BYTES
    );
    Ok(payload)
}

fn persist_worker_command_receipts_in_place(
    path: &Path,
    receipts: &mut Vec<WorkerCommandReceipt>,
) -> anyhow::Result<()> {
    let payload = prepare_receipts_for_persistence(receipts)?;

    #[cfg(unix)]
    {
        let lock = af_runner::job_receipts::ConfinedFileLock::acquire(path, 0o700)
            .context("acquiring confined lock for worker command receipts")?;
        lock.write_atomic(&payload, 0o600)
            .context("atomically persisting confined 0600 worker command receipts")?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;
        let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
            anyhow::bail!("worker command receipts path must have a parent directory");
        };
        std::fs::create_dir_all(parent)?;
        let tmp_path = parent.join(format!(
            ".cluster_worker_command_receipts.{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        if let Err(err) = tmp_file
            .write_all(&payload)
            .and_then(|_| tmp_file.sync_all())
        {
            drop(tmp_file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err).context("writing worker command receipts temp file");
        }
        drop(tmp_file);
        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err).context("activating worker command receipts file");
        }
        Ok(())
    }
}

/// Atomically persists the bounded `0600` worker command execution receipt ledger via
/// `af_runner::job_receipts::ConfinedFileLock`. Recycles ONLY master-confirmed terminal receipts;
/// fails closed instead of dropping unconfirmed/intent entries or exceeding the byte bound.
pub fn persist_worker_command_receipts_atomic(
    path: &Path,
    receipts: &[WorkerCommandReceipt],
) -> anyhow::Result<()> {
    let mut bounded = receipts.to_vec();
    persist_worker_command_receipts_in_place(path, &mut bounded)
}

/// Strictly loads persisted worker command execution receipts using confined `O_NOFOLLOW` I/O.
/// Missing files return `Ok(Vec::new())`; symlinks, hardlinks, non-regular files, oversized files,
/// malformed JSON, invalid entries, or over-capacity unconfirmed ledgers fail closed with `Err`.
pub fn load_worker_command_receipts_strict(
    path: &Path,
) -> anyhow::Result<Vec<WorkerCommandReceipt>> {
    let raw_opt = {
        #[cfg(unix)]
        {
            let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
                anyhow::bail!("worker command receipts path must have a parent directory");
            };
            let Some(file_name) = path.file_name() else {
                anyhow::bail!("worker command receipts path must have a filename");
            };
            let Some(dir) = af_runner::job_receipts::ReceiptDirectory::open_existing(parent)
                .context("opening confined worker command receipts directory")?
            else {
                return Ok(Vec::new());
            };
            dir.read_regular_bounded(file_name, MAX_WORKER_COMMAND_RECEIPTS_BYTES)
                .context("reading confined worker command receipts")?
        }
        #[cfg(not(unix))]
        {
            match std::fs::File::open(path) {
                Ok(file) => {
                    let mut buf = Vec::new();
                    file.take((MAX_WORKER_COMMAND_RECEIPTS_BYTES as u64) + 1)
                        .read_to_end(&mut buf)?;
                    if buf.len() > MAX_WORKER_COMMAND_RECEIPTS_BYTES {
                        anyhow::bail!("worker command receipts exceed maximum size");
                    }
                    Some(buf)
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(err.into()),
            }
        }
    };

    let Some(raw) = raw_opt else {
        return Ok(Vec::new());
    };
    let mut parsed: Vec<WorkerCommandReceipt> =
        serde_json::from_slice(&raw).context("parsing worker command receipts JSON")?;
    validate_worker_command_receipts(&parsed)?;
    recycle_confirmed_worker_command_receipts(&mut parsed, MAX_WORKER_COMMAND_RECEIPTS);
    anyhow::ensure!(
        parsed.len() <= MAX_WORKER_COMMAND_RECEIPTS,
        "worker command receipt ledger contains {} unconfirmed/intent entries, exceeding limit {}",
        parsed.len(),
        MAX_WORKER_COMMAND_RECEIPTS
    );
    Ok(parsed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedServiceMutation {
    pub id: String,
    pub service: String,
    pub action: String,
    pub lease_generation: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkerCommandDispatchPlan {
    Execute(AdmittedServiceMutation),
    SendAckOnly(WorkerCommandAck),
    AlreadyInFlight,
    RejectedStaleLease,
    RejectedConflictingIdentity,
    RejectedCapacitySaturated,
    RejectedStorageFailure,
}

#[derive(Debug, Clone, Copy)]
enum CapacityBackpressureReason {
    ReceiptEntry,
    ReceiptByte,
    OutboxEntry,
    OutboxByte,
}

impl CapacityBackpressureReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptEntry => "receipt_entry_limit",
            Self::ReceiptByte => "receipt_byte_limit",
            Self::OutboxEntry => "outbox_entry_limit",
            Self::OutboxByte => "outbox_byte_limit",
        }
    }
}

struct WorkerCommandRuntimeState {
    node_id: String,
    receipts: Vec<WorkerCommandReceipt>,
    pending_acks: Vec<WorkerCommandAck>,
    in_flight: std::collections::HashSet<String>,
    storage_corrupt: Option<String>,
}

fn try_prepare_new_receipt_with_backpressure(
    guard: &WorkerCommandRuntimeState,
    candidate: WorkerCommandReceipt,
) -> Result<Vec<WorkerCommandReceipt>, CapacityBackpressureReason> {
    let candidate_ack = candidate.to_ack();
    let mut next_receipts = guard.receipts.clone();
    next_receipts.push(candidate);

    // 1. Entry bound: recycle ONLY master-confirmed terminal receipts.
    recycle_confirmed_worker_command_receipts(&mut next_receipts, MAX_WORKER_COMMAND_RECEIPTS);
    if next_receipts.len() > MAX_WORKER_COMMAND_RECEIPTS {
        return Err(CapacityBackpressureReason::ReceiptEntry);
    }

    // 2. Receipt byte bound (reserving worst-case completion headroom for every active `Intent`).
    let intent_count = next_receipts
        .iter()
        .filter(|r| r.phase == WorkerCommandReceiptPhase::Intent)
        .count();
    let receipt_headroom = intent_count.saturating_mul(RECEIPT_INTENT_COMPLETION_HEADROOM_BYTES);
    loop {
        let pretty_len = serde_json::to_vec_pretty(&next_receipts)
            .map(|buf| buf.len())
            .unwrap_or(usize::MAX);
        if pretty_len.saturating_add(receipt_headroom) <= MAX_WORKER_COMMAND_RECEIPTS_BYTES {
            break;
        }
        if let Some(pos) = next_receipts.iter().position(is_recyclable_receipt) {
            next_receipts.remove(pos);
        } else {
            return Err(CapacityBackpressureReason::ReceiptByte);
        }
    }

    // 3. Outbox entry and byte bounds (reserving future ACK slots & bytes for active `Intent`s).
    let mut projected_pending = guard.pending_acks.clone();
    if let Some(ack) = candidate_ack {
        if let Some(existing) = projected_pending.iter_mut().find(|a| a.id == ack.id) {
            *existing = ack;
        } else {
            projected_pending.push(ack);
        }
    }
    let pending_intent_slots = next_receipts
        .iter()
        .filter(|r| {
            r.phase == WorkerCommandReceiptPhase::Intent
                && !projected_pending.iter().any(|a| a.id == r.id)
        })
        .count();
    if projected_pending.len().saturating_add(pending_intent_slots) > MAX_WORKER_ACK_OUTBOX_ENTRIES
    {
        return Err(CapacityBackpressureReason::OutboxEntry);
    }
    let outbox_pretty_len = serde_json::to_vec_pretty(&projected_pending)
        .map(|buf| buf.len())
        .unwrap_or(usize::MAX);
    let outbox_headroom =
        pending_intent_slots.saturating_mul(OUTBOX_INTENT_COMPLETION_HEADROOM_BYTES);
    if outbox_pretty_len.saturating_add(outbox_headroom) > MAX_WORKER_ACK_OUTBOX_BYTES {
        return Err(CapacityBackpressureReason::OutboxByte);
    }

    Ok(next_receipts)
}

/// Coordinates durable confined worker command execution intent, terminal receipts,
/// lease-generation reattachment, legacy outbox recovery, and ACK confirmation.
pub(crate) struct WorkerCommandCoordinator {
    outbox_path: std::path::PathBuf,
    receipts_path: std::path::PathBuf,
    state: std::sync::Mutex<WorkerCommandRuntimeState>,
}

pub(super) struct InFlightCommandGuard {
    coordinator: Arc<WorkerCommandCoordinator>,
    cmd_id: String,
    armed: bool,
}

impl InFlightCommandGuard {
    pub(super) fn new(coordinator: Arc<WorkerCommandCoordinator>, cmd_id: String) -> Self {
        Self {
            coordinator,
            cmd_id,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for InFlightCommandGuard {
    fn drop(&mut self) {
        if self.armed {
            self.coordinator.release_in_flight_on_abort(&self.cmd_id);
        }
    }
}

impl WorkerCommandCoordinator {
    /// Loads durable receipts and legacy outbox entries, converting any orphaned pre-mutation
    /// `Intent` receipts from a crashed/restarted worker process into distinct `Unknown` results
    /// before admitting new commands.
    pub(crate) fn load_and_recover(
        node_id: &str,
        outbox_path: &Path,
        receipts_path: &Path,
    ) -> Self {
        let clean_node = node_id.trim().to_string();
        let mut storage_corrupt: Option<String> = None;

        let mut pending_acks = match load_worker_ack_outbox_strict(outbox_path) {
            Ok(loaded) => loaded,
            Err(err) => {
                let err_str = truncate_diagnostic_utf8(&err.to_string(), 512);
                tracing::error!(
                    path = %outbox_path.display(),
                    error = %err_str,
                    "failed loading confined worker ack outbox; failing closed for new mutations"
                );
                storage_corrupt = Some(err_str);
                Vec::new()
            }
        };

        let mut receipts = match load_worker_command_receipts_strict(receipts_path) {
            Ok(loaded) => loaded,
            Err(err) => {
                let err_str = truncate_diagnostic_utf8(&err.to_string(), 512);
                tracing::error!(
                    path = %receipts_path.display(),
                    error = %err_str,
                    "failed loading confined worker command receipts; failing closed for new mutations"
                );
                if storage_corrupt.is_none() {
                    storage_corrupt = Some(err_str);
                }
                Vec::new()
            }
        };

        if storage_corrupt.is_none() {
            let now_iso = Utc::now().to_rfc3339();
            let mut receipts_changed = false;
            let confirmed_receipt_ids: std::collections::HashSet<String> = receipts
                .iter()
                .filter(|r| r.ack_confirmed && r.phase.is_terminal())
                .map(|r| r.id.trim().to_string())
                .collect();

            // 1. Import legacy outbox entries so restarted/upgraded workers recognize completed
            //    commands even when no receipt ledger existed previously. Never let a stale or
            //    generation-less outbox entry overwrite a generation-fenced `Intent`.
            for ack in &pending_acks {
                let clean_id = ack.id.trim();
                let Some(phase) = WorkerCommandReceiptPhase::from_ack_status(&ack.status) else {
                    continue;
                };
                let valid_gen = ack.lease_generation.filter(|&g| g > 0);
                if let Some(existing) = receipts.iter_mut().find(|r| r.id.trim() == clean_id) {
                    if existing.phase == WorkerCommandReceiptPhase::Intent {
                        let node_matches = existing
                            .node_id
                            .as_deref()
                            .is_none_or(|rn| clean_node.is_empty() || rn == clean_node);
                        let lease_proven = match (existing.lease_generation, valid_gen) {
                            (Some(rec_gen), Some(ack_gen)) => ack_gen >= rec_gen,
                            (Some(_), None) => false,
                            (None, _) => true,
                        };
                        if node_matches && lease_proven {
                            existing.phase = phase;
                            existing.lease_generation = valid_gen.or(existing.lease_generation);
                            existing.result_message = ack
                                .result_message
                                .as_deref()
                                .map(truncate_receipt_result_message);
                            existing.ack_confirmed = false;
                            existing.updated_at = now_iso.clone();
                            receipts_changed = true;
                        }
                    }
                } else {
                    receipts.push(WorkerCommandReceipt {
                        id: clean_id.to_string(),
                        node_id: None,
                        cmd_type: None,
                        target: None,
                        action: None,
                        phase,
                        lease_generation: valid_gen,
                        result_message: ack
                            .result_message
                            .as_deref()
                            .map(truncate_receipt_result_message),
                        ack_confirmed: false,
                        updated_at: now_iso.clone(),
                    });
                    receipts_changed = true;
                }
            }

            // 2. Any `Intent` still on disk at startup belongs to a dead prior process whose
            //    non-idempotent mutation may have executed: transition to distinct `Unknown`.
            for receipt in &mut receipts {
                if receipt.phase == WorkerCommandReceiptPhase::Intent {
                    receipt.phase = WorkerCommandReceiptPhase::Unknown;
                    receipt.ack_confirmed = false;
                    receipt.result_message =
                        Some(build_interrupted_intent_unknown_message(receipt));
                    receipt.updated_at = now_iso.clone();
                    receipts_changed = true;
                    tracing::warn!(
                        command_id = %receipt.id,
                        lease_generation = ?receipt.lease_generation,
                        "recovered interrupted cluster command intent as unknown on worker startup"
                    );
                }
            }

            if receipts_changed {
                if let Err(err) =
                    persist_worker_command_receipts_in_place(receipts_path, &mut receipts)
                {
                    let err_str = truncate_diagnostic_utf8(&err.to_string(), 512);
                    tracing::error!(
                        path = %receipts_path.display(),
                        error = %err_str,
                        "failed persisting recovered worker command receipts; failing closed"
                    );
                    storage_corrupt = Some(err_str);
                }
            }

            // 3. Reconcile authoritative receipts into the 0600 ack outbox without dropping any
            //    unconfirmed entries. Confirmed receipts are pruned from the outbox first.
            if storage_corrupt.is_none() {
                let mut next_pending = pending_acks.clone();
                let mut outbox_changed = false;

                let before_len = next_pending.len();
                next_pending.retain(|ack| {
                    let clean_id = ack.id.trim();
                    !confirmed_receipt_ids.contains(clean_id)
                });
                if next_pending.len() != before_len {
                    outbox_changed = true;
                }

                for receipt in &receipts {
                    if receipt.ack_confirmed || !receipt.phase.is_terminal() {
                        continue;
                    }
                    if let Some(ref rec_node) = receipt.node_id {
                        if !clean_node.is_empty() && rec_node != &clean_node {
                            continue;
                        }
                    }
                    let Some(ack) = receipt.to_ack() else {
                        continue;
                    };
                    if let Some(existing) = next_pending
                        .iter_mut()
                        .find(|a| a.id.trim() == ack.id.as_str())
                    {
                        if *existing != ack {
                            *existing = ack;
                            outbox_changed = true;
                        }
                    } else {
                        next_pending.push(ack);
                        outbox_changed = true;
                    }
                }
                if outbox_changed {
                    match persist_worker_ack_outbox_atomic(outbox_path, &next_pending) {
                        Ok(()) => pending_acks = next_pending,
                        Err(err) => {
                            let err_str = truncate_diagnostic_utf8(&err.to_string(), 512);
                            tracing::error!(
                                path = %outbox_path.display(),
                                error = %err_str,
                                "failed persisting reconciled worker ack outbox on startup; failing closed"
                            );
                            storage_corrupt = Some(err_str);
                        }
                    }
                }
            }
        }

        Self {
            outbox_path: outbox_path.to_path_buf(),
            receipts_path: receipts_path.to_path_buf(),
            state: std::sync::Mutex::new(WorkerCommandRuntimeState {
                node_id: clean_node,
                receipts,
                pending_acks,
                in_flight: std::collections::HashSet::new(),
                storage_corrupt,
            }),
        }
    }

    pub(crate) fn set_node_id(&self, node_id: &str) {
        if let Ok(mut guard) = self.state.lock() {
            guard.node_id = node_id.trim().to_string();
        }
    }

    pub(crate) fn pending_acks_snapshot(&self) -> Vec<WorkerCommandAck> {
        self.state
            .lock()
            .map(|g| g.pending_acks.clone())
            .unwrap_or_default()
    }

    pub(crate) fn mark_confirmed(&self, confirmed_ids: &[String]) {
        if confirmed_ids.is_empty() {
            return;
        }
        let Ok(mut guard) = self.state.lock() else {
            return;
        };
        let _ = evict_confirmed_acks_from_outbox(
            &self.outbox_path,
            &mut guard.pending_acks,
            confirmed_ids,
        );
        if guard.storage_corrupt.is_some() {
            return;
        }
        let mut next_receipts = guard.receipts.clone();
        let mut receipts_changed = false;
        let now_iso = Utc::now().to_rfc3339();
        for receipt in &mut next_receipts {
            if receipt.phase.is_terminal()
                && !receipt.ack_confirmed
                && confirmed_ids.iter().any(|cid| cid == &receipt.id)
            {
                receipt.ack_confirmed = true;
                receipt.updated_at = now_iso.clone();
                receipts_changed = true;
            }
        }
        if receipts_changed
            && persist_worker_command_receipts_in_place(&self.receipts_path, &mut next_receipts)
                .is_ok()
        {
            guard.receipts = next_receipts;
        }
    }

    pub(crate) fn prepare_command_dispatch(
        &self,
        cmd: PendingWorkerCommand,
    ) -> WorkerCommandDispatchPlan {
        let Ok(mut guard) = self.state.lock() else {
            return WorkerCommandDispatchPlan::RejectedStorageFailure;
        };
        if let Some(ref reason) = guard.storage_corrupt {
            tracing::error!(
                command_id = %cmd.id,
                error = %reason,
                "refusing cluster command admission because confined receipt storage is unhealthy"
            );
            return WorkerCommandDispatchPlan::RejectedStorageFailure;
        }

        let cmd_id = cmd.id.trim().to_string();
        if cmd_id.is_empty() {
            return WorkerCommandDispatchPlan::RejectedConflictingIdentity;
        }
        let incoming_gen = extract_command_lease_generation(&cmd);
        let identity = WorkerCommandIdentity::from_command(&guard.node_id, &cmd);
        let now_iso = Utc::now().to_rfc3339();

        // 1. Check durable receipts for existing intent or terminal outcome FIRST so existing
        //    commands, reattachments, and orphaned-intent recoveries continue draining even at
        //    capacity saturation.
        if let Some(idx) = guard.receipts.iter().position(|r| r.id == cmd_id) {
            let existing = guard.receipts[idx].clone();
            if !existing.matches_identity(&identity) {
                tracing::warn!(
                    command_id = %cmd_id,
                    recorded_node_id = ?existing.node_id,
                    incoming_node_id = %identity.node_id,
                    recorded_cmd_type = ?existing.cmd_type,
                    incoming_cmd_type = %identity.cmd_type,
                    recorded_target = ?existing.target,
                    incoming_target = %identity.target,
                    "rejecting cluster command with conflicting identity against durable receipt"
                );
                return WorkerCommandDispatchPlan::RejectedConflictingIdentity;
            }
            if let Some(recorded_gen) = existing.lease_generation {
                if incoming_gen.is_none_or(|g| g < recorded_gen) {
                    tracing::warn!(
                        command_id = %cmd_id,
                        recorded_lease_generation = recorded_gen,
                        incoming_lease_generation = ?incoming_gen,
                        "rejecting stale cluster command lease delivery"
                    );
                    return WorkerCommandDispatchPlan::RejectedStaleLease;
                }
            }

            if existing.phase == WorkerCommandReceiptPhase::Intent {
                if guard.in_flight.contains(&cmd_id) {
                    if let Some(fresh_gen) = incoming_gen {
                        if existing.lease_generation.is_none_or(|g| fresh_gen > g) {
                            let mut next_receipts = guard.receipts.clone();
                            next_receipts[idx].lease_generation = Some(fresh_gen);
                            next_receipts[idx].updated_at = now_iso;
                            if persist_worker_command_receipts_in_place(
                                &self.receipts_path,
                                &mut next_receipts,
                            )
                            .is_ok()
                            {
                                guard.receipts = next_receipts;
                            }
                        }
                    }
                    return WorkerCommandDispatchPlan::AlreadyInFlight;
                }

                // Defensive recovery: an intent receipt with no active in-process owner
                // (e.g., aborted/panicked task) must resolve to `Unknown`, never replay.
                let attached_gen = incoming_gen.or(existing.lease_generation);
                let mut next_receipts = guard.receipts.clone();
                let rec = &mut next_receipts[idx];
                rec.phase = WorkerCommandReceiptPhase::Unknown;
                rec.lease_generation = attached_gen;
                rec.ack_confirmed = false;
                rec.result_message = Some(build_interrupted_intent_unknown_message(rec));
                rec.updated_at = now_iso;
                let ack = match rec.to_ack() {
                    Some(a) => a,
                    None => return WorkerCommandDispatchPlan::RejectedStorageFailure,
                };
                if let Err(err) = persist_worker_command_receipts_in_place(
                    &self.receipts_path,
                    &mut next_receipts,
                ) {
                    tracing::error!(
                        command_id = %cmd_id,
                        error = %err,
                        "failed persisting orphaned-intent unknown receipt"
                    );
                    return WorkerCommandDispatchPlan::RejectedStorageFailure;
                }
                guard.receipts = next_receipts;
                if let Err(err) = enqueue_worker_ack_outbox_entry(
                    &self.outbox_path,
                    &mut guard.pending_acks,
                    ack.clone(),
                ) {
                    tracing::error!(
                        command_id = %cmd_id,
                        error = %err,
                        "failed persisting orphaned-intent unknown ack to outbox"
                    );
                    return WorkerCommandDispatchPlan::RejectedStorageFailure;
                }
                return WorkerCommandDispatchPlan::SendAckOnly(ack);
            }

            // Known terminal durable result (`Executed`, `Failed`, or `Unknown`):
            // reattach to the freshly observed lease generation without rerunning the effect.
            let attached_gen = incoming_gen.or(existing.lease_generation);
            let mut next_receipts = guard.receipts.clone();
            let rec = &mut next_receipts[idx];
            let metadata_bound = (rec.node_id.is_none() && !identity.node_id.is_empty())
                || rec.cmd_type.is_none()
                || rec.target.is_none()
                || (rec.action.is_none() && identity.action.is_some());
            if rec.node_id.is_none() && !identity.node_id.is_empty() {
                rec.node_id = Some(identity.node_id);
            }
            if rec.cmd_type.is_none() {
                rec.cmd_type = Some(identity.cmd_type);
            }
            if rec.target.is_none() {
                rec.target = Some(identity.target);
            }
            if rec.action.is_none() {
                rec.action = identity.action;
            }
            let receipt_dirty =
                rec.lease_generation != attached_gen || rec.ack_confirmed || metadata_bound;
            rec.lease_generation = attached_gen;
            rec.ack_confirmed = false;
            if receipt_dirty {
                rec.updated_at = now_iso;
            }
            let ack = match rec.to_ack() {
                Some(a) => a,
                None => return WorkerCommandDispatchPlan::RejectedStorageFailure,
            };
            if receipt_dirty {
                if let Err(err) = persist_worker_command_receipts_in_place(
                    &self.receipts_path,
                    &mut next_receipts,
                ) {
                    tracing::error!(
                        command_id = %cmd_id,
                        error = %err,
                        "failed persisting reattached worker command receipt before ACK"
                    );
                    return WorkerCommandDispatchPlan::RejectedStorageFailure;
                }
                guard.receipts = next_receipts;
            }
            if let Err(err) = enqueue_worker_ack_outbox_entry(
                &self.outbox_path,
                &mut guard.pending_acks,
                ack.clone(),
            ) {
                tracing::error!(
                    command_id = %cmd_id,
                    error = %err,
                    "failed persisting reattached worker command ack to outbox before ACK"
                );
                return WorkerCommandDispatchPlan::RejectedStorageFailure;
            }
            return WorkerCommandDispatchPlan::SendAckOnly(ack);
        }

        if guard.in_flight.contains(&cmd_id) {
            return WorkerCommandDispatchPlan::AlreadyInFlight;
        }

        tracing::info!(
            command_id = %cmd_id,
            cmd_type = %identity.cmd_type,
            lease_generation = ?incoming_gen,
            "cluster worker executing remote command from master"
        );

        // 2. Non-mutating commands (`ping`) and pre-mutation validation rejections persist their
        //    terminal outcome directly before ACK without writing an `Intent` phase.
        if identity.cmd_type == "ping" {
            let receipt = WorkerCommandReceipt {
                id: cmd_id.clone(),
                node_id: (!identity.node_id.is_empty()).then_some(identity.node_id),
                cmd_type: Some(identity.cmd_type),
                target: Some(identity.target),
                action: None,
                phase: WorkerCommandReceiptPhase::Executed,
                lease_generation: incoming_gen,
                result_message: Some("pong".to_string()),
                ack_confirmed: false,
                updated_at: now_iso,
            };
            return self.persist_immediate_terminal_receipt(&mut guard, receipt);
        }

        let Some(svc_action) = identity.action.clone() else {
            let msg = format!(
                "unsupported command type '{}'",
                truncate_utf8(&identity.cmd_type, 64)
            );
            let receipt = WorkerCommandReceipt {
                id: cmd_id.clone(),
                node_id: (!identity.node_id.is_empty()).then_some(identity.node_id),
                cmd_type: Some(identity.cmd_type),
                target: Some(identity.target),
                action: None,
                phase: WorkerCommandReceiptPhase::Failed,
                lease_generation: incoming_gen,
                result_message: Some(truncate_receipt_result_message(&msg)),
                ack_confirmed: false,
                updated_at: now_iso,
            };
            return self.persist_immediate_terminal_receipt(&mut guard, receipt);
        };

        if identity.target.is_empty() {
            let receipt = WorkerCommandReceipt {
                id: cmd_id.clone(),
                node_id: (!identity.node_id.is_empty()).then_some(identity.node_id),
                cmd_type: Some(identity.cmd_type),
                target: Some(String::new()),
                action: Some(svc_action),
                phase: WorkerCommandReceiptPhase::Failed,
                lease_generation: incoming_gen,
                result_message: Some("missing target service parameter".to_string()),
                ack_confirmed: false,
                updated_at: now_iso,
            };
            return self.persist_immediate_terminal_receipt(&mut guard, receipt);
        }

        // 3. Admitted non-idempotent service mutation: check bounded backpressure (recycling ONLY
        //    master-confirmed terminal receipts) and persist durable `Intent` receipt BEFORE
        //    invoking `control_service`. If saturated or persistence fails, refuse admission so
        //    the command remains genuinely unstarted.
        let intent_receipt = WorkerCommandReceipt {
            id: cmd_id.clone(),
            node_id: (!identity.node_id.is_empty()).then_some(identity.node_id),
            cmd_type: Some(identity.cmd_type),
            target: Some(identity.target.clone()),
            action: Some(svc_action.clone()),
            phase: WorkerCommandReceiptPhase::Intent,
            lease_generation: incoming_gen,
            result_message: None,
            ack_confirmed: false,
            updated_at: now_iso,
        };
        let mut next_receipts = match try_prepare_new_receipt_with_backpressure(
            &guard,
            intent_receipt,
        ) {
            Ok(planned) => planned,
            Err(reason) => {
                tracing::warn!(
                    command_id = %cmd_id,
                    service = %identity.target,
                    action = %svc_action,
                    reason = reason.as_str(),
                    receipt_count = guard.receipts.len(),
                    pending_ack_count = guard.pending_acks.len(),
                    "applying fail-closed backpressure: worker receipt/outbox saturated by unconfirmed outcomes or active intents"
                );
                return WorkerCommandDispatchPlan::RejectedCapacitySaturated;
            }
        };
        if let Err(err) =
            persist_worker_command_receipts_in_place(&self.receipts_path, &mut next_receipts)
        {
            tracing::error!(
                command_id = %cmd_id,
                service = %identity.target,
                action = %svc_action,
                error = %err,
                "failed persisting pre-mutation execution intent; refusing non-idempotent mutation"
            );
            return WorkerCommandDispatchPlan::RejectedStorageFailure;
        }
        guard.receipts = next_receipts;
        guard.in_flight.insert(cmd_id.clone());

        WorkerCommandDispatchPlan::Execute(AdmittedServiceMutation {
            id: cmd_id,
            service: identity.target,
            action: svc_action,
            lease_generation: incoming_gen,
        })
    }

    fn persist_immediate_terminal_receipt(
        &self,
        guard: &mut WorkerCommandRuntimeState,
        receipt: WorkerCommandReceipt,
    ) -> WorkerCommandDispatchPlan {
        let Some(ack) = receipt.to_ack() else {
            return WorkerCommandDispatchPlan::RejectedStorageFailure;
        };
        let mut next_receipts = match try_prepare_new_receipt_with_backpressure(guard, receipt) {
            Ok(planned) => planned,
            Err(reason) => {
                tracing::warn!(
                    command_id = %ack.id,
                    reason = reason.as_str(),
                    receipt_count = guard.receipts.len(),
                    pending_ack_count = guard.pending_acks.len(),
                    "applying fail-closed backpressure before immediate terminal command dispatch"
                );
                return WorkerCommandDispatchPlan::RejectedCapacitySaturated;
            }
        };
        if let Err(err) =
            persist_worker_command_receipts_in_place(&self.receipts_path, &mut next_receipts)
        {
            tracing::error!(
                command_id = %ack.id,
                error = %err,
                "failed persisting terminal worker command receipt before ACK"
            );
            return WorkerCommandDispatchPlan::RejectedStorageFailure;
        }
        guard.receipts = next_receipts;
        if let Err(err) =
            enqueue_worker_ack_outbox_entry(&self.outbox_path, &mut guard.pending_acks, ack.clone())
        {
            tracing::error!(
                command_id = %ack.id,
                error = %err,
                "failed persisting worker command ack to outbox before ACK"
            );
            return WorkerCommandDispatchPlan::RejectedStorageFailure;
        }
        WorkerCommandDispatchPlan::SendAckOnly(ack)
    }

    /// Persists the terminal execution result (`Executed` or `Failed`) into the confined receipt
    /// ledger and `0600` ack outbox BEFORE returning the `WorkerCommandAck` to send.
    pub(crate) fn complete_admitted_mutation(
        &self,
        mutation: &AdmittedServiceMutation,
        result: Result<(), String>,
    ) -> anyhow::Result<WorkerCommandAck> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("worker command coordinator mutex poisoned"))?;
        let now_iso = Utc::now().to_rfc3339();
        let (phase, result_message) = match result {
            Ok(()) => (
                WorkerCommandReceiptPhase::Executed,
                Some(truncate_receipt_result_message(&format!(
                    "{} {} succeeded",
                    mutation.action, mutation.service
                ))),
            ),
            Err(err_msg) => {
                tracing::warn!(
                    service = %mutation.service,
                    action = %mutation.action,
                    error = %err_msg,
                    "cluster worker command failed"
                );
                (
                    WorkerCommandReceiptPhase::Failed,
                    Some(truncate_receipt_result_message(&err_msg)),
                )
            }
        };

        let mut next_receipts = guard.receipts.clone();
        let effective_gen =
            if let Some(rec) = next_receipts.iter_mut().find(|r| r.id == mutation.id) {
                let gen = match (rec.lease_generation, mutation.lease_generation) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
                rec.phase = phase;
                rec.lease_generation = gen;
                rec.result_message = result_message.clone();
                rec.ack_confirmed = false;
                rec.updated_at = now_iso;
                gen
            } else {
                let gen = mutation.lease_generation;
                next_receipts.push(WorkerCommandReceipt {
                    id: mutation.id.clone(),
                    node_id: (!guard.node_id.is_empty()).then_some(guard.node_id.clone()),
                    cmd_type: None,
                    target: Some(mutation.service.clone()),
                    action: Some(mutation.action.clone()),
                    phase,
                    lease_generation: gen,
                    result_message: result_message.clone(),
                    ack_confirmed: false,
                    updated_at: now_iso,
                });
                gen
            };
        persist_worker_command_receipts_in_place(&self.receipts_path, &mut next_receipts)?;
        guard.receipts = next_receipts;

        let ack = WorkerCommandAck {
            id: mutation.id.clone(),
            status: phase
                .as_ack_status()
                .unwrap_or(WORKER_COMMAND_STATUS_FAILED)
                .to_string(),
            result_message,
            lease_generation: effective_gen,
        };
        let outbox_res = enqueue_worker_ack_outbox_entry(
            &self.outbox_path,
            &mut guard.pending_acks,
            ack.clone(),
        );
        guard.in_flight.remove(&mutation.id);
        outbox_res?;
        Ok(ack)
    }

    pub(crate) fn release_in_flight_on_abort(&self, cmd_id: &str) {
        if let Ok(mut guard) = self.state.lock() {
            guard.in_flight.remove(cmd_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_daemon::{
        acknowledge_worker_command, enqueue_cluster_command, ensure_cluster_schema,
        lease_next_worker_command, list_cluster_commands, process_worker_heartbeat,
        register_worker_node, route_cluster_http_request, PeerTransportAuth, RegisterWorkerRequest,
        WorkerCommandAckRequest, WorkerHeartbeatRequest,
    };
    use std::collections::HashMap;

    #[cfg(unix)]
    #[test]
    fn worker_command_restart_between_intent_and_result_reports_unknown_without_replay() {
        let name = "cluster_daemon::receipts::tests::worker_command_restart_between_intent_and_result_reports_unknown_without_replay";
        if !crate::inventory_regressions::isolated(name) {
            return;
        }
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!("af-cluster-dur-1-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("cluster.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &db_path);
        }
        let psk = "durability-master-psk-at-least-32-chars!!";
        env::set_var("CLUSTER_PSK", psk);
        af_db::init_db().unwrap();
        ensure_cluster_schema();

        let reg = register_worker_node(&RegisterWorkerRequest {
            node_id: "node-alpha".to_string(),
            hostname: "alpha".to_string(),
            address: "127.0.0.1:8080".to_string(),
            psk: psk.to_string(),
            version: "4.0.0".to_string(),
            system_info: None,
        })
        .unwrap();
        assert!(reg.accepted);

        let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
        let receipts_path = resolve_worker_command_receipts_path(&outbox_path);

        // 1. Enqueue non-idempotent service restart and lease generation 1.
        let queued = enqueue_cluster_command("node-alpha", "restart_service", "sonarr").unwrap();
        let first_lease = lease_next_worker_command("node-alpha", 1000, 30).unwrap();
        assert_eq!(first_lease.id, queued.id);
        assert_eq!(first_lease.lease_generation, 1);

        // Worker #1 admits mutation -> persists confined 0600 `Intent` receipt BEFORE mutation runs.
        let worker_1 =
            WorkerCommandCoordinator::load_and_recover("node-alpha", &outbox_path, &receipts_path);
        let plan_1 = worker_1.prepare_command_dispatch(first_lease);
        let mutation = match plan_1 {
            WorkerCommandDispatchPlan::Execute(m) => m,
            other => panic!("expected Execute plan for unstarted command, got {other:?}"),
        };
        assert_eq!(mutation.service, "sonarr");
        assert_eq!(mutation.action, "restart");

        let receipts_mode = std::fs::symlink_metadata(&receipts_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(receipts_mode, 0o600);
        let on_disk = load_worker_command_receipts_strict(&receipts_path).unwrap();
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].phase, WorkerCommandReceiptPhase::Intent);
        assert_eq!(on_disk[0].lease_generation, Some(1));

        // Simulate crash/restart BEFORE `complete_admitted_mutation` persists a final outcome.
        drop(worker_1);

        // 2. Restarted worker #2 transitions orphaned `Intent` -> distinct `Unknown` without replay.
        let worker_2 =
            WorkerCommandCoordinator::load_and_recover("node-alpha", &outbox_path, &receipts_path);
        let recovered = load_worker_command_receipts_strict(&receipts_path).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].phase, WorkerCommandReceiptPhase::Unknown);
        assert_eq!(recovered[0].lease_generation, Some(1));
        assert!(recovered[0]
            .result_message
            .as_deref()
            .unwrap_or("")
            .contains("inspect service state before retrying"));

        let pending_before_gen2 = worker_2.pending_acks_snapshot();
        assert_eq!(pending_before_gen2.len(), 1);
        assert_eq!(pending_before_gen2[0].status, WORKER_COMMAND_STATUS_UNKNOWN);
        assert_eq!(pending_before_gen2[0].lease_generation, Some(1));

        // Master lease expires -> lease generation advances to 2 before gen-1 ACK arrives.
        let expired_re_lease = lease_next_worker_command("node-alpha", 1031, 30).unwrap();
        assert_eq!(expired_re_lease.id, queued.id);
        assert_eq!(expired_re_lease.lease_generation, 2);

        // Heartbeat carrying stale gen-1 `unknown` ACK MUST be fenced by master!
        let hb_stale = process_worker_heartbeat(&WorkerHeartbeatRequest {
            node_id: "node-alpha".to_string(),
            hostname: "alpha".to_string(),
            address: "127.0.0.1:8080".to_string(),
            psk: psk.to_string(),
            timestamp: 1035,
            command_acks: pending_before_gen2,
            ..Default::default()
        })
        .unwrap();
        assert!(hb_stale.confirmed_command_ids.is_empty());

        // Worker #2 observes fresh lease_generation=2 -> reattaches durable `unknown` WITHOUT rerunning!
        let plan_2 = worker_2.prepare_command_dispatch(expired_re_lease);
        let reattached_ack = match plan_2 {
            WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
            other => panic!("expected SendAckOnly reattachment of unknown receipt, got {other:?}"),
        };
        assert_eq!(reattached_ack.id, queued.id);
        assert_eq!(reattached_ack.status, WORKER_COMMAND_STATUS_UNKNOWN);
        assert_eq!(reattached_ack.lease_generation, Some(2));

        // Reattached generation=2 ACK is persisted before delivery and commits `unknown` on master.
        assert_eq!(
            load_worker_ack_outbox_nofollow(&outbox_path)[0].lease_generation,
            Some(2)
        );
        let hb_commit = process_worker_heartbeat(&WorkerHeartbeatRequest {
            node_id: "node-alpha".to_string(),
            hostname: "alpha".to_string(),
            address: "127.0.0.1:8080".to_string(),
            psk: psk.to_string(),
            timestamp: 1040,
            command_acks: worker_2.pending_acks_snapshot(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(hb_commit.confirmed_command_ids, vec![queued.id.clone()]);
        assert!(hb_commit.command.is_none());
        worker_2.mark_confirmed(&hb_commit.confirmed_command_ids);
        assert!(load_worker_ack_outbox_nofollow(&outbox_path).is_empty());

        let listed = list_cluster_commands(Some("node-alpha"), 10).unwrap();
        assert_eq!(listed[0].status, WORKER_COMMAND_STATUS_UNKNOWN);
        assert_eq!(listed[0].lease_generation, 2);
        assert!(listed[0]
            .result_message
            .as_deref()
            .unwrap_or("")
            .contains("inspect service state"));
        assert!(lease_next_worker_command("node-alpha", 2000, 30).is_none());

        // 3. Normal retry semantics for a genuinely unstarted command (lease 1 lost on wire).
        let unstarted = enqueue_cluster_command("node-alpha", "restart_service", "radarr").unwrap();
        let lost_gen1 = lease_next_worker_command("node-alpha", 2010, 30).unwrap();
        assert_eq!(lost_gen1.lease_generation, 1);
        let gen2 = lease_next_worker_command("node-alpha", 2045, 30).unwrap();
        assert_eq!(gen2.id, unstarted.id);
        assert_eq!(gen2.lease_generation, 2);

        let unstarted_mutation = match worker_2.prepare_command_dispatch(gen2) {
            WorkerCommandDispatchPlan::Execute(m) => m,
            other => panic!("genuinely unstarted command must still execute, got {other:?}"),
        };
        let done_ack = worker_2
            .complete_admitted_mutation(&unstarted_mutation, Ok(()))
            .unwrap();
        assert_eq!(done_ack.status, WORKER_COMMAND_STATUS_EXECUTED);
        assert_eq!(done_ack.lease_generation, Some(2));
        assert!(acknowledge_worker_command("node-alpha", &done_ack).unwrap());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn worker_command_retry_after_lost_ack_and_new_lease_reattaches_without_rerun() {
        let name = "cluster_daemon::receipts::tests::worker_command_retry_after_lost_ack_and_new_lease_reattaches_without_rerun";
        if !crate::inventory_regressions::isolated(name) {
            return;
        }

        let root = env::temp_dir().join(format!("af-cluster-dur-2-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("cluster.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &db_path);
        }
        let psk = "durability-retry-psk-at-least-32-chars!!";
        env::set_var("CLUSTER_PSK", psk);
        af_db::init_db().unwrap();
        ensure_cluster_schema();

        let reg = register_worker_node(&RegisterWorkerRequest {
            node_id: "node-beta".to_string(),
            hostname: "beta".to_string(),
            address: "127.0.0.1:8081".to_string(),
            psk: psk.to_string(),
            version: "4.0.0".to_string(),
            system_info: None,
        })
        .unwrap();
        assert!(reg.accepted);

        let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
        let receipts_path = resolve_worker_command_receipts_path(&outbox_path);

        // 1. Execute once on gen=1, persist completed result before ACK, then lose ACK & re-lease gen=2.
        let cmd_rec = enqueue_cluster_command("node-beta", "restart_service", "plex").unwrap();
        let lease_1 = lease_next_worker_command("node-beta", 3000, 30).unwrap();
        assert_eq!(lease_1.lease_generation, 1);

        let worker =
            WorkerCommandCoordinator::load_and_recover("node-beta", &outbox_path, &receipts_path);
        let mut exec_count = 0usize;
        let mutation = match worker.prepare_command_dispatch(lease_1) {
            WorkerCommandDispatchPlan::Execute(m) => {
                exec_count += 1;
                m
            }
            other => panic!("expected Execute on first delivery, got {other:?}"),
        };
        let ack_gen1 = worker
            .complete_admitted_mutation(&mutation, Ok(()))
            .unwrap();
        assert_eq!(ack_gen1.status, WORKER_COMMAND_STATUS_EXECUTED);
        assert_eq!(ack_gen1.lease_generation, Some(1));
        assert_eq!(load_worker_ack_outbox_nofollow(&outbox_path).len(), 1);
        assert_eq!(
            load_worker_command_receipts_strict(&receipts_path).unwrap()[0].phase,
            WorkerCommandReceiptPhase::Executed
        );

        // ACK response is lost; master lease expires and issues gen=2.
        let lease_2 = lease_next_worker_command("node-beta", 3035, 30).unwrap();
        assert_eq!(lease_2.id, cmd_rec.id);
        assert_eq!(lease_2.lease_generation, 2);

        // Same worker reattaches durable `executed` result to gen=2 WITHOUT rerunning the mutation.
        let ack_gen2 = match worker.prepare_command_dispatch(lease_2) {
            WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
            other => panic!("expected SendAckOnly reattachment on gen=2, got {other:?}"),
        };
        assert_eq!(exec_count, 1, "side effect must not be rerun on new lease");
        assert_eq!(ack_gen2.status, WORKER_COMMAND_STATUS_EXECUTED);
        assert_eq!(ack_gen2.lease_generation, Some(2));
        assert_eq!(
            ack_gen2.result_message.as_deref(),
            Some("restart plex succeeded")
        );

        // Deliver reattached gen=2 ACK via /cluster/v1/commands/ack -> master commits and confirms.
        let ack_req_bytes = serde_json::to_vec(&WorkerCommandAckRequest {
            node_id: "node-beta".to_string(),
            psk: String::new(),
            acks: vec![ack_gen2],
        })
        .unwrap();
        let (code, _, body) = route_cluster_http_request(
            "POST",
            "/cluster/v1/commands/ack",
            "/cluster/v1/commands/ack",
            psk,
            &ack_req_bytes,
            &PeerTransportAuth::InsecureLoopback,
        );
        assert_eq!(code, 200);
        assert_eq!(
            body["confirmed_command_ids"],
            serde_json::json!([cmd_rec.id])
        );
        worker.mark_confirmed(std::slice::from_ref(&cmd_rec.id));
        assert!(load_worker_ack_outbox_nofollow(&outbox_path).is_empty());
        assert!(load_worker_command_receipts_strict(&receipts_path).unwrap()[0].ack_confirmed);

        // 2. Legacy outbox compatibility: restarted worker with ONLY legacy 0600 outbox file
        //    reattaches completed result to freshly observed lease generation without rerunning.
        let legacy_outbox = root.join("legacy/cluster_worker_ack_outbox.json");
        let legacy_receipts = resolve_worker_command_receipts_path(&legacy_outbox);
        let legacy_rec = enqueue_cluster_command("node-beta", "stop_service", "radarr").unwrap();
        let _legacy_gen1 = lease_next_worker_command("node-beta", 3100, 30).unwrap();
        let legacy_gen2 = lease_next_worker_command("node-beta", 3135, 30).unwrap();
        assert_eq!(legacy_gen2.lease_generation, 2);

        persist_worker_ack_outbox_atomic(
            &legacy_outbox,
            &[WorkerCommandAck {
                id: legacy_rec.id.clone(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("stop radarr succeeded".to_string()),
                lease_generation: Some(1),
            }],
        )
        .unwrap();
        assert!(!legacy_receipts.exists());

        let upgraded_worker = WorkerCommandCoordinator::load_and_recover(
            "node-beta",
            &legacy_outbox,
            &legacy_receipts,
        );
        let reattached_legacy = match upgraded_worker.prepare_command_dispatch(legacy_gen2) {
            WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
            other => panic!("legacy outbox record must reattach without rerun, got {other:?}"),
        };
        assert_eq!(reattached_legacy.id, legacy_rec.id);
        assert_eq!(reattached_legacy.status, WORKER_COMMAND_STATUS_EXECUTED);
        assert_eq!(reattached_legacy.lease_generation, Some(2));
        assert!(acknowledge_worker_command("node-beta", &reattached_legacy).unwrap());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn worker_command_stale_lease_conflicting_identity_and_confined_storage_guards() {
        let name = "cluster_daemon::receipts::tests::worker_command_stale_lease_conflicting_identity_and_confined_storage_guards";
        if !crate::inventory_regressions::isolated(name) {
            return;
        }

        let root = env::temp_dir().join(format!("af-cluster-dur-3-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("cluster.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &db_path);
        }
        let psk = "durability-fence-psk-at-least-32-chars!!";
        env::set_var("CLUSTER_PSK", psk);
        af_db::init_db().unwrap();
        ensure_cluster_schema();

        for (nid, host, addr) in [
            ("node-gamma", "gamma", "127.0.0.1:8082"),
            ("node-other", "other", "127.0.0.1:8083"),
        ] {
            let reg = register_worker_node(&RegisterWorkerRequest {
                node_id: nid.to_string(),
                hostname: host.to_string(),
                address: addr.to_string(),
                psk: psk.to_string(),
                version: "4.0.0".to_string(),
                system_info: None,
            })
            .unwrap();
            assert!(reg.accepted);
        }

        // 1. Master lease fencing & conflicting node/status rejection.
        let queued = enqueue_cluster_command("node-gamma", "restart_service", "sonarr").unwrap();
        let gen1 = lease_next_worker_command("node-gamma", 4000, 30).unwrap();
        let gen2 = lease_next_worker_command("node-gamma", 4035, 30).unwrap();
        assert_eq!(gen1.lease_generation, 1);
        assert_eq!(gen2.lease_generation, 2);

        assert!(!acknowledge_worker_command(
            "node-gamma",
            &WorkerCommandAck {
                id: queued.id.clone(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: None,
                lease_generation: Some(0),
            }
        )
        .unwrap());
        assert!(!acknowledge_worker_command(
            "node-gamma",
            &WorkerCommandAck {
                id: queued.id.clone(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("stale gen 1".to_string()),
                lease_generation: Some(1),
            }
        )
        .unwrap());
        assert!(!acknowledge_worker_command(
            "node-other",
            &WorkerCommandAck {
                id: queued.id.clone(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("wrong node".to_string()),
                lease_generation: Some(2),
            }
        )
        .unwrap());
        assert!(acknowledge_worker_command(
            "node-gamma",
            &WorkerCommandAck {
                id: queued.id.clone(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("restart sonarr succeeded".to_string()),
                lease_generation: Some(2),
            }
        )
        .unwrap());

        // Post-terminal stale lease & conflicting status ACKs must be rejected, while exact duplicate succeeds.
        assert!(!acknowledge_worker_command(
            "node-gamma",
            &WorkerCommandAck {
                id: queued.id.clone(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: None,
                lease_generation: Some(1),
            }
        )
        .unwrap());
        assert!(!acknowledge_worker_command(
            "node-gamma",
            &WorkerCommandAck {
                id: queued.id.clone(),
                status: WORKER_COMMAND_STATUS_FAILED.to_string(),
                result_message: Some("conflicting outcome".to_string()),
                lease_generation: Some(2),
            }
        )
        .unwrap());
        assert!(acknowledge_worker_command(
            "node-gamma",
            &WorkerCommandAck {
                id: queued.id.clone(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("restart sonarr succeeded".to_string()),
                lease_generation: Some(2),
            }
        )
        .unwrap());

        // 2. Worker-side stale lease rejection and conflicting command identity rejection.
        let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
        let receipts_path = resolve_worker_command_receipts_path(&outbox_path);
        let worker =
            WorkerCommandCoordinator::load_and_recover("node-gamma", &outbox_path, &receipts_path);
        let m = match worker.prepare_command_dispatch(gen2.clone()) {
            WorkerCommandDispatchPlan::Execute(m) => m,
            other => panic!("expected Execute on gen=2, got {other:?}"),
        };
        worker.complete_admitted_mutation(&m, Ok(())).unwrap();

        // Stale gen=1 delivery must be rejected without downgrading stored gen=2.
        assert_eq!(
            worker.prepare_command_dispatch(gen1),
            WorkerCommandDispatchPlan::RejectedStaleLease
        );
        assert_eq!(
            load_worker_command_receipts_strict(&receipts_path).unwrap()[0].lease_generation,
            Some(2)
        );

        // Conflicting verb/target under same cmd_id must be rejected without executing or overwriting.
        let mut conflicting_target = gen2.clone();
        conflicting_target.lease_generation = 3;
        conflicting_target
            .params
            .insert("service".to_string(), "radarr".to_string());
        conflicting_target
            .params
            .insert("target".to_string(), "radarr".to_string());
        assert_eq!(
            worker.prepare_command_dispatch(conflicting_target),
            WorkerCommandDispatchPlan::RejectedConflictingIdentity
        );

        let mut conflicting_verb = gen2.clone();
        conflicting_verb.lease_generation = 3;
        conflicting_verb.cmd_type = "stop_service".to_string();
        assert_eq!(
            worker.prepare_command_dispatch(conflicting_verb),
            WorkerCommandDispatchPlan::RejectedConflictingIdentity
        );

        // 3. Confined storage rejects symlinks/hardlinks and fails closed on tampered receipt store.
        let sym_receipts = root.join("state/symlink_receipts.json");
        std::os::unix::fs::symlink(&receipts_path, &sym_receipts).unwrap();
        assert!(load_worker_command_receipts_strict(&sym_receipts).is_err());
        assert!(persist_worker_command_receipts_atomic(&sym_receipts, &[]).is_err());
        let tampered_worker =
            WorkerCommandCoordinator::load_and_recover("node-gamma", &outbox_path, &sym_receipts);
        assert_eq!(
            tampered_worker.prepare_command_dispatch(PendingWorkerCommand {
                id: "cmd-fresh-tampered".to_string(),
                cmd_type: "restart_service".to_string(),
                params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
                lease_generation: 1,
            }),
            WorkerCommandDispatchPlan::RejectedStorageFailure
        );

        let hardlink_alias = root.join("state/hardlink_alias.json");
        std::fs::hard_link(&receipts_path, &hardlink_alias).unwrap();
        assert!(load_worker_command_receipts_strict(&receipts_path).is_err());
        let _ = std::fs::remove_file(&hardlink_alias);

        // 4. Bounded storage caps receipt ledger at MAX_WORKER_COMMAND_RECEIPTS while keeping active intents.
        let bounded_path = root.join("bounded/cluster_worker_command_receipts.json");
        let mut many: Vec<WorkerCommandReceipt> = (0..MAX_WORKER_COMMAND_RECEIPTS + 5)
            .map(|i| WorkerCommandReceipt {
                id: format!("cmd-confirmed-{i}"),
                node_id: Some("node-gamma".to_string()),
                cmd_type: Some("ping".to_string()),
                target: Some(String::new()),
                action: None,
                phase: WorkerCommandReceiptPhase::Executed,
                lease_generation: Some(1),
                result_message: Some("pong".to_string()),
                ack_confirmed: true,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            })
            .collect();
        many.insert(
            0,
            WorkerCommandReceipt {
                id: "cmd-active-intent".to_string(),
                node_id: Some("node-gamma".to_string()),
                cmd_type: Some("restart_service".to_string()),
                target: Some("sonarr".to_string()),
                action: Some("restart".to_string()),
                phase: WorkerCommandReceiptPhase::Intent,
                lease_generation: Some(1),
                result_message: None,
                ack_confirmed: false,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            },
        );
        persist_worker_command_receipts_atomic(&bounded_path, &many).unwrap();
        let loaded_bounded = load_worker_command_receipts_strict(&bounded_path).unwrap();
        assert_eq!(loaded_bounded.len(), MAX_WORKER_COMMAND_RECEIPTS);
        assert!(
            loaded_bounded.iter().any(|r| r.id == "cmd-active-intent"),
            "active intent receipt must survive eviction of older confirmed receipts"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn worker_command_saturation_preserves_unconfirmed_and_intents_applies_backpressure_and_drains()
    {
        let root = env::temp_dir().join(format!("af-cluster-sat-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
        let receipts_path = resolve_worker_command_receipts_path(&outbox_path);

        // 1. Direct persistence must NEVER evict unconfirmed terminal receipts or active intents.
        let unconfirmed_overflow: Vec<WorkerCommandReceipt> = (0..=MAX_WORKER_COMMAND_RECEIPTS)
            .map(|i| WorkerCommandReceipt {
                id: format!("cmd-direct-unconfirmed-{i}"),
                node_id: Some("node-sat".to_string()),
                cmd_type: Some("restart_service".to_string()),
                target: Some("sonarr".to_string()),
                action: Some("restart".to_string()),
                phase: WorkerCommandReceiptPhase::Executed,
                lease_generation: Some(1),
                result_message: Some("restart sonarr succeeded".to_string()),
                ack_confirmed: false,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            })
            .collect();
        assert!(
            persist_worker_command_receipts_atomic(&receipts_path, &unconfirmed_overflow).is_err()
        );

        let intent_overflow: Vec<WorkerCommandReceipt> = (0..=MAX_WORKER_COMMAND_RECEIPTS)
            .map(|i| WorkerCommandReceipt {
                id: format!("cmd-direct-intent-{i}"),
                node_id: Some("node-sat".to_string()),
                cmd_type: Some("restart_service".to_string()),
                target: Some("sonarr".to_string()),
                action: Some("restart".to_string()),
                phase: WorkerCommandReceiptPhase::Intent,
                lease_generation: Some(1),
                result_message: None,
                ack_confirmed: false,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            })
            .collect();
        assert!(persist_worker_command_receipts_atomic(&receipts_path, &intent_overflow).is_err());

        // 2. Saturate coordinator with 255 unconfirmed terminal receipts + 1 active in-flight Intent
        //    (seed the first 254 via durable startup reconciliation, then execute slots 255 & 256 live).
        let seeded_unconfirmed: Vec<WorkerCommandReceipt> = (0..(MAX_WORKER_COMMAND_RECEIPTS - 2))
            .map(|i| WorkerCommandReceipt {
                id: format!("cmd-unconfirmed-{i}"),
                node_id: Some("node-sat".to_string()),
                cmd_type: Some("restart_service".to_string()),
                target: Some("sonarr".to_string()),
                action: Some("restart".to_string()),
                phase: WorkerCommandReceiptPhase::Executed,
                lease_generation: Some(1),
                result_message: Some("restart sonarr succeeded".to_string()),
                ack_confirmed: false,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            })
            .collect();
        persist_worker_command_receipts_atomic(&receipts_path, &seeded_unconfirmed).unwrap();

        let worker =
            WorkerCommandCoordinator::load_and_recover("node-sat", &outbox_path, &receipts_path);
        assert_eq!(
            worker.pending_acks_snapshot().len(),
            MAX_WORKER_COMMAND_RECEIPTS - 2
        );
        let slot_255_cmd = PendingWorkerCommand {
            id: format!("cmd-unconfirmed-{}", MAX_WORKER_COMMAND_RECEIPTS - 2),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
            lease_generation: 1,
        };
        let slot_255_mutation = match worker.prepare_command_dispatch(slot_255_cmd) {
            WorkerCommandDispatchPlan::Execute(m) => m,
            other => panic!("expected Execute for 255th slot, got {other:?}"),
        };
        worker
            .complete_admitted_mutation(&slot_255_mutation, Ok(()))
            .unwrap();
        let inflight_cmd = PendingWorkerCommand {
            id: "cmd-inflight-last".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), "radarr".to_string())]),
            lease_generation: 1,
        };
        let inflight_mutation = match worker.prepare_command_dispatch(inflight_cmd) {
            WorkerCommandDispatchPlan::Execute(m) => m,
            other => panic!("expected Execute for 256th slot, got {other:?}"),
        };

        // 3. At saturation, unseen new commands (both mutating and non-mutating) MUST fail closed
        //    with explicit backpressure BEFORE dispatch and WITHOUT evicting any entry.
        let fresh_mutation = PendingWorkerCommand {
            id: "cmd-fresh-blocked".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), "plex".to_string())]),
            lease_generation: 1,
        };
        assert_eq!(
            worker.prepare_command_dispatch(fresh_mutation.clone()),
            WorkerCommandDispatchPlan::RejectedCapacitySaturated
        );
        assert_eq!(
            worker.prepare_command_dispatch(PendingWorkerCommand {
                id: "cmd-fresh-ping-blocked".to_string(),
                cmd_type: "ping".to_string(),
                params: HashMap::new(),
                lease_generation: 1,
            }),
            WorkerCommandDispatchPlan::RejectedCapacitySaturated
        );

        let disk_at_sat = load_worker_command_receipts_strict(&receipts_path).unwrap();
        assert_eq!(disk_at_sat.len(), MAX_WORKER_COMMAND_RECEIPTS);
        assert!(disk_at_sat.iter().any(|r| r.id == "cmd-unconfirmed-0"));
        assert!(disk_at_sat
            .iter()
            .any(|r| r.id == "cmd-inflight-last" && r.phase == WorkerCommandReceiptPhase::Intent));
        assert!(!disk_at_sat.iter().any(|r| r.id == "cmd-fresh-blocked"));

        // 4. At saturation, existing commands MUST still reattach, complete, and drain ACKs.
        let reattach_cmd = PendingWorkerCommand {
            id: "cmd-unconfirmed-0".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
            lease_generation: 2,
        };
        let reattached = match worker.prepare_command_dispatch(reattach_cmd) {
            WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
            other => panic!("existing receipt must reattach at saturation, got {other:?}"),
        };
        assert_eq!(reattached.id, "cmd-unconfirmed-0");
        assert_eq!(reattached.lease_generation, Some(2));
        assert_eq!(reattached.status, WORKER_COMMAND_STATUS_EXECUTED);

        let finished_ack = worker
            .complete_admitted_mutation(&inflight_mutation, Ok(()))
            .expect("in-flight intent must complete cleanly at saturation");
        assert_eq!(finished_ack.id, "cmd-inflight-last");
        assert_eq!(finished_ack.status, WORKER_COMMAND_STATUS_EXECUTED);
        assert_eq!(
            worker.pending_acks_snapshot().len(),
            MAX_WORKER_COMMAND_RECEIPTS
        );

        // 5. Confirming ONE receipt via master ACK frees exactly one recyclable slot and unblocks
        //    the next dispatch without losing any other unconfirmed receipt.
        worker.mark_confirmed(&["cmd-unconfirmed-0".to_string()]);
        assert_eq!(
            worker.pending_acks_snapshot().len(),
            MAX_WORKER_COMMAND_RECEIPTS - 1
        );

        let unblocked = match worker.prepare_command_dispatch(fresh_mutation) {
            WorkerCommandDispatchPlan::Execute(m) => m,
            other => panic!("expected Execute after one confirmed receipt drained, got {other:?}"),
        };
        assert_eq!(unblocked.id, "cmd-fresh-blocked");
        let after_recycle = load_worker_command_receipts_strict(&receipts_path).unwrap();
        assert_eq!(after_recycle.len(), MAX_WORKER_COMMAND_RECEIPTS);
        assert!(!after_recycle.iter().any(|r| r.id == "cmd-unconfirmed-0"));
        assert!(after_recycle.iter().any(|r| r.id == "cmd-unconfirmed-1"));
        assert!(after_recycle.iter().any(|r| r.id == "cmd-inflight-last"));
        assert!(after_recycle
            .iter()
            .any(|r| r.id == "cmd-fresh-blocked" && r.phase == WorkerCommandReceiptPhase::Intent));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn worker_command_byte_bound_and_legacy_outbox_reconciliation_guards() {
        let root = env::temp_dir().join(format!("af-cluster-recon-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();

        // 1. Outbox fits 256 max-length (1024-byte) result messages cleanly and rejects overflow.
        let full_outbox_path = root.join("full_outbox/cluster_worker_ack_outbox.json");
        let msg_1024 = "m".repeat(1024);
        let full_acks: Vec<WorkerCommandAck> = (0..MAX_WORKER_ACK_OUTBOX_ENTRIES)
            .map(|i| WorkerCommandAck {
                id: format!("cmd-full-ack-{i:03}"),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some(msg_1024.clone()),
                lease_generation: Some(1),
            })
            .collect();
        persist_worker_ack_outbox_atomic(&full_outbox_path, &full_acks)
            .expect("256 max-length ACKs must fit within outbox byte bound");
        assert_eq!(
            load_worker_ack_outbox_strict(&full_outbox_path)
                .unwrap()
                .len(),
            MAX_WORKER_ACK_OUTBOX_ENTRIES
        );

        let mut oversized_outbox = vec![WorkerCommandAck {
            id: "cmd-giant-outbox".to_string(),
            status: WORKER_COMMAND_STATUS_FAILED.to_string(),
            result_message: Some("z".repeat(MAX_WORKER_ACK_OUTBOX_BYTES + 16)),
            lease_generation: Some(1),
        }];
        let giant_outbox_path = root.join("giant_outbox/cluster_worker_ack_outbox.json");
        assert!(
            persist_worker_ack_outbox_atomic(&giant_outbox_path, &oversized_outbox).is_err(),
            "outbox persistence must fail closed instead of writing an unreadable oversized file"
        );
        oversized_outbox.clear();

        // 2. Receipt byte-bound enforcement recycles ONLY confirmed entries and applies
        //    backpressure before dispatch even when entry count < MAX_WORKER_COMMAND_RECEIPTS.
        let byte_outbox = root.join("byte_bound/cluster_worker_ack_outbox.json");
        let byte_receipts = resolve_worker_command_receipts_path(&byte_outbox);
        let big_target = "s".repeat(16 * 1024);
        let unconfirmed_heavy: Vec<WorkerCommandReceipt> = (0..31)
            .map(|i| WorkerCommandReceipt {
                id: format!("cmd-heavy-{i:02}"),
                node_id: Some("node-bytes".to_string()),
                cmd_type: Some("restart_service".to_string()),
                target: Some(big_target.clone()),
                action: Some("restart".to_string()),
                phase: WorkerCommandReceiptPhase::Executed,
                lease_generation: Some(1),
                result_message: Some("ok".to_string()),
                ack_confirmed: false,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            })
            .collect();
        persist_worker_command_receipts_atomic(&byte_receipts, &unconfirmed_heavy).unwrap();

        let mut too_big_unconfirmed = unconfirmed_heavy.clone();
        too_big_unconfirmed.push(WorkerCommandReceipt {
            id: "cmd-heavy-overflow".to_string(),
            node_id: Some("node-bytes".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some(big_target.clone()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Executed,
            lease_generation: Some(1),
            result_message: Some("ok".to_string()),
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        });
        assert!(
            persist_worker_command_receipts_atomic(&byte_receipts, &too_big_unconfirmed).is_err(),
            "receipt persistence must fail closed on byte overflow when no confirmed entries exist"
        );

        let byte_worker =
            WorkerCommandCoordinator::load_and_recover("node-bytes", &byte_outbox, &byte_receipts);
        assert_eq!(
            byte_worker.prepare_command_dispatch(PendingWorkerCommand {
                id: "cmd-heavy-new".to_string(),
                cmd_type: "restart_service".to_string(),
                params: HashMap::from([("service".to_string(), big_target.clone())]),
                lease_generation: 1,
            }),
            WorkerCommandDispatchPlan::RejectedCapacitySaturated
        );

        // Confirming one heavy receipt frees enough bytes to recycle it and admit the new command,
        // and the reserved Intent completion headroom lets it complete cleanly within the byte bound.
        byte_worker.mark_confirmed(&["cmd-heavy-00".to_string()]);
        let admitted_heavy = match byte_worker.prepare_command_dispatch(PendingWorkerCommand {
            id: "cmd-heavy-new".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), big_target)]),
            lease_generation: 1,
        }) {
            WorkerCommandDispatchPlan::Execute(m) => m,
            other => {
                panic!("expected Execute after recycling confirmed heavy receipt, got {other:?}")
            }
        };
        assert_eq!(admitted_heavy.id, "cmd-heavy-new");
        let completed_heavy = byte_worker
            .complete_admitted_mutation(&admitted_heavy, Err("e".repeat(1024)))
            .expect(
                "reserved byte headroom must allow admitted intent to persist full-size outcome",
            );
        assert_eq!(completed_heavy.status, WORKER_COMMAND_STATUS_FAILED);
        assert_eq!(
            load_worker_command_receipts_strict(&byte_receipts)
                .unwrap()
                .len(),
            31
        );

        // 3. Corrupt / invalid legacy outbox fails closed instead of disappearing authority.
        let bad_outbox_dir = root.join("bad_outbox");
        std::fs::create_dir_all(&bad_outbox_dir).unwrap();
        let bad_outbox = bad_outbox_dir.join("cluster_worker_ack_outbox.json");
        let bad_receipts = resolve_worker_command_receipts_path(&bad_outbox);
        std::fs::write(
            &bad_outbox,
            r#"[{"id":"cmd-bad-gen","status":"executed","lease_generation":0}]"#,
        )
        .unwrap();
        assert!(load_worker_ack_outbox_strict(&bad_outbox).is_err());
        let bad_worker =
            WorkerCommandCoordinator::load_and_recover("node-bad", &bad_outbox, &bad_receipts);
        assert_eq!(
            bad_worker.prepare_command_dispatch(PendingWorkerCommand {
                id: "cmd-bad-gen".to_string(),
                cmd_type: "restart_service".to_string(),
                params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
                lease_generation: 1,
            }),
            WorkerCommandDispatchPlan::RejectedStorageFailure
        );

        // 4. Generation-less legacy outbox entry MUST NOT overwrite a leased `Intent` as `Executed`.
        let gen_outbox = root.join("gen_guard/cluster_worker_ack_outbox.json");
        let gen_receipts = resolve_worker_command_receipts_path(&gen_outbox);
        persist_worker_command_receipts_atomic(
            &gen_receipts,
            &[WorkerCommandReceipt {
                id: "cmd-leased-intent".to_string(),
                node_id: Some("node-gen".to_string()),
                cmd_type: Some("restart_service".to_string()),
                target: Some("sonarr".to_string()),
                action: Some("restart".to_string()),
                phase: WorkerCommandReceiptPhase::Intent,
                lease_generation: Some(2),
                result_message: None,
                ack_confirmed: false,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            }],
        )
        .unwrap();
        persist_worker_ack_outbox_atomic(
            &gen_outbox,
            &[WorkerCommandAck {
                id: "cmd-leased-intent".to_string(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("unproven legacy ack".to_string()),
                lease_generation: None,
            }],
        )
        .unwrap();
        let gen_worker =
            WorkerCommandCoordinator::load_and_recover("node-gen", &gen_outbox, &gen_receipts);
        let recovered_gen = load_worker_command_receipts_strict(&gen_receipts).unwrap();
        assert_eq!(recovered_gen.len(), 1);
        assert_eq!(recovered_gen[0].phase, WorkerCommandReceiptPhase::Unknown);
        assert_eq!(recovered_gen[0].lease_generation, Some(2));
        let reconciled_outbox = load_worker_ack_outbox_strict(&gen_outbox).unwrap();
        assert_eq!(reconciled_outbox.len(), 1);
        assert_eq!(reconciled_outbox[0].status, WORKER_COMMAND_STATUS_UNKNOWN);
        assert_eq!(reconciled_outbox[0].lease_generation, Some(2));
        drop(gen_worker);

        // 5. Startup legacy outbox import with 256 unconfirmed receipts + 1 extra legacy outbox
        //    entry fails closed instead of dropping authority, while preserving pending ACKs.
        let sat_recon_outbox = root.join("sat_recon/cluster_worker_ack_outbox.json");
        let sat_recon_receipts = resolve_worker_command_receipts_path(&sat_recon_outbox);
        let sat_256: Vec<WorkerCommandReceipt> = (0..MAX_WORKER_COMMAND_RECEIPTS)
            .map(|i| WorkerCommandReceipt {
                id: format!("cmd-sat-rec-{i:03}"),
                node_id: Some("node-recon".to_string()),
                cmd_type: Some("restart_service".to_string()),
                target: Some("sonarr".to_string()),
                action: Some("restart".to_string()),
                phase: WorkerCommandReceiptPhase::Executed,
                lease_generation: Some(1),
                result_message: Some("ok".to_string()),
                ack_confirmed: false,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            })
            .collect();
        persist_worker_command_receipts_atomic(&sat_recon_receipts, &sat_256).unwrap();
        persist_worker_ack_outbox_atomic(
            &sat_recon_outbox,
            &[WorkerCommandAck {
                id: "cmd-legacy-extra-257".to_string(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("legacy ok".to_string()),
                lease_generation: Some(1),
            }],
        )
        .unwrap();
        let sat_recon_worker = WorkerCommandCoordinator::load_and_recover(
            "node-recon",
            &sat_recon_outbox,
            &sat_recon_receipts,
        );
        assert_eq!(
            sat_recon_worker.prepare_command_dispatch(PendingWorkerCommand {
                id: "cmd-blocked-after-overflow".to_string(),
                cmd_type: "restart_service".to_string(),
                params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
                lease_generation: 1,
            }),
            WorkerCommandDispatchPlan::RejectedStorageFailure
        );
        assert_eq!(sat_recon_worker.pending_acks_snapshot().len(), 1);
        assert_eq!(
            load_worker_command_receipts_strict(&sat_recon_receipts)
                .unwrap()
                .len(),
            MAX_WORKER_COMMAND_RECEIPTS
        );

        // 6. Startup legacy outbox import with confirmed receipts recycles confirmed entries and
        //    prunes already-confirmed IDs lingering in the outbox.
        let recycle_recon_outbox = root.join("recycle_recon/cluster_worker_ack_outbox.json");
        let recycle_recon_receipts = resolve_worker_command_receipts_path(&recycle_recon_outbox);
        let confirmed_256: Vec<WorkerCommandReceipt> = (0..MAX_WORKER_COMMAND_RECEIPTS)
            .map(|i| WorkerCommandReceipt {
                id: format!("cmd-conf-rec-{i:03}"),
                node_id: Some("node-recon2".to_string()),
                cmd_type: Some("ping".to_string()),
                target: Some(String::new()),
                action: None,
                phase: WorkerCommandReceiptPhase::Executed,
                lease_generation: Some(1),
                result_message: Some("pong".to_string()),
                ack_confirmed: true,
                updated_at: "2026-11-21T00:00:00Z".to_string(),
            })
            .collect();
        persist_worker_command_receipts_atomic(&recycle_recon_receipts, &confirmed_256).unwrap();
        persist_worker_ack_outbox_atomic(
            &recycle_recon_outbox,
            &[
                WorkerCommandAck {
                    id: "cmd-conf-rec-000".to_string(),
                    status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                    result_message: Some("pong".to_string()),
                    lease_generation: Some(1),
                },
                WorkerCommandAck {
                    id: "cmd-conf-rec-005".to_string(),
                    status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                    result_message: Some("pong".to_string()),
                    lease_generation: Some(1),
                },
                WorkerCommandAck {
                    id: "cmd-legacy-imported".to_string(),
                    status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                    result_message: Some("legacy done".to_string()),
                    lease_generation: Some(1),
                },
            ],
        )
        .unwrap();
        let recycle_worker = WorkerCommandCoordinator::load_and_recover(
            "node-recon2",
            &recycle_recon_outbox,
            &recycle_recon_receipts,
        );
        let post_recon_receipts =
            load_worker_command_receipts_strict(&recycle_recon_receipts).unwrap();
        assert_eq!(post_recon_receipts.len(), MAX_WORKER_COMMAND_RECEIPTS);
        assert!(post_recon_receipts
            .iter()
            .any(|r| r.id == "cmd-legacy-imported" && !r.ack_confirmed));
        let post_recon_outbox = load_worker_ack_outbox_strict(&recycle_recon_outbox).unwrap();
        assert_eq!(post_recon_outbox.len(), 1);
        assert_eq!(post_recon_outbox[0].id, "cmd-legacy-imported");
        drop(recycle_worker);

        let _ = std::fs::remove_dir_all(&root);
    }
}
