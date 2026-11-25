//! Distributed Jellyfin transcoding (`/?tab=cluster`, design file 50):
//! global transcoding switch, local transcode worker service toggle, `jellyfin-ffmpeg`
//! version alignment table with local/proxied **Update to match** triggers, per-worker
//! capability/grant-gated configuration cards with path-parity testing, and recent
//! transcode job history over local same-origin `/api/v1/admin/peers/transcode`.

use super::peers::{
    compatibility_presentation, status_presentation, supports_transcode, PeerLinkView,
};
use super::{
    local_same_origin_post, peer_api_request, peer_package_update_path, PeerApiError,
    PeerErrorAlert, PEER_TRANSCODE_PATH,
};
use crate::state::{app, owned_resource_reads, run_resource_read, ResourceReads};
use crate::tabs::busy::{SetBusyGuard, ValueBusyGuard};
use crate::tabs::l10n::{tt, tt_with, Badge, EmptyState, ObsCard};
use af_web_core::charts::{format_duration_span, parse_utc_timestamp_str_ms};
use af_web_core::i18n::{translate, translate_with};
use leptos::prelude::*;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use wasm_bindgen_futures::spawn_local;

pub const WORKER_WEIGHT_MIN: u32 = 1;
pub const WORKER_WEIGHT_MAX: u32 = 100;
pub const WORKER_MAX_JOBS_MIN: u32 = 1;
pub const WORKER_MAX_JOBS_MAX: u32 = 64;

fn deserialize_opt_string_or_number<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<Value>::deserialize(deserializer)?;
    match opt {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Some(Value::Number(num)) => Ok(Some(num.to_string())),
        Some(other) => Ok(Some(other.to_string())),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscodeRenderNodeView {
    pub path: String,
    pub vendor_id: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalTranscodeInfoView {
    pub server_name: String,
    pub ffmpeg_version: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub encoders: Vec<String>,
    pub render_nodes: Vec<TranscodeRenderNodeView>,
    pub primary_render_node: Option<String>,
    pub transcoding_temp_path: Option<String>,
    pub tmp_dir: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscodeWorkerView {
    pub link_id: String,
    pub peer_name: String,
    pub link_state: String,
    pub compatibility: String,
    pub supports_transcode: bool,
    pub has_transcode_write_grant: bool,
    pub has_updates_write_grant: bool,
    pub enabled: bool,
    pub eligible: bool,
    pub ineligible_reason: Option<String>,
    pub weight: u32,
    pub max_jobs: u32,
    pub active_jobs: u32,
    #[serde(default, deserialize_with = "deserialize_opt_string_or_number")]
    pub unhealthy_until: Option<String>,
    pub ffmpeg_version: Option<String>,
    pub package_version: Option<String>,
    pub ffmpeg_mismatch: bool,
    pub ffmpeg_mismatch_message: Option<String>,
    pub align_target: Option<String>,
    pub encoders: Vec<String>,
    pub render_node: Option<String>,
    pub parity_ok: bool,
    pub parity_error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscodeJobView {
    pub id: String,
    pub link_id: Option<String>,
    pub peer_name: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub exit_code: Option<i32>,
    pub request_id: Option<String>,
    pub ran_locally: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ParityTestResultView {
    pub link_id: String,
    pub ok: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscodeConfigResponse {
    pub enabled: bool,
    pub worker_service_enabled: bool,
    pub worker_service_active: bool,
    pub dispatcher_active: bool,
    pub dispatcher_socket: String,
    pub shim_installed: bool,
    pub shim_path: String,
    pub jellyfin_dropin_enabled: bool,
    pub jellyfin_reported_ffmpeg: Option<String>,
    #[serde(default)]
    pub api_restart_scheduled: bool,
    pub local: LocalTranscodeInfoView,
    pub workers: Vec<TranscodeWorkerView>,
    pub recent_jobs: Vec<TranscodeJobView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parity_result: Option<ParityTestResultView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateTranscodeWorkerRequest {
    pub link_id: String,
    pub enabled: bool,
    pub weight: u32,
    pub max_jobs: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateTranscodeConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_service_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<Vec<UpdateTranscodeWorkerRequest>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_parity_test_link_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlignAction {
    None,
    UpdateLocal {
        path: String,
    },
    UpdatePeer {
        link_id: String,
        peer_name: String,
        path: String,
    },
    DisabledMissingUpdatesGrant {
        peer_name: String,
        reason_key: &'static str,
    },
    DisabledLinkUnavailable {
        peer_name: String,
        reason_key: &'static str,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerDraft {
    pub enabled: bool,
    pub weight_input: String,
    pub max_jobs_input: String,
}

impl WorkerDraft {
    pub fn from_worker(worker: &TranscodeWorkerView) -> Self {
        let weight = worker.weight.clamp(WORKER_WEIGHT_MIN, WORKER_WEIGHT_MAX);
        let max_jobs = worker
            .max_jobs
            .clamp(WORKER_MAX_JOBS_MIN, WORKER_MAX_JOBS_MAX);
        Self {
            enabled: worker.enabled,
            weight_input: weight.to_string(),
            max_jobs_input: max_jobs.to_string(),
        }
    }

    pub fn is_dirty(&self, worker: &TranscodeWorkerView) -> bool {
        self.enabled != worker.enabled
            || self.weight_input.trim() != worker.weight.to_string()
            || self.max_jobs_input.trim() != worker.max_jobs.to_string()
    }
}

/// Pure view-model state container for [`TranscodeSection`].
/// Preserves unsaved per-worker edits across 10-second background refreshes while
/// syncing clean workers and clearing state cleanly on session-epoch changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TranscodeSectionState {
    pub config: Option<TranscodeConfigResponse>,
    pub drafts: BTreeMap<String, WorkerDraft>,
    pub dirty_workers: BTreeSet<String>,
    pub parity_results: BTreeMap<String, ParityTestResultView>,
}

impl TranscodeSectionState {
    pub fn reset(&mut self) {
        self.config = None;
        self.drafts.clear();
        self.dirty_workers.clear();
        self.parity_results.clear();
    }

    pub fn apply_loaded(&mut self, resp: TranscodeConfigResponse) {
        if let Some(parity) = resp.parity_result.clone() {
            if !parity.link_id.trim().is_empty() {
                self.parity_results.insert(parity.link_id.clone(), parity);
            }
        }
        let valid_ids: BTreeSet<String> = resp
            .workers
            .iter()
            .map(|worker| worker.link_id.clone())
            .collect();
        self.drafts.retain(|id, _| valid_ids.contains(id));
        self.dirty_workers.retain(|id| valid_ids.contains(id));
        self.parity_results.retain(|id, _| valid_ids.contains(id));

        for worker in &resp.workers {
            if !self.dirty_workers.contains(&worker.link_id)
                || !self.drafts.contains_key(&worker.link_id)
            {
                self.drafts
                    .insert(worker.link_id.clone(), WorkerDraft::from_worker(worker));
            }
        }
        self.config = Some(resp);
    }

    pub fn apply_worker_saved(&mut self, saved_link_id: &str, resp: TranscodeConfigResponse) {
        self.dirty_workers.remove(saved_link_id);
        self.apply_loaded(resp);
    }

    pub fn update_worker_draft(&mut self, link_id: &str, mutate: impl FnOnce(&mut WorkerDraft)) {
        let existing_worker = self
            .config
            .as_ref()
            .and_then(|cfg| cfg.workers.iter().find(|w| w.link_id == link_id))
            .cloned();
        let entry = self.drafts.entry(link_id.to_string()).or_insert_with(|| {
            existing_worker
                .as_ref()
                .map(WorkerDraft::from_worker)
                .unwrap_or_default()
        });
        mutate(entry);
        match existing_worker {
            Some(worker) if entry.is_dirty(&worker) => {
                self.dirty_workers.insert(link_id.to_string());
            }
            Some(_) => {
                self.dirty_workers.remove(link_id);
            }
            None => {
                self.dirty_workers.insert(link_id.to_string());
            }
        }
    }

    pub fn draft_for(&self, worker: &TranscodeWorkerView) -> WorkerDraft {
        self.drafts
            .get(&worker.link_id)
            .cloned()
            .unwrap_or_else(|| WorkerDraft::from_worker(worker))
    }

    pub fn is_worker_dirty(&self, link_id: &str) -> bool {
        self.dirty_workers.contains(link_id)
    }
}

pub fn parse_worker_weight(raw: &str) -> Result<u32, &'static str> {
    let trimmed = raw.trim();
    let value = trimmed
        .parse::<u32>()
        .map_err(|_| "Cluster.transcodeValidationWeightRange")?;
    if (WORKER_WEIGHT_MIN..=WORKER_WEIGHT_MAX).contains(&value) {
        Ok(value)
    } else {
        Err("Cluster.transcodeValidationWeightRange")
    }
}

pub fn parse_worker_max_jobs(raw: &str) -> Result<u32, &'static str> {
    let trimmed = raw.trim();
    let value = trimmed
        .parse::<u32>()
        .map_err(|_| "Cluster.transcodeValidationMaxJobsRange")?;
    if (WORKER_MAX_JOBS_MIN..=WORKER_MAX_JOBS_MAX).contains(&value) {
        Ok(value)
    } else {
        Err("Cluster.transcodeValidationMaxJobsRange")
    }
}

pub fn build_toggle_enabled_request(enabled: bool) -> UpdateTranscodeConfigRequest {
    UpdateTranscodeConfigRequest {
        enabled: Some(enabled),
        ..Default::default()
    }
}

pub fn build_toggle_worker_service_request(enabled: bool) -> UpdateTranscodeConfigRequest {
    UpdateTranscodeConfigRequest {
        worker_service_enabled: Some(enabled),
        ..Default::default()
    }
}

pub fn build_update_worker_request(
    link_id: &str,
    enabled: bool,
    weight_raw: &str,
    max_jobs_raw: &str,
) -> Result<UpdateTranscodeConfigRequest, &'static str> {
    let trimmed_id = link_id.trim();
    if trimmed_id.is_empty() {
        return Err("Cluster.transcodeValidationLinkIdRequired");
    }
    let weight = parse_worker_weight(weight_raw)?;
    let max_jobs = parse_worker_max_jobs(max_jobs_raw)?;
    Ok(UpdateTranscodeConfigRequest {
        workers: Some(vec![UpdateTranscodeWorkerRequest {
            link_id: trimmed_id.to_string(),
            enabled,
            weight,
            max_jobs,
        }]),
        ..Default::default()
    })
}

pub fn build_parity_test_request(
    link_id: &str,
) -> Result<UpdateTranscodeConfigRequest, &'static str> {
    let trimmed_id = link_id.trim();
    if trimmed_id.is_empty() {
        return Err("Cluster.transcodeValidationLinkIdRequired");
    }
    Ok(UpdateTranscodeConfigRequest {
        run_parity_test_link_id: Some(trimmed_id.to_string()),
        ..Default::default()
    })
}

pub fn effective_worker_supports_transcode(
    worker: &TranscodeWorkerView,
    live_peer: Option<&PeerLinkView>,
) -> bool {
    worker.compatibility != "incompatible"
        && worker.supports_transcode
        && live_peer.is_none_or(supports_transcode)
}

/// Returns `true` when the peer has granted a scope that authorizes Jellyfin package alignment
/// (`POST /api/v1/peers/{id}/admin/packages/jellyfin/update`): `updates: write` (narrowed to
/// Jellyfin updates on the peer) or `marketplace: write`.
pub fn has_peer_jellyfin_update_grant(
    worker: &TranscodeWorkerView,
    live_peer: Option<&PeerLinkView>,
) -> bool {
    worker.has_updates_write_grant
        || live_peer.is_some_and(|peer| {
            peer.grants
                .outbound
                .as_ref()
                .is_some_and(|grant| grant.access.marketplace.allows_write())
        })
}

pub fn resolve_align_action_for_peer(
    worker: &TranscodeWorkerView,
    live_peer: Option<&PeerLinkView>,
) -> AlignAction {
    if !worker.ffmpeg_mismatch {
        return AlignAction::None;
    }
    match worker.align_target.as_deref().map(str::trim) {
        Some("local") => AlignAction::UpdateLocal {
            path: peer_package_update_path(None),
        },
        Some("peer") => {
            if !has_peer_jellyfin_update_grant(worker, live_peer) {
                return AlignAction::DisabledMissingUpdatesGrant {
                    peer_name: worker.peer_name.clone(),
                    reason_key: "Cluster.transcodeAlignRequiresUpdatesGrant",
                };
            }
            if worker.link_state != "active" {
                return AlignAction::DisabledLinkUnavailable {
                    peer_name: worker.peer_name.clone(),
                    reason_key: "Cluster.transcodeAlignRequiresActiveLink",
                };
            }
            let trimmed_id = worker.link_id.trim();
            if trimmed_id.is_empty() {
                return AlignAction::None;
            }
            AlignAction::UpdatePeer {
                link_id: trimmed_id.to_string(),
                peer_name: worker.peer_name.clone(),
                path: peer_package_update_path(Some(trimmed_id)),
            }
        }
        _ => AlignAction::None,
    }
}

pub fn resolve_align_action(worker: &TranscodeWorkerView) -> AlignAction {
    resolve_align_action_for_peer(worker, None)
}

pub fn can_enable_worker(worker: &TranscodeWorkerView, live_peer: Option<&PeerLinkView>) -> bool {
    effective_worker_supports_transcode(worker, live_peer)
        && worker.has_transcode_write_grant
        && worker.link_state == "active"
}

pub fn can_save_worker(
    worker: &TranscodeWorkerView,
    draft_enabled: bool,
    live_peer: Option<&PeerLinkView>,
) -> bool {
    if draft_enabled {
        can_enable_worker(worker, live_peer)
    } else {
        worker.enabled || can_enable_worker(worker, live_peer)
    }
}

pub fn can_run_parity_test(worker: &TranscodeWorkerView, live_peer: Option<&PeerLinkView>) -> bool {
    effective_worker_supports_transcode(worker, live_peer)
        && worker.has_transcode_write_grant
        && worker.link_state == "active"
        && !worker.link_id.trim().is_empty()
}

pub fn worker_capability_reason(
    locale: &str,
    worker: &TranscodeWorkerView,
    live_peer: Option<&PeerLinkView>,
) -> Option<String> {
    if worker.compatibility == "incompatible"
        || live_peer.is_some_and(|peer| peer.compatibility == "incompatible")
    {
        return Some(translate_with(
            locale,
            "Cluster.compatIncompatibleHint",
            &[("peer", &worker.peer_name)],
        ));
    }
    if !effective_worker_supports_transcode(worker, live_peer) {
        return Some(translate_with(
            locale,
            "Cluster.transcodeUpdatePeerHint",
            &[("peer", &worker.peer_name)],
        ));
    }
    None
}

pub fn worker_control_disabled_reason(
    locale: &str,
    worker: &TranscodeWorkerView,
    live_peer: Option<&PeerLinkView>,
) -> Option<String> {
    if let Some(cap_reason) = worker_capability_reason(locale, worker, live_peer) {
        return Some(cap_reason);
    }
    if !worker.has_transcode_write_grant {
        return Some(translate_with(
            locale,
            "Cluster.transcodeMissingWriteGrant",
            &[("peer", &worker.peer_name)],
        ));
    }
    if worker.link_state != "active" {
        return Some(translate_with(
            locale,
            "Cluster.transcodeLinkNotActive",
            &[("peer", &worker.peer_name)],
        ));
    }
    None
}

pub fn worker_eligibility_presentation(
    worker: &TranscodeWorkerView,
) -> (&'static str, &'static str) {
    if !worker.enabled {
        ("Cluster.transcodeEligibilityDisabled", "muted")
    } else if worker.eligible {
        ("Cluster.transcodeEligibilityEligible", "success")
    } else if worker.ffmpeg_mismatch {
        ("Cluster.transcodeEligibilityVersionMismatch", "warning")
    } else if worker
        .unhealthy_until
        .as_deref()
        .is_some_and(|ts| !ts.trim().is_empty())
    {
        ("Cluster.transcodeEligibilityUnhealthy", "danger")
    } else {
        ("Cluster.transcodeEligibilityIneligible", "warning")
    }
}

pub fn worker_parity_presentation(worker: &TranscodeWorkerView) -> (&'static str, &'static str) {
    if worker.parity_ok {
        ("Cluster.transcodeParityPassed", "success")
    } else if worker
        .parity_error
        .as_deref()
        .is_some_and(|err| !err.trim().is_empty())
    {
        ("Cluster.transcodeParityFailed", "danger")
    } else {
        ("Cluster.transcodeParityUntested", "muted")
    }
}

pub fn format_ffmpeg_version(
    locale: &str,
    package_version: Option<&str>,
    ffmpeg_version: Option<&str>,
) -> String {
    let pkg = package_version.map(str::trim).filter(|s| !s.is_empty());
    let ff = ffmpeg_version.map(str::trim).filter(|s| !s.is_empty());
    match (pkg, ff) {
        (Some(p), Some(f)) if p == f => p.to_string(),
        (Some(p), Some(f)) => format!("{p} ({f})"),
        (Some(p), None) => p.to_string(),
        (None, Some(f)) => f.to_string(),
        (None, None) => translate(locale, "Not reported"),
    }
}

pub fn format_local_render_node(locale: &str, local: &LocalTranscodeInfoView) -> String {
    let primary = local
        .primary_render_node
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            local
                .render_nodes
                .first()
                .map(|node| node.path.trim())
                .filter(|s| !s.is_empty())
        });
    let Some(path) = primary else {
        return translate(locale, "Not reported");
    };
    let vendor = local
        .render_nodes
        .iter()
        .find(|node| node.path.trim() == path)
        .and_then(|node| node.vendor.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match vendor {
        Some(v) => format!("{path} ({v})"),
        None => path.to_string(),
    }
}

pub fn format_mismatch_banner(
    locale: &str,
    local: &LocalTranscodeInfoView,
    worker: &TranscodeWorkerView,
) -> Option<String> {
    if !worker.ffmpeg_mismatch {
        return None;
    }
    if let Some(msg) = worker
        .ffmpeg_mismatch_message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(msg.to_string());
    }
    let local_name = if local.server_name.trim().is_empty() {
        translate(locale, "Cluster.transcodeLocalDefaultName")
    } else {
        local.server_name.trim().to_string()
    };
    let local_version = format_ffmpeg_version(
        locale,
        local.package_version.as_deref(),
        local.ffmpeg_version.as_deref(),
    );
    let peer_version = format_ffmpeg_version(
        locale,
        worker.package_version.as_deref(),
        worker.ffmpeg_version.as_deref(),
    );
    Some(translate_with(
        locale,
        "Cluster.transcodeVersionMismatchFallback",
        &[
            ("local_name", &local_name),
            ("local_version", &local_version),
            ("peer_name", &worker.peer_name),
            ("peer_version", &peer_version),
        ],
    ))
}

pub fn format_parity_result_banner(
    locale: &str,
    peer_name: &str,
    result: &ParityTestResultView,
) -> String {
    let ms = result.elapsed_ms.to_string();
    if result.ok {
        translate_with(
            locale,
            "Cluster.transcodeParityResultPassed",
            &[("peer", peer_name), ("ms", &ms)],
        )
    } else if let Some(err) = result
        .error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        translate_with(
            locale,
            "Cluster.transcodeParityResultFailed",
            &[("peer", peer_name), ("ms", &ms), ("error", err)],
        )
    } else {
        translate_with(
            locale,
            "Cluster.transcodeParityResultFailedNoDetail",
            &[("peer", peer_name), ("ms", &ms)],
        )
    }
}

pub fn format_job_target(locale: &str, job: &TranscodeJobView) -> String {
    if job.ran_locally {
        return translate(locale, "Cluster.transcodeJobTargetLocal");
    }
    let peer = job
        .peer_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            job.link_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        });
    match peer {
        Some(name) => translate_with(
            locale,
            "Cluster.transcodeJobTargetRemote",
            &[("peer", name)],
        ),
        None => translate(locale, "Cluster.transcodeJobTargetRemoteUnknown"),
    }
}

pub fn format_job_duration(locale: &str, started_at: &str, ended_at: Option<&str>) -> String {
    let Some(end_raw) = ended_at.map(str::trim).filter(|s| !s.is_empty()) else {
        return translate(locale, "Cluster.transcodeJobRunning");
    };
    let (Some(start_ms), Some(end_ms)) = (
        parse_utc_timestamp_str_ms(started_at),
        parse_utc_timestamp_str_ms(end_raw),
    ) else {
        return translate(locale, "Not reported");
    };
    if !start_ms.is_finite() || !end_ms.is_finite() || end_ms < start_ms {
        return translate(locale, "Not reported");
    }
    let delta_ms = (end_ms - start_ms).round() as u64;
    if delta_ms < 1_000 {
        format!("{delta_ms} ms")
    } else {
        format_duration_span(delta_ms / 1_000, locale)
    }
}

pub fn job_exit_presentation(
    locale: &str,
    exit_code: Option<i32>,
    ended_at: Option<&str>,
) -> (String, &'static str) {
    match exit_code {
        Some(0) => (translate(locale, "Cluster.transcodeJobExitOk"), "success"),
        Some(code) => (
            translate_with(
                locale,
                "Cluster.transcodeJobExitFailed",
                &[("code", &code.to_string())],
            ),
            "danger",
        ),
        None => {
            if ended_at.map(str::trim).is_none_or(str::is_empty) {
                (translate(locale, "Cluster.transcodeJobRunning"), "indigo")
            } else {
                (
                    translate(locale, "Cluster.transcodeJobExitUnknown"),
                    "muted",
                )
            }
        }
    }
}

fn dom_safe_id(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum TranscodeAction {
    #[default]
    Idle,
    ToggleGlobal,
    ToggleWorkerService,
    SaveWorker(String),
    RunParity(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StatusNotice {
    AlignQueuedLocal,
    AlignQueuedPeer(String),
}

#[component]
pub fn TranscodeSection(
    peers: Signal<Vec<PeerLinkView>>,
    parent_revision: RwSignal<u64>,
    on_refresh_peers: Callback<()>,
) -> impl IntoView {
    let context = app();
    let state = RwSignal::new(TranscodeSectionState::default());
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(None::<PeerApiError>);
    let mutation_error = RwSignal::new(None::<PeerApiError>);
    let status_notice = RwSignal::new(None::<StatusNotice>);
    let local_revision = RwSignal::new(0u64);
    let load_generation = RwSignal::new(0u64);
    let mutation_generation = RwSignal::new(0u64);
    let busy_action = RwSignal::new(TranscodeAction::Idle);
    let align_busy = RwSignal::new(BTreeSet::<String>::new());
    let reads = owned_resource_reads();
    let last_epoch = StoredValue::new(context.session_epoch.get_untracked());

    on_cleanup(move || {
        let _ = mutation_generation.try_update(|g| *g = g.wrapping_add(1));
        let _ = load_generation.try_update(|g| *g = g.wrapping_add(1));
        reads.with_value(ResourceReads::cancel);
    });

    let trigger_local_refresh = Callback::new(move |()| {
        local_revision.update(|rev| *rev = rev.wrapping_add(1));
    });

    // Fenced GET /api/v1/admin/peers/transcode on mount, parent poll ticks, session switches,
    // and explicit refresh actions.
    Effect::new(move |_| {
        let epoch = context.session_epoch.get();
        if last_epoch.get_value() != epoch {
            state.update(TranscodeSectionState::reset);
            load_error.set(None);
            mutation_error.set(None);
            status_notice.set(None);
            busy_action.set(TranscodeAction::Idle);
            align_busy.update(BTreeSet::clear);
            mutation_generation.update(|g| *g = g.wrapping_add(1));
            last_epoch.set_value(epoch);
        }
        let _parent_rev = parent_revision.get();
        let _local_rev = local_revision.get();
        if !context.is_admin() {
            reads.with_value(ResourceReads::cancel);
            loading.set(false);
            return;
        }
        load_generation.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = load_generation.get_untracked();
        loading.set(true);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let work = async move {
                if load_generation.try_get_untracked() != Some(ticket)
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                {
                    return None;
                }
                Some(
                    peer_api_request::<TranscodeConfigResponse>(PEER_TRANSCODE_PATH, "GET", None)
                        .await,
                )
            };
            let Some(Some(result)) = run_resource_read(job, work).await else {
                return;
            };
            if load_generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(data) => {
                    state.update(|s| s.apply_loaded(data));
                    load_error.set(None);
                }
                Err(error) => {
                    load_error.set(Some(error));
                }
            }
            loading.set(false);
        });
    });

    let config_memo = Memo::new(move |_| state.with(|s| s.config.clone()));
    let is_mutating = Signal::derive(move || busy_action.get() != TranscodeAction::Idle);

    // Submits a targeted PUT /api/v1/admin/peers/transcode fenced by session epoch and
    // mutation generation, cancelling any stale in-flight GET before applying the result.
    let submit_put = move |action: TranscodeAction,
                           req: UpdateTranscodeConfigRequest,
                           saved_worker_id: Option<String>,
                           on_success: Callback<TranscodeConfigResponse>| {
        if busy_action.get_untracked() != TranscodeAction::Idle || !context.is_admin_untracked() {
            return;
        }
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                mutation_error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        let epoch = context.session_epoch.get_untracked();
        let ticket = mutation_generation.get_untracked();
        mutation_error.set(None);
        busy_action.set(action);
        let mut guard = ValueBusyGuard::for_generation(busy_action, mutation_generation, ticket);
        spawn_local(async move {
            let result = peer_api_request::<TranscodeConfigResponse>(
                PEER_TRANSCODE_PATH,
                "PUT",
                Some(&body),
            )
            .await;
            if mutation_generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(epoch)
                || !context.is_admin_untracked()
            {
                return;
            }
            guard.release();
            match result {
                Ok(updated) => {
                    // Cancel any older GET so it cannot overwrite this newer PUT response.
                    load_generation.update(|g| *g = g.wrapping_add(1));
                    reads.with_value(ResourceReads::cancel);
                    loading.set(false);
                    load_error.set(None);
                    mutation_error.set(None);
                    let response_for_cb = updated.clone();
                    state.update(|s| {
                        if let Some(ref link_id) = saved_worker_id {
                            s.apply_worker_saved(link_id, updated);
                        } else {
                            s.apply_loaded(updated);
                        }
                    });
                    on_success.run(response_for_cb);
                }
                Err(api_err) => {
                    mutation_error.set(Some(api_err));
                }
            }
        });
    };

    let submit_align_update = Callback::new(move |action: AlignAction| {
        if !context.is_admin_untracked() {
            return;
        }
        let (target_key, path, peer_label) = match action {
            AlignAction::UpdateLocal { path } => ("local".to_string(), path, None),
            AlignAction::UpdatePeer {
                link_id,
                peer_name,
                path,
            } => (format!("peer:{link_id}"), path, Some(peer_name)),
            AlignAction::None
            | AlignAction::DisabledMissingUpdatesGrant { .. }
            | AlignAction::DisabledLinkUnavailable { .. } => return,
        };
        if align_busy.with_untracked(|set| set.contains(&target_key)) {
            return;
        }
        let epoch = context.session_epoch.get_untracked();
        let ticket = mutation_generation.get_untracked();
        mutation_error.set(None);
        align_busy.update(|set| {
            set.insert(target_key.clone());
        });
        let mut guard = SetBusyGuard::for_generation(
            align_busy,
            target_key.clone(),
            mutation_generation,
            ticket,
        );
        spawn_local(async move {
            let result = if peer_label.is_some() {
                peer_api_request::<Value>(&path, "POST", None).await
            } else {
                // Strictly local same-origin POST with CSRF even when a remote peer is selected.
                local_same_origin_post::<Value>(&path, None).await
            };
            if mutation_generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(epoch)
                || !context.is_admin_untracked()
            {
                return;
            }
            guard.release();
            match result {
                Ok(_) => {
                    mutation_error.set(None);
                    match peer_label {
                        Some(peer_name) => {
                            status_notice
                                .set(Some(StatusNotice::AlignQueuedPeer(peer_name.clone())));
                            context.toast_with(
                                "Cluster.transcodeAlignQueuedPeerToast",
                                &[("peer", &peer_name)],
                                false,
                            );
                        }
                        None => {
                            status_notice.set(Some(StatusNotice::AlignQueuedLocal));
                            context.toast("Cluster.transcodeAlignQueuedLocalToast", false);
                        }
                    }
                    trigger_local_refresh.run(());
                    on_refresh_peers.run(());
                }
                Err(api_err) => {
                    mutation_error.set(Some(api_err));
                }
            }
        });
    });

    let toggle_global = move |_| {
        let current = config_memo.with_untracked(|cfg| cfg.as_ref().is_some_and(|c| c.enabled));
        let next = !current;
        submit_put(
            TranscodeAction::ToggleGlobal,
            build_toggle_enabled_request(next),
            None,
            Callback::new(move |updated: TranscodeConfigResponse| {
                let key = if updated.enabled {
                    "Cluster.transcodeGlobalEnabledToast"
                } else {
                    "Cluster.transcodeGlobalDisabledToast"
                };
                context.toast(key, false);
            }),
        );
    };

    let toggle_worker_service = move |_| {
        let current = config_memo
            .with_untracked(|cfg| cfg.as_ref().is_some_and(|c| c.worker_service_enabled));
        let next = !current;
        submit_put(
            TranscodeAction::ToggleWorkerService,
            build_toggle_worker_service_request(next),
            None,
            Callback::new(move |updated: TranscodeConfigResponse| {
                let key = if updated.worker_service_enabled {
                    "Cluster.transcodeWorkerServiceEnabledToast"
                } else {
                    "Cluster.transcodeWorkerServiceDisabledToast"
                };
                context.toast(key, false);
            }),
        );
    };

    let on_save_worker = Callback::new(move |(link_id, peer_name): (String, String)| {
        let draft = state.with_untracked(|s| {
            s.config
                .as_ref()
                .and_then(|cfg| cfg.workers.iter().find(|w| w.link_id == link_id))
                .map(|worker| s.draft_for(worker))
        });
        let Some(draft) = draft else {
            return;
        };
        let req = match build_update_worker_request(
            &link_id,
            draft.enabled,
            &draft.weight_input,
            &draft.max_jobs_input,
        ) {
            Ok(req) => req,
            Err(key) => {
                mutation_error.set(Some(PeerApiError::client(tt(context, key))));
                return;
            }
        };
        let peer_for_toast = peer_name.clone();
        submit_put(
            TranscodeAction::SaveWorker(link_id.clone()),
            req,
            Some(link_id),
            Callback::new(move |_updated: TranscodeConfigResponse| {
                context.toast_with(
                    "Cluster.transcodeWorkerSavedToast",
                    &[("peer", &peer_for_toast)],
                    false,
                );
            }),
        );
    });

    let on_run_parity = Callback::new(move |(link_id, peer_name): (String, String)| {
        let req = match build_parity_test_request(&link_id) {
            Ok(req) => req,
            Err(key) => {
                mutation_error.set(Some(PeerApiError::client(tt(context, key))));
                return;
            }
        };
        let peer_for_toast = peer_name.clone();
        let link_for_check = link_id.clone();
        submit_put(
            TranscodeAction::RunParity(link_id),
            req,
            None,
            Callback::new(move |updated: TranscodeConfigResponse| {
                if let Some(parity) = updated.parity_result.as_ref() {
                    let ms = parity.elapsed_ms.to_string();
                    if parity.ok {
                        context.toast_with(
                            "Cluster.transcodeParityPassedToast",
                            &[("peer", &peer_for_toast), ("ms", &ms)],
                            false,
                        );
                    } else {
                        context.toast_with(
                            "Cluster.transcodeParityFailedToast",
                            &[("peer", &peer_for_toast)],
                            true,
                        );
                    }
                } else if let Some(worker) =
                    updated.workers.iter().find(|w| w.link_id == link_for_check)
                {
                    if worker.parity_ok {
                        context.toast_with(
                            "Cluster.transcodeParityPassedToast",
                            &[("peer", &peer_for_toast), ("ms", "0")],
                            false,
                        );
                    } else {
                        context.toast_with(
                            "Cluster.transcodeParityFailedToast",
                            &[("peer", &peer_for_toast)],
                            true,
                        );
                    }
                }
            }),
        );
    });

    let worker_ids = Memo::new(move |_| {
        config_memo.with(|cfg| {
            cfg.as_ref()
                .map(|c| {
                    c.workers
                        .iter()
                        .map(|w| w.link_id.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
    });

    view! {
        <ObsCard>
            <div data-testid="cluster-transcode-section" class="space-y-6 min-w-0">
                <div class="flex flex-wrap justify-between items-start gap-4">
                    <div class="space-y-1 min-w-0">
                        <h2 class="text-lg font-semibold">
                            {move || tt(context, "Cluster.transcodeHeading")}
                        </h2>
                        <p class="text-sm text-slate-400">
                            {move || tt(context, "Cluster.transcodeDescription")}
                        </p>
                    </div>
                    <button
                        type="button"
                        class="glass-button px-3 py-1.5 text-sm shrink-0"
                        disabled=move || loading.get() || is_mutating.get()
                        aria-label=move || tt(context, "Cluster.transcodeRefreshAction")
                        on:click=move |_| trigger_local_refresh.run(())
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                </div>

                <Show when=move || loading.get() && config_memo.with(Option::is_none)>
                    <p role="status" class="text-sm text-slate-400 py-2">
                        {move || tt(context, "Common.loading")}
                    </p>
                </Show>

                <Show when=move || load_error.get().is_some()>
                    <div class="space-y-3">
                        <PeerErrorAlert error=load_error />
                        <div>
                            <button
                                type="button"
                                class="glass-button px-3 py-2 text-sm"
                                on:click=move |_| trigger_local_refresh.run(())
                            >
                                {move || tt(context, "Common.retry")}
                            </button>
                        </div>
                    </div>
                </Show>

                <PeerErrorAlert
                    error=mutation_error
                    on_dismiss=Callback::new(move |()| mutation_error.set(None))
                />

                <Show when=move || status_notice.get().is_some()>
                    {move || {
                        status_notice.get().map(|notice| {
                            let message = match notice {
                                StatusNotice::AlignQueuedLocal => {
                                    tt(context, "Cluster.transcodeAlignQueuedLocalStatus")
                                }
                                StatusNotice::AlignQueuedPeer(peer_name) => tt_with(
                                    context,
                                    "Cluster.transcodeAlignQueuedPeerStatus",
                                    &[("peer", &peer_name)],
                                ),
                            };
                            view! {
                                <div
                                    role="status"
                                    data-testid="transcode-status-notice"
                                    class="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-xs text-emerald-200 flex items-start justify-between gap-3"
                                >
                                    <p class="break-words">{message}</p>
                                    <button
                                        type="button"
                                        class="glass-button px-2 py-0.5 text-xs shrink-0"
                                        aria-label=move || tt(context, "Cluster.dismissError")
                                        on:click=move |_| status_notice.set(None)
                                    >
                                        "×"
                                    </button>
                                </div>
                            }
                        })
                    }}
                </Show>

                <Show when=move || config_memo.with(Option::is_some)>
                    // 1. Global dispatcher & local worker service controls + runtime badges
                    <div class="space-y-4">
                        <div class="grid md:grid-cols-2 gap-4">
                            <div class="rounded-xl border border-white/10 bg-white/5 p-4 flex items-start justify-between gap-4 min-w-0">
                                <div class="space-y-1 min-w-0">
                                    <p class="text-sm font-semibold text-slate-100">
                                        {move || tt(context, "Cluster.transcodeGlobalEnableLabel")}
                                    </p>
                                    <p class="text-xs text-slate-400 break-words">
                                        {move || tt(context, "Cluster.transcodeGlobalEnableHint")}
                                    </p>
                                </div>
                                <button
                                    type="button"
                                    role="switch"
                                    data-testid="transcode-global-toggle"
                                    aria-checked=move || {
                                        if config_memo.with(|c| c.as_ref().is_some_and(|cfg| cfg.enabled)) {
                                            "true"
                                        } else {
                                            "false"
                                        }
                                    }
                                    aria-label=move || tt(context, "Cluster.transcodeGlobalEnableLabel")
                                    disabled=move || is_mutating.get()
                                    class=move || {
                                        let on = config_memo.with(|c| c.as_ref().is_some_and(|cfg| cfg.enabled));
                                        if on {
                                            "glass-button-primary px-3 py-1.5 text-xs shrink-0"
                                        } else {
                                            "glass-button px-3 py-1.5 text-xs shrink-0"
                                        }
                                    }
                                    on:click=toggle_global
                                >
                                    {move || {
                                        if busy_action.get() == TranscodeAction::ToggleGlobal {
                                            tt(context, "Cluster.transcodeSwitchUpdating")
                                        } else if config_memo.with(|c| c.as_ref().is_some_and(|cfg| cfg.enabled)) {
                                            tt(context, "Cluster.transcodeSwitchEnabled")
                                        } else {
                                            tt(context, "Cluster.transcodeSwitchDisabled")
                                        }
                                    }}
                                </button>
                            </div>

                            <div class="rounded-xl border border-white/10 bg-white/5 p-4 flex items-start justify-between gap-4 min-w-0">
                                <div class="space-y-1 min-w-0">
                                    <p class="text-sm font-semibold text-slate-100">
                                        {move || tt(context, "Cluster.transcodeWorkerServiceLabel")}
                                    </p>
                                    <p class="text-xs text-slate-400 break-words">
                                        {move || tt(context, "Cluster.transcodeWorkerServiceHint")}
                                    </p>
                                </div>
                                <button
                                    type="button"
                                    role="switch"
                                    data-testid="transcode-worker-service-toggle"
                                    aria-checked=move || {
                                        if config_memo.with(|c| c.as_ref().is_some_and(|cfg| cfg.worker_service_enabled)) {
                                            "true"
                                        } else {
                                            "false"
                                        }
                                    }
                                    aria-label=move || tt(context, "Cluster.transcodeWorkerServiceLabel")
                                    disabled=move || is_mutating.get()
                                    class=move || {
                                        let on = config_memo.with(|c| c.as_ref().is_some_and(|cfg| cfg.worker_service_enabled));
                                        if on {
                                            "glass-button-primary px-3 py-1.5 text-xs shrink-0"
                                        } else {
                                            "glass-button px-3 py-1.5 text-xs shrink-0"
                                        }
                                    }
                                    on:click=toggle_worker_service
                                >
                                    {move || {
                                        if busy_action.get() == TranscodeAction::ToggleWorkerService {
                                            tt(context, "Cluster.transcodeSwitchUpdating")
                                        } else if config_memo.with(|c| c.as_ref().is_some_and(|cfg| cfg.worker_service_enabled)) {
                                            tt(context, "Cluster.transcodeSwitchEnabled")
                                        } else {
                                            tt(context, "Cluster.transcodeSwitchDisabled")
                                        }
                                    }}
                                </button>
                            </div>
                        </div>

                        {move || {
                            let cfg = config_memo.get()?;
                            let dispatcher_badge = if cfg.dispatcher_active {
                                ("Cluster.transcodeStatusDispatcherActive", "success")
                            } else {
                                ("Cluster.transcodeStatusDispatcherInactive", "muted")
                            };
                            let shim_badge = if cfg.shim_installed {
                                ("Cluster.transcodeStatusShimInstalled", "success")
                            } else {
                                ("Cluster.transcodeStatusShimMissing", "muted")
                            };
                            let dropin_badge = if cfg.jellyfin_dropin_enabled {
                                ("Cluster.transcodeStatusDropinEnabled", "success")
                            } else {
                                ("Cluster.transcodeStatusDropinDisabled", "muted")
                            };
                            let worker_badge = if cfg.worker_service_active {
                                ("Cluster.transcodeStatusWorkerActive", "success")
                            } else if cfg.worker_service_enabled {
                                ("Cluster.transcodeStatusWorkerEnabledStopped", "warning")
                            } else {
                                ("Cluster.transcodeStatusWorkerDisabled", "muted")
                            };
                            let dispatcher_socket = cfg.dispatcher_socket.clone();
                            let shim_path = cfg.shim_path.clone();
                            let reported_ffmpeg = cfg
                                .jellyfin_reported_ffmpeg
                                .clone()
                                .filter(|s| !s.trim().is_empty());
                            let local_paths = match (
                                cfg.local.transcoding_temp_path.as_deref().filter(|s| !s.trim().is_empty()),
                                cfg.local.tmp_dir.as_deref().filter(|s| !s.trim().is_empty()),
                            ) {
                                (Some(tx), Some(tmp)) => Some(format!("{tx} · {tmp}")),
                                (Some(tx), None) => Some(tx.to_string()),
                                (None, Some(tmp)) => Some(tmp.to_string()),
                                (None, None) => None,
                            };

                            Some(view! {
                                <div class="rounded-xl border border-white/10 bg-white/5 p-3.5 space-y-3">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <Badge label=dispatcher_badge.0 tone=dispatcher_badge.1 />
                                        <Badge label=shim_badge.0 tone=shim_badge.1 />
                                        <Badge label=dropin_badge.0 tone=dropin_badge.1 />
                                        <Badge label=worker_badge.0 tone=worker_badge.1 />
                                    </div>
                                    <dl class="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                                        <div class="space-y-0.5 min-w-0">
                                            <dt class="text-slate-400">
                                                {move || tt(context, "Cluster.transcodeDispatcherSocketLabel")}
                                            </dt>
                                            <dd class="font-mono text-slate-200 break-all">
                                                {dispatcher_socket}
                                            </dd>
                                        </div>
                                        <div class="space-y-0.5 min-w-0">
                                            <dt class="text-slate-400">
                                                {move || tt(context, "Cluster.transcodeShimPathLabel")}
                                            </dt>
                                            <dd class="font-mono text-slate-200 break-all">
                                                {shim_path}
                                            </dd>
                                        </div>
                                        {reported_ffmpeg.map(|reported| {
                                            view! {
                                                <div class="space-y-0.5 min-w-0">
                                                    <dt class="text-slate-400">
                                                        {move || tt(context, "Cluster.transcodeJellyfinReportedLabel")}
                                                    </dt>
                                                    <dd class="font-mono text-cyan-200 break-all">
                                                        {reported}
                                                    </dd>
                                                </div>
                                            }
                                        })}
                                        {local_paths.map(|paths| {
                                            view! {
                                                <div class="space-y-0.5 min-w-0">
                                                    <dt class="text-slate-400">
                                                        {move || tt(context, "Cluster.transcodeLocalPathsLabel")}
                                                    </dt>
                                                    <dd class="font-mono text-slate-300 break-all">
                                                        {paths}
                                                    </dd>
                                                </div>
                                            }
                                        })}
                                    </dl>
                                </div>
                            })
                        }}
                    </div>

                    // 2. jellyfin-ffmpeg version alignment section
                    <div
                        data-testid="transcode-version-alignment"
                        class="border-t border-white/10 pt-5 space-y-3 min-w-0"
                    >
                        <div class="space-y-1">
                            <h3 class="text-base font-semibold">
                                {move || tt(context, "Cluster.transcodeVersionHeading")}
                            </h3>
                            <p class="text-xs text-slate-400">
                                {move || tt(context, "Cluster.transcodeVersionDescription")}
                            </p>
                        </div>

                        {move || {
                            let cfg = config_memo.get()?;
                            let locale = crate::tabs::l10n::locale(context);
                            let mismatches: Vec<(String, String)> = cfg
                                .workers
                                .iter()
                                .filter_map(|w| {
                                    format_mismatch_banner(&locale, &cfg.local, w)
                                        .map(|msg| (w.link_id.clone(), msg))
                                })
                                .collect();
                            (!mismatches.is_empty()).then(|| {
                                view! {
                                    <div class="space-y-2">
                                        {mismatches
                                            .into_iter()
                                            .map(|(link_id, msg)| {
                                                view! {
                                                    <div
                                                        role="alert"
                                                        data-testid=format!("transcode-mismatch-banner-{link_id}")
                                                        class="af-warning-banner text-xs font-medium break-words"
                                                    >
                                                        {msg}
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                }
                            })
                        }}

                        {move || {
                            let cfg = config_memo.get()?;
                            let locale = crate::tabs::l10n::locale(context);
                            let local_name = if cfg.local.server_name.trim().is_empty() {
                                translate(&locale, "Cluster.transcodeLocalDefaultName")
                            } else {
                                cfg.local.server_name.clone()
                            };
                            let local_ver = format_ffmpeg_version(
                                &locale,
                                cfg.local.package_version.as_deref(),
                                cfg.local.ffmpeg_version.as_deref(),
                            );
                            let local_pkg_name = cfg
                                .local
                                .package_name
                                .clone()
                                .filter(|s| !s.trim().is_empty());
                            let local_render = format_local_render_node(&locale, &cfg.local);
                            let local_encoders = if cfg.local.encoders.is_empty() {
                                translate(&locale, "Not reported")
                            } else {
                                cfg.local.encoders.join(", ")
                            };
                            let local_needs_update = cfg.workers.iter().any(|w| {
                                matches!(resolve_align_action(w), AlignAction::UpdateLocal { .. })
                            });
                            let any_mismatch = cfg.workers.iter().any(|w| w.ffmpeg_mismatch);
                            let live_peers = peers.get();
                            let workers_for_table = cfg.workers.clone();

                            Some(view! {
                                <div
                                    class="overflow-x-auto rounded-xl border border-white/10 bg-white/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
                                    tabindex="0"
                                    role="region"
                                    aria-label=move || tt(context, "Cluster.transcodeVersionHeading")
                                >
                                    <table class="w-full text-left text-xs">
                                        <thead class="border-b border-white/10 text-slate-400">
                                            <tr>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeColServer")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeColRole")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeColFfmpegVersion")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeColRenderNode")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeColEncoders")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium text-right">
                                                    {move || tt(context, "Cluster.transcodeColAlignment")}
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-white/10">
                                            <tr data-testid="transcode-version-row-local">
                                                <td class="py-3 px-3 font-semibold text-slate-100">
                                                    {local_name}
                                                </td>
                                                <td class="py-3 px-3">
                                                    <Badge label="Cluster.transcodeRoleLocal" tone="indigo" />
                                                </td>
                                                <td class="py-3 px-3 font-mono text-slate-200 break-all">
                                                    <div>{local_ver}</div>
                                                    {local_pkg_name.map(|pkg| {
                                                        view! {
                                                            <div class="text-slate-400">{pkg}</div>
                                                        }
                                                    })}
                                                </td>
                                                <td class="py-3 px-3 font-mono text-slate-300 break-all">
                                                    {local_render}
                                                </td>
                                                <td class="py-3 px-3 font-mono text-slate-300 break-words">
                                                    {local_encoders}
                                                </td>
                                                <td class="py-3 px-3 text-right">
                                                    {if local_needs_update {
                                                        let local_path = peer_package_update_path(None);
                                                        view! {
                                                            <div class="inline-flex flex-wrap items-center justify-end gap-2">
                                                                <Badge label="Cluster.transcodeAlignDiffers" tone="warning" />
                                                                <button
                                                                    type="button"
                                                                    data-testid="transcode-align-local-button"
                                                                    class="glass-button-primary px-2.5 py-1 text-xs"
                                                                    aria-label=move || tt(context, "Cluster.transcodeAlignUpdateLocalAria")
                                                                    disabled=move || align_busy.with(|set| set.contains("local"))
                                                                    on:click=move |_| {
                                                                        submit_align_update.run(AlignAction::UpdateLocal {
                                                                            path: local_path.clone(),
                                                                        });
                                                                    }
                                                                >
                                                                    {move || {
                                                                        if align_busy.with(|set| set.contains("local")) {
                                                                            tt(context, "Cluster.transcodeAlignUpdating")
                                                                        } else {
                                                                            tt(context, "Cluster.transcodeAlignUpdateAction")
                                                                        }
                                                                    }}
                                                                </button>
                                                            </div>
                                                        }.into_any()
                                                    } else if any_mismatch {
                                                        view! {
                                                            <Badge label="Cluster.transcodeAlignLocalNewer" tone="indigo" />
                                                        }.into_any()
                                                    } else {
                                                        view! {
                                                            <Badge label="Cluster.transcodeAlignMatched" tone="success" />
                                                        }.into_any()
                                                    }}
                                                </td>
                                            </tr>
                                            {workers_for_table
                                                .into_iter()
                                                .map(|worker| {
                                                    let row_link_id = worker.link_id.clone();
                                                    let peer_name = worker.peer_name.clone();
                                                    let (state_key, state_tone) = status_presentation(&worker.link_state);
                                                    let version_text = format_ffmpeg_version(
                                                        &locale,
                                                        worker.package_version.as_deref(),
                                                        worker.ffmpeg_version.as_deref(),
                                                    );
                                                    let render_text = worker
                                                        .render_node
                                                        .as_deref()
                                                        .map(str::trim)
                                                        .filter(|s| !s.is_empty())
                                                        .map(str::to_string)
                                                        .unwrap_or_else(|| translate(&locale, "Not reported"));
                                                    let encoders_text = if worker.encoders.is_empty() {
                                                        translate(&locale, "Not reported")
                                                    } else {
                                                        worker.encoders.join(", ")
                                                    };
                                                    let live_peer = live_peers
                                                        .iter()
                                                        .find(|p| p.id == worker.link_id);
                                                    let align_action =
                                                        resolve_align_action_for_peer(
                                                            &worker,
                                                            live_peer,
                                                        );
                                                    let has_version = worker.package_version.is_some()
                                                        || worker.ffmpeg_version.is_some();

                                                    view! {
                                                        <tr data-testid=format!("transcode-version-row-{row_link_id}")>
                                                            <td class="py-3 px-3">
                                                                <div class="font-semibold text-slate-100 break-all">
                                                                    {peer_name.clone()}
                                                                </div>
                                                                <div class="mt-1">
                                                                    <Badge label=state_key tone=state_tone />
                                                                </div>
                                                            </td>
                                                            <td class="py-3 px-3">
                                                                <Badge label="Cluster.transcodeRoleWorker" tone="muted" />
                                                            </td>
                                                            <td class="py-3 px-3 font-mono text-slate-200 break-all">
                                                                {version_text}
                                                            </td>
                                                            <td class="py-3 px-3 font-mono text-slate-300 break-all">
                                                                {render_text}
                                                            </td>
                                                            <td class="py-3 px-3 font-mono text-slate-300 break-words">
                                                                {encoders_text}
                                                            </td>
                                                            <td class="py-3 px-3 text-right">
                                                                {match align_action {
                                                                    AlignAction::UpdateLocal { path } => {
                                                                        view! {
                                                                            <div class="inline-flex flex-wrap items-center justify-end gap-2">
                                                                                <Badge label="Cluster.transcodeAlignDiffers" tone="warning" />
                                                                                <button
                                                                                    type="button"
                                                                                    class="glass-button-primary px-2.5 py-1 text-xs"
                                                                                    aria-label=move || tt(context, "Cluster.transcodeAlignUpdateLocalAria")
                                                                                    disabled=move || align_busy.with(|set| set.contains("local"))
                                                                                    on:click=move |_| {
                                                                                        submit_align_update.run(AlignAction::UpdateLocal {
                                                                                            path: path.clone(),
                                                                                        });
                                                                                    }
                                                                                >
                                                                                    {move || {
                                                                                        if align_busy.with(|set| set.contains("local")) {
                                                                                            tt(context, "Cluster.transcodeAlignUpdating")
                                                                                        } else {
                                                                                            tt(context, "Cluster.transcodeAlignUpdateAction")
                                                                                        }
                                                                                    }}
                                                                                </button>
                                                                            </div>
                                                                        }.into_any()
                                                                    }
                                                                    AlignAction::UpdatePeer {
                                                                        link_id,
                                                                        peer_name: target_peer,
                                                                        path,
                                                                    } => {
                                                                        let busy_key = format!("peer:{link_id}");
                                                                        let busy_key_label = busy_key.clone();
                                                                        let peer_aria = target_peer.clone();
                                                                        let test_id = format!("transcode-align-peer-{link_id}");
                                                                        view! {
                                                                            <div class="inline-flex flex-wrap items-center justify-end gap-2">
                                                                                <Badge label="Cluster.transcodeAlignDiffers" tone="warning" />
                                                                                <button
                                                                                    type="button"
                                                                                    data-testid=test_id
                                                                                    class="glass-button-primary px-2.5 py-1 text-xs"
                                                                                    aria-label=move || {
                                                                                        tt_with(
                                                                                            context,
                                                                                            "Cluster.transcodeAlignUpdatePeerAria",
                                                                                            &[("peer", &peer_aria)],
                                                                                        )
                                                                                    }
                                                                                    disabled=move || align_busy.with(|set| set.contains(&busy_key))
                                                                                    on:click=move |_| {
                                                                                        submit_align_update.run(AlignAction::UpdatePeer {
                                                                                            link_id: link_id.clone(),
                                                                                            peer_name: target_peer.clone(),
                                                                                            path: path.clone(),
                                                                                        });
                                                                                    }
                                                                                >
                                                                                    {move || {
                                                                                        if align_busy.with(|set| set.contains(&busy_key_label)) {
                                                                                            tt(context, "Cluster.transcodeAlignUpdating")
                                                                                        } else {
                                                                                            tt(context, "Cluster.transcodeAlignUpdateAction")
                                                                                        }
                                                                                    }}
                                                                                </button>
                                                                            </div>
                                                                        }.into_any()
                                                                    }
                                                                    AlignAction::DisabledMissingUpdatesGrant {
                                                                        peer_name: target_peer,
                                                                        reason_key,
                                                                    } => {
                                                                        let reason_id = format!(
                                                                            "transcode-align-reason-{}",
                                                                            dom_safe_id(&row_link_id)
                                                                        );
                                                                        let reason_id_ref = reason_id.clone();
                                                                        let peer_aria = target_peer.clone();
                                                                        view! {
                                                                            <div class="inline-flex flex-col items-end gap-1">
                                                                                <div class="inline-flex flex-wrap items-center justify-end gap-2">
                                                                                    <Badge label="Cluster.transcodeAlignDiffers" tone="warning" />
                                                                                    <button
                                                                                        type="button"
                                                                                        data-testid=format!("transcode-align-disabled-{row_link_id}")
                                                                                        class="glass-button px-2.5 py-1 text-xs opacity-60"
                                                                                        disabled=true
                                                                                        title=move || tt(context, reason_key)
                                                                                        aria-describedby=reason_id_ref
                                                                                        aria-label=move || {
                                                                                            tt_with(
                                                                                                context,
                                                                                                "Cluster.transcodeAlignUpdatePeerAria",
                                                                                                &[("peer", &peer_aria)],
                                                                                            )
                                                                                        }
                                                                                    >
                                                                                        {move || tt(context, "Cluster.transcodeAlignUpdateAction")}
                                                                                    </button>
                                                                                </div>
                                                                                <span
                                                                                    id=reason_id
                                                                                    class="text-amber-300 text-right max-w-xs"
                                                                                >
                                                                                    {move || tt(context, reason_key)}
                                                                                </span>
                                                                            </div>
                                                                        }.into_any()
                                                                    }
                                                                    AlignAction::DisabledLinkUnavailable {
                                                                        peer_name: target_peer,
                                                                        reason_key,
                                                                    } => {
                                                                        let reason_id = format!(
                                                                            "transcode-align-reason-{}",
                                                                            dom_safe_id(&row_link_id)
                                                                        );
                                                                        let reason_id_ref = reason_id.clone();
                                                                        let peer_for_reason = target_peer.clone();
                                                                        let peer_for_title = target_peer.clone();
                                                                        view! {
                                                                            <div class="inline-flex flex-col items-end gap-1">
                                                                                <div class="inline-flex flex-wrap items-center justify-end gap-2">
                                                                                    <Badge label="Cluster.transcodeAlignDiffers" tone="warning" />
                                                                                    <button
                                                                                        type="button"
                                                                                        class="glass-button px-2.5 py-1 text-xs opacity-60"
                                                                                        disabled=true
                                                                                        title=move || {
                                                                                            tt_with(
                                                                                                context,
                                                                                                reason_key,
                                                                                                &[("peer", &peer_for_title)],
                                                                                            )
                                                                                        }
                                                                                        aria-describedby=reason_id_ref
                                                                                    >
                                                                                        {move || tt(context, "Cluster.transcodeAlignUpdateAction")}
                                                                                    </button>
                                                                                </div>
                                                                                <span
                                                                                    id=reason_id
                                                                                    class="text-amber-300 text-right max-w-xs"
                                                                                >
                                                                                    {move || {
                                                                                        tt_with(
                                                                                            context,
                                                                                            reason_key,
                                                                                            &[("peer", &peer_for_reason)],
                                                                                        )
                                                                                    }}
                                                                                </span>
                                                                            </div>
                                                                        }.into_any()
                                                                    }
                                                                    AlignAction::None => {
                                                                        if worker.ffmpeg_mismatch {
                                                                            view! {
                                                                                <Badge label="Cluster.transcodeAlignDiffers" tone="warning" />
                                                                            }.into_any()
                                                                        } else if has_version {
                                                                            view! {
                                                                                <Badge label="Cluster.transcodeAlignMatched" tone="success" />
                                                                            }.into_any()
                                                                        } else {
                                                                            view! {
                                                                                <Badge label="Cluster.transcodeAlignUnknown" tone="muted" />
                                                                            }.into_any()
                                                                        }
                                                                    }
                                                                }}
                                                            </td>
                                                        </tr>
                                                    }
                                                })
                                                .collect_view()}
                                        </tbody>
                                    </table>
                                </div>
                            })
                        }}
                    </div>

                    // 3. Per-worker configuration cards
                    <div
                        data-testid="transcode-workers-list"
                        class="border-t border-white/10 pt-5 space-y-3 min-w-0"
                    >
                        <div class="space-y-1">
                            <h3 class="text-base font-semibold">
                                {move || tt(context, "Cluster.transcodeWorkersHeading")}
                            </h3>
                            <p class="text-xs text-slate-400">
                                {move || tt(context, "Cluster.transcodeWorkersDescription")}
                            </p>
                        </div>

                        <Show
                            when=move || !worker_ids.with(Vec::is_empty)
                            fallback=move || {
                                view! {
                                    <EmptyState
                                        title="Cluster.transcodeWorkersEmptyTitle"
                                        description="Cluster.transcodeWorkersEmptyDescription"
                                    />
                                }
                            }
                        >
                            <div class="space-y-4">
                                <For
                                    each=move || worker_ids.get()
                                    key=|id| id.clone()
                                    children=move |link_id| {
                                        view! {
                                            <TranscodeWorkerCard
                                                link_id=link_id
                                                state=state
                                                peers=peers
                                                busy_action=busy_action
                                                on_save=on_save_worker
                                                on_run_parity=on_run_parity
                                            />
                                        }
                                    }
                                />
                            </div>
                        </Show>
                    </div>

                    // 4. Recent transcode jobs
                    <div
                        data-testid="transcode-recent-jobs"
                        class="border-t border-white/10 pt-5 space-y-3 min-w-0"
                    >
                        <div class="space-y-1">
                            <h3 class="text-base font-semibold">
                                {move || tt(context, "Cluster.transcodeJobsHeading")}
                            </h3>
                            <p class="text-xs text-slate-400">
                                {move || tt(context, "Cluster.transcodeJobsDescription")}
                            </p>
                        </div>

                        {move || {
                            let cfg = config_memo.get()?;
                            let locale = crate::tabs::l10n::locale(context);
                            if cfg.recent_jobs.is_empty() {
                                return Some(view! {
                                    <EmptyState
                                        title="Cluster.transcodeJobsEmptyTitle"
                                        description="Cluster.transcodeJobsEmptyDescription"
                                    />
                                }.into_any());
                            }
                            let jobs = cfg.recent_jobs.clone();
                            Some(view! {
                                <div
                                    class="overflow-x-auto rounded-xl border border-white/10 bg-white/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
                                    tabindex="0"
                                    role="region"
                                    aria-label=move || tt(context, "Cluster.transcodeJobsHeading")
                                >
                                    <table class="w-full text-left text-xs">
                                        <thead class="border-b border-white/10 text-slate-400">
                                            <tr>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeJobColTarget")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeJobColStarted")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeJobColEnded")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeJobColDuration")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeJobColExitCode")}
                                                </th>
                                                <th class="py-2.5 px-3 font-medium">
                                                    {move || tt(context, "Cluster.transcodeJobColRequestId")}
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-white/10">
                                            {jobs
                                                .into_iter()
                                                .map(|job| {
                                                    let job_id = job.id.clone();
                                                    let target_label = format_job_target(&locale, &job);
                                                    let target_tone = if job.ran_locally { "muted" } else { "indigo" };
                                                    let started = job.started_at.clone();
                                                    let ended = job
                                                        .ended_at
                                                        .as_deref()
                                                        .map(str::trim)
                                                        .filter(|s| !s.is_empty())
                                                        .map(str::to_string)
                                                        .unwrap_or_else(|| "—".to_string());
                                                    let duration = format_job_duration(
                                                        &locale,
                                                        &job.started_at,
                                                        job.ended_at.as_deref(),
                                                    );
                                                    let (exit_label, exit_tone) = job_exit_presentation(
                                                        &locale,
                                                        job.exit_code,
                                                        job.ended_at.as_deref(),
                                                    );
                                                    let request_id = job
                                                        .request_id
                                                        .as_deref()
                                                        .map(str::trim)
                                                        .filter(|s| !s.is_empty())
                                                        .map(str::to_string)
                                                        .unwrap_or_else(|| "—".to_string());

                                                    view! {
                                                        <tr data-testid=format!("transcode-job-row-{job_id}")>
                                                            <td class="py-2.5 px-3">
                                                                <span class=format!("af-badge af-badge-{target_tone}")>
                                                                    {target_label}
                                                                </span>
                                                            </td>
                                                            <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                                                                {started}
                                                            </td>
                                                            <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                                                                {ended}
                                                            </td>
                                                            <td class="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">
                                                                {duration}
                                                            </td>
                                                            <td class="py-2.5 px-3 whitespace-nowrap">
                                                                <span class=format!("af-badge af-badge-{exit_tone}")>
                                                                    {exit_label}
                                                                </span>
                                                            </td>
                                                            <td class="py-2.5 px-3 font-mono text-slate-400 break-all">
                                                                {request_id}
                                                            </td>
                                                        </tr>
                                                    }
                                                })
                                                .collect_view()}
                                        </tbody>
                                    </table>
                                </div>
                            }.into_any())
                        }}
                    </div>
                </Show>
            </div>
        </ObsCard>
    }
}

#[component]
fn TranscodeWorkerCard(
    link_id: String,
    state: RwSignal<TranscodeSectionState>,
    peers: Signal<Vec<PeerLinkView>>,
    busy_action: RwSignal<TranscodeAction>,
    on_save: Callback<(String, String)>,
    on_run_parity: Callback<(String, String)>,
) -> impl IntoView {
    let context = app();
    let link_id_store = StoredValue::new(link_id);

    let worker = Memo::new(move |_| {
        link_id_store.with_value(|id| {
            state.with(|s| {
                s.config
                    .as_ref()
                    .and_then(|cfg| cfg.workers.iter().find(|w| w.link_id == *id).cloned())
            })
        })
    });
    let live_peer = Memo::new(move |_| {
        link_id_store.with_value(|id| peers.with(|list| list.iter().find(|p| p.id == *id).cloned()))
    });
    let draft = Memo::new(move |_| {
        worker.with(|w| {
            w.as_ref()
                .map(|worker| state.with(|s| s.draft_for(worker)))
                .unwrap_or_default()
        })
    });
    let is_dirty =
        Memo::new(move |_| link_id_store.with_value(|id| state.with(|s| s.is_worker_dirty(id))));
    let latest_parity = Memo::new(move |_| {
        link_id_store.with_value(|id| state.with(|s| s.parity_results.get(id).cloned()))
    });
    let can_save = Memo::new(move |_| {
        worker.with(|w| {
            w.as_ref().is_some_and(|cur| {
                let live = live_peer.get();
                can_save_worker(cur, draft.get().enabled, live.as_ref())
            })
        })
    });

    let safe_dom = link_id_store.with_value(|id| dom_safe_id(id));
    let enable_input_id = format!("cluster-transcode-worker-enabled-{safe_dom}");
    let weight_input_id = format!("cluster-transcode-worker-weight-{safe_dom}");
    let max_jobs_input_id = format!("cluster-transcode-worker-max-jobs-{safe_dom}");
    let disabled_reason_id = format!("cluster-transcode-worker-reason-{safe_dom}");

    view! {
        {move || {
            let current = worker.get()?;
            let current_live_peer = live_peer.get();
            let locale = crate::tabs::l10n::locale(context);
            let peer_name = current.peer_name.clone();
            let link_id_val = current.link_id.clone();
            let (status_key, status_tone) = status_presentation(&current.link_state);
            let (compat_key, compat_tone) = compatibility_presentation(&current.compatibility);
            let (elig_key, elig_tone) = worker_eligibility_presentation(&current);
            let (parity_key, parity_tone) = worker_parity_presentation(&current);
            let grant_badge = if current.has_transcode_write_grant {
                ("Cluster.transcodeGrantWriteBadge", "success")
            } else {
                ("Cluster.transcodeGrantMissingBadge", "warning")
            };
            let active_jobs_text = translate_with(
                &locale,
                "Cluster.transcodeActiveJobsCount",
                &[
                    ("active", &current.active_jobs.to_string()),
                    ("max", &current.max_jobs.to_string()),
                ],
            );
            let version_text = format_ffmpeg_version(
                &locale,
                current.package_version.as_deref(),
                current.ffmpeg_version.as_deref(),
            );
            let render_node_text = current
                .render_node
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| translate(&locale, "Not reported"));
            let encoders_list = current.encoders.clone();
            let cap_reason = worker_capability_reason(&locale, &current, current_live_peer.as_ref());
            let disabled_reason =
                worker_control_disabled_reason(&locale, &current, current_live_peer.as_ref());
            let ineligible_reason = current
                .ineligible_reason
                .clone()
                .filter(|s| !s.trim().is_empty());
            let unhealthy_until = current
                .unhealthy_until
                .clone()
                .filter(|s| !s.trim().is_empty());
            let parity_error = (!current.parity_ok)
                .then(|| current.parity_error.clone())
                .flatten()
                .filter(|s| !s.trim().is_empty());
            let mismatch_msg = current
                .ffmpeg_mismatch
                .then(|| current.ffmpeg_mismatch_message.clone())
                .flatten()
                .filter(|s| !s.trim().is_empty());

            let enable_allowed = can_enable_worker(&current, current_live_peer.as_ref());
            let parity_allowed = can_run_parity_test(&current, current_live_peer.as_ref());

            let link_for_submit = link_id_val.clone();
            let peer_for_submit = peer_name.clone();
            let link_for_parity = link_id_val.clone();
            let peer_for_parity = peer_name.clone();
            let link_for_enable_change = link_id_val.clone();
            let link_for_weight_input = link_id_val.clone();
            let link_for_max_jobs_input = link_id_val.clone();
            let link_for_saving_label = link_id_val.clone();
            let link_for_parity_label = link_id_val.clone();
            let peer_for_save_aria = peer_name.clone();
            let peer_for_parity_aria = peer_name.clone();
            let peer_for_parity_banner = peer_name.clone();

            let enable_id = enable_input_id.clone();
            let enable_id_label = enable_input_id.clone();
            let weight_id = weight_input_id.clone();
            let weight_id_label = weight_input_id.clone();
            let max_jobs_id = max_jobs_input_id.clone();
            let max_jobs_id_label = max_jobs_input_id.clone();
            let reason_id_el = disabled_reason_id.clone();
            let reason_id_for_parity = disabled_reason_id.clone();
            let reason_title_parity = disabled_reason.clone().unwrap_or_default();
            let reason_title_enable = disabled_reason.clone().unwrap_or_default();

            Some(view! {
                <article
                    data-testid=format!("transcode-worker-card-{link_id_val}")
                    class="rounded-xl border border-white/10 bg-white/5 p-4 space-y-4 min-w-0"
                >
                    <div class="flex flex-wrap items-start justify-between gap-3">
                        <div class="space-y-1.5 min-w-0">
                            <div class="flex flex-wrap items-center gap-2">
                                <h4 class="text-base font-semibold break-all">{peer_name}</h4>
                                <Badge label=status_key tone=status_tone />
                                <Badge label=compat_key tone=compat_tone />
                                <Badge label=grant_badge.0 tone=grant_badge.1 />
                                <Badge label=elig_key tone=elig_tone />
                                <Badge label=parity_key tone=parity_tone />
                                <Show when=move || is_dirty.get()>
                                    <Badge label="Common.unsavedChanges" tone="warning" />
                                </Show>
                            </div>
                        </div>
                        <span class="text-xs font-mono text-slate-400 shrink-0">
                            {active_jobs_text}
                        </span>
                    </div>

                    {cap_reason.as_ref().cloned().map(|reason| {
                        let same_as_disabled = disabled_reason.as_deref() == Some(reason.as_str());
                        view! {
                            <div
                                id=same_as_disabled.then(|| reason_id_el.clone())
                                role="status"
                                data-testid="transcode-worker-compat-warning"
                                class="af-warning-banner text-xs break-words"
                            >
                                {reason}
                            </div>
                        }
                    })}

                    {disabled_reason
                        .as_ref()
                        .filter(|r| cap_reason.as_deref() != Some(r.as_str()))
                        .cloned()
                        .map(|reason| {
                            view! {
                                <div
                                    id=reason_id_el.clone()
                                    role="status"
                                    data-testid="transcode-worker-disabled-reason"
                                    class="af-warning-banner text-xs break-words"
                                >
                                    {reason}
                                </div>
                            }
                        })}

                    {mismatch_msg.map(|msg| {
                        view! {
                            <div role="status" class="af-warning-banner text-xs break-words">
                                {msg}
                            </div>
                        }
                    })}

                    {ineligible_reason.map(|reason| {
                        view! {
                            <p role="status" class="text-xs text-amber-300 break-words">
                                <span class="font-semibold">
                                    {move || tt(context, "Cluster.transcodeIneligibleReasonLabel")}
                                </span>
                                ": "
                                {reason}
                            </p>
                        }
                    })}

                    {unhealthy_until.map(|until| {
                        view! {
                            <p class="text-xs text-amber-300 font-mono break-all">
                                <span class="font-sans font-semibold">
                                    {move || tt(context, "Cluster.transcodeUnhealthyUntilLabel")}
                                </span>
                                ": "
                                {until}
                            </p>
                        }
                    })}

                    {parity_error.map(|err_msg| {
                        view! {
                            <p role="status" class="af-danger-banner text-xs break-words">
                                <span class="font-semibold">
                                    {move || tt(context, "Cluster.transcodeParityErrorLabel")}
                                </span>
                                ": "
                                {err_msg}
                            </p>
                        }
                    })}

                    {move || {
                        latest_parity.get().map(|res| {
                            let loc = crate::tabs::l10n::locale(context);
                            let text = format_parity_result_banner(&loc, &peer_for_parity_banner, &res);
                            if res.ok {
                                view! {
                                    <div
                                        role="status"
                                        data-testid="transcode-parity-result-ok"
                                        class="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-2.5 text-xs text-emerald-200 break-words"
                                    >
                                        {text}
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div
                                        role="alert"
                                        data-testid="transcode-parity-result-failed"
                                        class="af-danger-banner text-xs break-words"
                                    >
                                        {text}
                                    </div>
                                }.into_any()
                            }
                        })
                    }}

                    <dl class="grid sm:grid-cols-3 gap-3 text-xs">
                        <div class="space-y-0.5 min-w-0">
                            <dt class="text-slate-400">
                                {move || tt(context, "Cluster.transcodeColFfmpegVersion")}
                            </dt>
                            <dd class="font-mono text-slate-200 break-all">{version_text}</dd>
                        </div>
                        <div class="space-y-0.5 min-w-0">
                            <dt class="text-slate-400">
                                {move || tt(context, "Cluster.transcodeColRenderNode")}
                            </dt>
                            <dd class="font-mono text-slate-200 break-all">{render_node_text}</dd>
                        </div>
                        <div class="space-y-0.5 min-w-0">
                            <dt class="text-slate-400">
                                {move || tt(context, "Cluster.transcodeColEncoders")}
                            </dt>
                            <dd class="text-slate-200">
                                {if encoders_list.is_empty() {
                                    view! {
                                        <span class="text-slate-400">
                                            {move || tt(context, "Not reported")}
                                        </span>
                                    }.into_any()
                                } else {
                                    view! {
                                        <div class="flex flex-wrap gap-1">
                                            {encoders_list
                                                .into_iter()
                                                .map(|enc| {
                                                    view! {
                                                        <span class="px-1.5 py-0.5 rounded bg-white/10 font-mono text-slate-200">
                                                            {enc}
                                                        </span>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    }.into_any()
                                }}
                            </dd>
                        </div>
                    </dl>

                    <form
                        class="border-t border-white/10 pt-3 flex flex-wrap items-end justify-between gap-4"
                        on:submit=move |event| {
                            event.prevent_default();
                            on_save.run((link_for_submit.clone(), peer_for_submit.clone()));
                        }
                    >
                        <div class="flex flex-wrap items-end gap-4 min-w-0">
                            <label
                                for=enable_id_label
                                class="flex items-center gap-2 text-xs font-medium text-slate-200 py-2 cursor-pointer"
                                title=reason_title_enable
                            >
                                <input
                                    id=enable_id
                                    type="checkbox"
                                    class="obs-checkbox"
                                    disabled=move || {
                                        busy_action.get() != TranscodeAction::Idle
                                            || (!enable_allowed && !draft.get().enabled)
                                    }
                                    prop:checked=move || draft.get().enabled
                                    on:change=move |event| {
                                        let checked = event_target_checked(&event);
                                        state.update(|s| {
                                            s.update_worker_draft(&link_for_enable_change, |d| {
                                                d.enabled = checked;
                                            });
                                        });
                                    }
                                />
                                <span>{move || tt(context, "Cluster.transcodeWorkerEnableLabel")}</span>
                            </label>

                            <div class="space-y-1">
                                <label
                                    for=weight_id_label
                                    class="block text-xs text-slate-300"
                                >
                                    {move || tt(context, "Cluster.transcodeWorkerWeightLabel")}
                                </label>
                                <input
                                    id=weight_id
                                    type="number"
                                    min=WORKER_WEIGHT_MIN.to_string()
                                    max=WORKER_WEIGHT_MAX.to_string()
                                    inputmode="numeric"
                                    class="glass-input px-2.5 py-1.5 w-24 text-sm font-mono"
                                    disabled=move || {
                                        busy_action.get() != TranscodeAction::Idle || !can_save.get()
                                    }
                                    prop:value=move || draft.get().weight_input
                                    on:input=move |event| {
                                        let value = event_target_value(&event);
                                        state.update(|s| {
                                            s.update_worker_draft(&link_for_weight_input, |d| {
                                                d.weight_input = value;
                                            });
                                        });
                                    }
                                />
                            </div>

                            <div class="space-y-1">
                                <label
                                    for=max_jobs_id_label
                                    class="block text-xs text-slate-300"
                                >
                                    {move || tt(context, "Cluster.transcodeWorkerMaxJobsLabel")}
                                </label>
                                <input
                                    id=max_jobs_id
                                    type="number"
                                    min=WORKER_MAX_JOBS_MIN.to_string()
                                    max=WORKER_MAX_JOBS_MAX.to_string()
                                    inputmode="numeric"
                                    class="glass-input px-2.5 py-1.5 w-24 text-sm font-mono"
                                    disabled=move || {
                                        busy_action.get() != TranscodeAction::Idle || !can_save.get()
                                    }
                                    prop:value=move || draft.get().max_jobs_input
                                    on:input=move |event| {
                                        let value = event_target_value(&event);
                                        state.update(|s| {
                                            s.update_worker_draft(&link_for_max_jobs_input, |d| {
                                                d.max_jobs_input = value;
                                            });
                                        });
                                    }
                                />
                            </div>
                        </div>

                        <div class="flex flex-wrap items-center gap-2 shrink-0">
                            <button
                                type="button"
                                class="glass-button px-3 py-1.5 text-xs"
                                title=reason_title_parity
                                aria-describedby=disabled_reason.is_some().then_some(reason_id_for_parity)
                                aria-label=move || {
                                    tt_with(
                                        context,
                                        "Cluster.transcodeRunParityAria",
                                        &[("peer", &peer_for_parity_aria)],
                                    )
                                }
                                disabled=move || {
                                    busy_action.get() != TranscodeAction::Idle || !parity_allowed
                                }
                                on:click=move |_| {
                                    on_run_parity.run((
                                        link_for_parity.clone(),
                                        peer_for_parity.clone(),
                                    ));
                                }
                            >
                                {move || {
                                    if busy_action.get()
                                        == TranscodeAction::RunParity(link_for_parity_label.clone())
                                    {
                                        tt(context, "Cluster.transcodeRunningParity")
                                    } else {
                                        tt(context, "Cluster.transcodeRunParityAction")
                                    }
                                }}
                            </button>
                            <button
                                type="submit"
                                class="glass-button-primary px-3 py-1.5 text-xs"
                                aria-label=move || {
                                    tt_with(
                                        context,
                                        "Cluster.transcodeWorkerSaveAria",
                                        &[("peer", &peer_for_save_aria)],
                                    )
                                }
                                disabled=move || {
                                    busy_action.get() != TranscodeAction::Idle || !can_save.get()
                                }
                            >
                                {move || {
                                    if busy_action.get()
                                        == TranscodeAction::SaveWorker(link_for_saving_label.clone())
                                    {
                                        tt(context, "Cluster.transcodeWorkerSaving")
                                    } else {
                                        tt(context, "Cluster.transcodeWorkerSaveAction")
                                    }
                                }}
                            </button>
                        </div>
                    </form>
                </article>
            })
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_section3_payload() -> Value {
        json!({
            "enabled": false,
            "worker_service_enabled": false,
            "worker_service_active": false,
            "dispatcher_active": false,
            "dispatcher_socket": "/run/aetherflow-transcode/transcode.sock",
            "shim_installed": false,
            "shim_path": "/usr/lib/aetherflow/transcode/ffmpeg",
            "jellyfin_dropin_enabled": false,
            "jellyfin_reported_ffmpeg": null,
            "local": {
                "server_name": "seedbox-1",
                "ffmpeg_version": "8.1.3-Jellyfin",
                "package_name": "jellyfin-ffmpeg8",
                "package_version": "8.1.3-1-trixie",
                "encoders": ["h264_vaapi", "hevc_vaapi", "libx264"],
                "render_nodes": [
                    { "path": "/dev/dri/renderD128", "vendor_id": "0x8086", "vendor": "intel" }
                ],
                "primary_render_node": "/dev/dri/renderD128",
                "transcoding_temp_path": "/var/cache/jellyfin/transcodes",
                "tmp_dir": "/var/cache/jellyfin/af-tmp"
            },
            "workers": [
                {
                    "link_id": "link-1",
                    "peer_name": "media-2",
                    "link_state": "active",
                    "compatibility": "compatible",
                    "supports_transcode": true,
                    "has_transcode_write_grant": true,
                    "has_updates_write_grant": true,
                    "enabled": true,
                    "eligible": true,
                    "ineligible_reason": null,
                    "weight": 1,
                    "max_jobs": 2,
                    "active_jobs": 0,
                    "unhealthy_until": null,
                    "ffmpeg_version": "8.1.3-Jellyfin",
                    "package_version": "8.1.3-1-trixie",
                    "ffmpeg_mismatch": false,
                    "ffmpeg_mismatch_message": null,
                    "align_target": null,
                    "encoders": ["h264_vaapi", "hevc_vaapi", "libx264"],
                    "render_node": "/dev/dri/renderD128",
                    "parity_ok": true,
                    "parity_error": null
                }
            ],
            "recent_jobs": [
                {
                    "id": "job-1",
                    "link_id": "link-1",
                    "peer_name": "media-2",
                    "started_at": "2026-11-24T03:00:00Z",
                    "ended_at": "2026-11-24T03:00:12Z",
                    "exit_code": 0,
                    "request_id": "req-123",
                    "ran_locally": false
                }
            ],
            "parity_result": {
                "link_id": "link-1",
                "ok": true,
                "elapsed_ms": 420,
                "error": null
            }
        })
    }

    #[test]
    fn transcode_config_response_round_trips_exact_section3_contract() {
        let payload = sample_section3_payload();
        let parsed: TranscodeConfigResponse = serde_json::from_value(payload).unwrap();

        assert!(!parsed.enabled);
        assert!(!parsed.worker_service_enabled);
        assert!(!parsed.worker_service_active);
        assert!(!parsed.dispatcher_active);
        assert_eq!(
            parsed.dispatcher_socket,
            "/run/aetherflow-transcode/transcode.sock"
        );
        assert!(!parsed.shim_installed);
        assert_eq!(parsed.shim_path, "/usr/lib/aetherflow/transcode/ffmpeg");
        assert!(!parsed.jellyfin_dropin_enabled);
        assert_eq!(parsed.jellyfin_reported_ffmpeg, None);

        assert_eq!(parsed.local.server_name, "seedbox-1");
        assert_eq!(
            parsed.local.ffmpeg_version.as_deref(),
            Some("8.1.3-Jellyfin")
        );
        assert_eq!(
            parsed.local.package_name.as_deref(),
            Some("jellyfin-ffmpeg8")
        );
        assert_eq!(
            parsed.local.package_version.as_deref(),
            Some("8.1.3-1-trixie")
        );
        assert_eq!(
            parsed.local.encoders,
            vec!["h264_vaapi", "hevc_vaapi", "libx264"]
        );
        assert_eq!(parsed.local.render_nodes.len(), 1);
        assert_eq!(parsed.local.render_nodes[0].path, "/dev/dri/renderD128");
        assert_eq!(
            parsed.local.render_nodes[0].vendor_id.as_deref(),
            Some("0x8086")
        );
        assert_eq!(
            parsed.local.render_nodes[0].vendor.as_deref(),
            Some("intel")
        );
        assert_eq!(
            parsed.local.primary_render_node.as_deref(),
            Some("/dev/dri/renderD128")
        );
        assert_eq!(
            parsed.local.transcoding_temp_path.as_deref(),
            Some("/var/cache/jellyfin/transcodes")
        );
        assert_eq!(
            parsed.local.tmp_dir.as_deref(),
            Some("/var/cache/jellyfin/af-tmp")
        );

        assert_eq!(parsed.workers.len(), 1);
        let worker = &parsed.workers[0];
        assert_eq!(worker.link_id, "link-1");
        assert_eq!(worker.peer_name, "media-2");
        assert!(worker.supports_transcode);
        assert!(worker.has_transcode_write_grant);
        assert!(worker.has_updates_write_grant);
        assert!(worker.enabled);
        assert!(worker.eligible);
        assert_eq!(worker.weight, 1);
        assert_eq!(worker.max_jobs, 2);
        assert_eq!(worker.active_jobs, 0);
        assert!(worker.parity_ok);

        assert_eq!(parsed.recent_jobs.len(), 1);
        let job = &parsed.recent_jobs[0];
        assert_eq!(job.id, "job-1");
        assert_eq!(job.link_id.as_deref(), Some("link-1"));
        assert_eq!(job.peer_name.as_deref(), Some("media-2"));
        assert_eq!(job.exit_code, Some(0));
        assert_eq!(job.request_id.as_deref(), Some("req-123"));
        assert!(!job.ran_locally);

        let parity = parsed.parity_result.as_ref().expect("parity_result");
        assert_eq!(parity.link_id, "link-1");
        assert!(parity.ok);
        assert_eq!(parity.elapsed_ms, 420);
        assert_eq!(parity.error, None);

        // Full round-trip back through JSON preserves every field.
        let encoded = serde_json::to_string(&parsed).unwrap();
        let reparsed: TranscodeConfigResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(reparsed, parsed);

        // Numeric and string `unhealthy_until` both deserialize cleanly.
        let numeric_worker: TranscodeWorkerView = serde_json::from_value(json!({
            "link_id": "link-2",
            "peer_name": "gpu-3",
            "unhealthy_until": 1763954000
        }))
        .unwrap();
        assert_eq!(
            numeric_worker.unhealthy_until.as_deref(),
            Some("1763954000")
        );
    }

    #[test]
    fn update_transcode_config_request_serializes_targeted_payloads_without_extra_keys() {
        assert_eq!(
            serde_json::to_value(build_toggle_enabled_request(true)).unwrap(),
            json!({ "enabled": true })
        );
        assert_eq!(
            serde_json::to_value(build_toggle_worker_service_request(false)).unwrap(),
            json!({ "worker_service_enabled": false })
        );
        assert_eq!(
            serde_json::to_value(build_update_worker_request("link-1", true, "2", "4").unwrap())
                .unwrap(),
            json!({
                "workers": [
                    {
                        "link_id": "link-1",
                        "enabled": true,
                        "weight": 2,
                        "max_jobs": 4
                    }
                ]
            })
        );
        assert_eq!(
            serde_json::to_value(build_parity_test_request("link-1").unwrap()).unwrap(),
            json!({ "run_parity_test_link_id": "link-1" })
        );
    }

    #[test]
    fn align_action_resolves_local_peer_encoding_and_updates_write_grant_gating() {
        let base_worker = TranscodeWorkerView {
            link_id: "link-1".into(),
            peer_name: "media-2".into(),
            link_state: "active".into(),
            compatibility: "compatible".into(),
            supports_transcode: true,
            has_transcode_write_grant: true,
            has_updates_write_grant: true,
            ffmpeg_mismatch: false,
            align_target: None,
            ..Default::default()
        };
        assert_eq!(resolve_align_action(&base_worker), AlignAction::None);

        // Local server is older -> local package update path.
        let local_older = TranscodeWorkerView {
            ffmpeg_mismatch: true,
            align_target: Some("local".into()),
            has_updates_write_grant: false,
            ..base_worker.clone()
        };
        assert_eq!(
            resolve_align_action(&local_older),
            AlignAction::UpdateLocal {
                path: "/api/v1/admin/packages/jellyfin/update".into(),
            }
        );

        // Peer worker is older and has updates write grant -> percent-encoded proxy path.
        let peer_older = TranscodeWorkerView {
            link_id: "link 1/gpu".into(),
            ffmpeg_mismatch: true,
            align_target: Some("peer".into()),
            has_updates_write_grant: true,
            ..base_worker.clone()
        };
        assert_eq!(
            resolve_align_action(&peer_older),
            AlignAction::UpdatePeer {
                link_id: "link 1/gpu".into(),
                peer_name: "media-2".into(),
                path: "/api/v1/peers/link%201%2Fgpu/admin/packages/jellyfin/update".into(),
            }
        );

        // Peer worker is older WITHOUT updates write or marketplace write grant -> disabled with explicit reason.
        let peer_no_grant = TranscodeWorkerView {
            ffmpeg_mismatch: true,
            align_target: Some("peer".into()),
            has_updates_write_grant: false,
            ..base_worker.clone()
        };
        assert_eq!(
            resolve_align_action(&peer_no_grant),
            AlignAction::DisabledMissingUpdatesGrant {
                peer_name: "media-2".into(),
                reason_key: "Cluster.transcodeAlignRequiresUpdatesGrant",
            }
        );
        assert_eq!(
            translate("en", "Cluster.transcodeAlignRequiresUpdatesGrant"),
            "Requires updates or marketplace write grant on this peer for Jellyfin updates"
        );

        // Peer worker without updates:write is still authorized when peer granted marketplace:write.
        let marketplace_write_peer = PeerLinkView {
            id: "link-1".into(),
            name: "media-2".into(),
            grants: crate::tabs::cluster::peers::LinkGrantsView {
                inbound: None,
                outbound: Some(crate::tabs::cluster::peers::GrantSummaryView {
                    access: crate::tabs::cluster::peers::AccessMapView {
                        marketplace: crate::tabs::cluster::peers::AccessLevel::Write,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            },
            ..Default::default()
        };
        assert_eq!(
            resolve_align_action_for_peer(&peer_no_grant, Some(&marketplace_write_peer)),
            AlignAction::UpdatePeer {
                link_id: "link-1".into(),
                peer_name: "media-2".into(),
                path: "/api/v1/peers/link-1/admin/packages/jellyfin/update".into(),
            }
        );

        // Read-only marketplace grant is not sufficient for Jellyfin package updates.
        let marketplace_read_peer = PeerLinkView {
            grants: crate::tabs::cluster::peers::LinkGrantsView {
                inbound: None,
                outbound: Some(crate::tabs::cluster::peers::GrantSummaryView {
                    access: crate::tabs::cluster::peers::AccessMapView {
                        marketplace: crate::tabs::cluster::peers::AccessLevel::Read,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            },
            ..marketplace_write_peer
        };
        assert_eq!(
            resolve_align_action_for_peer(&peer_no_grant, Some(&marketplace_read_peer)),
            AlignAction::DisabledMissingUpdatesGrant {
                peer_name: "media-2".into(),
                reason_key: "Cluster.transcodeAlignRequiresUpdatesGrant",
            }
        );

        // Peer worker is older with grant, but link is down -> disabled cleanly.
        let peer_down = TranscodeWorkerView {
            link_state: "down".into(),
            ffmpeg_mismatch: true,
            align_target: Some("peer".into()),
            has_updates_write_grant: true,
            ..base_worker
        };
        assert_eq!(
            resolve_align_action(&peer_down),
            AlignAction::DisabledLinkUnavailable {
                peer_name: "media-2".into(),
                reason_key: "Cluster.transcodeAlignRequiresActiveLink",
            }
        );
    }

    #[test]
    fn worker_weight_and_max_jobs_validation_enforces_bounds() {
        for valid in ["1", " 1 ", "42", "100"] {
            assert!(parse_worker_weight(valid).is_ok(), "weight={valid:?}");
        }
        for invalid in ["", "0", "101", "-1", "1.5", "abc"] {
            assert_eq!(
                parse_worker_weight(invalid).unwrap_err(),
                "Cluster.transcodeValidationWeightRange",
                "weight={invalid:?}"
            );
        }

        for valid in ["1", "2", " 16 ", "64"] {
            assert!(parse_worker_max_jobs(valid).is_ok(), "max_jobs={valid:?}");
        }
        for invalid in ["", "0", "65", "-2", "2.5", "xyz"] {
            assert_eq!(
                parse_worker_max_jobs(invalid).unwrap_err(),
                "Cluster.transcodeValidationMaxJobsRange",
                "max_jobs={invalid:?}"
            );
        }

        assert_eq!(
            build_update_worker_request("  ", true, "1", "2").unwrap_err(),
            "Cluster.transcodeValidationLinkIdRequired"
        );
        assert_eq!(
            build_parity_test_request("").unwrap_err(),
            "Cluster.transcodeValidationLinkIdRequired"
        );
    }

    #[test]
    fn capability_grant_eligibility_and_parity_helpers_cover_cuj6_and_cuj8() {
        let ready = TranscodeWorkerView {
            link_id: "link-1".into(),
            peer_name: "media-2".into(),
            link_state: "active".into(),
            compatibility: "compatible".into(),
            supports_transcode: true,
            has_transcode_write_grant: true,
            enabled: true,
            eligible: true,
            parity_ok: true,
            ..Default::default()
        };
        assert!(can_enable_worker(&ready, None));
        assert!(can_run_parity_test(&ready, None));
        assert!(worker_control_disabled_reason("en", &ready, None).is_none());
        assert_eq!(
            worker_eligibility_presentation(&ready),
            ("Cluster.transcodeEligibilityEligible", "success")
        );
        assert_eq!(
            worker_parity_presentation(&ready),
            ("Cluster.transcodeParityPassed", "success")
        );

        // CUJ 8: limited peer missing `transcode` capability shows "Update <peer> to use this".
        let limited = TranscodeWorkerView {
            compatibility: "limited".into(),
            supports_transcode: false,
            enabled: false,
            eligible: false,
            ..ready.clone()
        };
        assert!(!can_enable_worker(&limited, None));
        assert!(!can_run_parity_test(&limited, None));
        assert_eq!(
            worker_capability_reason("en", &limited, None).as_deref(),
            Some("Update media-2 to use this")
        );

        // Missing transcoding:write grant disables enabling & parity tests, but allows turning OFF
        // an already-enabled worker.
        let no_grant = TranscodeWorkerView {
            has_transcode_write_grant: false,
            enabled: true,
            eligible: false,
            ..ready.clone()
        };
        assert!(!can_enable_worker(&no_grant, None));
        assert!(!can_save_worker(&no_grant, true, None));
        assert!(can_save_worker(&no_grant, false, None));
        assert!(!can_run_parity_test(&no_grant, None));
        assert!(worker_control_disabled_reason("en", &no_grant, None)
            .unwrap()
            .contains("media-2"));

        // Version mismatch & unhealthy cooldown & failed parity presentation.
        let mismatch = TranscodeWorkerView {
            eligible: false,
            ffmpeg_mismatch: true,
            ffmpeg_mismatch_message: Some(
                "jellyfin-ffmpeg differs: seedbox-1 8.1.3-1-trixie vs media-2 8.1.2-1-trixie"
                    .into(),
            ),
            parity_ok: false,
            parity_error: Some("NFS transcode directory readback timed out".into()),
            ..ready.clone()
        };
        assert_eq!(
            worker_eligibility_presentation(&mismatch),
            ("Cluster.transcodeEligibilityVersionMismatch", "warning")
        );
        assert_eq!(
            worker_parity_presentation(&mismatch),
            ("Cluster.transcodeParityFailed", "danger")
        );
        assert_eq!(
            format_mismatch_banner("en", &LocalTranscodeInfoView::default(), &mismatch).as_deref(),
            Some("jellyfin-ffmpeg differs: seedbox-1 8.1.3-1-trixie vs media-2 8.1.2-1-trixie")
        );

        // Fallback mismatch formatting when backend omits explicit message.
        let fallback_mismatch = TranscodeWorkerView {
            ffmpeg_mismatch_message: None,
            package_version: Some("8.1.2-1-trixie".into()),
            ffmpeg_version: Some("8.1.2-Jellyfin".into()),
            ..mismatch
        };
        let local = LocalTranscodeInfoView {
            server_name: "seedbox-1".into(),
            package_version: Some("8.1.3-1-trixie".into()),
            ffmpeg_version: Some("8.1.3-Jellyfin".into()),
            ..Default::default()
        };
        let fallback_text = format_mismatch_banner("en", &local, &fallback_mismatch).unwrap();
        assert!(fallback_text.contains("seedbox-1"));
        assert!(fallback_text.contains("8.1.3-1-trixie"));
        assert!(fallback_text.contains("media-2"));
        assert!(fallback_text.contains("8.1.2-1-trixie"));

        let cooldown = TranscodeWorkerView {
            eligible: false,
            unhealthy_until: Some("2026-11-24T04:10:00Z".into()),
            ..ready
        };
        assert_eq!(
            worker_eligibility_presentation(&cooldown),
            ("Cluster.transcodeEligibilityUnhealthy", "danger")
        );
    }

    #[test]
    fn recent_job_target_duration_and_exit_code_formatting_handle_all_states() {
        let remote_job = TranscodeJobView {
            id: "j-1".into(),
            link_id: Some("link-1".into()),
            peer_name: Some("media-2".into()),
            started_at: "2026-11-24T03:00:00Z".into(),
            ended_at: Some("2026-11-24T03:00:12Z".into()),
            exit_code: Some(0),
            request_id: Some("req-1".into()),
            ran_locally: false,
        };
        assert_eq!(format_job_target("en", &remote_job), "Remote (media-2)");
        assert_eq!(
            format_job_duration("en", &remote_job.started_at, remote_job.ended_at.as_deref()),
            "12s"
        );
        assert_eq!(
            job_exit_presentation("en", remote_job.exit_code, remote_job.ended_at.as_deref()),
            ("Exit 0".to_string(), "success")
        );

        let local_failed = TranscodeJobView {
            id: "j-2".into(),
            link_id: None,
            peer_name: None,
            started_at: "2026-11-24T03:00:00Z".into(),
            ended_at: Some("2026-11-24T03:02:05Z".into()),
            exit_code: Some(137),
            request_id: None,
            ran_locally: true,
        };
        assert_eq!(format_job_target("en", &local_failed), "Local");
        assert_eq!(
            format_job_duration(
                "en",
                &local_failed.started_at,
                local_failed.ended_at.as_deref()
            ),
            "2m 5s"
        );
        assert_eq!(
            job_exit_presentation(
                "en",
                local_failed.exit_code,
                local_failed.ended_at.as_deref()
            ),
            ("Exit 137".to_string(), "danger")
        );

        // Sub-second, running, and clock-skew / malformed timestamps degrade safely.
        assert_eq!(
            format_job_duration(
                "en",
                "2026-11-24T03:00:00.000Z",
                Some("2026-11-24T03:00:00.420Z")
            ),
            "420 ms"
        );
        assert_eq!(
            format_job_duration("en", "2026-11-24T03:00:00Z", None),
            "Running"
        );
        assert_eq!(
            job_exit_presentation("en", None, None),
            ("Running".to_string(), "indigo")
        );
        assert_eq!(
            job_exit_presentation("en", None, Some("2026-11-24T03:00:10Z")),
            ("Unknown".to_string(), "muted")
        );
        assert_eq!(
            format_job_duration("en", "2026-11-24T03:05:00Z", Some("2026-11-24T03:00:00Z")),
            "Not reported"
        );
        assert_eq!(
            format_job_duration("en", "not-a-timestamp", Some("also-bad")),
            "Not reported"
        );
    }

    #[test]
    fn transcode_section_state_preserves_dirty_drafts_across_polls_and_resets_cleanly() {
        let mut state = TranscodeSectionState::default();
        let initial = TranscodeConfigResponse {
            workers: vec![
                TranscodeWorkerView {
                    link_id: "link-1".into(),
                    peer_name: "media-2".into(),
                    enabled: true,
                    weight: 1,
                    max_jobs: 2,
                    ..Default::default()
                },
                TranscodeWorkerView {
                    link_id: "link-2".into(),
                    peer_name: "gpu-3".into(),
                    enabled: false,
                    weight: 3,
                    max_jobs: 4,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        state.apply_loaded(initial);

        // User edits link-1 weight without saving yet.
        state.update_worker_draft("link-1", |d| {
            d.weight_input = "25".into();
        });
        assert!(state.is_worker_dirty("link-1"));
        assert!(!state.is_worker_dirty("link-2"));

        // Background poll updates link-2 weight on server and delivers a parity_result.
        let poll = TranscodeConfigResponse {
            workers: vec![
                TranscodeWorkerView {
                    link_id: "link-1".into(),
                    peer_name: "media-2".into(),
                    enabled: true,
                    weight: 1,
                    max_jobs: 2,
                    ..Default::default()
                },
                TranscodeWorkerView {
                    link_id: "link-2".into(),
                    peer_name: "gpu-3".into(),
                    enabled: true,
                    weight: 5,
                    max_jobs: 8,
                    ..Default::default()
                },
            ],
            parity_result: Some(ParityTestResultView {
                link_id: "link-1".into(),
                ok: true,
                elapsed_ms: 350,
                error: None,
            }),
            ..Default::default()
        };
        state.apply_loaded(poll);
        assert_eq!(state.drafts["link-1"].weight_input, "25");
        assert!(state.is_worker_dirty("link-1"));
        assert_eq!(state.drafts["link-2"].weight_input, "5");
        assert_eq!(state.drafts["link-2"].max_jobs_input, "8");
        assert_eq!(state.parity_results["link-1"].elapsed_ms, 350);

        // Saving link-1 clears its dirty marker and adopts server values.
        let saved = TranscodeConfigResponse {
            workers: vec![TranscodeWorkerView {
                link_id: "link-1".into(),
                peer_name: "media-2".into(),
                enabled: true,
                weight: 25,
                max_jobs: 2,
                ..Default::default()
            }],
            ..Default::default()
        };
        state.apply_worker_saved("link-1", saved);
        assert!(!state.is_worker_dirty("link-1"));
        assert_eq!(state.drafts["link-1"].weight_input, "25");
        assert!(!state.drafts.contains_key("link-2"));

        // Session reset clears all cached config, drafts, and parity feedback.
        state.reset();
        assert!(state.config.is_none());
        assert!(state.drafts.is_empty());
        assert!(state.dirty_workers.is_empty());
        assert!(state.parity_results.is_empty());
    }

    #[test]
    fn transcode_i18n_keys_resolve_across_all_six_locales() {
        let keys = [
            "Cluster.transcodeHeading",
            "Cluster.transcodeDescription",
            "Cluster.transcodeGlobalEnableLabel",
            "Cluster.transcodeWorkerServiceLabel",
            "Cluster.transcodeVersionHeading",
            "Cluster.transcodeAlignUpdateAction",
            "Cluster.transcodeAlignRequiresUpdatesGrant",
            "Cluster.transcodeUpdatePeerHint",
            "Cluster.transcodeRunParityAction",
            "Cluster.transcodeWorkersEmptyTitle",
            "Cluster.transcodeJobsHeading",
            "Cluster.transcodeJobsEmptyTitle",
            "Cluster.transcodeJobTargetLocal",
            "Cluster.transcodeJobTargetRemote",
            "Cluster.transcodeJobExitOk",
            "Cluster.transcodeJobExitFailed",
            "Cluster.transcodeParityResultPassed",
            "Cluster.transcodeParityResultFailed",
            "Cluster.transcodeValidationWeightRange",
            "Cluster.transcodeValidationMaxJobsRange",
        ];
        for locale in ["en", "de", "dk", "es", "fr", "zh"] {
            for key in keys {
                let translated = translate(locale, key);
                assert_ne!(translated, key, "missing translation for {locale}/{key}");
                assert!(
                    !translated.trim().is_empty(),
                    "empty translation for {locale}/{key}"
                );
            }
            let parity_ok = format_parity_result_banner(
                locale,
                "media-2",
                &ParityTestResultView {
                    link_id: "link-1".into(),
                    ok: true,
                    elapsed_ms: 420,
                    error: None,
                },
            );
            assert!(
                parity_ok.contains("media-2") && parity_ok.contains("420"),
                "{locale}: {parity_ok}"
            );
        }
    }
}
