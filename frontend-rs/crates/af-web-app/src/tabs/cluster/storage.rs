//! Peer media storage (`/?tab=cluster`, design file 40): local NFS export selection with
//! explicit write opt-in and warning, authenticated remote export catalog discovery, local mount
//! management with state/error hints, interior app library folder hints, high-latency warnings,
//! and media-app safety guidance over direct local `/api/v1/admin/peers/:id/*` routes.

use super::peers::{compatibility_guidance, format_rtt, supports_storage_catalog, PeerLinkView};
use super::{
    copy_text_to_clipboard, local_fs_browse_path, local_same_origin_get, peer_api_request,
    peer_api_request_with_request_id, peer_exports_path, peer_mounts_path, sanitize_request_id,
    CompletionScope, DialogGate, MutationToken, PeerApiError, PeerErrorAlert,
};
use crate::state::app;
use crate::tabs::l10n::{tt, tt_with, Badge, Modal};
use af_web_core::i18n::{translate, translate_with};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

pub const LOCAL_FS_QUICK_ROOTS: [&str; 5] = ["/srv", "/mnt", "/media", "/data", "/home"];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerExportView {
    pub id: String,
    pub link_id: String,
    pub path: String,
    pub writable: bool,
    pub squash_uid: Option<u32>,
    pub squash_gid: Option<u32>,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerMountView {
    pub id: String,
    pub link_id: String,
    pub remote_path: String,
    pub mount_path: String,
    pub unit_name: String,
    pub writable: bool,
    pub purpose: String,
    pub state: String,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerErrorEnvelope {
    pub code: String,
    pub server: String,
    pub step: String,
    pub message: String,
    pub action: String,
    pub request_id: Option<String>,
}

impl PeerErrorEnvelope {
    pub fn to_peer_api_error(&self) -> PeerApiError {
        self.to_peer_api_error_with_fallback(None)
    }

    pub fn to_peer_api_error_with_fallback(
        &self,
        fallback_request_id: Option<&str>,
    ) -> PeerApiError {
        let non_empty = |text: &str| {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        };
        let message = non_empty(&self.message).unwrap_or_else(|| "Peer request failed".to_string());
        let request_id = self
            .request_id
            .as_deref()
            .and_then(sanitize_request_id)
            .or_else(|| fallback_request_id.and_then(sanitize_request_id));
        PeerApiError::from_envelope(
            0,
            non_empty(&self.code),
            non_empty(&self.server),
            non_empty(&self.step),
            message,
            non_empty(&self.action),
            request_id,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerExportListResponse {
    pub exports: Vec<PeerExportView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePeerExportRequest {
    pub path: String,
    pub writable: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CreatePeerExportResponse {
    pub export: PeerExportView,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletePeerExportRequest {
    pub export_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerMountListResponse {
    pub mounts: Vec<PeerMountView>,
    pub available_exports: Vec<PeerExportView>,
    #[serde(default)]
    pub exports_error: Option<PeerErrorEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePeerMountRequest {
    pub export_id: String,
    pub writable: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CreatePeerMountResponse {
    pub mount: PeerMountView,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletePeerMountRequest {
    pub mount_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalFsListing {
    pub current_path: String,
    pub parent_path: Option<String>,
    pub directories: Vec<String>,
}

fn normalize_absolute_dir_segments(raw: &str) -> Result<Vec<&str>, &'static str> {
    if raw.chars().any(char::is_control) {
        return Err("Cluster.validationExportPathInvalid");
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err("Cluster.validationExportPathRequired");
    }
    if trimmed.contains('\\') || trimmed.len() > 4096 {
        return Err("Cluster.validationExportPathInvalid");
    }
    let mut segments = Vec::new();
    for part in trimmed.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err("Cluster.validationExportPathInvalid"),
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        return Err("Cluster.validationExportPathRequired");
    }
    Ok(segments)
}

/// Validates and normalizes an absolute local directory path strictly below `/`.
pub fn validate_export_path(raw: &str) -> Result<String, &'static str> {
    let segments = normalize_absolute_dir_segments(raw)?;
    Ok(format!("/{}", segments.join("/")))
}

/// Derives the interior library path strictly below a peer mount root (e.g.
/// `/mnt/af-peers/media-2/movies` -> `/mnt/af-peers/media-2/movies/library`).
/// Never returns the mount root itself, `/`, or any path containing traversal or control chars.
pub fn app_library_hint_path(mount_path: &str) -> Option<String> {
    let segments = normalize_absolute_dir_segments(mount_path).ok()?;
    let normalized = format!("/{}", segments.join("/"));
    Some(format!("{normalized}/library"))
}

fn normalize_compare_path(path: &str) -> String {
    let trimmed = path.trim().trim_end_matches('/');
    if trimmed.is_empty() && path.trim().starts_with('/') {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn is_export_already_mounted(export: &PeerExportView, mounts: &[PeerMountView]) -> bool {
    let target = normalize_compare_path(&export.path);
    !target.is_empty()
        && mounts
            .iter()
            .any(|mount| normalize_compare_path(&mount.remote_path) == target)
}

pub fn build_create_export_request(
    raw_path: &str,
    writable: bool,
) -> Result<CreatePeerExportRequest, &'static str> {
    let path = validate_export_path(raw_path)?;
    Ok(CreatePeerExportRequest { path, writable })
}

pub fn build_create_mount_request(
    selected_export: Option<&PeerExportView>,
    writable: bool,
    mounts: &[PeerMountView],
) -> Result<CreatePeerMountRequest, &'static str> {
    let export = selected_export
        .filter(|exp| !exp.id.trim().is_empty())
        .ok_or("Cluster.validationMountExportRequired")?;
    if is_export_already_mounted(export, mounts) {
        return Err("Cluster.storageAvailableAlreadyMountedNote");
    }
    // Never request write access unless the remote export explicitly permits writes.
    let effective_writable = writable && export.writable;
    Ok(CreatePeerMountRequest {
        export_id: export.id.clone(),
        writable: effective_writable,
    })
}

pub fn is_peer_high_latency(peer: &PeerLinkView, rtt_warn_ms: f64) -> bool {
    peer.high_latency
        || peer
            .rtt_ms
            .is_some_and(|rtt| rtt.is_finite() && rtt_warn_ms.is_finite() && rtt > rtt_warn_ms)
}

pub fn format_high_latency_banner(
    locale: &str,
    peer: &PeerLinkView,
    rtt_warn_ms: f64,
) -> Option<String> {
    if !is_peer_high_latency(peer, rtt_warn_ms) {
        return None;
    }
    let threshold = format!("{rtt_warn_ms:.0}");
    match peer.rtt_ms {
        Some(rtt) if rtt.is_finite() && rtt >= 0.0 => {
            let formatted = format_rtt(locale, Some(rtt));
            Some(translate_with(
                locale,
                "Cluster.storageHighLatencyBanner",
                &[("rtt", &formatted), ("threshold", &threshold)],
            ))
        }
        _ => Some(translate_with(
            locale,
            "Cluster.storageHighLatencyBannerNoRtt",
            &[("threshold", &threshold)],
        )),
    }
}

pub fn mount_state_presentation(
    mount_state: &str,
    peer_state: &str,
) -> (&'static str, &'static str) {
    let normalized = mount_state.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "mounted" | "active" => ("Cluster.storageMountStateMounted", "success"),
        "stopped_link_down" | "stopped-link-down" | "stopped: link down" | "link_down" => {
            ("Cluster.storageMountStateStoppedLinkDown", "danger")
        }
        "stopped_sentinel" | "stopped-sentinel" | "sentinel_failed" | "stopped_sentinel_failed" => {
            ("Cluster.storageMountStateStoppedSentinel", "danger")
        }
        "stopped" | "unmounted" | "inactive" => {
            if peer_state == "down" {
                ("Cluster.storageMountStateStoppedLinkDown", "danger")
            } else {
                ("Cluster.storageMountStateStopped", "warning")
            }
        }
        "mounting" | "starting" | "pending" => ("Cluster.storageMountStateMounting", "warning"),
        "unmounting" | "stopping" => ("Cluster.storageMountStateStopping", "warning"),
        "error" | "failed" | "degraded" => ("Cluster.storageMountStateError", "danger"),
        _ => ("Cluster.storageMountStateUnknown", "muted"),
    }
}

pub fn mount_state_hint_key(mount_state: &str, peer_state: &str) -> Option<&'static str> {
    let normalized = mount_state.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "mounted" | "active" => Some("Cluster.storageMountHintMounted"),
        "stopped_link_down" | "stopped-link-down" | "stopped: link down" | "link_down" => {
            Some("Cluster.storageMountHintStoppedLinkDown")
        }
        "stopped_sentinel" | "stopped-sentinel" | "sentinel_failed" | "stopped_sentinel_failed" => {
            Some("Cluster.storageMountHintStoppedSentinel")
        }
        "stopped" | "unmounted" | "inactive" => {
            if peer_state == "down" {
                Some("Cluster.storageMountHintStoppedLinkDown")
            } else {
                Some("Cluster.storageMountHintStopped")
            }
        }
        "error" | "failed" | "degraded" => Some("Cluster.storageMountHintError"),
        _ => None,
    }
}

pub fn mount_purpose_label_key(purpose: &str) -> Option<&'static str> {
    match purpose.trim().to_ascii_lowercase().as_str() {
        "media" => Some("Cluster.storageMountPurposeMedia"),
        "transcode" => Some("Cluster.storageMountPurposeTranscode"),
        _ => None,
    }
}

pub fn initial_browser_path(draft_path: &str) -> String {
    validate_export_path(draft_path).unwrap_or_else(|_| LOCAL_FS_QUICK_ROOTS[0].to_string())
}

pub fn join_local_child_dir(current_path: &str, child_name: &str) -> Result<String, &'static str> {
    let name = child_name.trim();
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err("Cluster.validationExportPathInvalid");
    }
    let base = current_path.trim().trim_end_matches('/');
    let combined = if base.is_empty() {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    };
    validate_export_path(&combined)
}

pub fn parse_local_fs_listing(requested_path: &str, value: &Value) -> LocalFsListing {
    let current_path = value
        .get("current_path")
        .and_then(Value::as_str)
        .and_then(|raw| validate_export_path(raw).ok())
        .or_else(|| validate_export_path(requested_path).ok())
        .unwrap_or_else(|| LOCAL_FS_QUICK_ROOTS[0].to_string());

    let parent_path = value
        .get("parent_path")
        .and_then(Value::as_str)
        .and_then(|raw| validate_export_path(raw).ok())
        .filter(|parent| parent != &current_path);

    let mut directories: Vec<String> =
        if let Some(dirs) = value.get("directories").and_then(Value::as_array) {
            dirs.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|name| {
                    !name.is_empty()
                        && !matches!(*name, "." | "..")
                        && !name.contains(['/', '\\'])
                        && !name.chars().any(char::is_control)
                })
                .map(str::to_string)
                .collect()
        } else {
            value
                .get("entries")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|entry| entry["is_dir"] == true || entry["isDir"] == true)
                .filter_map(|entry| entry.get("name").and_then(Value::as_str))
                .map(str::trim)
                .filter(|name| {
                    !name.is_empty()
                        && !matches!(*name, "." | "..")
                        && !name.contains(['/', '\\'])
                        && !name.chars().any(char::is_control)
                })
                .map(str::to_string)
                .collect()
        };
    directories.sort();
    directories.dedup();

    LocalFsListing {
        current_path,
        parent_path,
        directories,
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

/// Pure form & loaded-storage state machine for [`StorageManagerModal`].
/// Preserves export/mount drafts across typed backend errors, keeps writes opt-in by default,
/// and preserves local mount management even when remote export discovery fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageModalState {
    pub exports: Vec<PeerExportView>,
    pub mounts: Vec<PeerMountView>,
    pub available_exports: Vec<PeerExportView>,
    pub catalog_error: Option<PeerApiError>,
    pub export_path: String,
    pub export_writable: bool,
    pub selected_export_id: String,
    pub mount_writable: bool,
    pub confirm_remove_export_id: Option<String>,
    pub confirm_remove_mount_id: Option<String>,
}

impl StorageModalState {
    pub fn apply_exports_loaded(&mut self, exports: Vec<PeerExportView>) {
        if let Some(pending) = self.confirm_remove_export_id.as_deref() {
            if !exports.iter().any(|exp| exp.id == pending) {
                self.confirm_remove_export_id = None;
            }
        }
        self.exports = exports;
    }

    pub fn apply_mounts_loaded(&mut self, resp: PeerMountListResponse) {
        self.apply_mounts_loaded_with_request_id(resp, None);
    }

    pub fn apply_mounts_loaded_with_request_id(
        &mut self,
        resp: PeerMountListResponse,
        header_request_id: Option<&str>,
    ) {
        self.mounts = resp.mounts;
        self.available_exports = resp.available_exports;
        self.catalog_error = resp
            .exports_error
            .as_ref()
            .map(|env| env.to_peer_api_error_with_fallback(header_request_id));
        if let Some(pending) = self.confirm_remove_mount_id.as_deref() {
            if !self.mounts.iter().any(|mount| mount.id == pending) {
                self.confirm_remove_mount_id = None;
            }
        }
        self.reconcile_selected_export();
    }

    fn reconcile_selected_export(&mut self) {
        let existing_valid = self
            .available_exports
            .iter()
            .find(|exp| exp.id == self.selected_export_id)
            .cloned();
        match existing_valid {
            Some(exp) if !is_export_already_mounted(&exp, &self.mounts) => {
                if !exp.writable {
                    self.mount_writable = false;
                }
            }
            _ => {
                let next = self
                    .available_exports
                    .iter()
                    .find(|exp| !is_export_already_mounted(exp, &self.mounts))
                    .or_else(|| self.available_exports.first())
                    .cloned();
                self.selected_export_id =
                    next.as_ref().map(|exp| exp.id.clone()).unwrap_or_default();
                self.mount_writable = false;
            }
        }
    }

    pub fn select_remote_export(&mut self, export_id: String) {
        if self.selected_export_id != export_id {
            self.selected_export_id = export_id;
            // Require explicit write opt-in per chosen remote export.
            self.mount_writable = false;
        }
    }

    pub fn selected_remote_export(&self) -> Option<&PeerExportView> {
        self.available_exports
            .iter()
            .find(|exp| exp.id == self.selected_export_id)
    }

    pub fn apply_export_created(&mut self, export: PeerExportView) {
        if let Some(slot) = self.exports.iter_mut().find(|item| item.id == export.id) {
            *slot = export;
        } else {
            self.exports.push(export);
        }
        self.export_path.clear();
        self.export_writable = false;
    }

    pub fn apply_export_removed(&mut self, export_id: &str) {
        self.exports.retain(|item| item.id != export_id);
        if self.confirm_remove_export_id.as_deref() == Some(export_id) {
            self.confirm_remove_export_id = None;
        }
    }

    pub fn apply_mount_created(&mut self, mount: PeerMountView) {
        if let Some(slot) = self.mounts.iter_mut().find(|item| item.id == mount.id) {
            *slot = mount;
        } else {
            self.mounts.push(mount);
        }
        self.mount_writable = false;
        self.reconcile_selected_export();
    }

    pub fn apply_mount_removed(&mut self, mount_id: &str) {
        self.mounts.retain(|item| item.id != mount_id);
        if self.confirm_remove_mount_id.as_deref() == Some(mount_id) {
            self.confirm_remove_mount_id = None;
        }
        self.reconcile_selected_export();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SectionLoadState {
    Idle,
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StorageAction {
    CreateExport,
    RemoveExport(String),
    CreateMount,
    RemoveMount(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StorageNotice {
    ExportCreated { path: String, peer_name: String },
    ExportRemoved { path: String, peer_name: String },
    MountCreated { path: String, peer_name: String },
    MountRemoved { path: String, peer_name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StorageFocusTarget {
    ExportPathInput,
    ExportRemoveKeep(String),
    ExportRemoveOpen(String),
    MountSubmit,
    MountRemoveKeep(String),
    MountRemoveOpen(String),
}

fn storage_focus_selector(target: &StorageFocusTarget) -> String {
    match target {
        StorageFocusTarget::ExportPathInput => {
            "#cluster-storage-export-path:not([disabled])".into()
        }
        StorageFocusTarget::ExportRemoveKeep(id) => {
            format!(
                "#cluster-storage-export-keep-{}:not([disabled])",
                dom_safe_id(id)
            )
        }
        StorageFocusTarget::ExportRemoveOpen(id) => {
            format!(
                "#cluster-storage-export-remove-{}:not([disabled])",
                dom_safe_id(id)
            )
        }
        StorageFocusTarget::MountSubmit => "#cluster-storage-mount-submit:not([disabled])".into(),
        StorageFocusTarget::MountRemoveKeep(id) => {
            format!(
                "#cluster-storage-mount-keep-{}:not([disabled])",
                dom_safe_id(id)
            )
        }
        StorageFocusTarget::MountRemoveOpen(id) => {
            format!(
                "#cluster-storage-mount-remove-{}:not([disabled])",
                dom_safe_id(id)
            )
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn try_focus_storage_control(body: &web_sys::Element, selector: &str) -> bool {
    use wasm_bindgen::JsCast;

    if !body.is_connected() || body.closest("dialog[open]").ok().flatten().is_none() {
        return false;
    }
    let Ok(Some(element)) = body.query_selector(selector) else {
        return false;
    };
    let Ok(html_el) = element.dyn_into::<web_sys::HtmlElement>() else {
        return false;
    };
    if !html_el.is_connected() || html_el.matches(":disabled").unwrap_or(true) {
        return false;
    }
    let _ = html_el.focus();
    web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.active_element())
        .as_ref()
        == Some(html_el.unchecked_ref())
}

#[derive(Clone, Copy)]
struct StorageModalFocus {
    body_ref: NodeRef<leptos::html::Div>,
    timer: StoredValue<Option<gloo_timers::callback::Timeout>, LocalStorage>,
    open: RwSignal<bool>,
    target: RwSignal<Option<PeerLinkView>>,
    gate: DialogGate,
    session_epoch: RwSignal<u64>,
}

impl StorageModalFocus {
    fn clear(self) {
        self.timer.set_value(None);
    }

    #[cfg(target_arch = "wasm32")]
    fn schedule(self, token: MutationToken, peer_id: String, focus_target: StorageFocusTarget) {
        self.clear();
        let peer_id_check = peer_id.clone();
        let matches_target = move || {
            self.target
                .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id_check))
                .unwrap_or(false)
        };
        if self
            .gate
            .classify(self.session_epoch, self.open, token, matches_target)
            != CompletionScope::CurrentDialog
        {
            return;
        }
        let selector = storage_focus_selector(&focus_target);
        if let Some(body) = self.body_ref.get_untracked() {
            if try_focus_storage_control(&body, &selector) {
                return;
            }
        }
        let timer = gloo_timers::callback::Timeout::new(0, move || {
            let matches_later = move || {
                self.target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            };
            if self
                .gate
                .classify(self.session_epoch, self.open, token, matches_later)
                != CompletionScope::CurrentDialog
            {
                return;
            }
            if let Some(body) = self.body_ref.get_untracked() {
                if !try_focus_storage_control(&body, &selector)
                    && matches!(focus_target, StorageFocusTarget::ExportPathInput)
                {
                    let _ = try_focus_storage_control(&body, "#cluster-storage-close");
                }
            }
        });
        self.timer.set_value(Some(timer));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn schedule(self, token: MutationToken, peer_id: String, focus_target: StorageFocusTarget) {
        let _ = (
            self.body_ref,
            self.timer,
            self.open,
            self.target,
            self.gate,
            self.session_epoch,
            token,
            peer_id,
            storage_focus_selector(&focus_target),
        );
    }
}

/// Compact live summary rendered on each [`super::peers::PeerRowCard`] whenever the peer
/// has stored local exports or mounts. Updates automatically on 10-second health polls.
#[component]
pub fn PeerRowStorageSummary(
    peer: Memo<Option<PeerLinkView>>,
    rtt_warn_ms: Signal<f64>,
) -> impl IntoView {
    let context = app();
    let has_storage = Memo::new(move |_| {
        peer.with(|p| {
            p.as_ref()
                .is_some_and(|p| !p.exports.is_empty() || !p.mounts.is_empty())
        })
    });

    view! {
        <Show when=move || has_storage.get()>
            {move || {
                let current = peer.get()?;
                let locale = crate::tabs::l10n::locale(context);
                let peer_state = current.state.clone();
                let exports_count = current.exports.len().to_string();
                let mounts_count = current.mounts.len().to_string();
                let summary_text = translate_with(
                    &locale,
                    "Cluster.storageSummaryBadge",
                    &[("exports", &exports_count), ("mounts", &mounts_count)],
                );
                let latency_banner =
                    format_high_latency_banner(&locale, &current, rtt_warn_ms.get());

                Some(view! {
                    <div
                        data-testid=format!("peer-storage-summary-{}", current.id)
                        class="af-surface-inset p-3 space-y-3"
                    >
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <h4 class="text-xs font-semibold uppercase tracking-wide text-slate-300">
                                {move || tt(context, "Cluster.storageRowHeading")}
                            </h4>
                            <span class="text-xs font-mono text-slate-400">{summary_text}</span>
                        </div>

                        {latency_banner.map(|warning| {
                            view! {
                                <div
                                    role="status"
                                    data-testid="peer-storage-latency-warning"
                                    class="af-warning-banner text-xs"
                                >
                                    {warning}
                                </div>
                            }
                        })}

                        {(!current.mounts.is_empty()).then(|| {
                            let mounts = current.mounts.clone();
                            let peer_state_mounts = peer_state.clone();
                            view! {
                                <ul class="space-y-2">
                                    {mounts
                                        .into_iter()
                                        .map(|mount| {
                                            let (state_key, state_tone) = mount_state_presentation(
                                                &mount.state,
                                                &peer_state_mounts,
                                            );
                                            let mode_key = if mount.writable {
                                                "Cluster.storageExportModeReadWrite"
                                            } else {
                                                "Cluster.storageExportModeReadOnly"
                                            };
                                            let mode_tone = if mount.writable { "warning" } else { "indigo" };
                                            let library_path = app_library_hint_path(&mount.mount_path);
                                            let last_error = mount
                                                .last_error
                                                .clone()
                                                .filter(|msg| !msg.trim().is_empty());
                                            let remote_path = mount.remote_path.clone();
                                            let remote_for_aria = remote_path.clone();

                                            view! {
                                                <li class="af-surface-inset p-2.5 space-y-1.5 text-xs">
                                                    <div class="flex flex-wrap items-center justify-between gap-2">
                                                        <span class="font-mono text-slate-200 break-all">
                                                            {remote_path}
                                                        </span>
                                                        <div class="flex flex-wrap items-center gap-1.5 shrink-0">
                                                            <Badge label=state_key tone=state_tone />
                                                            <Badge label=mode_key tone=mode_tone />
                                                        </div>
                                                    </div>
                                                    {match library_path {
                                                        Some(lib_path) => {
                                                            let copy_value = lib_path.clone();
                                                            view! {
                                                                <div class="flex flex-wrap items-center justify-between gap-2 text-slate-300">
                                                                    <div class="min-w-0">
                                                                        <span class="text-slate-400">
                                                                            {move || tt(context, "Cluster.storageMountLibraryPathLabel")}
                                                                        </span>
                                                                        ": "
                                                                        <code
                                                                            data-testid="peer-mount-library-path"
                                                                            class="font-mono text-cyan-200 break-all"
                                                                        >
                                                                            {lib_path}
                                                                        </code>
                                                                    </div>
                                                                    <button
                                                                        type="button"
                                                                        class="af-btn px-2 py-1 text-xs shrink-0"
                                                                        aria-label=move || {
                                                                            tt_with(
                                                                                context,
                                                                                "Cluster.storageCopyLibraryPathAria",
                                                                                &[("path", &remote_for_aria)],
                                                                            )
                                                                        }
                                                                        on:click=move |_| {
                                                                            copy_text_to_clipboard(context, copy_value.clone());
                                                                        }
                                                                    >
                                                                        {move || tt(context, "Cluster.storageCopyLibraryPathAction")}
                                                                    </button>
                                                                </div>
                                                            }
                                                            .into_any()
                                                        }
                                                        None => view! {
                                                            <p class="text-slate-400">
                                                                {move || tt(context, "Cluster.storageMountLibraryPathUnavailable")}
                                                            </p>
                                                        }
                                                        .into_any(),
                                                    }}
                                                    {last_error.map(|err_msg| {
                                                        view! {
                                                            <p role="status" class="af-danger-banner text-xs break-words">
                                                                <span class="font-semibold">
                                                                    {move || tt(context, "Cluster.lastErrorLabel")}
                                                                </span>
                                                                ": "
                                                                {err_msg}
                                                            </p>
                                                        }
                                                    })}
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            }
                        })}

                        {(!current.exports.is_empty()).then(|| {
                            let exports = current.exports.clone();
                            view! {
                                <ul class="flex flex-wrap gap-2">
                                    {exports
                                        .into_iter()
                                        .map(|export| {
                                            let mode_key = if export.writable {
                                                "Cluster.storageExportModeReadWrite"
                                            } else {
                                                "Cluster.storageExportModeReadOnly"
                                            };
                                            let mode_tone = if export.writable { "warning" } else { "muted" };
                                            view! {
                                                <li class="af-surface-inset inline-flex items-center gap-2 px-2.5 py-1 text-xs">
                                                    <span class="font-mono text-slate-200 break-all">
                                                        {export.path}
                                                    </span>
                                                    <Badge label=mode_key tone=mode_tone />
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            }
                        })}
                    </div>
                })
            }}
        </Show>
    }
}

#[component]
pub fn StorageManagerModal(
    open: RwSignal<bool>,
    target: RwSignal<Option<PeerLinkView>>,
    rtt_warn_ms: Signal<f64>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let exports_load_state = RwSignal::new(SectionLoadState::Idle);
    let mounts_load_state = RwSignal::new(SectionLoadState::Idle);
    let exports_load_error = RwSignal::new(None::<PeerApiError>);
    let mounts_load_error = RwSignal::new(None::<PeerApiError>);
    let mutation_error = RwSignal::new(None::<PeerApiError>);
    let status_notice = RwSignal::new(None::<StorageNotice>);
    let active_action = RwSignal::new(None::<StorageAction>);
    let state = RwSignal::new(StorageModalState::default());

    let exports_fetch_ticket = RwSignal::new(0u64);
    let mounts_fetch_ticket = RwSignal::new(0u64);

    // Inline local folder browser state (strictly local `/api/v1/auth/fs`).
    let browser_open = RwSignal::new(false);
    let browser_loading = RwSignal::new(false);
    let browser_error = RwSignal::new(None::<PeerApiError>);
    let browser_listing = RwSignal::new(None::<LocalFsListing>);
    let browser_ticket = RwSignal::new(0u64);

    let gate = DialogGate::new();
    let body_ref = NodeRef::<leptos::html::Div>::new();
    let focus = StorageModalFocus {
        body_ref,
        timer: StoredValue::new_local(None::<gloo_timers::callback::Timeout>),
        open,
        target,
        gate,
        session_epoch: context.session_epoch,
    };
    let last_session =
        StoredValue::new((false, None::<String>, context.session_epoch.get_untracked()));

    on_cleanup(move || {
        focus.clear();
    });

    let fetch_exports = move |peer_id: String, token: MutationToken| {
        if !context.is_admin_untracked() {
            return;
        }
        exports_fetch_ticket.update(|t| *t = t.wrapping_add(1));
        let ticket = exports_fetch_ticket.get_untracked();
        exports_load_error.set(None);
        exports_load_state.set(SectionLoadState::Loading);
        let path = peer_exports_path(&peer_id);
        spawn_local(async move {
            let result = peer_api_request::<PeerExportListResponse>(&path, "GET", None).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession | CompletionScope::StaleDialog => return,
                CompletionScope::CurrentDialog => {}
            }
            if exports_fetch_ticket.try_get_untracked() != Some(ticket) {
                return;
            }
            match result {
                Ok(resp) => {
                    state.update(|s| s.apply_exports_loaded(resp.exports));
                    exports_load_error.set(None);
                    exports_load_state.set(SectionLoadState::Ready);
                }
                Err(api_err) => {
                    exports_load_error.set(Some(api_err));
                    exports_load_state.set(SectionLoadState::Failed);
                }
            }
        });
    };

    let fetch_mounts = move |peer_id: String, token: MutationToken| {
        if !context.is_admin_untracked() {
            return;
        }
        mounts_fetch_ticket.update(|t| *t = t.wrapping_add(1));
        let ticket = mounts_fetch_ticket.get_untracked();
        mounts_load_error.set(None);
        mounts_load_state.set(SectionLoadState::Loading);
        let path = peer_mounts_path(&peer_id);
        spawn_local(async move {
            let result =
                peer_api_request_with_request_id::<PeerMountListResponse>(&path, "GET", None).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession | CompletionScope::StaleDialog => return,
                CompletionScope::CurrentDialog => {}
            }
            if mounts_fetch_ticket.try_get_untracked() != Some(ticket) {
                return;
            }
            match result {
                Ok((resp, header_request_id)) => {
                    state.update(|s| {
                        s.apply_mounts_loaded_with_request_id(resp, header_request_id.as_deref())
                    });
                    mounts_load_error.set(None);
                    mounts_load_state.set(SectionLoadState::Ready);
                }
                Err(api_err) => {
                    mounts_load_error.set(Some(api_err));
                    mounts_load_state.set(SectionLoadState::Failed);
                }
            }
        });
    };

    let fetch_local_dir = move |dir_path: String| {
        if !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let peer_id = peer.id;
        let token = gate.current_token(context.session_epoch);
        browser_ticket.update(|t| *t = t.wrapping_add(1));
        let ticket = browser_ticket.get_untracked();
        browser_loading.set(true);
        browser_error.set(None);
        let url = local_fs_browse_path(&dir_path);
        spawn_local(async move {
            let result = local_same_origin_get::<Value>(&url).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession | CompletionScope::StaleDialog => return,
                CompletionScope::CurrentDialog => {}
            }
            if browser_ticket.try_get_untracked() != Some(ticket) {
                return;
            }
            browser_loading.set(false);
            match result {
                Ok(val) => {
                    let listing = parse_local_fs_listing(&dir_path, &val);
                    browser_listing.set(Some(listing));
                    browser_error.set(None);
                }
                Err(err) => {
                    browser_error.set(Some(err));
                }
            }
        });
    };

    Effect::new(move |_| {
        let is_open = open.get();
        let epoch = context.session_epoch.get();
        let target_id = if is_open {
            target.with(|peer| peer.as_ref().map(|p| p.id.clone()))
        } else {
            None
        };
        let next_session = (is_open, target_id.clone(), epoch);
        if last_session.get_value() == next_session {
            return;
        }
        last_session.set_value(next_session);
        focus.clear();
        gate.reset();
        exports_fetch_ticket.update(|t| *t = t.wrapping_add(1));
        mounts_fetch_ticket.update(|t| *t = t.wrapping_add(1));
        browser_ticket.update(|t| *t = t.wrapping_add(1));
        exports_load_error.set(None);
        mounts_load_error.set(None);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(None);
        browser_open.set(false);
        browser_loading.set(false);
        browser_error.set(None);
        browser_listing.set(None);
        state.set(StorageModalState::default());

        if let (true, Some(peer_id)) = (is_open, target_id) {
            // Seed initial rows from the live PeersSnapshot so stored items remain immediately
            // visible while the fresh GET requests complete.
            if let Some(peer) = target.get_untracked() {
                state.update(|s| {
                    s.exports = peer.exports;
                    s.mounts = peer.mounts;
                });
            }
            let token = gate.current_token(context.session_epoch);
            fetch_exports(peer_id.clone(), token);
            fetch_mounts(peer_id.clone(), token);
            focus.schedule(token, peer_id, StorageFocusTarget::ExportPathInput);
        } else {
            exports_load_state.set(SectionLoadState::Idle);
            mounts_load_state.set(SectionLoadState::Idle);
        }
    });

    let retry_exports = move || {
        if !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let token = gate.current_token(context.session_epoch);
        fetch_exports(peer.id, token);
    };

    let retry_mounts = move || {
        if !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let token = gate.current_token(context.session_epoch);
        fetch_mounts(peer.id, token);
    };

    let refresh_all = move || {
        if !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let token = gate.current_token(context.session_epoch);
        fetch_exports(peer.id.clone(), token);
        fetch_mounts(peer.id, token);
    };

    let submit_create_export = move || {
        if gate.is_busy_untracked() || !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        if !supports_storage_catalog(&peer) {
            return;
        }
        let snapshot = state.get_untracked();
        let req = match build_create_export_request(&snapshot.export_path, snapshot.export_writable)
        {
            Ok(req) => req,
            Err(key) => {
                status_notice.set(None);
                mutation_error.set(Some(PeerApiError::client(tt(context, key))));
                return;
            }
        };
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                mutation_error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        let peer_id = peer.id.clone();
        let peer_name = peer.name.clone();
        let path = peer_exports_path(&peer.id);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(Some(StorageAction::CreateExport));
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result =
                peer_api_request::<CreatePeerExportResponse>(&path, "POST", Some(&body)).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            active_action.set(None);
            busy_guard.release();
            match result {
                Ok(resp) => {
                    let created_path = resp.export.path.clone();
                    exports_fetch_ticket.update(|t| *t = t.wrapping_add(1));
                    state.update(|s| s.apply_export_created(resp.export));
                    exports_load_state.set(SectionLoadState::Ready);
                    exports_load_error.set(None);
                    browser_open.set(false);
                    status_notice.set(Some(StorageNotice::ExportCreated {
                        path: created_path.clone(),
                        peer_name: peer_name.clone(),
                    }));
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.storageExportCreatedToast",
                        &[("path", &created_path), ("peer", &peer_name)],
                        false,
                    );
                    focus.schedule(token, peer_id, StorageFocusTarget::ExportPathInput);
                }
                Err(api_err) => {
                    mutation_error.set(Some(api_err));
                    focus.schedule(token, peer_id, StorageFocusTarget::ExportPathInput);
                }
            }
        });
    };

    let confirm_remove_export = move |export_id: String, export_path: String| {
        if gate.is_busy_untracked() || !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let req = DeletePeerExportRequest {
            export_id: export_id.clone(),
        };
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                mutation_error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        let peer_id = peer.id.clone();
        let peer_name = peer.name.clone();
        let path = peer_exports_path(&peer.id);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(Some(StorageAction::RemoveExport(export_id.clone())));
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<Value>(&path, "DELETE", Some(&body)).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            active_action.set(None);
            busy_guard.release();
            match result {
                Ok(_) => {
                    exports_fetch_ticket.update(|t| *t = t.wrapping_add(1));
                    state.update(|s| s.apply_export_removed(&export_id));
                    status_notice.set(Some(StorageNotice::ExportRemoved {
                        path: export_path.clone(),
                        peer_name: peer_name.clone(),
                    }));
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.storageExportRemovedToast",
                        &[("path", &export_path), ("peer", &peer_name)],
                        false,
                    );
                    focus.schedule(token, peer_id, StorageFocusTarget::ExportPathInput);
                }
                Err(api_err) => {
                    mutation_error.set(Some(api_err));
                }
            }
        });
    };

    let submit_create_mount = move || {
        if gate.is_busy_untracked() || !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        if !supports_storage_catalog(&peer) || peer.state == "down" {
            return;
        }
        let snapshot = state.get_untracked();
        let req = match build_create_mount_request(
            snapshot.selected_remote_export(),
            snapshot.mount_writable,
            &snapshot.mounts,
        ) {
            Ok(req) => req,
            Err(key) => {
                status_notice.set(None);
                mutation_error.set(Some(PeerApiError::client(tt_with(
                    context,
                    key,
                    &[("peer", &peer.name)],
                ))));
                return;
            }
        };
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                mutation_error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        let peer_id = peer.id.clone();
        let peer_name = peer.name.clone();
        let path = peer_mounts_path(&peer.id);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(Some(StorageAction::CreateMount));
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result =
                peer_api_request::<CreatePeerMountResponse>(&path, "POST", Some(&body)).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            active_action.set(None);
            busy_guard.release();
            match result {
                Ok(resp) => {
                    let mounted_remote = resp.mount.remote_path.clone();
                    mounts_fetch_ticket.update(|t| *t = t.wrapping_add(1));
                    state.update(|s| s.apply_mount_created(resp.mount));
                    mounts_load_state.set(SectionLoadState::Ready);
                    mounts_load_error.set(None);
                    status_notice.set(Some(StorageNotice::MountCreated {
                        path: mounted_remote.clone(),
                        peer_name: peer_name.clone(),
                    }));
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.storageMountCreatedToast",
                        &[("path", &mounted_remote), ("peer", &peer_name)],
                        false,
                    );
                    focus.schedule(token, peer_id, StorageFocusTarget::MountSubmit);
                }
                Err(api_err) => {
                    mutation_error.set(Some(api_err));
                    focus.schedule(token, peer_id, StorageFocusTarget::MountSubmit);
                }
            }
        });
    };

    let confirm_remove_mount = move |mount_id: String, remote_path: String| {
        if gate.is_busy_untracked() || !context.is_admin_untracked() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let req = DeletePeerMountRequest {
            mount_id: mount_id.clone(),
        };
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                mutation_error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        let peer_id = peer.id.clone();
        let peer_name = peer.name.clone();
        let path = peer_mounts_path(&peer.id);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(Some(StorageAction::RemoveMount(mount_id.clone())));
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<Value>(&path, "DELETE", Some(&body)).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            active_action.set(None);
            busy_guard.release();
            match result {
                Ok(_) => {
                    mounts_fetch_ticket.update(|t| *t = t.wrapping_add(1));
                    state.update(|s| s.apply_mount_removed(&mount_id));
                    status_notice.set(Some(StorageNotice::MountRemoved {
                        path: remote_path.clone(),
                        peer_name: peer_name.clone(),
                    }));
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.storageMountRemovedToast",
                        &[("path", &remote_path)],
                        false,
                    );
                }
                Err(api_err) => {
                    mutation_error.set(Some(api_err));
                }
            }
        });
    };

    let modal_title = Signal::derive(move || {
        let name = target.with(|peer| peer.as_ref().map(|p| p.name.clone()).unwrap_or_default());
        tt_with(context, "Cluster.storageModalTitle", &[("peer", &name)])
    });
    let peer_name_memo = Memo::new(move |_| {
        target.with(|peer| peer.as_ref().map(|p| p.name.clone()).unwrap_or_default())
    });
    let peer_tunnel_ip_memo = Memo::new(move |_| {
        target.with(|peer| {
            peer.as_ref()
                .map(|p| p.tunnel_ip.clone())
                .unwrap_or_default()
        })
    });
    let peer_state_memo = Memo::new(move |_| {
        target.with(|peer| peer.as_ref().map(|p| p.state.clone()).unwrap_or_default())
    });
    let peer_is_down = Memo::new(move |_| peer_state_memo.get() == "down");
    let storage_supported =
        Memo::new(move |_| target.with(|peer| peer.as_ref().is_some_and(supports_storage_catalog)));
    let exports_list = Memo::new(move |_| state.with(|s| s.exports.clone()));
    let confirm_export_id = Memo::new(move |_| state.with(|s| s.confirm_remove_export_id.clone()));
    let mounts_list = Memo::new(move |_| state.with(|s| s.mounts.clone()));
    let confirm_mount_id = Memo::new(move |_| state.with(|s| s.confirm_remove_mount_id.clone()));
    let available_exports_list = Memo::new(move |_| state.with(|s| s.available_exports.clone()));
    let has_available_exports = Memo::new(move |_| state.with(|s| !s.available_exports.is_empty()));
    let selected_export_id_memo = Memo::new(move |_| state.with(|s| s.selected_export_id.clone()));
    let has_selected_export =
        Memo::new(move |_| state.with(|s| s.selected_remote_export().is_some()));
    let selected_already_mounted = Memo::new(move |_| {
        state.with(|s| {
            s.selected_remote_export()
                .is_some_and(|exp| is_export_already_mounted(exp, &s.mounts))
        })
    });
    let selected_allows_write = Memo::new(move |_| {
        state.with(|s| {
            s.selected_remote_export()
                .is_some_and(|exp| exp.writable && !is_export_already_mounted(exp, &s.mounts))
        })
    });
    let mount_writable_memo = Memo::new(move |_| state.with(|s| s.mount_writable));
    let catalog_error_memo = Memo::new(move |_| state.with(|s| s.catalog_error.clone()));
    let catalog_error_signal = Signal::derive(move || catalog_error_memo.get());

    view! {
        <Modal open=open title=modal_title>
            <div node_ref=body_ref class="space-y-5">
                {move || {
                    if storage_supported.get() {
                        return None;
                    }
                    let locale = crate::tabs::l10n::locale(context);
                    let hint = target.with(|peer| {
                        peer.as_ref().and_then(|peer| compatibility_guidance(&locale, peer))
                    });
                    hint.map(|text| view! {
                        <div
                            role="status"
                            data-testid="cluster-storage-compat-warning"
                            class="af-warning-banner text-xs"
                        >
                            {text}
                        </div>
                    })
                }}

                <Show when=move || peer_is_down.get()>
                    <div
                        role="status"
                        data-testid="cluster-storage-down-warning"
                        class="af-warning-banner text-xs"
                    >
                        {move || {
                            let peer = peer_name_memo.get();
                            tt_with(context, "Cluster.storageDownWarning", &[("peer", &peer)])
                        }}
                    </div>
                </Show>

                {move || {
                    let locale = crate::tabs::l10n::locale(context);
                    let threshold = rtt_warn_ms.get();
                    target
                        .with(|peer| {
                            peer.as_ref()
                                .and_then(|p| format_high_latency_banner(&locale, p, threshold))
                        })
                        .map(|warning| {
                            view! {
                                <div
                                    role="status"
                                    data-testid="cluster-storage-latency-warning"
                                    class="af-warning-banner text-xs"
                                >
                                    {warning}
                                </div>
                            }
                        })
                }}

                <PeerErrorAlert
                    error=mutation_error
                    on_dismiss=Callback::new(move |()| mutation_error.set(None))
                />

                {move || {
                    status_notice.get().map(|notice| {
                        let text = match notice {
                            StorageNotice::ExportCreated { path, peer_name } => tt_with(
                                context,
                                "Cluster.storageExportCreatedStatus",
                                &[("path", &path), ("peer", &peer_name)],
                            ),
                            StorageNotice::ExportRemoved { path, peer_name } => tt_with(
                                context,
                                "Cluster.storageExportRemovedStatus",
                                &[("path", &path), ("peer", &peer_name)],
                            ),
                            StorageNotice::MountCreated { path, peer_name } => tt_with(
                                context,
                                "Cluster.storageMountCreatedStatus",
                                &[("path", &path), ("peer", &peer_name)],
                            ),
                            StorageNotice::MountRemoved { path, peer_name } => tt_with(
                                context,
                                "Cluster.storageMountRemovedStatus",
                                &[("path", &path), ("peer", &peer_name)],
                            ),
                        };
                        view! {
                            <div
                                role="status"
                                class="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200 break-words"
                            >
                                {text}
                            </div>
                        }
                    })
                }}

                // ── Section 1: Local exports (this server -> peer) ──────────────────────
                <section
                    aria-labelledby="cluster-storage-exports-heading"
                    class="af-surface-inset border-indigo-500/30 p-4 space-y-4"
                >
                    <div class="space-y-1">
                        <h3
                            id="cluster-storage-exports-heading"
                            class="text-base font-semibold text-slate-200 break-words"
                        >
                            {move || {
                                let peer = peer_name_memo.get();
                                tt_with(context, "Cluster.storageExportsHeading", &[("peer", &peer)])
                            }}
                        </h3>
                        <p class="text-xs text-slate-400 break-words">
                            {move || {
                                let peer = peer_name_memo.get();
                                let tunnel_ip = peer_tunnel_ip_memo.get();
                                tt_with(
                                    context,
                                    "Cluster.storageExportsDescription",
                                    &[("peer", &peer), ("tunnel_ip", &tunnel_ip)],
                                )
                            }}
                        </p>
                    </div>

                    <Show when=move || exports_load_state.get() == SectionLoadState::Loading>
                        <p role="status" class="text-xs text-slate-400">
                            {move || tt(context, "Cluster.storageExportsLoading")}
                        </p>
                    </Show>

                    <Show when=move || exports_load_state.get() == SectionLoadState::Failed>
                        <div class="space-y-2">
                            <PeerErrorAlert error=exports_load_error />
                            <button
                                id="cluster-storage-exports-retry"
                                type="button"
                                class="af-btn px-3 py-1.5 text-xs"
                                on:click=move |_| retry_exports()
                            >
                                {move || tt(context, "Common.retry")}
                            </button>
                        </div>
                    </Show>

                    {move || {
                        let exports = exports_list.get();
                        let pending_confirm = confirm_export_id.get();
                        let peer_name = peer_name_memo.get();
                        if exports.is_empty() {
                            if exports_load_state.get() == SectionLoadState::Ready {
                                Some(view! {
                                    <p class="text-sm text-slate-400 break-words">
                                        {tt_with(
                                            context,
                                            "Cluster.storageExportsEmpty",
                                            &[("peer", &peer_name)],
                                        )}
                                    </p>
                                }.into_any())
                            } else {
                                None
                            }
                        } else {
                            Some(view! {
                                <ul
                                    data-testid="cluster-storage-exports-list"
                                    class="space-y-2.5"
                                >
                                    {exports
                                        .into_iter()
                                        .map(|export| {
                                            let exp_id = export.id.clone();
                                            let exp_path = export.path.clone();
                                            let exp_path_for_aria = exp_path.clone();
                                            let exp_path_for_prompt = exp_path.clone();
                                            let exp_path_for_remove = exp_path.clone();
                                            let exp_id_for_open = exp_id.clone();
                                            let exp_id_for_keep = exp_id.clone();
                                            let exp_id_for_confirm = exp_id.clone();
                                            let exp_id_for_busy = exp_id.clone();
                                            let safe_id = dom_safe_id(&exp_id);
                                            let confirming =
                                                pending_confirm.as_deref() == Some(exp_id.as_str());
                                            let peer_name_row = peer_name.clone();
                                            let peer_name_prompt = peer_name.clone();
                                            let mode_key = if export.writable {
                                                "Cluster.storageExportModeReadWrite"
                                            } else {
                                                "Cluster.storageExportModeReadOnly"
                                            };
                                            let mode_tone = if export.writable { "warning" } else { "indigo" };
                                            let squash_info = match (export.squash_uid, export.squash_gid) {
                                                (Some(uid), Some(gid)) => Some((uid.to_string(), gid.to_string())),
                                                _ => None,
                                            };
                                            let created_at = export.created_at.trim().to_string();

                                            view! {
                                                <li class="af-surface-inset p-3 space-y-2">
                                                    <div class="flex flex-wrap items-start justify-between gap-2">
                                                        <div class="space-y-1 min-w-0">
                                                            <div class="flex flex-wrap items-center gap-2">
                                                                <code class="text-sm font-mono text-slate-100 break-all">
                                                                    {exp_path}
                                                                </code>
                                                                <Badge label=mode_key tone=mode_tone />
                                                            </div>
                                                            {squash_info.map(|(uid, gid)| {
                                                                view! {
                                                                    <p class="text-xs text-slate-400 font-mono">
                                                                        {move || tt_with(
                                                                            context,
                                                                            "Cluster.storageExportOwnerMapping",
                                                                            &[("uid", &uid), ("gid", &gid)],
                                                                        )}
                                                                    </p>
                                                                }
                                                            })}
                                                            {(!created_at.is_empty()).then(|| {
                                                                view! {
                                                                    <p class="text-xs text-slate-500 font-mono">
                                                                        {move || tt_with(
                                                                            context,
                                                                            "Cluster.storageExportCreatedAt",
                                                                            &[("created_at", &created_at)],
                                                                        )}
                                                                    </p>
                                                                }
                                                            })}
                                                        </div>
                                                        {if confirming {
                                                            view! {
                                                                <div class="space-y-2 text-right">
                                                                    <p class="text-xs font-medium text-rose-300 break-words">
                                                                        {move || tt_with(
                                                                            context,
                                                                            "Cluster.storageExportRemoveConfirmPrompt",
                                                                            &[("path", &exp_path_for_prompt), ("peer", &peer_name_prompt)],
                                                                        )}
                                                                    </p>
                                                                    <div class="flex flex-wrap justify-end gap-2">
                                                                        <button
                                                                            id=format!("cluster-storage-export-keep-{safe_id}")
                                                                            type="button"
                                                                            class="af-btn px-2.5 py-1 text-xs"
                                                                            disabled=move || gate.is_busy()
                                                                            on:click=move |_| {
                                                                                state.update(|s| s.confirm_remove_export_id = None);
                                                                                if let Some(peer) = target.get_untracked() {
                                                                                    let token = gate.current_token(context.session_epoch);
                                                                                    focus.schedule(
                                                                                        token,
                                                                                        peer.id,
                                                                                        StorageFocusTarget::ExportRemoveOpen(exp_id_for_keep.clone()),
                                                                                    );
                                                                                }
                                                                            }
                                                                        >
                                                                            {move || tt(context, "Cluster.storageExportRemoveKeepAction")}
                                                                        </button>
                                                                        <button
                                                                            id=format!("cluster-storage-export-confirm-{safe_id}")
                                                                            type="button"
                                                                            class="af-btn px-2.5 py-1 text-xs"
                                                                            data-tone="danger"
                                                                            disabled=move || gate.is_busy()
                                                                            on:click=move |_| {
                                                                                confirm_remove_export(
                                                                                    exp_id_for_confirm.clone(),
                                                                                    exp_path_for_remove.clone(),
                                                                                );
                                                                            }
                                                                        >
                                                                            {move || {
                                                                                if active_action.get()
                                                                                    == Some(StorageAction::RemoveExport(exp_id_for_busy.clone()))
                                                                                {
                                                                                    tt(context, "Cluster.storageExportRemoving")
                                                                                } else {
                                                                                    tt(context, "Cluster.storageExportRemoveConfirmAction")
                                                                                }
                                                                            }}
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                            }.into_any()
                                                        } else {
                                                            view! {
                                                                <button
                                                                    id=format!("cluster-storage-export-remove-{safe_id}")
                                                                    type="button"
                                                                    class="af-btn px-2.5 py-1 text-xs shrink-0"
                                                                    data-tone="danger"
                                                                    disabled=move || gate.is_busy()
                                                                    aria-label=move || tt_with(
                                                                        context,
                                                                        "Cluster.storageExportRemoveAria",
                                                                        &[("path", &exp_path_for_aria), ("peer", &peer_name_row)],
                                                                    )
                                                                    on:click=move |_| {
                                                                        mutation_error.set(None);
                                                                        state.update(|s| {
                                                                            s.confirm_remove_export_id = Some(exp_id_for_open.clone());
                                                                            s.confirm_remove_mount_id = None;
                                                                        });
                                                                        if let Some(peer) = target.get_untracked() {
                                                                            let token = gate.current_token(context.session_epoch);
                                                                            focus.schedule(
                                                                                token,
                                                                                peer.id,
                                                                                StorageFocusTarget::ExportRemoveKeep(exp_id_for_open.clone()),
                                                                            );
                                                                        }
                                                                    }
                                                                >
                                                                    {move || tt(context, "Cluster.storageExportRemoveAction")}
                                                                </button>
                                                            }.into_any()
                                                        }}
                                                    </div>
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            }.into_any())
                        }
                    }}

                    <form
                        class="space-y-3 border-t border-[var(--af-border-hairline)] pt-3"
                        on:submit=move |event| {
                            event.prevent_default();
                            submit_create_export();
                        }
                    >
                        <div class="space-y-1.5">
                            <label
                                for="cluster-storage-export-path"
                                class="block text-xs font-medium text-slate-200"
                            >
                                {move || tt(context, "Cluster.storageExportPathLabel")}
                            </label>
                            <div class="flex flex-wrap gap-2">
                                <input
                                    id="cluster-storage-export-path"
                                    type="text"
                                    data-af-autofocus="true"
                                    autocomplete="off"
                                    aria-describedby="cluster-storage-export-path-hint"
                                    class="af-input px-3 py-2 flex-1 min-w-48 font-mono text-sm"
                                    placeholder=move || tt(context, "Cluster.storageExportPathPlaceholder")
                                    disabled=move || gate.is_busy() || !storage_supported.get()
                                    prop:value=move || state.with(|s| s.export_path.clone())
                                    on:input=move |event| {
                                        mutation_error.set(None);
                                        let next = event_target_value(&event);
                                        state.update(|s| s.export_path = next);
                                    }
                                />
                                <button
                                    id="cluster-storage-browse-toggle"
                                    type="button"
                                    class="af-btn px-3 py-2 text-xs shrink-0"
                                    disabled=move || gate.is_busy() || !storage_supported.get()
                                    aria-expanded=move || browser_open.get().to_string()
                                    on:click=move |_| {
                                        let next = !browser_open.get_untracked();
                                        browser_open.set(next);
                                        if next {
                                            let start = initial_browser_path(
                                                &state.with_untracked(|s| s.export_path.clone()),
                                            );
                                            fetch_local_dir(start);
                                        }
                                    }
                                >
                                    {move || {
                                        if browser_open.get() {
                                            tt(context, "Cluster.storageHideBrowserAction")
                                        } else {
                                            tt(context, "Cluster.storageBrowseFoldersAction")
                                        }
                                    }}
                                </button>
                            </div>
                            <p id="cluster-storage-export-path-hint" class="text-xs text-slate-400">
                                {move || tt(context, "Cluster.storageExportPathHint")}
                            </p>
                        </div>

                        <Show when=move || browser_open.get()>
                            <div
                                data-testid="cluster-storage-folder-browser"
                                class="af-surface-inset p-3 space-y-3"
                            >
                                <div class="flex flex-wrap items-center justify-between gap-2">
                                    <h4 class="text-xs font-semibold text-slate-200">
                                        {move || tt(context, "Cluster.storageBrowserHeading")}
                                    </h4>
                                    <div class="flex flex-wrap items-center gap-1.5">
                                        <span class="text-xs text-slate-400">
                                            {move || tt(context, "Cluster.storageBrowserRootsLabel")}
                                        </span>
                                        {LOCAL_FS_QUICK_ROOTS
                                            .into_iter()
                                            .map(|root| {
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="af-btn px-2 py-1 text-xs font-mono"
                                                        disabled=move || browser_loading.get()
                                                        on:click=move |_| fetch_local_dir(root.to_string())
                                                    >
                                                        {root}
                                                    </button>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                </div>

                                {move || {
                                    browser_listing.get().map(|listing| {
                                        let current = listing.current_path.clone();
                                        let current_for_use = current.clone();
                                        let parent = listing.parent_path.clone();
                                        let has_parent = parent.is_some();
                                        view! {
                                            <div class="flex flex-wrap items-center justify-between gap-2">
                                                <p class="text-xs font-mono text-slate-300 break-all">
                                                    {tt_with(
                                                        context,
                                                        "Cluster.storageBrowserCurrentPath",
                                                        &[("path", &current)],
                                                    )}
                                                </p>
                                                <div class="flex flex-wrap gap-2 shrink-0">
                                                    <button
                                                        id="cluster-storage-browser-up"
                                                        type="button"
                                                        class="af-btn px-2.5 py-1 text-xs"
                                                        disabled=move || {
                                                            browser_loading.get() || !has_parent
                                                        }
                                                        on:click=move |_| {
                                                            if let Some(p) = parent.clone() {
                                                                fetch_local_dir(p);
                                                            }
                                                        }
                                                    >
                                                        {move || tt(context, "Cluster.storageBrowserUpAction")}
                                                    </button>
                                                    <button
                                                        id="cluster-storage-browser-use"
                                                        type="button"
                                                        class="af-btn-primary px-2.5 py-1 text-xs"
                                                        disabled=move || browser_loading.get()
                                                        on:click=move |_| {
                                                            mutation_error.set(None);
                                                            state.update(|s| {
                                                                s.export_path = current_for_use.clone();
                                                            });
                                                            browser_open.set(false);
                                                        }
                                                    >
                                                        {move || tt(context, "Cluster.storageBrowserUseFolderAction")}
                                                    </button>
                                                </div>
                                            </div>
                                        }
                                    })
                                }}

                                <Show when=move || browser_loading.get()>
                                    <p role="status" class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.storageBrowserLoading")}
                                    </p>
                                </Show>

                                <PeerErrorAlert error=browser_error />

                                <Show when=move || !browser_loading.get() && browser_error.with(Option::is_none)>
                                    {move || {
                                        let listing = browser_listing.get()?;
                                        if listing.directories.is_empty() {
                                            return Some(view! {
                                                <p class="text-xs text-slate-400">
                                                    {move || tt(context, "Cluster.storageBrowserEmpty")}
                                                </p>
                                            }.into_any());
                                        }
                                        let base = listing.current_path.clone();
                                        Some(view! {
                                            <div class="max-h-44 overflow-auto space-y-1">
                                                {listing
                                                    .directories
                                                    .into_iter()
                                                    .map(|name| {
                                                        let label = name.clone();
                                                        let base_for_click = base.clone();
                                                        view! {
                                                            <button
                                                                type="button"
                                                                class="block w-full text-left af-btn px-2.5 py-1.5 text-xs font-mono break-all"
                                                                on:click=move |_| {
                                                                    match join_local_child_dir(&base_for_click, &name) {
                                                                        Ok(child) => fetch_local_dir(child),
                                                                        Err(key) => {
                                                                            browser_error.set(Some(PeerApiError::client(tt(context, key))));
                                                                        }
                                                                    }
                                                                }
                                                            >
                                                                {label}
                                                            </button>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </div>
                                        }.into_any())
                                    }}
                                </Show>
                            </div>
                        </Show>

                        <div class="space-y-2">
                            <label
                                for="cluster-storage-export-writable"
                                class="flex items-start gap-2.5 text-xs text-slate-200 cursor-pointer"
                            >
                                <input
                                    id="cluster-storage-export-writable"
                                    type="checkbox"
                                    class="obs-checkbox mt-0.5"
                                    disabled=move || gate.is_busy() || !storage_supported.get()
                                    prop:checked=move || state.with(|s| s.export_writable)
                                    on:change=move |event| {
                                        let checked = event_target_checked(&event);
                                        state.update(|s| s.export_writable = checked);
                                    }
                                />
                                <span>
                                    {move || {
                                        let peer = peer_name_memo.get();
                                        tt_with(
                                            context,
                                            "Cluster.storageExportWritableLabel",
                                            &[("peer", &peer)],
                                        )
                                    }}
                                </span>
                            </label>

                            <Show
                                when=move || state.with(|s| s.export_writable)
                                fallback=move || {
                                    view! {
                                        <p class="text-xs text-slate-400">
                                            {move || {
                                                let peer = peer_name_memo.get();
                                                tt_with(
                                                    context,
                                                    "Cluster.storageExportReadOnlyDefaultNote",
                                                    &[("peer", &peer)],
                                                )
                                            }}
                                        </p>
                                    }
                                }
                            >
                                <div
                                    role="alert"
                                    data-testid="cluster-export-write-warning"
                                    class="af-warning-banner text-xs break-words"
                                >
                                    {move || {
                                        let peer = peer_name_memo.get();
                                        let tunnel_ip = peer_tunnel_ip_memo.get();
                                        tt_with(
                                            context,
                                            "Cluster.storageExportWriteWarning",
                                            &[("peer", &peer), ("tunnel_ip", &tunnel_ip)],
                                        )
                                    }}
                                </div>
                            </Show>
                        </div>

                        <div class="flex flex-wrap justify-end">
                            <button
                                id="cluster-storage-export-submit"
                                type="submit"
                                class="af-btn-primary px-4 py-2 text-sm"
                                disabled=move || gate.is_busy() || !storage_supported.get()
                            >
                                {move || {
                                    if active_action.get() == Some(StorageAction::CreateExport) {
                                        tt(context, "Cluster.storageExportSubmitting")
                                    } else {
                                        tt(context, "Cluster.storageExportSubmitAction")
                                    }
                                }}
                            </button>
                        </div>
                    </form>
                </section>

                // ── Section 2: Local mounts & remote export catalog (peer -> this server) ──
                <section
                    aria-labelledby="cluster-storage-mounts-heading"
                    class="af-surface-inset p-4 space-y-4"
                >
                    <div class="space-y-1">
                        <h3
                            id="cluster-storage-mounts-heading"
                            class="text-base font-semibold text-slate-200 break-words"
                        >
                            {move || {
                                let peer = peer_name_memo.get();
                                tt_with(context, "Cluster.storageMountsHeading", &[("peer", &peer)])
                            }}
                        </h3>
                        <p class="text-xs text-slate-400 break-words">
                            {move || tt(context, "Cluster.storageMountsDescription")}
                        </p>
                    </div>

                    <div
                        data-testid="cluster-storage-media-safety"
                        class="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-3 space-y-1.5 text-xs text-slate-200"
                    >
                        <p class="font-semibold text-cyan-200">
                            {move || tt(context, "Cluster.storageMediaSafetyHeading")}
                        </p>
                        <ul class="list-disc pl-5 space-y-1 text-slate-300">
                            <li>{move || tt(context, "Cluster.storageMediaSafetyInteriorRule")}</li>
                            <li>{move || tt(context, "Cluster.storageMediaSafetyJellyfin")}</li>
                            <li>{move || tt(context, "Cluster.storageMediaSafetyPlex")}</li>
                            <li>{move || tt(context, "Cluster.storageMediaSafetyEmbyArr")}</li>
                        </ul>
                    </div>

                    <Show when=move || mounts_load_state.get() == SectionLoadState::Loading>
                        <p role="status" class="text-xs text-slate-400">
                            {move || tt(context, "Cluster.storageMountsLoading")}
                        </p>
                    </Show>

                    <Show when=move || mounts_load_state.get() == SectionLoadState::Failed>
                        <div class="space-y-2">
                            <PeerErrorAlert error=mounts_load_error />
                            <button
                                id="cluster-storage-mounts-retry"
                                type="button"
                                class="af-btn px-3 py-1.5 text-xs"
                                on:click=move |_| retry_mounts()
                            >
                                {move || tt(context, "Common.retry")}
                            </button>
                        </div>
                    </Show>

                    // Stored local mounts (always visible and removable even when remote catalog fails).
                    {move || {
                        let mounts = mounts_list.get();
                        let pending_confirm = confirm_mount_id.get();
                        let peer_name = peer_name_memo.get();
                        let peer_state = peer_state_memo.get();
                        if mounts.is_empty() {
                            if mounts_load_state.get() == SectionLoadState::Ready {
                                Some(view! {
                                    <p class="text-sm text-slate-400 break-words">
                                        {tt_with(
                                            context,
                                            "Cluster.storageMountsEmpty",
                                            &[("peer", &peer_name)],
                                        )}
                                    </p>
                                }.into_any())
                            } else {
                                None
                            }
                        } else {
                            Some(view! {
                                <ul
                                    data-testid="cluster-storage-mounts-list"
                                    class="space-y-3"
                                >
                                    {mounts
                                        .into_iter()
                                        .map(|mount| {
                                            let mount_id = mount.id.clone();
                                            let remote_path = mount.remote_path.clone();
                                            let remote_for_copy_aria = remote_path.clone();
                                            let remote_for_remove_aria = remote_path.clone();
                                            let remote_for_prompt = remote_path.clone();
                                            let remote_for_confirm = remote_path.clone();
                                            let mount_id_for_open = mount_id.clone();
                                            let mount_id_for_keep = mount_id.clone();
                                            let mount_id_for_confirm = mount_id.clone();
                                            let mount_id_for_busy = mount_id.clone();
                                            let safe_id = dom_safe_id(&mount_id);
                                            let confirming =
                                                pending_confirm.as_deref() == Some(mount_id.as_str());
                                            let peer_name_aria = peer_name.clone();
                                            let peer_name_prompt = peer_name.clone();
                                            let (state_key, state_tone) =
                                                mount_state_presentation(&mount.state, &peer_state);
                                            let state_hint =
                                                mount_state_hint_key(&mount.state, &peer_state);
                                            let mode_key = if mount.writable {
                                                "Cluster.storageExportModeReadWrite"
                                            } else {
                                                "Cluster.storageExportModeReadOnly"
                                            };
                                            let mode_tone = if mount.writable { "warning" } else { "indigo" };
                                            let purpose_key = mount_purpose_label_key(&mount.purpose);
                                            let library_path = app_library_hint_path(&mount.mount_path);
                                            let last_error = mount
                                                .last_error
                                                .clone()
                                                .filter(|msg| !msg.trim().is_empty());

                                            view! {
                                                <li class="af-surface-inset p-3 space-y-2.5">
                                                    <div class="flex flex-wrap items-start justify-between gap-2">
                                                        <div class="space-y-1 min-w-0">
                                                            <p class="text-xs text-slate-400">
                                                                {move || tt(context, "Cluster.storageMountRemotePathLabel")}
                                                            </p>
                                                            <div class="flex flex-wrap items-center gap-2">
                                                                <code class="text-sm font-mono text-slate-100 break-all">
                                                                    {remote_path}
                                                                </code>
                                                                <Badge label=state_key tone=state_tone />
                                                                <Badge label=mode_key tone=mode_tone />
                                                                {purpose_key.map(|p_key| {
                                                                    view! { <Badge label=p_key tone="muted" /> }
                                                                })}
                                                            </div>
                                                        </div>
                                                        {if confirming {
                                                            view! {
                                                                <div class="space-y-2 text-right">
                                                                    <p class="text-xs font-medium text-rose-300 break-words">
                                                                        {move || tt_with(
                                                                            context,
                                                                            "Cluster.storageMountRemoveConfirmPrompt",
                                                                            &[("path", &remote_for_prompt), ("peer", &peer_name_prompt)],
                                                                        )}
                                                                    </p>
                                                                    <div class="flex flex-wrap justify-end gap-2">
                                                                        <button
                                                                            id=format!("cluster-storage-mount-keep-{safe_id}")
                                                                            type="button"
                                                                            class="af-btn px-2.5 py-1 text-xs"
                                                                            disabled=move || gate.is_busy()
                                                                            on:click=move |_| {
                                                                                state.update(|s| s.confirm_remove_mount_id = None);
                                                                                if let Some(peer) = target.get_untracked() {
                                                                                    let token = gate.current_token(context.session_epoch);
                                                                                    focus.schedule(
                                                                                        token,
                                                                                        peer.id,
                                                                                        StorageFocusTarget::MountRemoveOpen(mount_id_for_keep.clone()),
                                                                                    );
                                                                                }
                                                                            }
                                                                        >
                                                                            {move || tt(context, "Cluster.storageMountRemoveKeepAction")}
                                                                        </button>
                                                                        <button
                                                                            id=format!("cluster-storage-mount-confirm-{safe_id}")
                                                                            type="button"
                                                                            class="af-btn px-2.5 py-1 text-xs"
                                                                            data-tone="danger"
                                                                            disabled=move || gate.is_busy()
                                                                            on:click=move |_| {
                                                                                confirm_remove_mount(
                                                                                    mount_id_for_confirm.clone(),
                                                                                    remote_for_confirm.clone(),
                                                                                );
                                                                            }
                                                                        >
                                                                            {move || {
                                                                                if active_action.get()
                                                                                    == Some(StorageAction::RemoveMount(mount_id_for_busy.clone()))
                                                                                {
                                                                                    tt(context, "Cluster.storageMountRemoving")
                                                                                } else {
                                                                                    tt(context, "Cluster.storageMountRemoveConfirmAction")
                                                                                }
                                                                            }}
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                            }.into_any()
                                                        } else {
                                                            view! {
                                                                <button
                                                                    id=format!("cluster-storage-mount-remove-{safe_id}")
                                                                    type="button"
                                                                    class="af-btn px-2.5 py-1 text-xs shrink-0"
                                                                    data-tone="danger"
                                                                    disabled=move || gate.is_busy()
                                                                    aria-label=move || tt_with(
                                                                        context,
                                                                        "Cluster.storageMountRemoveAria",
                                                                        &[("path", &remote_for_remove_aria), ("peer", &peer_name_aria)],
                                                                    )
                                                                    on:click=move |_| {
                                                                        mutation_error.set(None);
                                                                        state.update(|s| {
                                                                            s.confirm_remove_mount_id = Some(mount_id_for_open.clone());
                                                                            s.confirm_remove_export_id = None;
                                                                        });
                                                                        if let Some(peer) = target.get_untracked() {
                                                                            let token = gate.current_token(context.session_epoch);
                                                                            focus.schedule(
                                                                                token,
                                                                                peer.id,
                                                                                StorageFocusTarget::MountRemoveKeep(mount_id_for_open.clone()),
                                                                            );
                                                                        }
                                                                    }
                                                                >
                                                                    {move || tt(context, "Cluster.storageMountRemoveAction")}
                                                                </button>
                                                            }.into_any()
                                                        }}
                                                    </div>

                                                    {state_hint.map(|hint_key| {
                                                        view! {
                                                            <p class="text-xs text-slate-400 break-words">
                                                                {move || tt(context, hint_key)}
                                                            </p>
                                                        }
                                                    })}

                                                    <div class="af-surface-inset p-2.5 space-y-1.5">
                                                        <div class="flex flex-wrap items-center justify-between gap-2">
                                                            <span class="text-xs font-medium text-slate-300">
                                                                {move || tt(context, "Cluster.storageMountLibraryPathLabel")}
                                                            </span>
                                                            {library_path.clone().map(|copy_value| {
                                                                view! {
                                                                    <button
                                                                        type="button"
                                                                        class="af-btn px-2.5 py-1 text-xs shrink-0"
                                                                        aria-label=move || tt_with(
                                                                            context,
                                                                            "Cluster.storageCopyLibraryPathAria",
                                                                            &[("path", &remote_for_copy_aria)],
                                                                        )
                                                                        on:click=move |_| {
                                                                            copy_text_to_clipboard(context, copy_value.clone());
                                                                        }
                                                                    >
                                                                        {move || tt(context, "Cluster.storageCopyLibraryPathAction")}
                                                                    </button>
                                                                }
                                                            })}
                                                        </div>
                                                        {match library_path {
                                                            Some(lib_path) => view! {
                                                                <code
                                                                    data-testid="storage-mount-library-path"
                                                                    class="block text-xs font-mono text-cyan-200 break-all"
                                                                >
                                                                    {lib_path}
                                                                </code>
                                                                <p class="text-xs text-slate-400">
                                                                    {move || tt(context, "Cluster.storageMountLibraryPathHint")}
                                                                </p>
                                                            }.into_any(),
                                                            None => view! {
                                                                <p class="text-xs text-slate-400">
                                                                    {move || tt(context, "Cluster.storageMountLibraryPathUnavailable")}
                                                                </p>
                                                            }.into_any(),
                                                        }}
                                                    </div>

                                                    {last_error.map(|err_msg| {
                                                        view! {
                                                            <p role="status" class="af-danger-banner text-xs break-words">
                                                                <span class="font-semibold">
                                                                    {move || tt(context, "Cluster.lastErrorLabel")}
                                                                </span>
                                                                ": "
                                                                {err_msg}
                                                            </p>
                                                        }
                                                    })}
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            }.into_any())
                        }
                    }}

                    // Remote export catalog & new mount creation form.
                    <div class="border-t border-[var(--af-border-hairline)] pt-3 space-y-3">
                        <div class="space-y-1">
                            <h4 class="text-sm font-semibold text-slate-200 break-words">
                                {move || {
                                    let peer = peer_name_memo.get();
                                    tt_with(context, "Cluster.storageAvailableHeading", &[("peer", &peer)])
                                }}
                            </h4>
                            <p class="text-xs text-slate-400 break-words">
                                {move || {
                                    let peer = peer_name_memo.get();
                                    tt_with(context, "Cluster.storageAvailableDescription", &[("peer", &peer)])
                                }}
                            </p>
                        </div>

                        <Show when=move || catalog_error_signal.with(Option::is_some)>
                            <div
                                data-testid="cluster-storage-catalog-error"
                                class="space-y-2.5"
                            >
                                <p class="text-xs text-slate-300">
                                    {move || tt(context, "Cluster.storageAvailableUnavailableNote")}
                                </p>
                                <PeerErrorAlert error=catalog_error_signal />
                                <div>
                                    <button
                                        id="cluster-storage-retry-catalog"
                                        type="button"
                                        class="af-btn px-3 py-1.5 text-xs"
                                        disabled=move || {
                                            gate.is_busy()
                                                || mounts_load_state.get() == SectionLoadState::Loading
                                        }
                                        on:click=move |_| retry_mounts()
                                    >
                                        {move || tt(context, "Cluster.storageRetryCatalogAction")}
                                    </button>
                                </div>
                            </div>
                        </Show>

                        <Show when=move || {
                            mounts_load_state.get() == SectionLoadState::Ready
                                && catalog_error_memo.with(Option::is_none)
                        }>
                            <Show
                                when=move || has_available_exports.get()
                                fallback=move || {
                                    view! {
                                        <p class="text-sm text-slate-400 break-words">
                                            {move || {
                                                let peer_name = peer_name_memo.get();
                                                tt_with(
                                                    context,
                                                    "Cluster.storageAvailableEmpty",
                                                    &[("peer", &peer_name)],
                                                )
                                            }}
                                        </p>
                                    }
                                }
                            >
                                <form
                                    class="space-y-3"
                                    on:submit=move |event| {
                                        event.prevent_default();
                                        submit_create_mount();
                                    }
                                >
                                    <div class="space-y-1.5">
                                        <label
                                            for="cluster-storage-mount-export"
                                            class="block text-xs font-medium text-slate-200"
                                        >
                                            {move || tt(context, "Cluster.storageAvailableSelectLabel")}
                                        </label>
                                        <select
                                            id="cluster-storage-mount-export"
                                            class="af-input px-3 py-2 w-full text-sm font-mono"
                                            disabled=move || {
                                                gate.is_busy()
                                                    || !storage_supported.get()
                                                    || peer_is_down.get()
                                            }
                                            prop:value=move || selected_export_id_memo.get()
                                            on:change=move |event| {
                                                mutation_error.set(None);
                                                let next_id = event_target_value(&event);
                                                state.update(|s| s.select_remote_export(next_id));
                                            }
                                        >
                                            {move || {
                                                let locale = crate::tabs::l10n::locale(context);
                                                let available = available_exports_list.get();
                                                let mounts = mounts_list.get();
                                                available
                                                    .into_iter()
                                                    .map(|exp| {
                                                        let mounted = is_export_already_mounted(&exp, &mounts);
                                                        let opt_key = if mounted {
                                                            "Cluster.storageAvailableOptionMounted"
                                                        } else if exp.writable {
                                                            "Cluster.storageAvailableOptionReadWrite"
                                                        } else {
                                                            "Cluster.storageAvailableOptionReadOnly"
                                                        };
                                                        let label = translate_with(
                                                            &locale,
                                                            opt_key,
                                                            &[("path", &exp.path)],
                                                        );
                                                        view! {
                                                            <option value=exp.id>{label}</option>
                                                        }
                                                    })
                                                    .collect_view()
                                            }}
                                        </select>
                                    </div>

                                    <Show when=move || selected_already_mounted.get()>
                                        <p class="text-xs text-slate-400">
                                            {move || tt(context, "Cluster.storageAvailableAlreadyMountedNote")}
                                        </p>
                                    </Show>

                                    <div class="space-y-2">
                                        <label
                                            for="cluster-storage-mount-writable"
                                            class="flex items-start gap-2.5 text-xs text-slate-200 cursor-pointer"
                                        >
                                            <input
                                                id="cluster-storage-mount-writable"
                                                type="checkbox"
                                                class="obs-checkbox mt-0.5"
                                                disabled=move || {
                                                    gate.is_busy()
                                                        || !storage_supported.get()
                                                        || peer_is_down.get()
                                                        || !selected_allows_write.get()
                                                }
                                                prop:checked=move || {
                                                    selected_allows_write.get()
                                                        && mount_writable_memo.get()
                                                }
                                                on:change=move |event| {
                                                    let checked = event_target_checked(&event);
                                                    let allowed = selected_allows_write.get_untracked();
                                                    state.update(|s| {
                                                        s.mount_writable = checked && allowed;
                                                    });
                                                }
                                            />
                                            <span>
                                                {move || tt(context, "Cluster.storageMountWritableLabel")}
                                            </span>
                                        </label>

                                        <Show when=move || {
                                            !selected_allows_write.get()
                                                && !selected_already_mounted.get()
                                        }>
                                            <p
                                                data-testid="cluster-mount-readonly-hint"
                                                class="text-xs text-slate-400 break-words"
                                            >
                                                {move || {
                                                    let peer = peer_name_memo.get();
                                                    tt_with(
                                                        context,
                                                        "Cluster.storageMountWritableDisabledHint",
                                                        &[("peer", &peer)],
                                                    )
                                                }}
                                            </p>
                                        </Show>

                                        <Show when=move || {
                                            selected_allows_write.get() && mount_writable_memo.get()
                                        }>
                                            <div
                                                role="alert"
                                                data-testid="cluster-mount-write-warning"
                                                class="af-warning-banner text-xs break-words"
                                            >
                                                {move || {
                                                    let peer = peer_name_memo.get();
                                                    tt_with(
                                                        context,
                                                        "Cluster.storageMountWriteWarning",
                                                        &[("peer", &peer)],
                                                    )
                                                }}
                                            </div>
                                        </Show>
                                    </div>

                                    <div class="flex flex-wrap justify-end">
                                        <button
                                            id="cluster-storage-mount-submit"
                                            type="submit"
                                            class="af-btn-primary px-4 py-2 text-sm"
                                            disabled=move || {
                                                gate.is_busy()
                                                    || !storage_supported.get()
                                                    || peer_is_down.get()
                                                    || selected_already_mounted.get()
                                                    || !has_selected_export.get()
                                            }
                                        >
                                            {move || {
                                                if active_action.get()
                                                    == Some(StorageAction::CreateMount)
                                                {
                                                    tt(context, "Cluster.storageMountSubmitting")
                                                } else {
                                                    tt(context, "Cluster.storageMountSubmitAction")
                                                }
                                            }}
                                        </button>
                                    </div>
                                </form>
                            </Show>
                        </Show>
                    </div>
                </section>

                <div class="flex flex-wrap justify-between gap-3 pt-1">
                    <button
                        id="cluster-storage-refresh"
                        type="button"
                        class="af-btn px-3 py-2 text-sm"
                        disabled=move || {
                            gate.is_busy()
                                || exports_load_state.get() == SectionLoadState::Loading
                                || mounts_load_state.get() == SectionLoadState::Loading
                        }
                        on:click=move |_| refresh_all()
                    >
                        {move || tt(context, "Cluster.storageRefreshAction")}
                    </button>
                    <button
                        id="cluster-storage-close"
                        type="button"
                        class="af-btn px-4 py-2"
                        on:click=move |_| open.set(false)
                    >
                        {move || tt(context, "Cluster.storageCloseAction")}
                    </button>
                </div>
            </div>
        </Modal>
    }
}

/// Formats read-only export/mount summaries for [`super::peers::PeerDetailsDrawer`].
pub fn format_drawer_exports_summary(locale: &str, exports: &[PeerExportView]) -> String {
    if exports.is_empty() {
        return translate(locale, "Cluster.detailStorageNone");
    }
    exports
        .iter()
        .map(|exp| {
            let mode = if exp.writable {
                translate(locale, "Cluster.storageExportModeReadWrite")
            } else {
                translate(locale, "Cluster.storageExportModeReadOnly")
            };
            format!("{} ({mode})", exp.path)
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Formats read-only mount summaries for [`super::peers::PeerDetailsDrawer`], exposing ONLY
/// interior library paths (never bare mount roots).
pub fn format_drawer_mounts_summary(
    locale: &str,
    mounts: &[PeerMountView],
    peer_state: &str,
) -> String {
    if mounts.is_empty() {
        return translate(locale, "Cluster.detailStorageNone");
    }
    mounts
        .iter()
        .map(|mount| {
            let (state_key, _) = mount_state_presentation(&mount.state, peer_state);
            let state_label = translate(locale, state_key);
            match app_library_hint_path(&mount.mount_path) {
                Some(lib_path) => format!("{} → {} ({state_label})", mount.remote_path, lib_path),
                None => format!("{} ({state_label})", mount.remote_path),
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn app_library_hint_always_points_strictly_inside_mount_root() {
        assert_eq!(
            app_library_hint_path("/mnt/af-peers/media-2/movies").as_deref(),
            Some("/mnt/af-peers/media-2/movies/library")
        );
        assert_eq!(
            app_library_hint_path(" /mnt/af-peers/media-2/movies/ ").as_deref(),
            Some("/mnt/af-peers/media-2/movies/library")
        );
        assert_eq!(
            app_library_hint_path("/mnt/af-peers/media-2/movies/tv").as_deref(),
            Some("/mnt/af-peers/media-2/movies/tv/library")
        );
        // Never expose bare root, relative paths, traversal, or control characters.
        for bad in [
            "",
            "/",
            "///",
            "mnt/af-peers/media-2/movies",
            "/mnt/af-peers/../etc",
            "/mnt/af-peers\\movies",
            "/mnt/af-peers/movies\n",
        ] {
            assert_eq!(
                app_library_hint_path(bad),
                None,
                "unexpected hint for {bad:?}"
            );
        }
    }

    #[test]
    fn export_request_defaults_read_only_and_rejects_invalid_paths() {
        let ro = build_create_export_request(" /srv/media/movies/ ", false).unwrap();
        assert_eq!(
            serde_json::to_value(&ro).unwrap(),
            json!({ "path": "/srv/media/movies", "writable": false })
        );

        let rw = build_create_export_request("/srv/media/uploads", true).unwrap();
        assert_eq!(
            serde_json::to_value(&rw).unwrap(),
            json!({ "path": "/srv/media/uploads", "writable": true })
        );

        assert_eq!(
            build_create_export_request("", false).unwrap_err(),
            "Cluster.validationExportPathRequired"
        );
        assert_eq!(
            build_create_export_request("/", false).unwrap_err(),
            "Cluster.validationExportPathRequired"
        );
        assert_eq!(
            build_create_export_request("srv/media", false).unwrap_err(),
            "Cluster.validationExportPathRequired"
        );
        assert_eq!(
            build_create_export_request("/srv/../etc", false).unwrap_err(),
            "Cluster.validationExportPathInvalid"
        );
        assert_eq!(
            build_create_export_request("/srv/media\\bad", false).unwrap_err(),
            "Cluster.validationExportPathInvalid"
        );
    }

    #[test]
    fn mount_request_sends_only_export_id_and_writable_and_clamps_readonly_exports() {
        let ro_export = PeerExportView {
            id: "exp-ro".into(),
            link_id: "link-1".into(),
            path: "/srv/media/movies".into(),
            writable: false,
            squash_uid: None,
            squash_gid: None,
            created_at: "2026-11-24T00:00:00Z".into(),
        };
        let rw_export = PeerExportView {
            id: "exp-rw".into(),
            writable: true,
            path: "/srv/media/incoming".into(),
            ..ro_export.clone()
        };

        // Even if caller passes writable=true on a read-only remote export, clamp to false.
        let req_ro = build_create_mount_request(Some(&ro_export), true, &[]).unwrap();
        assert_eq!(
            serde_json::to_value(&req_ro).unwrap(),
            json!({ "export_id": "exp-ro", "writable": false })
        );

        // Writable remote export permits explicit opt-in.
        let req_rw = build_create_mount_request(Some(&rw_export), true, &[]).unwrap();
        assert_eq!(
            serde_json::to_value(&req_rw).unwrap(),
            json!({ "export_id": "exp-rw", "writable": true })
        );

        // Already mounted remote export is rejected locally.
        let existing_mount = PeerMountView {
            id: "mnt-1".into(),
            link_id: "link-1".into(),
            remote_path: "/srv/media/movies".into(),
            mount_path: "/mnt/af-peers/media-2/movies".into(),
            unit_name: "mnt-af\\x2dpeers-media\\x2d2-movies.mount".into(),
            writable: false,
            purpose: "media".into(),
            state: "mounted".into(),
            last_error: None,
        };
        assert_eq!(
            build_create_mount_request(Some(&ro_export), false, &[existing_mount]).unwrap_err(),
            "Cluster.storageAvailableAlreadyMountedNote"
        );
        assert_eq!(
            build_create_mount_request(None, false, &[]).unwrap_err(),
            "Cluster.validationMountExportRequired"
        );
    }

    #[test]
    fn degraded_mount_list_preserves_local_mounts_and_typed_exports_error() {
        let payload = json!({
            "mounts": [
                {
                    "id": "mnt-1",
                    "link_id": "link-1",
                    "remote_path": "/srv/media/movies",
                    "mount_path": "/mnt/af-peers/media-2/movies",
                    "unit_name": "mnt-af\\x2dpeers-media\\x2d2-movies.mount",
                    "writable": false,
                    "purpose": "media",
                    "state": "stopped_link_down",
                    "last_error": "WireGuard peer handshake expired"
                }
            ],
            "available_exports": [],
            "exports_error": {
                "code": "LINK_DOWN",
                "server": "media-2",
                "step": "list_remote_exports",
                "message": "Peer tunnel is unreachable",
                "action": "Confirm UDP 51821 connectivity and retry"
            }
        });
        let resp: PeerMountListResponse = serde_json::from_value(payload.clone()).unwrap();
        let mut modal = StorageModalState::default();
        modal.apply_mounts_loaded(resp);

        assert_eq!(modal.mounts.len(), 1);
        assert_eq!(modal.mounts[0].id, "mnt-1");
        assert!(modal.available_exports.is_empty());
        let err = modal.catalog_error.as_ref().expect("typed exports_error");
        assert_eq!(err.code(), Some("LINK_DOWN"));
        assert_eq!(err.server(), Some("media-2"));
        assert_eq!(err.step(), Some("list_remote_exports"));
        assert_eq!(err.message(), "Peer tunnel is unreachable");
        assert_eq!(
            err.action(),
            Some("Confirm UDP 51821 connectivity and retry")
        );
        assert_eq!(err.request_id(), None);

        // Header fallback populates catalog_error.request_id when exports_error omits it.
        let resp_no_rid: PeerMountListResponse = serde_json::from_value(payload.clone()).unwrap();
        modal.apply_mounts_loaded_with_request_id(resp_no_rid, Some("req-hdr-mounts-1"));
        assert_eq!(
            modal
                .catalog_error
                .as_ref()
                .and_then(PeerApiError::request_id),
            Some("req-hdr-mounts-1")
        );

        // Control-only envelope request_id falls back cleanly to the sanitized header ID.
        let mut control_only = payload.clone();
        control_only["exports_error"]["request_id"] = json!("\u{0000}\u{0007}");
        let resp_control: PeerMountListResponse = serde_json::from_value(control_only).unwrap();
        modal.apply_mounts_loaded_with_request_id(resp_control, Some("  req-hdr-clean-3  "));
        assert_eq!(
            modal
                .catalog_error
                .as_ref()
                .and_then(PeerApiError::request_id),
            Some("req-hdr-clean-3")
        );

        // Envelope request_id takes precedence over header fallback.
        let mut with_body_rid = payload;
        with_body_rid["exports_error"]["request_id"] = json!("req-env-mounts-2");
        let resp_with_rid: PeerMountListResponse = serde_json::from_value(with_body_rid).unwrap();
        modal.apply_mounts_loaded_with_request_id(resp_with_rid, Some("req-hdr-ignored"));
        assert_eq!(
            modal
                .catalog_error
                .as_ref()
                .and_then(PeerApiError::request_id),
            Some("req-env-mounts-2")
        );

        // Local mount removal works even while remote catalog listing failed.
        modal.apply_mount_removed("mnt-1");
        assert!(modal.mounts.is_empty());
    }

    #[test]
    fn modal_state_resets_write_opt_in_when_switching_remote_export_or_after_create() {
        let exp1 = PeerExportView {
            id: "exp-1".into(),
            path: "/srv/media/writable".into(),
            writable: true,
            ..Default::default()
        };
        let exp2 = PeerExportView {
            id: "exp-2".into(),
            path: "/srv/media/readonly".into(),
            writable: false,
            ..Default::default()
        };
        let mut modal = StorageModalState::default();
        modal.apply_mounts_loaded(PeerMountListResponse {
            mounts: vec![],
            available_exports: vec![exp1.clone(), exp2.clone()],
            exports_error: None,
        });
        assert_eq!(modal.selected_export_id, "exp-1");
        assert!(!modal.mount_writable);

        modal.mount_writable = true;
        modal.select_remote_export("exp-2".into());
        assert!(
            !modal.mount_writable,
            "switching remote exports must reset write opt-in"
        );

        modal.export_path = "/srv/media/tv".into();
        modal.export_writable = true;
        modal.apply_export_created(PeerExportView {
            id: "local-1".into(),
            path: "/srv/media/tv".into(),
            writable: true,
            ..Default::default()
        });
        assert!(modal.export_path.is_empty());
        assert!(!modal.export_writable);
        assert_eq!(modal.exports.len(), 1);
    }

    #[test]
    fn catalog_reselection_requires_write_opt_in_for_the_new_export() {
        let first = PeerExportView {
            id: "first".into(),
            path: "/srv/media/first".into(),
            writable: true,
            ..Default::default()
        };
        let second = PeerExportView {
            id: "second".into(),
            path: "/srv/media/second".into(),
            writable: true,
            ..Default::default()
        };
        let mut modal = StorageModalState::default();
        modal.apply_mounts_loaded(PeerMountListResponse {
            mounts: vec![],
            available_exports: vec![first, second.clone()],
            exports_error: None,
        });
        assert_eq!(modal.selected_export_id, "first");
        modal.mount_writable = true;

        modal.apply_mounts_loaded(PeerMountListResponse {
            mounts: vec![],
            available_exports: vec![second],
            exports_error: None,
        });
        assert_eq!(modal.selected_export_id, "second");
        assert!(!modal.mount_writable);
    }

    #[test]
    fn mount_state_presentation_and_high_latency_banner_cover_cuj5_and_degraded_states() {
        assert_eq!(
            mount_state_presentation("mounted", "active"),
            ("Cluster.storageMountStateMounted", "success")
        );
        assert_eq!(
            mount_state_presentation("stopped_link_down", "down"),
            ("Cluster.storageMountStateStoppedLinkDown", "danger")
        );
        assert_eq!(
            mount_state_presentation("stopped", "down"),
            ("Cluster.storageMountStateStoppedLinkDown", "danger")
        );
        assert_eq!(
            mount_state_presentation("stopped", "active"),
            ("Cluster.storageMountStateStopped", "warning")
        );
        assert_eq!(
            mount_state_presentation("stopped_sentinel", "active"),
            ("Cluster.storageMountStateStoppedSentinel", "danger")
        );
        assert_eq!(
            mount_state_presentation("error", "active"),
            ("Cluster.storageMountStateError", "danger")
        );

        let fast = PeerLinkView {
            rtt_ms: Some(4.2),
            high_latency: false,
            ..Default::default()
        };
        assert!(!is_peer_high_latency(&fast, 25.0));
        assert!(format_high_latency_banner("en", &fast, 25.0).is_none());

        let slow = PeerLinkView {
            rtt_ms: Some(42.6),
            high_latency: false,
            ..Default::default()
        };
        assert!(is_peer_high_latency(&slow, 25.0));
        let banner = format_high_latency_banner("en", &slow, 25.0).unwrap();
        assert!(banner.contains("42.6 ms"));
        assert!(banner.contains("25 ms"));
        assert!(banner.contains("NFS"));
    }

    #[test]
    fn local_fs_listing_parses_directories_and_rejects_traversal_children() {
        let listing = parse_local_fs_listing(
            "/srv/media",
            &json!({
                "current_path": "/srv/media",
                "parent_path": "/srv",
                "directories": ["tv", "movies", "..", "bad/name", "movies"]
            }),
        );
        assert_eq!(listing.current_path, "/srv/media");
        assert_eq!(listing.parent_path.as_deref(), Some("/srv"));
        assert_eq!(listing.directories, vec!["movies", "tv"]);

        assert_eq!(
            join_local_child_dir("/srv/media", "movies").unwrap(),
            "/srv/media/movies"
        );
        assert!(join_local_child_dir("/srv/media", "..").is_err());
        assert!(join_local_child_dir("/srv/media", "a/b").is_err());
        assert_eq!(initial_browser_path("/mnt/nas"), "/mnt/nas");
        assert_eq!(initial_browser_path(""), "/srv");
    }

    #[test]
    fn drawer_mounts_summary_only_exposes_interior_library_paths() {
        let mounts = vec![PeerMountView {
            id: "m-1".into(),
            remote_path: "/srv/media/movies".into(),
            mount_path: "/mnt/af-peers/media-2/movies".into(),
            state: "stopped_link_down".into(),
            ..Default::default()
        }];
        let summary = format_drawer_mounts_summary("en", &mounts, "down");
        assert!(summary.contains("/mnt/af-peers/media-2/movies/library"));
        assert!(summary.contains("Stopped: link down"));
    }
}
