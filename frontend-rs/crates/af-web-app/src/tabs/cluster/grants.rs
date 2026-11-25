//! Peer grant editor (`/?tab=cluster`, design file 36): per-area none/read/write access
//! controls, two presets, explicit directional summaries, inbound revocation, and informational
//! two-way grant offers over direct local `/api/v1/admin/peers/:id/*` routes.

use super::peers::{
    compatibility_guidance, direction_summary_for_grants, summarize_access_map,
    supports_grant_delivery, AccessLevel, AccessMapView, GrantSummaryView, LinkGrantsView,
    PeerLinkView,
};
use super::{
    peer_api_request, peer_grant_offer_path, peer_grant_path, CompletionScope, DialogGate,
    MutationToken, PeerApiError, PeerErrorAlert,
};
use crate::state::app;
use crate::tabs::l10n::{tt, tt_with, Badge, Modal};
use af_web_core::i18n::translate_with;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantArea {
    Services,
    Marketplace,
    Settings,
    Files,
    Users,
    Network,
    Updates,
    Transcoding,
}

impl GrantArea {
    pub const ALL: [Self; 8] = [
        Self::Services,
        Self::Marketplace,
        Self::Settings,
        Self::Files,
        Self::Users,
        Self::Network,
        Self::Updates,
        Self::Transcoding,
    ];

    pub const fn as_key(self) -> &'static str {
        match self {
            Self::Services => "services",
            Self::Marketplace => "marketplace",
            Self::Settings => "settings",
            Self::Files => "files",
            Self::Users => "users",
            Self::Network => "network",
            Self::Updates => "updates",
            Self::Transcoding => "transcoding",
        }
    }

    pub const fn dom_id(self) -> &'static str {
        match self {
            Self::Services => "cluster-grant-area-services",
            Self::Marketplace => "cluster-grant-area-marketplace",
            Self::Settings => "cluster-grant-area-settings",
            Self::Files => "cluster-grant-area-files",
            Self::Users => "cluster-grant-area-users",
            Self::Network => "cluster-grant-area-network",
            Self::Updates => "cluster-grant-area-updates",
            Self::Transcoding => "cluster-grant-area-transcoding",
        }
    }

    pub const fn label_key(self) -> &'static str {
        match self {
            Self::Services => "Cluster.grantAreaServices",
            Self::Marketplace => "Cluster.grantAreaMarketplace",
            Self::Settings => "Cluster.grantAreaSettings",
            Self::Files => "Cluster.grantAreaFiles",
            Self::Users => "Cluster.grantAreaUsers",
            Self::Network => "Cluster.grantAreaNetwork",
            Self::Updates => "Cluster.grantAreaUpdates",
            Self::Transcoding => "Cluster.grantAreaTranscoding",
        }
    }

    pub const fn get(self, access: &AccessMapView) -> AccessLevel {
        match self {
            Self::Services => access.services,
            Self::Marketplace => access.marketplace,
            Self::Settings => access.settings,
            Self::Files => access.files,
            Self::Users => access.users,
            Self::Network => access.network,
            Self::Updates => access.updates,
            Self::Transcoding => access.transcoding,
        }
    }

    pub fn set(self, access: &mut AccessMapView, level: AccessLevel) {
        match self {
            Self::Services => access.services = level,
            Self::Marketplace => access.marketplace = level,
            Self::Settings => access.settings = level,
            Self::Files => access.files = level,
            Self::Users => access.users = level,
            Self::Network => access.network = level,
            Self::Updates => access.updates = level,
            Self::Transcoding => access.transcoding = level,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantPreset {
    ReadOnlyAll,
    ReadWriteAll,
}

impl GrantPreset {
    pub const fn access_map(self) -> AccessMapView {
        match self {
            Self::ReadOnlyAll => AccessMapView {
                services: AccessLevel::Read,
                marketplace: AccessLevel::Read,
                settings: AccessLevel::Read,
                files: AccessLevel::Read,
                users: AccessLevel::Read,
                network: AccessLevel::Read,
                updates: AccessLevel::Read,
                transcoding: AccessLevel::Read,
            },
            Self::ReadWriteAll => AccessMapView {
                services: AccessLevel::Write,
                marketplace: AccessLevel::Write,
                settings: AccessLevel::Write,
                files: AccessLevel::Write,
                users: AccessLevel::Write,
                network: AccessLevel::Write,
                updates: AccessLevel::Write,
                transcoding: AccessLevel::Write,
            },
        }
    }
}

pub fn matching_preset(access: &AccessMapView) -> Option<GrantPreset> {
    if *access == GrantPreset::ReadOnlyAll.access_map() {
        Some(GrantPreset::ReadOnlyAll)
    } else if *access == GrantPreset::ReadWriteAll.access_map() {
        Some(GrantPreset::ReadWriteAll)
    } else {
        None
    }
}

pub const fn access_level_value(level: AccessLevel) -> &'static str {
    match level {
        AccessLevel::None => "none",
        AccessLevel::Read => "read",
        AccessLevel::Write => "write",
    }
}

pub fn parse_access_level(value: &str) -> AccessLevel {
    match value.trim() {
        "read" => AccessLevel::Read,
        "write" => AccessLevel::Write,
        _ => AccessLevel::None,
    }
}

pub const fn access_level_label_key(level: AccessLevel) -> &'static str {
    match level {
        AccessLevel::None => "Cluster.grantLevelNone",
        AccessLevel::Read => "Cluster.grantLevelRead",
        AccessLevel::Write => "Cluster.grantLevelWrite",
    }
}

pub const fn access_level_badge_tone(level: AccessLevel) -> &'static str {
    match level {
        AccessLevel::None => "muted",
        AccessLevel::Read => "indigo",
        AccessLevel::Write => "warning",
    }
}

pub fn access_has_write(access: &AccessMapView) -> bool {
    GrantArea::ALL
        .iter()
        .any(|area| area.get(access).allows_write())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveGrantRequest {
    pub access: AccessMapView,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SendGrantOfferResponse {
    pub sent: bool,
}

pub fn build_save_grant_request(
    access: &AccessMapView,
    has_existing_inbound: bool,
) -> Result<SaveGrantRequest, &'static str> {
    if !access.has_any_access() {
        return Err(if has_existing_inbound {
            "Cluster.validationGrantAreaOrRevoke"
        } else {
            "Cluster.validationGrantAreaRequired"
        });
    }
    Ok(SaveGrantRequest {
        access: access.clone(),
    })
}

pub fn format_grant_metadata(locale: &str, grant: &GrantSummaryView) -> Option<String> {
    let creator = grant.created_by.trim();
    let created_at = grant.created_at.trim();
    match (creator.is_empty(), created_at.is_empty()) {
        (false, false) => Some(translate_with(
            locale,
            "Cluster.grantMetadata",
            &[("creator", creator), ("created_at", created_at)],
        )),
        (true, false) => Some(translate_with(
            locale,
            "Cluster.grantMetadataCreatedOnly",
            &[("created_at", created_at)],
        )),
        _ => None,
    }
}

/// Pure form & loaded-grant state machine for the peer grant editor.
/// Preserves the operator's edited draft across typed backend errors and updates
/// both directions cleanly from server responses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantEditorDraft {
    pub loaded: LinkGrantsView,
    pub draft: AccessMapView,
    pub confirm_revoke: bool,
    pub offer_sent: bool,
}

impl GrantEditorDraft {
    pub fn has_inbound(&self) -> bool {
        self.loaded.inbound.is_some()
    }

    pub fn has_outbound(&self) -> bool {
        self.loaded.outbound.is_some()
    }

    pub fn apply_loaded(&mut self, view: LinkGrantsView) {
        self.draft = view
            .inbound
            .as_ref()
            .map(|grant| grant.access.clone())
            .unwrap_or_default();
        self.loaded = view;
        self.confirm_revoke = false;
    }

    pub fn apply_preset(&mut self, preset: GrantPreset) {
        self.draft = preset.access_map();
    }

    pub fn set_area(&mut self, area: GrantArea, level: AccessLevel) {
        area.set(&mut self.draft, level);
    }

    pub fn apply_save_result(&mut self, result: Result<LinkGrantsView, ()>) {
        if let Ok(view) = result {
            self.apply_loaded(view);
        }
    }

    pub fn apply_revoke_result(&mut self, result: Result<LinkGrantsView, ()>) {
        if let Ok(view) = result {
            self.apply_loaded(view);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantLoadState {
    Idle,
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantAction {
    Save,
    Revoke,
    Offer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum GrantNotice {
    Saved { peer_name: String },
    Revoked { peer_name: String },
    OfferSent { peer_name: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantFocusTarget {
    PrimaryEditor,
    RetryButton,
    SaveButton,
    RevokeOpenButton,
    RevokeKeepButton,
    RevokeConfirmButton,
    OfferButton,
}

fn grant_focus_selector(target: GrantFocusTarget) -> &'static str {
    match target {
        GrantFocusTarget::PrimaryEditor => "#cluster-grant-preset-ro:not([disabled])",
        GrantFocusTarget::RetryButton => "#cluster-grant-retry:not([disabled])",
        GrantFocusTarget::SaveButton => "#cluster-grant-save:not([disabled])",
        GrantFocusTarget::RevokeOpenButton => "#cluster-grant-revoke-open:not([disabled])",
        GrantFocusTarget::RevokeKeepButton => "#cluster-grant-revoke-keep:not([disabled])",
        GrantFocusTarget::RevokeConfirmButton => "#cluster-grant-revoke-confirm:not([disabled])",
        GrantFocusTarget::OfferButton => "#cluster-grant-offer:not([disabled])",
    }
}

#[cfg(target_arch = "wasm32")]
fn try_focus_grant_control(body: &web_sys::Element, selector: &str) -> bool {
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
struct GrantModalFocus {
    body_ref: NodeRef<leptos::html::Div>,
    timer: StoredValue<Option<gloo_timers::callback::Timeout>, LocalStorage>,
    open: RwSignal<bool>,
    target: RwSignal<Option<PeerLinkView>>,
    gate: DialogGate,
    session_epoch: RwSignal<u64>,
}

impl GrantModalFocus {
    fn clear(self) {
        self.timer.set_value(None);
    }

    #[cfg(target_arch = "wasm32")]
    fn schedule(self, token: MutationToken, peer_id: String, focus_target: GrantFocusTarget) {
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
        let selector = grant_focus_selector(focus_target);
        if let Some(body) = self.body_ref.get_untracked() {
            if try_focus_grant_control(&body, selector) {
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
                if !try_focus_grant_control(&body, selector)
                    && focus_target == GrantFocusTarget::PrimaryEditor
                {
                    // Give the primary control a chance to become enabled after rendering.
                    let _ = try_focus_grant_control(
                        &body,
                        "#cluster-grant-revoke-open:not([disabled]), #cluster-grant-close",
                    );
                }
            }
        });
        self.timer.set_value(Some(timer));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn schedule(self, token: MutationToken, peer_id: String, focus_target: GrantFocusTarget) {
        let _ = (
            self.body_ref,
            self.timer,
            self.open,
            self.target,
            self.gate,
            self.session_epoch,
            token,
            peer_id,
            grant_focus_selector(focus_target),
        );
    }
}

#[component]
pub fn GrantEditorModal(
    open: RwSignal<bool>,
    target: RwSignal<Option<PeerLinkView>>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let load_state = RwSignal::new(GrantLoadState::Idle);
    let load_error = RwSignal::new(None::<PeerApiError>);
    let mutation_error = RwSignal::new(None::<PeerApiError>);
    let status_notice = RwSignal::new(None::<GrantNotice>);
    let active_action = RwSignal::new(None::<GrantAction>);
    let draft = RwSignal::new(GrantEditorDraft::default());
    let gate = DialogGate::new();
    let body_ref = NodeRef::<leptos::html::Div>::new();
    let focus = GrantModalFocus {
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

    let start_fetch = move |peer_id: String| {
        if !context.is_admin() {
            return;
        }
        focus.clear();
        load_error.set(None);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(None);
        load_state.set(GrantLoadState::Loading);
        let path = peer_grant_path(&peer_id);
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<LinkGrantsView>(&path, "GET", None).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession | CompletionScope::StaleDialog => return,
                CompletionScope::CurrentDialog => {}
            }
            busy_guard.release();
            match result {
                Ok(view) => {
                    draft.update(|d| d.apply_loaded(view));
                    load_error.set(None);
                    load_state.set(GrantLoadState::Ready);
                    focus.schedule(token, peer_id, GrantFocusTarget::PrimaryEditor);
                }
                Err(api_err) => {
                    load_error.set(Some(api_err));
                    load_state.set(GrantLoadState::Failed);
                    focus.schedule(token, peer_id, GrantFocusTarget::RetryButton);
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
        load_error.set(None);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(None);
        draft.set(GrantEditorDraft::default());

        if let (true, Some(peer_id)) = (is_open, target_id) {
            start_fetch(peer_id);
        } else {
            load_state.set(GrantLoadState::Idle);
        }
    });

    let retry_fetch = move || {
        if gate.is_busy_untracked() || !context.is_admin() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        gate.reset();
        start_fetch(peer.id);
    };

    let submit_save = move || {
        if gate.is_busy_untracked()
            || !context.is_admin()
            || load_state.get_untracked() != GrantLoadState::Ready
        {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        if !supports_grant_delivery(&peer) {
            return;
        }
        let snapshot = draft.get_untracked();
        let req = match build_save_grant_request(&snapshot.draft, snapshot.has_inbound()) {
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
        let path = peer_grant_path(&peer.id);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(Some(GrantAction::Save));
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<LinkGrantsView>(&path, "PUT", Some(&body)).await;
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
                Ok(updated) => {
                    draft.update(|d| d.apply_save_result(Ok(updated)));
                    status_notice.set(Some(GrantNotice::Saved {
                        peer_name: peer_name.clone(),
                    }));
                    on_refresh.run(());
                    context.toast_with("Cluster.grantSavedToast", &[("peer", &peer_name)], false);
                    focus.schedule(token, peer_id, GrantFocusTarget::SaveButton);
                }
                Err(api_err) => {
                    // Preserve edited area selections so the admin can adjust and retry.
                    draft.update(|d| d.apply_save_result(Err(())));
                    mutation_error.set(Some(api_err));
                    focus.schedule(token, peer_id, GrantFocusTarget::SaveButton);
                }
            }
        });
    };

    let confirm_revoke = move || {
        if gate.is_busy_untracked()
            || !context.is_admin()
            || load_state.get_untracked() != GrantLoadState::Ready
        {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let peer_id = peer.id.clone();
        let peer_name = peer.name.clone();
        let path = peer_grant_path(&peer.id);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(Some(GrantAction::Revoke));
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<LinkGrantsView>(&path, "DELETE", None).await;
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
                Ok(updated) => {
                    draft.update(|d| d.apply_revoke_result(Ok(updated)));
                    status_notice.set(Some(GrantNotice::Revoked {
                        peer_name: peer_name.clone(),
                    }));
                    on_refresh.run(());
                    context.toast_with("Cluster.grantRevokedToast", &[("peer", &peer_name)], false);
                    focus.schedule(token, peer_id, GrantFocusTarget::PrimaryEditor);
                }
                Err(api_err) => {
                    draft.update(|d| d.apply_revoke_result(Err(())));
                    mutation_error.set(Some(api_err));
                    focus.schedule(token, peer_id, GrantFocusTarget::RevokeConfirmButton);
                }
            }
        });
    };

    let send_offer = move || {
        if gate.is_busy_untracked()
            || !context.is_admin()
            || load_state.get_untracked() != GrantLoadState::Ready
        {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        if !supports_grant_delivery(&peer) {
            return;
        }
        let peer_id = peer.id.clone();
        let peer_name = peer.name.clone();
        let path = peer_grant_offer_path(&peer.id);
        mutation_error.set(None);
        status_notice.set(None);
        active_action.set(Some(GrantAction::Offer));
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<SendGrantOfferResponse>(&path, "POST", None).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession | CompletionScope::StaleDialog => return,
                CompletionScope::CurrentDialog => {}
            }
            active_action.set(None);
            busy_guard.release();
            match result {
                Ok(resp) if resp.sent => {
                    draft.update(|d| d.offer_sent = true);
                    status_notice.set(Some(GrantNotice::OfferSent {
                        peer_name: peer_name.clone(),
                    }));
                    context.toast_with(
                        "Cluster.grantOfferSentToast",
                        &[("peer", &peer_name)],
                        false,
                    );
                    focus.schedule(token, peer_id, GrantFocusTarget::OfferButton);
                }
                Ok(_) => {
                    mutation_error.set(Some(PeerApiError::client(tt_with(
                        context,
                        "Cluster.grantOfferNotSentError",
                        &[("peer", &peer_name)],
                    ))));
                    focus.schedule(token, peer_id, GrantFocusTarget::OfferButton);
                }
                Err(api_err) => {
                    mutation_error.set(Some(api_err));
                    focus.schedule(token, peer_id, GrantFocusTarget::OfferButton);
                }
            }
        });
    };

    let modal_title = Signal::derive(move || {
        let name = target.with(|peer| peer.as_ref().map(|p| p.name.clone()).unwrap_or_default());
        tt_with(context, "Cluster.grantModalTitle", &[("peer", &name)])
    });

    let active_preset = Memo::new(move |_| draft.with(|d| matching_preset(&d.draft)));
    let has_inbound = Memo::new(move |_| draft.with(GrantEditorDraft::has_inbound));
    let has_outbound = Memo::new(move |_| draft.with(GrantEditorDraft::has_outbound));
    let draft_has_write = Memo::new(move |_| draft.with(|d| access_has_write(&d.draft)));
    let peer_name_memo = Memo::new(move |_| {
        target.with(|peer| peer.as_ref().map(|p| p.name.clone()).unwrap_or_default())
    });
    let peer_is_down =
        Memo::new(move |_| target.with(|peer| peer.as_ref().is_some_and(|p| p.state == "down")));

    let delivery_supported =
        Memo::new(move |_| target.with(|peer| peer.as_ref().is_some_and(supports_grant_delivery)));

    view! {
        <Modal open=open title=modal_title>
            <div node_ref=body_ref class="space-y-5">
                {move || {
                    if delivery_supported.get() {
                        return None;
                    }
                    let locale = crate::tabs::l10n::locale(context);
                    let hint = target.with(|peer| {
                        peer.as_ref().and_then(|peer| compatibility_guidance(&locale, peer))
                    });
                    hint.map(|text| view! {
                        <div role="status" class="af-warning-banner text-xs">{text}</div>
                    })
                }}
                <Show when=move || peer_is_down.get()>
                    <div role="status" class="af-warning-banner text-xs">
                        {move || {
                            let peer = peer_name_memo.get();
                            tt_with(context, "Cluster.grantDownWarning", &[("peer", &peer)])
                        }}
                    </div>
                </Show>

                <Show when=move || load_state.get() == GrantLoadState::Loading>
                    <p role="status" class="text-sm text-slate-300 py-3">
                        {move || tt(context, "Cluster.grantLoading")}
                    </p>
                </Show>

                <Show when=move || load_state.get() == GrantLoadState::Failed>
                    <div class="space-y-4">
                        <PeerErrorAlert error=load_error />
                        <div class="flex flex-wrap justify-end gap-3">
                            <button
                                type="button"
                                class="af-btn px-4 py-2"
                                on:click=move |_| open.set(false)
                            >
                                {move || tt(context, "Cluster.grantCloseAction")}
                            </button>
                            <button
                                id="cluster-grant-retry"
                                type="button"
                                data-af-autofocus="true"
                                class="af-btn-primary px-4 py-2"
                                disabled=move || gate.is_busy()
                                on:click=move |_| retry_fetch()
                            >
                                {move || tt(context, "Common.retry")}
                            </button>
                        </div>
                    </div>
                </Show>

                <Show when=move || load_state.get() == GrantLoadState::Ready>
                    <div class="space-y-5">
                        <div class="af-surface-inset p-3 space-y-1">
                            <p class="text-xs font-semibold text-slate-400">
                                {move || tt(context, "Cluster.grantDirectionOverviewHeading")}
                            </p>
                            <p class="text-sm text-slate-200 break-words">
                                {move || {
                                    let locale = crate::tabs::l10n::locale(context);
                                    let peer = peer_name_memo.get();
                                    draft.with(|d| {
                                        direction_summary_for_grants(&locale, &peer, &d.loaded)
                                    })
                                }}
                            </p>
                        </div>

                        <PeerErrorAlert
                            error=mutation_error
                            on_dismiss=Callback::new(move |()| mutation_error.set(None))
                        />

                        {move || {
                            status_notice.get().map(|notice| {
                                let text = match notice {
                                    GrantNotice::Saved { peer_name } => tt_with(
                                        context,
                                        "Cluster.grantSavedStatus",
                                        &[("peer", &peer_name)],
                                    ),
                                    GrantNotice::Revoked { peer_name } => tt_with(
                                        context,
                                        "Cluster.grantRevokedStatus",
                                        &[("peer", &peer_name)],
                                    ),
                                    GrantNotice::OfferSent { peer_name } => tt_with(
                                        context,
                                        "Cluster.grantOfferSentStatus",
                                        &[("peer", &peer_name)],
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

                        <section
                            aria-labelledby="cluster-grant-inbound-heading"
                            class="af-surface-inset border-indigo-500/30 p-4 space-y-4"
                        >
                            <div class="space-y-1.5">
                                <div class="flex flex-wrap items-center justify-between gap-2">
                                    <h3
                                        id="cluster-grant-inbound-heading"
                                        class="text-base font-semibold text-slate-200 break-words"
                                    >
                                        {move || {
                                            let peer = peer_name_memo.get();
                                            tt_with(
                                                context,
                                                "Cluster.grantInboundHeading",
                                                &[("peer", &peer)],
                                            )
                                        }}
                                    </h3>
                                    <div class="flex flex-wrap items-center gap-2 shrink-0">
                                        <Badge label="Cluster.grantInboundEditableBadge" tone="indigo" />
                                        {move || {
                                            if has_inbound.get() {
                                                view! {
                                                    <Badge label="Cluster.grantInboundActiveBadge" tone="success" />
                                                }
                                            } else {
                                                view! {
                                                    <Badge label="Cluster.grantInboundNoneBadge" tone="muted" />
                                                }
                                            }
                                        }}
                                    </div>
                                </div>
                                <p class="text-xs text-slate-400 break-words">
                                    {move || {
                                        let peer = peer_name_memo.get();
                                        tt_with(
                                            context,
                                            "Cluster.grantInboundDescription",
                                            &[("peer", &peer)],
                                        )
                                    }}
                                </p>
                                {move || {
                                    let locale = crate::tabs::l10n::locale(context);
                                    draft
                                        .with(|d| {
                                            d.loaded
                                                .inbound
                                                .as_ref()
                                                .and_then(|g| format_grant_metadata(&locale, g))
                                        })
                                        .map(|meta| {
                                            view! {
                                                <p class="text-xs font-mono text-slate-400 break-all">
                                                    {meta}
                                                </p>
                                            }
                                        })
                                }}
                            </div>

                            <form
                                class="space-y-4"
                                on:submit=move |event| {
                                    event.prevent_default();
                                    submit_save();
                                }
                            >
                                <div class="space-y-1.5">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <span class="text-xs font-medium text-slate-300">
                                            {move || tt(context, "Cluster.grantPresetsLabel")}
                                        </span>
                                        <button
                                            id="cluster-grant-preset-ro"
                                            type="button"
                                            data-af-autofocus="true"
                                            class="af-btn px-3 py-1.5 text-xs"
                                            data-tone=move || {
                                                (active_preset.get()
                                                    == Some(GrantPreset::ReadOnlyAll))
                                                .then_some("primary")
                                            }
                                            aria-pressed=move || {
                                                (active_preset.get()
                                                    == Some(GrantPreset::ReadOnlyAll))
                                                .to_string()
                                            }
                                            disabled=move || gate.is_busy() || !delivery_supported.get()
                                            on:click=move |_| {
                                                mutation_error.set(None);
                                                draft.update(|d| {
                                                    d.apply_preset(GrantPreset::ReadOnlyAll)
                                                });
                                            }
                                        >
                                            {move || tt(context, "Cluster.accessReadOnlyAll")}
                                        </button>
                                        <button
                                            id="cluster-grant-preset-rw"
                                            type="button"
                                            class="af-btn px-3 py-1.5 text-xs"
                                            data-tone=move || {
                                                (active_preset.get()
                                                    == Some(GrantPreset::ReadWriteAll))
                                                .then_some("primary")
                                            }
                                            aria-pressed=move || {
                                                (active_preset.get()
                                                    == Some(GrantPreset::ReadWriteAll))
                                                .to_string()
                                            }
                                            disabled=move || gate.is_busy() || !delivery_supported.get()
                                            on:click=move |_| {
                                                mutation_error.set(None);
                                                draft.update(|d| {
                                                    d.apply_preset(GrantPreset::ReadWriteAll)
                                                });
                                            }
                                        >
                                            {move || tt(context, "Cluster.accessReadWriteAll")}
                                        </button>
                                    </div>
                                    <p class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.grantPresetsHint")}
                                    </p>
                                </div>

                                <fieldset class="space-y-3 border-0 p-0">
                                    <legend class="sr-only">
                                        {move || {
                                            let peer = peer_name_memo.get();
                                            tt_with(
                                                context,
                                                "Cluster.grantAreasLegend",
                                                &[("peer", &peer)],
                                            )
                                        }}
                                    </legend>
                                    <div class="grid sm:grid-cols-2 gap-3">
                                        {GrantArea::ALL
                                            .into_iter()
                                            .map(|area| {
                                                view! {
                                                    <div class="space-y-1 min-w-0">
                                                        <label
                                                            for=area.dom_id()
                                                            class="block text-xs font-medium text-slate-200"
                                                        >
                                                            {move || tt(context, area.label_key())}
                                                        </label>
                                                        <select
                                                            id=area.dom_id()
                                                            class="af-input px-3 py-1.5 w-full text-sm"
                                                            disabled=move || gate.is_busy() || !delivery_supported.get()
                                                            prop:value=move || {
                                                                draft.with(|d| {
                                                                    access_level_value(area.get(&d.draft))
                                                                })
                                                            }
                                                            on:change=move |event| {
                                                                let level = parse_access_level(
                                                                    &event_target_value(&event),
                                                                );
                                                                mutation_error.set(None);
                                                                draft.update(|d| {
                                                                    d.set_area(area, level)
                                                                });
                                                            }
                                                        >
                                                            <option value="none">
                                                                {move || tt(context, "Cluster.grantLevelNone")}
                                                            </option>
                                                            <option value="read">
                                                                {move || tt(context, "Cluster.grantLevelRead")}
                                                            </option>
                                                            <option value="write">
                                                                {move || tt(context, "Cluster.grantLevelWrite")}
                                                            </option>
                                                        </select>
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                </fieldset>

                                <Show when=move || draft_has_write.get()>
                                    <p class="af-warning-banner text-xs break-words">
                                        {move || {
                                            let peer = peer_name_memo.get();
                                            tt_with(
                                                context,
                                                "Cluster.grantWriteCaution",
                                                &[("peer", &peer)],
                                            )
                                        }}
                                    </p>
                                </Show>

                                <div class="flex flex-wrap justify-end gap-3 pt-1">
                                    <button
                                        id="cluster-grant-save"
                                        type="submit"
                                        class="af-btn-primary px-4 py-2"
                                        disabled=move || gate.is_busy() || !delivery_supported.get()
                                    >
                                        {move || {
                                            if active_action.get() == Some(GrantAction::Save) {
                                                tt(context, "Common.saving")
                                            } else {
                                                tt(context, "Cluster.saveGrantAction")
                                            }
                                        }}
                                    </button>
                                </div>
                            </form>

                            <Show when=move || has_inbound.get()>
                                <div class="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 space-y-2.5">
                                    <div class="space-y-1">
                                        <h4 class="text-xs font-semibold text-rose-300">
                                            {move || tt(context, "Cluster.revokeGrantSectionHeading")}
                                        </h4>
                                        <p class="text-xs text-slate-300 break-words">
                                            {move || {
                                                let peer = peer_name_memo.get();
                                                tt_with(
                                                    context,
                                                    "Cluster.revokeGrantLinkKeptNote",
                                                    &[("peer", &peer)],
                                                )
                                            }}
                                        </p>
                                    </div>

                                    <Show
                                        when=move || draft.with(|d| d.confirm_revoke)
                                        fallback=move || {
                                            view! {
                                                <div class="flex flex-wrap justify-end">
                                                    <button
                                                        id="cluster-grant-revoke-open"
                                                        type="button"
                                                        class="af-btn px-3 py-1.5 text-xs"
                                                        data-tone="danger"
                                                        disabled=move || gate.is_busy()
                                                        aria-label=move || {
                                                            let peer = peer_name_memo.get();
                                                            tt_with(
                                                                context,
                                                                "Cluster.revokeGrantAria",
                                                                &[("peer", &peer)],
                                                            )
                                                        }
                                                        on:click=move |_| {
                                                            mutation_error.set(None);
                                                            draft.update(|d| d.confirm_revoke = true);
                                                            if let Some(peer) = target.get_untracked() {
                                                                let token = gate
                                                                    .current_token(context.session_epoch);
                                                                focus.schedule(
                                                                    token,
                                                                    peer.id,
                                                                    GrantFocusTarget::RevokeKeepButton,
                                                                );
                                                            }
                                                        }
                                                    >
                                                        {move || tt(context, "Cluster.revokeGrantAction")}
                                                    </button>
                                                </div>
                                            }
                                        }
                                    >
                                        <div class="space-y-2 pt-1">
                                            <p class="text-xs font-medium text-rose-300 break-words">
                                                {move || {
                                                    let peer = peer_name_memo.get();
                                                    tt_with(
                                                        context,
                                                        "Cluster.revokeGrantConfirmPrompt",
                                                        &[("peer", &peer)],
                                                    )
                                                }}
                                            </p>
                                            <div class="flex flex-wrap justify-end gap-2">
                                                <button
                                                    id="cluster-grant-revoke-keep"
                                                    type="button"
                                                    class="af-btn px-3 py-1.5 text-xs"
                                                    disabled=move || gate.is_busy()
                                                    on:click=move |_| {
                                                        draft.update(|d| d.confirm_revoke = false);
                                                        if let Some(peer) = target.get_untracked() {
                                                            let token = gate
                                                                .current_token(context.session_epoch);
                                                            focus.schedule(
                                                                token,
                                                                peer.id,
                                                                GrantFocusTarget::RevokeOpenButton,
                                                            );
                                                        }
                                                    }
                                                >
                                                    {move || tt(context, "Cluster.revokeGrantKeepAction")}
                                                </button>
                                                <button
                                                    id="cluster-grant-revoke-confirm"
                                                    type="button"
                                                    class="af-btn px-3 py-1.5 text-xs"
                                                    data-tone="danger"
                                                    disabled=move || gate.is_busy()
                                                    on:click=move |_| confirm_revoke()
                                                >
                                                    {move || {
                                                        if active_action.get()
                                                            == Some(GrantAction::Revoke)
                                                        {
                                                            tt(context, "Cluster.revokingGrant")
                                                        } else {
                                                            tt(
                                                                context,
                                                                "Cluster.revokeGrantConfirmAction",
                                                            )
                                                        }
                                                    }}
                                                </button>
                                            </div>
                                        </div>
                                    </Show>
                                </div>
                            </Show>
                        </section>

                        <section
                            aria-labelledby="cluster-grant-outbound-heading"
                            class="af-surface-inset p-4 space-y-4"
                        >
                            <div class="space-y-1.5">
                                <div class="flex flex-wrap items-center justify-between gap-2">
                                    <h3
                                        id="cluster-grant-outbound-heading"
                                        class="text-base font-semibold text-slate-200 break-words"
                                    >
                                        {move || {
                                            let peer = peer_name_memo.get();
                                            tt_with(
                                                context,
                                                "Cluster.grantOutboundHeading",
                                                &[("peer", &peer)],
                                            )
                                        }}
                                    </h3>
                                    <div class="flex flex-wrap items-center gap-2 shrink-0">
                                        <Badge label="Cluster.grantOutboundReadOnlyBadge" tone="muted" />
                                        {move || {
                                            if has_outbound.get() {
                                                view! {
                                                    <Badge label="Cluster.grantOutboundActiveBadge" tone="success" />
                                                }
                                            } else {
                                                view! {
                                                    <Badge label="Cluster.grantOutboundNoneBadge" tone="muted" />
                                                }
                                            }
                                        }}
                                    </div>
                                </div>
                                <p class="text-xs text-slate-400 break-words">
                                    {move || {
                                        let peer = peer_name_memo.get();
                                        tt_with(
                                            context,
                                            "Cluster.grantOutboundDescription",
                                            &[("peer", &peer)],
                                        )
                                    }}
                                </p>
                            </div>

                            {move || {
                                let locale = crate::tabs::l10n::locale(context);
                                let peer = peer_name_memo.get();
                                match draft.with(|d| d.loaded.outbound.clone()) {
                                    Some(grant) => {
                                        let summary = summarize_access_map(&locale, &grant.access);
                                        let meta = format_grant_metadata(&locale, &grant);
                                        let area_levels: Vec<(&'static str, AccessLevel)> =
                                            GrantArea::ALL
                                                .into_iter()
                                                .map(|area| (area.label_key(), area.get(&grant.access)))
                                                .collect();
                                        view! {
                                            <div class="space-y-3">
                                                <p class="text-sm text-slate-200 break-words">
                                                    {summary}
                                                </p>
                                                {meta.map(|line| {
                                                    view! {
                                                        <p class="text-xs font-mono text-slate-400 break-all">
                                                            {line}
                                                        </p>
                                                    }
                                                })}
                                                <dl class="grid sm:grid-cols-2 gap-2 text-xs">
                                                    {area_levels
                                                        .into_iter()
                                                        .map(|(label_key, level)| {
                                                            let level_key = access_level_label_key(level);
                                                            let tone = access_level_badge_tone(level);
                                                            view! {
                                                                <div class="af-surface-inset flex items-center justify-between gap-2 px-3 py-1.5">
                                                                    <dt class="text-slate-300">
                                                                        {move || tt(context, label_key)}
                                                                    </dt>
                                                                    <dd>
                                                                        <Badge label=level_key tone=tone />
                                                                    </dd>
                                                                </div>
                                                            }
                                                        })
                                                        .collect_view()}
                                                </dl>
                                            </div>
                                        }
                                        .into_any()
                                    }
                                    None => view! {
                                        <p class="text-sm text-slate-400 break-words">
                                            {translate_with(
                                                &locale,
                                                "Cluster.grantOutboundEmpty",
                                                &[("peer", &peer)],
                                            )}
                                        </p>
                                    }
                                    .into_any(),
                                }
                            }}

                            <div class="af-surface-inset p-3 space-y-2.5">
                                <div class="space-y-1">
                                    <h4 class="text-xs font-semibold text-slate-200">
                                        {move || tt(context, "Cluster.grantOfferHeading")}
                                    </h4>
                                    <p class="text-xs text-slate-400 break-words">
                                        {move || {
                                            let peer = peer_name_memo.get();
                                            tt_with(
                                                context,
                                                "Cluster.grantOfferDescription",
                                                &[("peer", &peer)],
                                            )
                                        }}
                                    </p>
                                </div>
                                <div class="flex flex-wrap justify-end">
                                    <button
                                        id="cluster-grant-offer"
                                        type="button"
                                        class="af-btn px-3 py-1.5 text-xs"
                                        disabled=move || gate.is_busy() || !delivery_supported.get()
                                        aria-label=move || {
                                            (active_action.get() != Some(GrantAction::Offer))
                                                .then(|| {
                                                    let peer = peer_name_memo.get();
                                                    tt_with(
                                                        context,
                                                        "Cluster.sendGrantOfferAria",
                                                        &[("peer", &peer)],
                                                    )
                                                })
                                        }
                                        on:click=move |_| send_offer()
                                    >
                                        {move || {
                                            if active_action.get() == Some(GrantAction::Offer) {
                                                tt(context, "Cluster.sendingGrantOffer")
                                            } else {
                                                tt(context, "Cluster.sendGrantOfferAction")
                                            }
                                        }}
                                    </button>
                                </div>
                            </div>
                        </section>

                        <div class="flex flex-wrap justify-end gap-3 pt-1">
                            <button
                                id="cluster-grant-close"
                                type="button"
                                class="af-btn px-4 py-2"
                                on:click=move |_| open.set(false)
                            >
                                {move || tt(context, "Cluster.grantCloseAction")}
                            </button>
                        </div>
                    </div>
                </Show>
            </div>
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_web_core::i18n::translate;
    use serde_json::json;

    #[test]
    fn presets_fill_all_eight_areas_and_detect_custom_modifications() {
        let ro = GrantPreset::ReadOnlyAll.access_map();
        for area in GrantArea::ALL {
            assert_eq!(area.get(&ro), AccessLevel::Read);
        }
        assert_eq!(matching_preset(&ro), Some(GrantPreset::ReadOnlyAll));
        assert!(!access_has_write(&ro));

        let rw = GrantPreset::ReadWriteAll.access_map();
        for area in GrantArea::ALL {
            assert_eq!(area.get(&rw), AccessLevel::Write);
        }
        assert_eq!(matching_preset(&rw), Some(GrantPreset::ReadWriteAll));
        assert!(access_has_write(&rw));

        let mut custom = ro.clone();
        GrantArea::Services.set(&mut custom, AccessLevel::Write);
        assert_eq!(matching_preset(&custom), None);
        assert!(access_has_write(&custom));

        assert_eq!(matching_preset(&AccessMapView::default()), None);
    }

    #[test]
    fn save_grant_request_serializes_exact_wire_contract_and_rejects_all_none() {
        assert_eq!(
            build_save_grant_request(&AccessMapView::default(), false).unwrap_err(),
            "Cluster.validationGrantAreaRequired"
        );
        assert_eq!(
            build_save_grant_request(&AccessMapView::default(), true).unwrap_err(),
            "Cluster.validationGrantAreaOrRevoke"
        );

        let mut access = AccessMapView::default();
        GrantArea::Services.set(&mut access, AccessLevel::Read);
        GrantArea::Marketplace.set(&mut access, AccessLevel::Write);
        GrantArea::Transcoding.set(&mut access, AccessLevel::Write);

        let req = build_save_grant_request(&access, false).unwrap();
        let encoded = serde_json::to_value(&req).unwrap();
        assert_eq!(
            encoded,
            json!({
                "access": {
                    "services": "read",
                    "marketplace": "write",
                    "settings": "none",
                    "files": "none",
                    "users": "none",
                    "network": "none",
                    "updates": "none",
                    "transcoding": "write"
                }
            })
        );
    }

    #[test]
    fn grant_editor_draft_retains_edits_on_error_and_preserves_outbound_on_inbound_revoke() {
        let outbound = GrantSummaryView {
            id: "g-out".into(),
            run_as_user_id: 99,
            access: GrantPreset::ReadWriteAll.access_map(),
            created_by: "remote-admin".into(),
            created_at: "2026-11-23T12:00:00Z".into(),
        };
        let inbound = GrantSummaryView {
            id: "g-in".into(),
            run_as_user_id: 42,
            access: AccessMapView {
                services: AccessLevel::Read,
                ..Default::default()
            },
            created_by: "alice".into(),
            created_at: "2026-11-23T12:05:00Z".into(),
        };

        let mut state = GrantEditorDraft::default();
        state.apply_loaded(LinkGrantsView {
            inbound: Some(inbound.clone()),
            outbound: Some(outbound.clone()),
        });
        assert!(state.has_inbound());
        assert!(state.has_outbound());
        assert_eq!(state.draft.services, AccessLevel::Read);
        assert_eq!(state.draft.files, AccessLevel::None);

        // User edits draft and encounters a typed save error: draft MUST stay intact.
        state.set_area(GrantArea::Files, AccessLevel::Write);
        state.set_area(GrantArea::Updates, AccessLevel::Read);
        state.apply_save_result(Err(()));
        assert_eq!(state.draft.services, AccessLevel::Read);
        assert_eq!(state.draft.files, AccessLevel::Write);
        assert_eq!(state.draft.updates, AccessLevel::Read);
        assert_eq!(state.loaded.inbound, Some(inbound));
        assert_eq!(state.loaded.outbound, Some(outbound.clone()));

        // Revoking inbound clears only inbound and leaves outbound untouched.
        state.confirm_revoke = true;
        state.apply_revoke_result(Ok(LinkGrantsView {
            inbound: None,
            outbound: Some(outbound.clone()),
        }));
        assert!(!state.has_inbound());
        assert!(state.has_outbound());
        assert!(!state.confirm_revoke);
        assert_eq!(state.draft, AccessMapView::default());
        assert_eq!(state.loaded.outbound, Some(outbound));
    }

    #[test]
    fn parses_grant_offer_response_and_grant_metadata() {
        let resp: SendGrantOfferResponse = serde_json::from_value(json!({ "sent": true })).unwrap();
        assert!(resp.sent);

        let not_sent: SendGrantOfferResponse =
            serde_json::from_value(json!({ "sent": false })).unwrap();
        assert!(!not_sent.sent);

        let grant = GrantSummaryView {
            id: "g-1".into(),
            run_as_user_id: 7,
            access: GrantPreset::ReadOnlyAll.access_map(),
            created_by: "alice".into(),
            created_at: "2026-11-23T13:00:00Z".into(),
        };
        assert_eq!(
            format_grant_metadata("en", &grant).as_deref(),
            Some("Granted by alice · 2026-11-23T13:00:00Z")
        );
        let no_creator = GrantSummaryView {
            created_by: String::new(),
            ..grant
        };
        assert_eq!(
            format_grant_metadata("en", &no_creator).as_deref(),
            Some("Granted 2026-11-23T13:00:00Z")
        );
    }

    #[test]
    fn access_level_parsing_and_focus_selectors_cover_every_variant() {
        for (raw, expected) in [
            ("none", AccessLevel::None),
            ("read", AccessLevel::Read),
            ("write", AccessLevel::Write),
            ("unknown", AccessLevel::None),
        ] {
            assert_eq!(parse_access_level(raw), expected);
        }
        for level in [AccessLevel::None, AccessLevel::Read, AccessLevel::Write] {
            assert_eq!(parse_access_level(access_level_value(level)), level);
            assert_ne!(
                translate("en", access_level_label_key(level)),
                access_level_label_key(level)
            );
        }
        for target in [
            GrantFocusTarget::PrimaryEditor,
            GrantFocusTarget::RetryButton,
            GrantFocusTarget::SaveButton,
            GrantFocusTarget::RevokeOpenButton,
            GrantFocusTarget::RevokeKeepButton,
            GrantFocusTarget::RevokeConfirmButton,
            GrantFocusTarget::OfferButton,
        ] {
            assert!(grant_focus_selector(target).contains(":not([disabled])"));
        }
    }
}
