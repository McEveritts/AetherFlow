use super::types::{
    ensure_admin, ImportResult, ReconciliationApplyRequest, ReconciliationApplyResponse,
    ReconciliationFieldChange, ReconciliationPreviewRequest, ReconciliationPreviewResponse,
    ReconciliationRowChange, ReconciliationRowState, SignedApprovalTokenPayload,
    StreamingImportError,
};
use super::validation::{current_history_revision, record_admin_audit};
use super::RECONCILIATION_TOKEN_TTL_SECS;
use crate::auth::AuthUser;
use crate::streaming_history::{
    inclusion_predicate, query_filters, resolve_query_scope, scope_filters, HistoryCounts,
    HistoryQuery,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, params_from_iter, Connection};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

static RECONCILIATION_SIGNING_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
});

fn hash_row_state(state: &ReconciliationRowState) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(state).expect("serializable ReconciliationRowState"));
    hex::encode(hasher.finalize())
}

fn compute_preview_hash(
    history_revision: i64,
    history_rows: i64,
    rows: &[ReconciliationRowChange],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("rev:{history_revision}|").as_bytes());
    hasher.update(format!("rows:{history_rows}|").as_bytes());
    for row in rows {
        hasher.update(serde_json::to_vec(row).expect("serializable ReconciliationRowChange"));
        hasher.update(b"|");
    }
    hex::encode(hasher.finalize())
}

fn sign_approval_token(payload: &SignedApprovalTokenPayload) -> String {
    let bytes = serde_json::to_vec(payload).expect("serializable SignedApprovalTokenPayload");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&*RECONCILIATION_SIGNING_KEY).expect("32-byte HMAC key");
    mac.update(&bytes);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&bytes),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn verify_approval_token(
    token: &str,
    expected_actor_id: i64,
    expected_preview_hash: &str,
    now: i64,
) -> ImportResult<SignedApprovalTokenPayload> {
    if token.len() > 16_384 {
        return Err(StreamingImportError::bad_request(
            "invalid_approval_token",
            "approvalToken exceeds maximum length",
        ));
    }
    let (encoded_payload, encoded_sig) = token.split_once('.').ok_or_else(|| {
        StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
    })?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(encoded_payload).map_err(|_| {
        StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
    })?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(encoded_sig).map_err(|_| {
        StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
    })?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&*RECONCILIATION_SIGNING_KEY).expect("32-byte HMAC key");
    mac.update(&payload_bytes);
    mac.verify_slice(&sig_bytes).map_err(|_| {
        StreamingImportError::bad_request(
            "invalid_approval_token_signature",
            "approvalToken signature verification failed",
        )
    })?;
    let payload: SignedApprovalTokenPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| {
            StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
        })?;
    if payload.version != 1 {
        return Err(StreamingImportError::bad_request(
            "invalid_approval_token",
            "Unsupported approvalToken version",
        ));
    }
    if payload.actor_id != expected_actor_id {
        return Err(StreamingImportError::forbidden(
            "approvalToken was issued to a different administrator",
        ));
    }
    if payload.preview_hash != expected_preview_hash {
        return Err(StreamingImportError::bad_request(
            "preview_hash_mismatch",
            "previewHash does not match the signed approvalToken",
        ));
    }
    if now >= payload.expires_at {
        return Err(StreamingImportError::conflict(
            "approval_token_expired",
            "Reconciliation approvalToken has expired; generate a fresh preview",
        ));
    }
    Ok(payload)
}

fn read_reconciliation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconciliationRowState> {
    Ok(ReconciliationRowState {
        id: row.get(0)?,
        session_key: row.get(1)?,
        provider: row.get(2)?,
        server_id: row.get(3)?,
        source_event_id: row.get(4)?,
        user_id: row.get(5)?,
        user_name: row.get(6)?,
        item_id: row.get(7)?,
        item_name: row.get(8)?,
        item_type: row.get(9)?,
        play_method: row.get(10)?,
        client_name: row.get(11)?,
        device_name: row.get(12)?,
        device_id: row.get(13)?,
        ip_address: row.get(14)?,
        duration_secs: row.get(15)?,
        watched_secs: row.get(16)?,
        data_used_bytes: row.get(17)?,
        bitrate_bps: row.get(18)?,
        started_at: row.get(19)?,
        last_seen_at: row.get(20)?,
        ended_at: row.get(21)?,
        provenance: row.get(22)?,
        timestamp_certainty: row.get(23)?,
        byte_accuracy: row.get(24)?,
        policy_status: row.get(25)?,
    })
}

fn propose_reconciliation_for_row(
    before: &ReconciliationRowState,
) -> Option<ReconciliationRowChange> {
    if before.provenance != "legacy_unverified" {
        return None;
    }

    let mut after = before.clone();
    let mut changes = Vec::new();
    let mut classifications = Vec::new();

    let is_sync_summary =
        before.session_key.contains(":sync:") || before.session_key.starts_with("sync:");
    let has_epoch_timestamp = before.started_at.trim().starts_with("1970-01-01");
    let has_empty_timestamp = before.started_at.trim().is_empty();
    let no_session_telemetry = before.client_name.trim().is_empty()
        && before.device_name.trim().is_empty()
        && before.device_id.trim().is_empty()
        && before.ip_address.trim().is_empty();

    if is_sync_summary {
        classifications.push("legacy_sync_item_summary");
        after.provenance = "item_summary".to_string();
        changes.push(ReconciliationFieldChange {
            field: "provenance".to_string(),
            before: before.provenance.clone(),
            after: after.provenance.clone(),
            reason: "Session key resembles an old item-summary sync; key shape alone does not establish provenance".to_string(),
        });

        let target_ts_certainty = if has_epoch_timestamp || has_empty_timestamp {
            "unrecorded"
        } else {
            before.timestamp_certainty.as_str()
        };
        if after.timestamp_certainty != target_ts_certainty {
            changes.push(ReconciliationFieldChange {
                field: "timestampCertainty".to_string(),
                before: before.timestamp_certainty.clone(),
                after: target_ts_certainty.to_string(),
                reason: "Historical summary timestamp certainty is unverified".to_string(),
            });
            after.timestamp_certainty = target_ts_certainty.to_string();
        }

        if has_epoch_timestamp {
            after.started_at = String::new();
            changes.push(ReconciliationFieldChange {
                field: "startedAt".to_string(),
                before: before.started_at.clone(),
                after: String::new(),
                reason: "Cleared synthetic 1970-01-01 epoch fallback timestamp".to_string(),
            });
        }

        if no_session_telemetry && !before.play_method.trim().is_empty() {
            after.play_method = String::new();
            changes.push(ReconciliationFieldChange {
                field: "playMethod".to_string(),
                before: before.play_method.clone(),
                after: String::new(),
                reason: "Cleared default play_method on item summary row with no session client/device telemetry".to_string(),
            });
        }

        if before.data_used_bytes != 0 || before.byte_accuracy != "unrecorded" {
            after.data_used_bytes = 0;
            after.byte_accuracy = "unrecorded".to_string();
            changes.push(ReconciliationFieldChange {
                field: "dataUsedBytes".to_string(),
                before: format!("{} ({})", before.data_used_bytes, before.byte_accuracy),
                after: "0 (unrecorded)".to_string(),
                reason: "Item summaries do not carry per-session transfer byte measurements"
                    .to_string(),
            });
        }
    } else {
        if has_epoch_timestamp {
            classifications.push("legacy_epoch_timestamp");
            after.started_at = String::new();
            after.timestamp_certainty = "unrecorded".to_string();
            changes.push(ReconciliationFieldChange {
                field: "startedAt".to_string(),
                before: before.started_at.clone(),
                after: String::new(),
                reason: "Cleared synthetic 1970-01-01 epoch fallback timestamp".to_string(),
            });
            changes.push(ReconciliationFieldChange {
                field: "timestampCertainty".to_string(),
                before: before.timestamp_certainty.clone(),
                after: "unrecorded".to_string(),
                reason: "Timestamp was synthetic epoch fallback".to_string(),
            });
        } else if has_empty_timestamp && before.timestamp_certainty != "unrecorded" {
            classifications.push("legacy_missing_timestamp");
            after.timestamp_certainty = "unrecorded".to_string();
            changes.push(ReconciliationFieldChange {
                field: "timestampCertainty".to_string(),
                before: before.timestamp_certainty.clone(),
                after: "unrecorded".to_string(),
                reason: "Empty started_at marked as unrecorded timestamp certainty".to_string(),
            });
        }

        // Check for unverified or implausibly inflated byte counters on legacy rows
        if before.data_used_bytes > 0 && before.byte_accuracy == "legacy_unverified" {
            let implausible_bytes = if before.watched_secs <= 0 || before.bitrate_bps <= 0 {
                true
            } else {
                let expected = (before.watched_secs as i128) * ((before.bitrate_bps as i128) / 8);
                (before.data_used_bytes as i128) > expected.saturating_mul(4)
            };
            if implausible_bytes {
                classifications.push("legacy_inflated_bytes");
                after.data_used_bytes = 0;
                after.byte_accuracy = "unrecorded".to_string();
                changes.push(ReconciliationFieldChange {
                    field: "dataUsedBytes".to_string(),
                    before: format!("{} ({})", before.data_used_bytes, before.byte_accuracy),
                    after: "0 (unrecorded)".to_string(),
                    reason: "Cleared legacy unverified byte total lacking supporting bitrate/watch-time evidence".to_string(),
                });
            }
        }
    }

    if changes.is_empty() {
        return None;
    }

    let classification = if classifications.is_empty() {
        "suspected_legacy_reconciliation".to_string()
    } else {
        format!("suspected_{}", classifications.join("+suspected_"))
    };
    for change in &mut changes {
        change.reason = format!(
            "Unverified proposal requiring source review: {}",
            change.reason
        );
    }

    Some(ReconciliationRowChange {
        id: before.id,
        session_key: before.session_key.clone(),
        classification,
        row_fingerprint: hash_row_state(before),
        before: before.clone(),
        after,
        changes,
    })
}

fn collect_reconciliation_candidates(
    conn: &Connection,
    candidate_ids: &[i64],
    limit: usize,
) -> ImportResult<Vec<ReconciliationRowChange>> {
    let base_select = "SELECT id, session_key, provider, server_id, source_event_id,
                              user_id, user_name, item_id, item_name, item_type,
                              play_method, client_name, device_name, device_id, ip_address,
                              COALESCE(duration_secs, 0), COALESCE(watched_secs, 0),
                              COALESCE(data_used_bytes, 0), COALESCE(bitrate_bps, 0),
                              COALESCE(started_at, ''), COALESCE(last_seen_at, ''), ended_at,
                              provenance, timestamp_certainty, byte_accuracy, policy_status
                       FROM streaming_history
                       WHERE provenance = 'legacy_unverified'
                       ORDER BY id ASC";
    let filter_set: Option<BTreeSet<i64>> = if candidate_ids.is_empty() {
        None
    } else {
        Some(candidate_ids.iter().copied().collect())
    };

    let mut stmt = conn.prepare(base_select)?;
    let rows = stmt.query_map([], read_reconciliation_row)?;

    let mut proposed = Vec::new();
    for row in rows {
        let state = row?;
        if let Some(ref set) = filter_set {
            if !set.contains(&state.id) {
                continue;
            }
        }
        if let Some(change) = propose_reconciliation_for_row(&state) {
            proposed.push(change);
            if proposed.len() >= limit {
                break;
            }
        }
    }
    Ok(proposed)
}

fn compute_canonical_counts(
    conn: &Connection,
    user: &AuthUser,
    now: i64,
) -> ImportResult<HistoryCounts> {
    let (query, watermark, _revision, as_of) =
        resolve_query_scope(conn, HistoryQuery::default(), user, now).map_err(|e| {
            StreamingImportError::internal(format!(
                "Failed to resolve canonical history scope: {}",
                e.message
            ))
        })?;
    let (mut clauses, mut values) = scope_filters(&query, user, watermark);
    let base_clauses = clauses.clone();
    let base_values = values.clone();
    query_filters(&query, as_of, &mut clauses, &mut values).map_err(|e| {
        StreamingImportError::internal(format!(
            "Failed to build canonical history filters: {}",
            e.message
        ))
    })?;
    let from_history = "FROM streaming_history h CROSS JOIN streaming_tracking_policies p";
    let available: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) {from_history} WHERE {}",
            base_clauses.join(" AND ")
        ),
        params_from_iter(&base_values),
        |row| row.get(0),
    )?;
    let inc = inclusion_predicate();
    let confirmed = format!("({inc}) AND h.provenance IN ('observed_session','imported_event')");
    let sql = format!(
        "SELECT COUNT(*),
                COALESCE(SUM(h.event_unix IS NULL),0),
                COALESCE(SUM(CASE WHEN {confirmed} THEN 1 ELSE 0 END),0),
                COALESCE(SUM(h.provenance = 'item_summary'),0),
                COALESCE(SUM(h.provenance = 'legacy_unverified'),0),
                COALESCE(SUM(CASE WHEN {confirmed} THEN MAX(COALESCE(h.watched_secs,0),0) ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN {confirmed} AND h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes,0),0) ELSE 0 END),0)
         {from_history} WHERE {}",
        clauses.join(" AND ")
    );
    let mut counts = conn.query_row(&sql, params_from_iter(&values), |row| {
        Ok(HistoryCounts {
            available_records: 0,
            matching_records: row.get(0)?,
            undated_records: row.get(1)?,
            confirmed_plays: row.get(2)?,
            item_summaries: row.get(3)?,
            legacy_records: row.get(4)?,
            watch_time_secs: row.get(5)?,
            estimated_bytes: row.get(6)?,
        })
    })?;
    counts.available_records = available;
    Ok(counts)
}

fn compute_projected_counts(
    conn: &Connection,
    user: &AuthUser,
    now: i64,
    proposed: &[ReconciliationRowChange],
) -> ImportResult<(HistoryCounts, HistoryCounts)> {
    let counts_before = compute_canonical_counts(conn, user, now)?;
    conn.execute_batch("SAVEPOINT streaming_count_projection")?;
    let projected = (|| -> ImportResult<HistoryCounts> {
        for change in proposed {
            let after = &change.after;
            conn.execute("UPDATE streaming_history SET server_id=?1,play_method=?2,data_used_bytes=?3,started_at=?4,provenance=?5,timestamp_certainty=?6,byte_accuracy=?7,policy_status=?8 WHERE id=?9 AND provenance='legacy_unverified'", params![after.server_id, after.play_method, after.data_used_bytes, after.started_at, after.provenance, after.timestamp_certainty, after.byte_accuracy, after.policy_status, change.id])?;
        }
        compute_canonical_counts(conn, user, now)
    })();
    conn.execute_batch(
        "ROLLBACK TO streaming_count_projection; RELEASE streaming_count_projection",
    )?;
    let counts_after = projected?;

    Ok((counts_before, counts_after))
}

/// Generates a read-only legacy reconciliation preview and a signed 15-minute approval token
/// bound to `user.user_id`, `history_revision`, and the exact per-row state fingerprints.
pub fn preview_legacy_reconciliation(
    conn: &Connection,
    request: ReconciliationPreviewRequest,
    user: &AuthUser,
    now: i64,
) -> ImportResult<ReconciliationPreviewResponse> {
    ensure_admin(user)?;
    let _transaction = conn.unchecked_transaction()?;
    let limit = request.limit.unwrap_or(500);
    if !(1..=1000).contains(&limit) {
        return Err(StreamingImportError::bad_request(
            "invalid_preview_limit",
            "limit must be between 1 and 1000",
        ));
    }

    let history_revision = current_history_revision(conn)?;
    let history_rows: i64 =
        conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
            row.get(0)
        })?;
    let affected_rows = collect_reconciliation_candidates(conn, &request.candidate_ids, limit)?;
    let preview_hash = compute_preview_hash(history_revision, history_rows, &affected_rows);
    let candidate_ids: Vec<i64> = affected_rows.iter().map(|r| r.id).collect();
    let expires_at_unix = now + RECONCILIATION_TOKEN_TTL_SECS;

    let approval_token = sign_approval_token(&SignedApprovalTokenPayload {
        version: 1,
        actor_id: user.user_id,
        preview_hash: preview_hash.clone(),
        history_revision,
        history_rows,
        candidate_ids,
        issued_at: now,
        expires_at: expires_at_unix,
    });

    let (counts_before, counts_after) = compute_projected_counts(conn, user, now, &affected_rows)?;

    let issued_at = DateTime::from_timestamp(now, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339();
    let expires_at = DateTime::from_timestamp(expires_at_unix, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339();

    Ok(ReconciliationPreviewResponse {
        preview_hash,
        approval_token,
        actor_id: user.user_id,
        history_revision,
        issued_at,
        expires_at,
        total_affected_rows: affected_rows.len(),
        counts_before,
        counts_after,
        affected_rows,
    })
}

/// Applies a previously previewed legacy reconciliation after:
/// 1. Verifying the admin actor and HMAC-signed `approval_token` + `preview_hash`,
/// 2. Creating and verifying a consistent SQLite backup (`af_db::streaming::verified_backup`)
///    before beginning the write transaction,
/// 3. Opening a `BEGIN IMMEDIATE` transaction, re-verifying `streaming_history_revision` and
///    every candidate row's exact fingerprint against `preview_hash`,
/// 4. Applying only the approved updates and writing a full before/after JSON audit entry to
///    `streaming_history_audit`.
pub fn apply_legacy_reconciliation_with_db_path(
    conn: &Connection,
    db_path: &str,
    request: ReconciliationApplyRequest,
    user: &AuthUser,
    now: i64,
) -> ImportResult<ReconciliationApplyResponse> {
    ensure_admin(user)?;
    let token_payload = verify_approval_token(
        &request.approval_token,
        user.user_id,
        &request.preview_hash,
        now,
    )?;
    if token_payload.candidate_ids.is_empty() {
        return Err(StreamingImportError::bad_request(
            "no_reconciliation_changes",
            "Preview contains no approved changes",
        ));
    }

    // Fast pre-check before running expensive VACUUM INTO backup: verify revision hasn't drifted.
    let pre_revision = current_history_revision(conn)?;
    let pre_rows: i64 = conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
        row.get(0)
    })?;
    if pre_revision != token_payload.history_revision || pre_rows != token_payload.history_rows {
        return Err(StreamingImportError::conflict(
            "reconciliation_stale",
            "Streaming history changed since the preview was generated; run preview again",
        ));
    }

    // Verified backup before mutating any rows.
    let backup_path_buf = af_db::streaming::verified_backup(conn, db_path).map_err(|err| {
        StreamingImportError::unavailable(
            "backup_verification_failed",
            format!(
                "Refusing to apply legacy reconciliation without a verified SQLite backup: {err}"
            ),
        )
    })?;
    let backup_path = Some(
        backup_path_buf
            .ok_or_else(|| {
                StreamingImportError::conflict(
                    "streaming_backup_required",
                    "Legacy reconciliation requires a verified on-disk SQLite backup",
                )
            })?
            .to_string_lossy()
            .into_owned(),
    );

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> ImportResult<ReconciliationApplyResponse> {
        let current_rev = current_history_revision(conn)?;
        let current_rows: i64 =
            conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
                row.get(0)
            })?;
        if current_rev != token_payload.history_revision
            || current_rows != token_payload.history_rows
        {
            return Err(StreamingImportError::conflict(
                "reconciliation_stale",
                "Streaming history revision changed before reconciliation lock was acquired",
            ));
        }

        // Recompute candidate changes inside the IMMEDIATE transaction and verify exact hash match.
        let limit = token_payload.candidate_ids.len().max(1);
        let current_candidates =
            collect_reconciliation_candidates(conn, &token_payload.candidate_ids, limit)?;
        if current_candidates.len() != token_payload.candidate_ids.len() {
            return Err(StreamingImportError::conflict(
                "reconciliation_stale",
                "Candidate row set changed since the preview was generated",
            ));
        }

        let recomputed_hash = compute_preview_hash(current_rev, current_rows, &current_candidates);
        if recomputed_hash != request.preview_hash {
            return Err(StreamingImportError::conflict(
                "reconciliation_stale",
                "One or more candidate rows changed since the preview was generated",
            ));
        }

        let (counts_before, _) = compute_projected_counts(conn, user, now, &current_candidates)?;

        let before_states: Vec<&ReconciliationRowState> =
            current_candidates.iter().map(|c| &c.before).collect();
        let after_states: Vec<&ReconciliationRowState> =
            current_candidates.iter().map(|c| &c.after).collect();
        let before_json = serde_json::to_string(&before_states)
            .map_err(|e| StreamingImportError::internal(e.to_string()))?;
        let after_json = serde_json::to_string(&after_states)
            .map_err(|e| StreamingImportError::internal(e.to_string()))?;

        for row_change in &current_candidates {
            let after = &row_change.after;
            let updated = conn.execute(
                "UPDATE streaming_history
                 SET server_id = ?1,
                     play_method = ?2,
                     data_used_bytes = ?3,
                     started_at = ?4,
                     provenance = ?5,
                     timestamp_certainty = ?6,
                     byte_accuracy = ?7,
                     policy_status = ?8
                 WHERE id = ?9 AND provenance = 'legacy_unverified'",
                params![
                    after.server_id,
                    after.play_method,
                    after.data_used_bytes,
                    after.started_at,
                    after.provenance,
                    after.timestamp_certainty,
                    after.byte_accuracy,
                    after.policy_status,
                    row_change.id,
                ],
            )?;
            if updated != 1 {
                return Err(StreamingImportError::conflict(
                    "reconciliation_stale",
                    format!("Row id={} could not be updated as expected", row_change.id),
                ));
            }
        }

        let created_at = DateTime::from_timestamp(now, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();
        conn.execute(
            "INSERT INTO streaming_history_audit (
                actor_id, operation, preview_hash, before_json, after_json, created_at
             ) VALUES (?1, 'legacy_reconciliation', ?2, ?3, ?4, ?5)",
            params![
                user.user_id,
                request.preview_hash,
                before_json,
                after_json,
                created_at
            ],
        )?;
        let audit_id = conn.last_insert_rowid();

        let counts_after = compute_canonical_counts(conn, user, now)?;
        let history_revision = current_history_revision(conn)?;

        record_admin_audit(
            conn,
            user,
            "streaming.reconciliation.apply",
            "streaming_history_audit",
            &audit_id.to_string(),
            &format!(
                "preview_hash={} applied_rows={} backup={}",
                request.preview_hash,
                current_candidates.len(),
                backup_path.as_deref().unwrap_or("in-memory")
            ),
        )?;

        Ok(ReconciliationApplyResponse {
            audit_id,
            preview_hash: request.preview_hash,
            applied_rows: current_candidates.len(),
            backup_path,
            history_revision,
            counts_before,
            counts_after,
            created_at,
        })
    })();

    match result {
        Ok(resp) => {
            conn.execute_batch("COMMIT")?;
            Ok(resp)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}
