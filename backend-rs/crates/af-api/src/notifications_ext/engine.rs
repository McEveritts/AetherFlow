use super::models::StoredChannel;
use super::rules::percentage_threshold;
use super::webhook::{
    delivery_retry_backoff_secs, prepare_channel_request, sanitize_diagnostic_error,
    send_prepared_channel_request, ChannelDispatchError, PreparedChannelRequest,
};
use crate::ws::broadcast_ws_message;
use chrono::Utc;
use futures::stream::{self, StreamExt};
use rusqlite::{params, OptionalExtension};
use std::time::Duration;

pub(super) const RULE_COOLDOWN_SECS: i64 = 15 * 60;
pub(super) const MAX_DELIVERY_ATTEMPTS: i32 = 3;
pub(super) const DELIVERY_CLAIM_LEASE_SECS: i64 = 60;
pub(super) const MAX_DELIVERIES_PER_TICK: usize = 16;
const MAX_CONCURRENT_DELIVERIES: usize = 4;

pub(super) const AMBIGUOUS_RECLAIM_NOTE: &str = "Previous delivery claim expired before receipt committed; retrying (upstream may have accepted prior attempt)";
pub(super) const AMBIGUOUS_DELIVERED_NOTE: &str =
    "Delivered after reclaiming expired claim; upstream may have received prior attempt";
pub(super) const AMBIGUOUS_UNCERTAIN_NOTE: &str = "Delivery claim expired before receipt committed; upstream outcome uncertain (may have been delivered)";

#[derive(Debug, Clone)]
struct RuleWithCooldown {
    rule: af_services::NotificationRule,
    last_triggered_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub(super) struct CommittedRuleTrigger {
    pub(super) notification: af_services::Notification,
    pub(super) queued_deliveries: usize,
}

#[derive(Debug, Clone)]
pub(super) struct ClaimedDelivery {
    pub(super) id: i64,
    pub(super) channel_id: i64,
    pub(super) channel_type: String,
    pub(super) notification_id: i64,
    pub(super) attempts: i32,
    pub(super) claim_token: String,
    pub(super) reclaimed_expired_lease: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DeliveryReceiptCommit {
    Committed(&'static str),
    StaleClaim,
}

pub(super) fn is_rule_on_cooldown(
    last_triggered_at: Option<i64>,
    now_epoch: i64,
    cooldown_secs: i64,
) -> bool {
    last_triggered_at.is_some_and(|last| {
        last > now_epoch.saturating_sub(cooldown_secs)
            && last <= now_epoch.saturating_add(cooldown_secs)
    })
}

pub(super) fn commit_rule_trigger_in_conn(
    conn: &rusqlite::Connection,
    rule: &af_services::NotificationRule,
    message: &str,
    now_epoch: i64,
    cooldown_secs: i64,
) -> anyhow::Result<Option<CommittedRuleTrigger>> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let min_eligible = now_epoch.saturating_sub(cooldown_secs);
    let max_clock_skew = now_epoch.saturating_add(cooldown_secs);
    let claimed_rule = tx.execute(
        "UPDATE notification_rules
         SET last_triggered_at = ?1
         WHERE id = ?2
           AND COALESCE(enabled, 1) != 0
           AND (
               last_triggered_at IS NULL
               OR last_triggered_at <= ?3
               OR last_triggered_at > ?4
           )",
        params![now_epoch, rule.id, min_eligible, max_clock_skew],
    )?;
    if claimed_rule == 0 {
        tx.commit()?;
        return Ok(None);
    }

    tx.execute(
        "INSERT INTO notifications (user_id, level, title, message) VALUES (NULL, ?1, ?2, ?3)",
        params![rule.level, rule.name, message],
    )?;
    let notif_id = tx.last_insert_rowid();
    anyhow::ensure!(notif_id > 0, "failed to allocate local notification id");
    let created_at: String = tx
        .query_row(
            "SELECT COALESCE(CAST(created_at AS TEXT), '') FROM notifications WHERE id = ?1",
            params![notif_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| Utc::now().to_rfc3339());

    let queued_deliveries = tx.execute(
        "INSERT INTO notification_delivery_log (
            channel_id,
            channel_type,
            notification_id,
            status,
            attempts,
            last_error,
            completed_at,
            next_attempt_at,
            claim_token,
            lease_until,
            updated_at
         )
         SELECT
            id,
            type,
            ?1,
            'pending',
            0,
            '',
            '',
            ?2,
            '',
            NULL,
            ?2
         FROM notification_channels
         WHERE COALESCE(enabled, 1) != 0
         ORDER BY id ASC",
        params![notif_id, now_epoch],
    )?;

    tx.commit()?;

    Ok(Some(CommittedRuleTrigger {
        notification: af_services::Notification {
            id: notif_id,
            user_id: None,
            level: rule.level.clone(),
            title: rule.name.clone(),
            message: message.to_string(),
            read: false,
            created_at,
        },
        queued_deliveries,
    }))
}

pub(super) fn claim_due_deliveries_in_conn(
    conn: &rusqlite::Connection,
    now_epoch: i64,
    now_rfc3339: &str,
    max_batch: usize,
) -> anyhow::Result<Vec<ClaimedDelivery>> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

    // Account for the ambiguous interval on the final attempt: if a worker crashed after
    // sending (and possibly after upstream accepted) before committing its receipt, never
    // retry past MAX_DELIVERY_ATTEMPTS; surface an operator-visible `uncertain` outcome.
    let finalized_uncertain = tx.execute(
        "UPDATE notification_delivery_log
         SET status = 'uncertain',
             claim_token = '',
             lease_until = NULL,
             completed_at = ?1,
             updated_at = ?2,
             last_error = ?3
         WHERE notification_id IS NOT NULL
           AND status = 'sending'
           AND lease_until IS NOT NULL
           AND lease_until <= ?2
           AND COALESCE(attempts, 0) >= ?4",
        params![
            now_rfc3339,
            now_epoch,
            AMBIGUOUS_UNCERTAIN_NOTE,
            MAX_DELIVERY_ATTEMPTS
        ],
    )?;
    if finalized_uncertain > 0 {
        tracing::warn!(
            count = finalized_uncertain,
            "Marked exhausted expired notification delivery claims as uncertain"
        );
    }

    let candidates: Vec<(i64, i64, String, i64, i32, String)> = {
        let mut stmt = tx.prepare(
            "SELECT id, channel_id, channel_type, notification_id, COALESCE(attempts, 0), status
             FROM notification_delivery_log
             WHERE notification_id IS NOT NULL
               AND COALESCE(attempts, 0) < ?1
               AND (
                   (status = 'pending' AND COALESCE(next_attempt_at, 0) <= ?2)
                   OR (status = 'sending' AND lease_until IS NOT NULL AND lease_until <= ?2)
               )
             ORDER BY id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![MAX_DELIVERY_ATTEMPTS, now_epoch, max_batch as i64],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let lease_until = now_epoch.saturating_add(DELIVERY_CLAIM_LEASE_SECS);
    let mut claimed = Vec::with_capacity(candidates.len());
    for (id, channel_id, channel_type, notification_id, prev_attempts, prev_status) in candidates {
        let claim_token = uuid::Uuid::new_v4().to_string();
        let updated = tx.execute(
            "UPDATE notification_delivery_log
             SET status = 'sending',
                 attempts = COALESCE(attempts, 0) + 1,
                 claim_token = ?1,
                 lease_until = ?2,
                 updated_at = ?3,
                 last_error = CASE
                     WHEN status = 'sending' THEN ?4
                     ELSE COALESCE(last_error, '')
                 END
             WHERE id = ?5
               AND COALESCE(attempts, 0) < ?6
               AND (
                   (status = 'pending' AND COALESCE(next_attempt_at, 0) <= ?3)
                   OR (status = 'sending' AND lease_until IS NOT NULL AND lease_until <= ?3)
               )",
            params![
                claim_token,
                lease_until,
                now_epoch,
                AMBIGUOUS_RECLAIM_NOTE,
                id,
                MAX_DELIVERY_ATTEMPTS
            ],
        )?;
        if updated == 1 {
            claimed.push(ClaimedDelivery {
                id,
                channel_id,
                channel_type,
                notification_id,
                attempts: prev_attempts + 1,
                claim_token,
                reclaimed_expired_lease: prev_status == "sending",
            });
        }
    }

    tx.commit()?;
    Ok(claimed)
}

pub(super) fn load_delivery_context_in_conn(
    conn: &rusqlite::Connection,
    claimed: &ClaimedDelivery,
) -> Result<(StoredChannel, PreparedChannelRequest), ChannelDispatchError> {
    let notif: Option<(String, String, String)> = conn
        .query_row(
            "SELECT n.level, n.title, n.message
             FROM notification_delivery_log d JOIN notifications n ON n.id = d.notification_id
             WHERE d.id = ?1 AND d.status = 'sending' AND d.claim_token = ?2",
            params![claimed.id, claimed.claim_token],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| {
            ChannelDispatchError::transient("Failed to load notification record", false)
        })?;
    let Some((level, title, message)) = notif else {
        return Err(ChannelDispatchError::permanent(
            "Notification record missing or delivery claim superseded",
            false,
        ));
    };

    let channel_opt: Option<StoredChannel> = conn
        .query_row(
            "SELECT id, name, type, config, COALESCE(enabled, 1) != 0, COALESCE(CAST(created_at AS TEXT), '')
             FROM notification_channels WHERE id = ?1",
            params![claimed.channel_id],
            |r| {
                Ok(StoredChannel {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    channel_type: r.get(2)?,
                    config: r.get(3)?,
                    enabled: r.get(4)?,
                    created_at: r.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|_| ChannelDispatchError::transient("Failed to load notification channel", false))?;
    let Some(channel) = channel_opt else {
        return Err(ChannelDispatchError::permanent(
            "Channel deleted before delivery",
            false,
        ));
    };
    if !channel.enabled {
        return Err(ChannelDispatchError::permanent(
            "Channel disabled before delivery",
            false,
        ));
    }

    let prepared = prepare_channel_request(&channel, &level, &title, &message)?;
    Ok((channel, prepared))
}

pub(super) fn complete_claimed_delivery_in_conn(
    conn: &rusqlite::Connection,
    claimed: &ClaimedDelivery,
    outcome: &Result<(), ChannelDispatchError>,
    finish_epoch: i64,
    finish_rfc3339: &str,
) -> anyhow::Result<DeliveryReceiptCommit> {
    let (next_status, next_attempt_at, completed_at, last_error): (
        &'static str,
        i64,
        &str,
        String,
    ) = match outcome {
        Ok(()) => {
            let note = if claimed.reclaimed_expired_lease {
                AMBIGUOUS_DELIVERED_NOTE.to_string()
            } else {
                String::new()
            };
            ("delivered", 0, finish_rfc3339, note)
        }
        Err(err) if err.is_transient() && claimed.attempts < MAX_DELIVERY_ATTEMPTS => {
            let backoff = delivery_retry_backoff_secs(claimed.attempts);
            (
                "pending",
                finish_epoch.saturating_add(backoff),
                "",
                sanitize_diagnostic_error(err.message()),
            )
        }
        Err(err) => (
            "failed",
            0,
            finish_rfc3339,
            sanitize_diagnostic_error(err.message()),
        ),
    };

    let updated = conn.execute(
        "UPDATE notification_delivery_log
         SET status = ?1,
             claim_token = '',
             lease_until = NULL,
             next_attempt_at = ?2,
             completed_at = ?3,
             updated_at = ?4,
             last_error = ?5
         WHERE id = ?6
           AND status = 'sending'
           AND claim_token = ?7",
        params![
            next_status,
            next_attempt_at,
            completed_at,
            finish_epoch,
            last_error,
            claimed.id,
            claimed.claim_token
        ],
    )?;

    if updated == 0 {
        return Ok(DeliveryReceiptCommit::StaleClaim);
    }
    Ok(DeliveryReceiptCommit::Committed(next_status))
}

fn broadcast_triggered_notification(notification: &af_services::Notification) {
    let val = serde_json::to_value(notification).unwrap_or_default();
    let ws_msg = serde_json::json!({
        "type": "NOTIFICATION",
        "data": val,
    });
    broadcast_ws_message(&ws_msg);
}

async fn drain_due_deliveries_once() {
    let now = Utc::now();
    // All claims in the batch expire together. Reserve one second for the whole-second
    // SQLite lease so later tasks cannot send beyond their claim.
    let dispatch_deadline =
        tokio::time::Instant::now() + Duration::from_secs((DELIVERY_CLAIM_LEASE_SECS - 1) as u64);
    let now_epoch = now.timestamp();
    let now_rfc3339 = now.to_rfc3339();
    let claimed =
        match tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<ClaimedDelivery>> {
            let conn = af_db::get_conn()?;
            claim_due_deliveries_in_conn(&conn, now_epoch, &now_rfc3339, MAX_DELIVERIES_PER_TICK)
        })
        .await
        {
            Ok(Ok(items)) => items,
            Ok(Err(error)) => {
                tracing::warn!(%error, "Failed to claim due notification deliveries");
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "Notification delivery claim task panicked");
                return;
            }
        };

    if claimed.is_empty() {
        return;
    }

    stream::iter(claimed)
        .for_each_concurrent(MAX_CONCURRENT_DELIVERIES, |item| async move {
            let item_for_load = item.clone();
            let context_res = tokio::task::spawn_blocking(move || {
                let conn = af_db::get_read_conn().map_err(|_| {
                    ChannelDispatchError::transient(
                        "Database unavailable for channel lookup",
                        false,
                    )
                })?;
                load_delivery_context_in_conn(&conn, &item_for_load)
            })
            .await
            .unwrap_or_else(|_| {
                Err(ChannelDispatchError::transient(
                    "Channel lookup task failed",
                    false,
                ))
            });

            if tokio::time::Instant::now() >= dispatch_deadline {
                return;
            }
            let send_outcome = match context_res {
                Ok((_channel, prepared)) => match tokio::time::timeout_at(
                    dispatch_deadline,
                    send_prepared_channel_request(&prepared),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        tracing::warn!(
                            delivery_id = item.id,
                            "Notification claim expired before a delivery receipt"
                        );
                        return;
                    }
                },
                Err(err) => Err(err),
            };

            let finish = Utc::now();
            let finish_epoch = finish.timestamp();
            let finish_rfc3339 = finish.to_rfc3339();
            let item_for_commit = item.clone();
            let outcome_for_commit = send_outcome.clone();
            let commit_res =
                tokio::task::spawn_blocking(move || -> anyhow::Result<DeliveryReceiptCommit> {
                    let conn = af_db::get_conn()?;
                    complete_claimed_delivery_in_conn(
                        &conn,
                        &item_for_commit,
                        &outcome_for_commit,
                        finish_epoch,
                        &finish_rfc3339,
                    )
                })
                .await;

            match commit_res {
                Ok(Ok(DeliveryReceiptCommit::Committed(status))) => {
                    if status != "delivered" {
                        tracing::warn!(
                            delivery_id = item.id,
                            channel_id = item.channel_id,
                            channel_type = %item.channel_type,
                            notification_id = item.notification_id,
                            attempts = item.attempts,
                            status,
                            "Notification channel delivery did not complete cleanly"
                        );
                    }
                }
                Ok(Ok(DeliveryReceiptCommit::StaleClaim)) => {
                    tracing::warn!(
                        delivery_id = item.id,
                        channel_id = item.channel_id,
                        notification_id = item.notification_id,
                        attempts = item.attempts,
                        "Skipped stale notification delivery receipt commit after claim lease loss"
                    );
                }
                Ok(Err(error)) => {
                    // Explicit ambiguous-interval handling: if upstream already accepted the
                    // send, do NOT revert the row to pending; leave the fenced `sending` lease
                    // to reconcile under the bounded attempt/uncertain policy.
                    tracing::error!(
                        delivery_id = item.id,
                        channel_id = item.channel_id,
                        notification_id = item.notification_id,
                        attempts = item.attempts,
                        upstream_accepted = send_outcome.is_ok(),
                        %error,
                        "Failed to persist notification delivery receipt"
                    );
                }
                Err(error) => {
                    tracing::error!(
                        delivery_id = item.id,
                        channel_id = item.channel_id,
                        notification_id = item.notification_id,
                        attempts = item.attempts,
                        upstream_accepted = send_outcome.is_ok(),
                        %error,
                        "Notification delivery receipt task failed"
                    );
                }
            }
        })
        .await;
}

async fn evaluate_active_rules_once() {
    let now_epoch = Utc::now().timestamp();
    let rules = match tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<RuleWithCooldown>> {
        let conn = af_db::get_read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, condition_type, condition_value, COALESCE(level, 'warning'), \
                    COALESCE(enabled, 1) != 0, COALESCE(CAST(created_at AS TEXT), ''), last_triggered_at \
             FROM notification_rules WHERE COALESCE(enabled, 1) != 0",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(RuleWithCooldown {
                rule: af_services::NotificationRule {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    condition_type: r.get(2)?,
                    condition_value: r.get(3)?,
                    level: r.get(4)?,
                    enabled: r.get(5)?,
                    created_at: r.get(6)?,
                },
                last_triggered_at: r.get(7)?,
            })
        })?;
        let mut rules_vec = Vec::new();
        for row in rows {
            let rule = row?;
            if !is_rule_on_cooldown(rule.last_triggered_at, now_epoch, RULE_COOLDOWN_SECS) {
                rules_vec.push(rule);
            }
        }
        Ok(rules_vec)
    })
    .await
    {
        Ok(Ok(rules)) => rules,
        Ok(Err(error)) => {
            tracing::warn!(%error, "Failed to load active notification rules");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "Notification rule load task failed");
            return;
        }
    };

    if rules.is_empty() {
        return;
    }

    let metrics = af_hardware::get_system_metrics_core();
    let needs_services = rules
        .iter()
        .any(|entry| entry.rule.condition_type == "service_down");
    let active_services = if needs_services {
        tokio::task::spawn_blocking(af_services::get_active_services)
            .await
            .map_err(anyhow::Error::from)
            .and_then(|services| services)
            .inspect_err(|error| {
                tracing::warn!(%error, "Skipping service-down rules while service state is unknown");
            })
            .ok()
    } else {
        None
    };

    for entry in rules {
        let rule = entry.rule;
        let mut triggered = false;
        let mut message = String::new();

        match rule.condition_type.as_str() {
            "disk_usage" => {
                let Ok(threshold) = percentage_threshold(&rule.condition_value) else {
                    continue;
                };
                for disk in &metrics.disks {
                    if disk.used_pct >= threshold {
                        triggered = true;
                        message = format!(
                            "Disk {} is at {:.1}% usage",
                            disk.mount_point, disk.used_pct
                        );
                        break;
                    }
                }
            }
            "cpu_usage" => {
                let Ok(threshold) = percentage_threshold(&rule.condition_value) else {
                    continue;
                };
                if metrics.cpu_usage >= threshold {
                    triggered = true;
                    message = format!("CPU usage is at {:.1}%", metrics.cpu_usage);
                }
            }
            "memory_usage" => {
                let Ok(threshold) = percentage_threshold(&rule.condition_value) else {
                    continue;
                };
                if let Some(&total) = metrics.memory.get("total") {
                    if total > 0.0 {
                        let used = metrics.memory.get("used").copied().unwrap_or(0.0);
                        let pct = (used / total) * 100.0;
                        if pct >= threshold {
                            triggered = true;
                            message = format!("Memory usage is at {:.1}%", pct);
                        }
                    }
                }
            }
            "service_down" => {
                let target_svc = rule.condition_value.trim();
                if !target_svc.is_empty()
                    && service_down_confirmed(active_services.as_ref(), target_svc)
                {
                    triggered = true;
                    message = format!("Service {} is down", target_svc);
                }
            }
            _ => {}
        }

        if triggered {
            let trigger_epoch = Utc::now().timestamp();
            let rule_for_commit = rule.clone();
            let msg_for_commit = message.clone();
            let commit_res = tokio::task::spawn_blocking(move || {
                let conn = af_db::get_conn()?;
                commit_rule_trigger_in_conn(
                    &conn,
                    &rule_for_commit,
                    &msg_for_commit,
                    trigger_epoch,
                    RULE_COOLDOWN_SECS,
                )
            })
            .await;

            match commit_res {
                Ok(Ok(Some(committed))) => {
                    tracing::debug!(
                        rule_id = rule.id,
                        notification_id = committed.notification.id,
                        queued_deliveries = committed.queued_deliveries,
                        "Committed triggered notification rule and delivery intents"
                    );
                    broadcast_triggered_notification(&committed.notification);
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        rule_id = rule.id,
                        %error,
                        "Failed to admit triggered notification rule; rolled back without cooldown"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        rule_id = rule.id,
                        %error,
                        "Notification admission task failed"
                    );
                }
            }
        }
    }
}

pub fn start_notification_engine() {
    tokio::spawn(async move {
        // Resume committed unsent channel deliveries immediately on startup without
        // prematurely firing rules before system telemetry settles.
        drain_due_deliveries_once().await;

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip immediate tick 0 so rule evaluation waits for startup to settle.
        interval.tick().await;
        loop {
            interval.tick().await;
            evaluate_active_rules_once().await;
            drain_due_deliveries_once().await;
        }
    });
}

pub(super) fn service_down_confirmed(
    services: Option<&std::collections::HashMap<String, af_services::ServiceStatusItem>>,
    target: &str,
) -> bool {
    services.is_some_and(|services| {
        !services.iter().any(|(label, item)| {
            (label.eq_ignore_ascii_case(target) || item.process.eq_ignore_ascii_case(target))
                && item.status == "running"
        })
    })
}
