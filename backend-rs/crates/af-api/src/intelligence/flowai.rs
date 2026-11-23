use super::ai_providers::{
    ai_endpoint_origin_tuple, allow_user_cloud_ai_providers, call_anthropic_api, call_gemini_api,
    call_openai_compatible_api, infer_local_runtime, is_forbidden_model_alias,
    is_loopback_ai_endpoint, is_self_target_ai_endpoint, is_valid_gemini_model_id,
    is_valid_local_model_id, resolve_provider, resolve_provider_settings, sanitize_chat_history,
    split_runtime_prefixed_model, ChatMessage, ProposedAction, ALLOWED_AI_MODELS,
    DEFAULT_ANTHROPIC_LOCAL_ENDPOINT,
};
use super::telemetry::{get_system_metrics_context, AUDIT_LOG_FALLBACK_SQL};
use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::params;

fn contains_identifier_token(lower_text: &str, token: &str) -> bool {
    let bytes = lower_text.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    lower_text.match_indices(token).any(|(idx, _)| {
        let before_ok = idx == 0 || !is_ident(bytes[idx - 1]);
        let end = idx + token.len();
        let after_ok = end >= bytes.len() || !is_ident(bytes[end]);
        before_ok && after_ok
    })
}

fn contains_word_token(lower_text: &str, word: &str) -> bool {
    let bytes = lower_text.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'\'';
    lower_text.match_indices(word).any(|(idx, _)| {
        let before_ok = idx == 0 || !is_word(bytes[idx - 1]);
        let end = idx + word.len();
        let after_ok = end >= bytes.len() || !is_word(bytes[end]);
        before_ok && after_ok
    })
}

pub(super) fn extract_service_target(message: &str) -> &'static str {
    let lower = message.to_lowercase();
    for (alias, canonical) in [
        ("aetherflow-api", "aetherflow-api"),
        ("aetherflow-runner", "aetherflow-runner"),
        ("apache2", "apache2"),
        ("apache", "apache2"),
        ("nginx", "nginx"),
        ("postgresql", "postgresql"),
        ("postgres", "postgresql"),
        ("valkey", "valkey"),
        ("redis", "valkey"),
        ("qbittorrent", "qbittorrent"),
        ("qui", "qui"),
        ("autobrr", "autobrr"),
        ("sonarr", "sonarr"),
        ("radarr", "radarr"),
        ("lidarr", "lidarr"),
        ("prowlarr", "prowlarr"),
        ("plex", "plex"),
        ("jellyfin", "jellyfin"),
        ("emby", "emby"),
        ("threadfin", "threadfin"),
        ("dispatcharr", "dispatcharr"),
        ("transmission", "transmission"),
        ("deluge", "deluge"),
        ("jackett", "jackett"),
        ("wireguard", "wireguard"),
        ("tailscale", "tailscale"),
        ("traefik", "traefik"),
        ("duplicati", "duplicati"),
        ("filebot", "filebot"),
        ("listenarr", "listenarr"),
        ("notifiarr", "notifiarr"),
        ("novnc", "novnc"),
        ("pyload", "pyload"),
        ("quassel", "quassel"),
        ("requestrr", "requestrr"),
        ("seedcross", "seedcross"),
        ("unmanic", "unmanic"),
        ("x2go", "x2go"),
        ("invidious", "invidious"),
        ("piped", "piped"),
    ] {
        if contains_identifier_token(&lower, alias) {
            return canonical;
        }
    }
    "target service"
}

fn is_negated_or_interrogative_sentence(sentence_lower: &str) -> bool {
    if sentence_lower.contains('?') {
        return true;
    }
    for phrase in [
        "do not",
        "should not",
        "would not",
        "could not",
        "no need",
        "instead of",
    ] {
        if sentence_lower.contains(phrase) {
            return true;
        }
    }
    for neg in [
        "not",
        "don't",
        "dont",
        "never",
        "without",
        "avoid",
        "shouldn't",
        "shouldnt",
        "cannot",
        "can't",
        "cant",
        "won't",
        "wont",
    ] {
        if contains_word_token(sentence_lower, neg) {
            return true;
        }
    }
    false
}

pub(super) fn extract_proposed_action(
    ai_reply: &str,
    user_message: &str,
) -> Option<ProposedAction> {
    if ai_reply.trim().is_empty() {
        return None;
    }
    let fallback_target = {
        let from_reply = extract_service_target(ai_reply);
        if from_reply != "target service" {
            from_reply
        } else {
            extract_service_target(user_message)
        }
    };
    if fallback_target == "target service" {
        return None;
    }

    let specs: &[(&[&str], &str, &str, &str)] = &[
        (
            &["restart", "reboot"],
            "warn",
            "Restart",
            "Service will be temporarily unavailable during restart (5-30 seconds).",
        ),
        (
            &["stop", "shutdown"],
            "warn",
            "Stop",
            "Service will become unavailable until manually started.",
        ),
    ];

    for raw_sentence in ai_reply.split(['\n', '.', '!', ';']) {
        let sentence = raw_sentence.trim().to_lowercase();
        if sentence.is_empty() || is_negated_or_interrogative_sentence(&sentence) {
            continue;
        }
        let sentence_target = {
            let t = extract_service_target(&sentence);
            if t != "target service" {
                t
            } else {
                fallback_target
            }
        };
        for (keywords, classification, verb, impact) in specs {
            for kw in *keywords {
                if contains_word_token(&sentence, kw) {
                    let title = format!("{} {}", verb, sentence_target);
                    return Some(ProposedAction {
                        action_type: "system_action".to_string(),
                        action_id: 0,
                        title: title.clone(),
                        description: format!("AI-proposed: {}", title),
                        danger_level: (*classification).to_string(),
                        impact: (*impact).to_string(),
                    });
                }
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_chat_session(
    user: Option<AuthUser>,
    ip: &str,
    ua: &str,
    system_prompt_override: &str,
    model_override: &str,
    provider_hint: &str,
    history: Vec<ChatMessage>,
    message: String,
) -> Response {
    let ps = resolve_provider_settings();
    let trimmed_override = model_override.trim();
    let (override_rt, clean_override) = split_runtime_prefixed_model(trimmed_override);

    if !trimmed_override.is_empty() && is_forbidden_model_alias(clean_override) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid AI model: provider or locality aliases cannot be used as model identifiers.",
        );
    }

    let effective_hint = if !provider_hint.trim().is_empty() {
        provider_hint.trim()
    } else if let Some(rt) = override_rt {
        rt
    } else if !ps.local_provider.is_empty() && trimmed_override.is_empty() {
        ps.local_provider.as_str()
    } else {
        ""
    };

    let ai_model = if !clean_override.is_empty() {
        clean_override.to_string()
    } else if !ps.local_model.is_empty()
        && matches!(
            effective_hint,
            "localai" | "lm-studio" | "ollama" | "anthropic-local"
        )
    {
        ps.local_model.clone()
    } else {
        ps.default_model.clone()
    };

    if is_forbidden_model_alias(&ai_model) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid AI model. Check settings for available models.",
        );
    }

    let provider_type = resolve_provider(effective_hint, &ai_model);
    if provider_type == "localai" {
        if !is_valid_local_model_id(&ai_model) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid AI model. Check settings for available models.",
            );
        }
    } else if !ALLOWED_AI_MODELS.contains(&ai_model.as_str()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid AI model. Check settings for available models.",
        );
    }

    let is_admin = user.as_ref().is_some_and(|u| u.role == "admin");
    let uses_paid_cloud_dispatch = match provider_type {
        "openai" | "gemini" => true,
        "anthropic" => {
            !ps.anthropic_api_key.trim().is_empty()
                || ps.anthropic_endpoint.trim().is_empty()
                || !is_loopback_ai_endpoint(&ps.anthropic_endpoint)
        }
        "localai" => false,
        _ => true,
    };
    if uses_paid_cloud_dispatch && !is_admin && !allow_user_cloud_ai_providers() {
        return api_error(
            StatusCode::FORBIDDEN,
            "AI_PROVIDER_ADMIN_ONLY",
            "Cloud AI providers are restricted to administrators",
        );
    }

    let prompt = if !system_prompt_override.is_empty() {
        system_prompt_override.to_string()
    } else if is_admin {
        format!(
            "{}\n\nLive system telemetry from this AetherFlow server is attached below:\n\n{}",
            ps.system_prompt,
            get_system_metrics_context()
        )
    } else {
        ps.system_prompt.clone()
    };

    let result = match provider_type {
        "openai" => {
            if ps.openai_api_key.is_empty() {
                Err(anyhow::anyhow!(
                    "AI provider initialization failed: openai API key not configured. Set it in Settings \u{2192} FlowAI Engine"
                ))
            } else {
                call_openai_compatible_api(
                    "https://api.openai.com",
                    &ps.openai_api_key,
                    &ai_model,
                    &prompt,
                    &history,
                    &message,
                )
                .await
            }
        }
        "anthropic" => {
            if !ps.anthropic_endpoint.trim().is_empty()
                && is_self_target_ai_endpoint(&ps.anthropic_endpoint)
            {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "AI_SELF_TARGET_REJECTED",
                    "AI endpoint cannot target the AetherFlow API server itself",
                );
            }
            call_anthropic_api(
                &ps.anthropic_endpoint,
                &ps.anthropic_api_key,
                &ai_model,
                &prompt,
                &history,
                &message,
            )
            .await
        }
        "localai" => {
            let local_runtime = infer_local_runtime(effective_hint, &ps);
            match local_runtime {
                "anthropic-local" => {
                    let endpoint = if !ps.anthropic_endpoint.trim().is_empty() {
                        ps.anthropic_endpoint.trim().to_string()
                    } else {
                        DEFAULT_ANTHROPIC_LOCAL_ENDPOINT.to_string()
                    };
                    if is_self_target_ai_endpoint(&endpoint) {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AI_SELF_TARGET_REJECTED",
                            "AI endpoint cannot target the AetherFlow API server itself",
                        );
                    }
                    call_anthropic_api(&endpoint, "", &ai_model, &prompt, &history, &message).await
                }
                "ollama" => {
                    let endpoint = if !ps.ollama_endpoint.trim().is_empty() {
                        ps.ollama_endpoint.trim().to_string()
                    } else {
                        "http://localhost:11434".to_string()
                    };
                    if is_self_target_ai_endpoint(&endpoint) {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AI_SELF_TARGET_REJECTED",
                            "AI endpoint cannot target the AetherFlow API server itself",
                        );
                    }
                    call_openai_compatible_api(
                        &endpoint, "", &ai_model, &prompt, &history, &message,
                    )
                    .await
                }
                _ => {
                    let endpoint = if !ps.lm_studio_endpoint.trim().is_empty() {
                        ps.lm_studio_endpoint.trim().to_string()
                    } else {
                        "http://localhost:1234".to_string()
                    };
                    if is_self_target_ai_endpoint(&endpoint) {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AI_SELF_TARGET_REJECTED",
                            "AI endpoint cannot target the AetherFlow API server itself",
                        );
                    }
                    call_openai_compatible_api(
                        &endpoint, "", &ai_model, &prompt, &history, &message,
                    )
                    .await
                }
            }
        }
        _ => call_gemini_api(&ps.gemini_api_key, &ai_model, &prompt, &history, &message).await,
    };

    let reply_text = match result {
        Ok(t) if !t.trim().is_empty() => t,
        Ok(_) => "I received an empty response. Please try again.".to_string(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                provider = provider_type,
                model = %ai_model,
                "FlowAI chat generation failed"
            );
            let msg = if is_admin {
                format!(
                    "Generation error: {}",
                    af_services::redact_secrets(&e.to_string())
                )
            } else {
                "AI generation failed due to an upstream provider error. Please try again later."
                    .to_string()
            };
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg);
        }
    };

    if is_admin {
        if let Some(mut proposal) = extract_proposed_action(&reply_text, &message) {
            // Invariant: only advertise a proposal or record its audit event after
            // SQLite commits a positive pending_actions row ID.
            match af_db::queue_action(
                &proposal.danger_level,
                "FlowAI",
                &proposal.title,
                &proposal.description,
            ) {
                af_db::QueueActionOutcome::Queued { action_id } if action_id > 0 => {
                    proposal.action_id = action_id;
                    let (uid, uname) = user
                        .map(|u| (u.user_id, u.username))
                        .unwrap_or((0, "anonymous".to_string()));
                    af_db::record_audit(
                        uid,
                        &uname,
                        "ai_action_proposed",
                        "pending_action",
                        &action_id.to_string(),
                        &format!(
                            "classification={} title={}",
                            proposal.danger_level, proposal.title
                        ),
                        ip,
                        ua,
                    );
                    return Json(serde_json::json!({
                        "reply": reply_text,
                        "proposed_action": proposal,
                    }))
                    .into_response();
                }
                af_db::QueueActionOutcome::CapacityReached {
                    pending_count,
                    limit,
                } => {
                    tracing::warn!(
                        pending_count,
                        limit,
                        title = %proposal.title,
                        "FlowAI proposed action skipped: Approval Inbox pending cap reached"
                    );
                }
                af_db::QueueActionOutcome::DbError(error) => {
                    tracing::warn!(
                        %error,
                        title = %proposal.title,
                        "FlowAI proposed action persistence failed; returning plain chat reply"
                    );
                }
                af_db::QueueActionOutcome::SkippedSafe
                | af_db::QueueActionOutcome::AlreadyPending
                | af_db::QueueActionOutcome::Queued { .. } => {}
            }
        }
    }

    Json(serde_json::json!({ "reply": reply_text })).into_response()
}

pub async fn ai_chat(req: Request) -> Response {
    let user = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 512 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if message.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "message is required",
        );
    }
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let history = sanitize_chat_history(
        body.get("history")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
    );

    run_chat_session(user, &ip, &ua, "", &model, &provider, history, message).await
}

fn sanitize_bounded_support_text(raw: &str, max_bytes: usize) -> String {
    let redacted = af_services::redact_secrets(raw);
    let cleaned: String = redacted
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect();
    if cleaned.len() <= max_bytes {
        return cleaned;
    }
    let mut end = max_bytes;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = cleaned[..end].to_string();
    out.push_str("\n...[truncated]");
    out
}

fn format_support_metrics_snapshot(snapshot: &serde_json::Value) -> Option<String> {
    if snapshot.is_null() {
        return None;
    }
    let serialized = match snapshot {
        serde_json::Value::String(s) => s.trim().to_string(),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    };
    if serialized.is_empty() {
        return None;
    }
    Some(sanitize_bounded_support_text(&serialized, 4096))
}

fn format_support_system_logs(raw_logs: &serde_json::Value) -> Option<String> {
    if raw_logs.is_null() {
        return None;
    }
    let text = match raw_logs {
        serde_json::Value::String(s) => s.trim().to_string(),
        serde_json::Value::Array(items) => items
            .iter()
            .rev()
            .take(100)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .filter_map(|item| match item {
                serde_json::Value::String(s) => Some(s.trim().to_string()),
                serde_json::Value::Object(_) => serde_json::to_string(item).ok(),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    };
    if text.is_empty() {
        return None;
    }
    Some(sanitize_bounded_support_text(&text, 8192))
}

fn load_recent_audit_log_context() -> Option<String> {
    let conn = match af_db::get_read_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "Unable to open SQLite for recent audit log support context");
            return None;
        }
    };
    let mut stmt = match conn.prepare(AUDIT_LOG_FALLBACK_SQL) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(%err, "Unable to prepare audit log fallback query for support context");
            return None;
        }
    };
    let rows_res = stmt.query_map(params![25i64], |row| {
        let ts: String = row.get(0)?;
        let action: String = row.get(1)?;
        let target: String = row.get(2)?;
        let detail: String = row.get(3)?;
        Ok(format!("[{}] {} ({}) {}", ts, action, target, detail))
    });
    let rows: Vec<String> = match rows_res {
        Ok(iter) => match iter.collect::<rusqlite::Result<Vec<_>>>() {
            Ok(items) => items,
            Err(err) => {
                tracing::warn!(%err, "Failed to decode audit log row for support context");
                return None;
            }
        },
        Err(err) => {
            tracing::warn!(%err, "Failed to query audit log rows for support context");
            return None;
        }
    };
    if rows.is_empty() {
        return None;
    }
    Some(sanitize_bounded_support_text(&rows.join("\n"), 4096))
}

pub(super) fn build_support_prompt(
    base_prompt: &str,
    context_mode: &str,
    body: &serde_json::Value,
) -> String {
    let mut sections = Vec::new();
    let include_metrics = matches!(context_mode, "metrics" | "full");
    let include_logs = matches!(context_mode, "logs" | "full");

    if include_metrics {
        sections.push(get_system_metrics_context());
        if let Some(snapshot) = body
            .get("metrics_snapshot")
            .and_then(format_support_metrics_snapshot)
        {
            sections.push(format!(
                "=== CLIENT METRICS SNAPSHOT ===\n{}\n=== END METRICS SNAPSHOT ===",
                snapshot
            ));
        }
    }

    if include_logs {
        if let Some(client_logs) = body.get("system_logs").and_then(format_support_system_logs) {
            sections.push(format!(
                "=== SYSTEM LOGS ===\n{}\n=== END SYSTEM LOGS ===",
                client_logs
            ));
        } else if let Some(audit_logs) = load_recent_audit_log_context() {
            sections.push(format!(
                "=== RECENT AUDIT LOGS ===\n{}\n=== END RECENT AUDIT LOGS ===",
                audit_logs
            ));
        }
    }

    format!(
        "{}\n\nYou are in SUPPORT MODE (context_mode={}). The user is troubleshooting a server issue. Use the following live system data to help diagnose problems:\n\n{}\n\nAnalyze the above data in context of the user's question.",
        base_prompt,
        context_mode,
        sections.join("\n\n")
    )
}

pub async fn ai_support(req: Request) -> Response {
    let user = req.extensions().get::<AuthUser>().cloned();
    if user.as_ref().map(|u| u.role.as_str()) != Some("admin") {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Forbidden: Admin access required for AI support diagnostics",
        );
    }
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 512 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if message.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "message is required",
        );
    }
    let context_mode = body
        .get("context_mode")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("full");
    if !["logs", "metrics", "full"].contains(&context_mode) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid context_mode. Allowed: logs, metrics, full",
        );
    }
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let history = sanitize_chat_history(
        body.get("history")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
    );

    let ps = resolve_provider_settings();
    let support_prompt = build_support_prompt(&ps.system_prompt, context_mode, &body);

    run_chat_session(
        user,
        &ip,
        &ua,
        &support_prompt,
        &model,
        &provider,
        history,
        message,
    )
    .await
}

fn is_openai_model_id(model: &str) -> bool {
    let m = model.trim();
    m.starts_with("gpt-") || m == "o3" || m.starts_with("o3-") || m.starts_with("o4-")
}

fn is_anthropic_model_id(model: &str) -> bool {
    model.trim().starts_with("claude-")
}

pub async fn test_ai_connection(
    axum::Extension(user): axum::Extension<AuthUser>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let mut ps = resolve_provider_settings();
    let stored_anth_endpoint = if ps.anthropic_endpoint.trim().is_empty() {
        "https://api.anthropic.com".to_string()
    } else {
        ps.anthropic_endpoint.trim().to_string()
    };
    let had_stored_anth_key = !ps.anthropic_api_key.trim().is_empty();
    let mut supplied_fresh_anth_key = false;

    let provider_type = req
        .get("provider")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("gemini");

    if let Some(k) = req
        .get("gemini_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****") && *s != af_db::SECRET_MASK)
    {
        ps.gemini_api_key = k.to_string();
    }
    if let Some(k) = req
        .get("openai_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****") && *s != af_db::SECRET_MASK)
    {
        ps.openai_api_key = k.to_string();
    }
    if let Some(k) = req
        .get("anthropic_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****") && *s != af_db::SECRET_MASK)
    {
        ps.anthropic_api_key = k.to_string();
        supplied_fresh_anth_key = true;
    }
    if let Some(ep) = req
        .get("endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if is_self_target_ai_endpoint(ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        if is_self_target_ai_endpoint(&clean_ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        let wants_anth = matches!(provider_type, "anthropic" | "anthropic-local")
            || req
                .get("local_provider")
                .and_then(|v| v.as_str())
                .is_some_and(|lp| lp.trim() == "anthropic-local");
        if wants_anth {
            ps.anthropic_endpoint = clean_ep.clone();
        }
        ps.lm_studio_endpoint = clean_ep.clone();
        ps.ollama_endpoint = clean_ep;
    }
    if let Some(ep) = req
        .get("anthropic_endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if is_self_target_ai_endpoint(ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        if is_self_target_ai_endpoint(&clean_ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        ps.anthropic_endpoint = clean_ep;
    }
    if let Some(ep) = req
        .get("lm_studio_endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if is_self_target_ai_endpoint(ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        if is_self_target_ai_endpoint(&clean_ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        ps.lm_studio_endpoint = clean_ep;
    }
    if let Some(ep) = req
        .get("ollama_endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if is_self_target_ai_endpoint(ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        if is_self_target_ai_endpoint(&clean_ep) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "AI_SELF_TARGET_REJECTED",
                "AI endpoint cannot target the AetherFlow API server itself",
            );
        }
        ps.ollama_endpoint = clean_ep;
    }

    let is_local_provider = matches!(
        provider_type,
        "localai" | "lm-studio" | "ollama" | "anthropic-local"
    );
    let explicit_local_rt = req
        .get("local_provider")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(provider_type);
    let is_anthropic_local_test =
        is_local_provider && infer_local_runtime(explicit_local_rt, &ps) == "anthropic-local";

    let next_anth_endpoint = if !ps.anthropic_endpoint.trim().is_empty() {
        ps.anthropic_endpoint.trim()
    } else if is_anthropic_local_test {
        DEFAULT_ANTHROPIC_LOCAL_ENDPOINT
    } else {
        "https://api.anthropic.com"
    };
    let anth_origin_changed = ai_endpoint_origin_tuple(&stored_anth_endpoint)
        != ai_endpoint_origin_tuple(next_anth_endpoint);
    if is_anthropic_local_test {
        // Local Anthropic-compatible runtimes never attach paid cloud API keys.
        ps.anthropic_api_key.clear();
    } else if had_stored_anth_key && !supplied_fresh_anth_key && anth_origin_changed {
        return api_error(
            StatusCode::BAD_REQUEST,
            "ENDPOINT_KEY_REBIND_DENIED",
            "Changing anthropic_endpoint while an API key is stored requires supplying a fresh API key",
        );
    }
    if !ps.anthropic_api_key.trim().is_empty()
        && !next_anth_endpoint.starts_with("https://")
        && !is_loopback_ai_endpoint(next_anth_endpoint)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INSECURE_AI_ENDPOINT",
            "Non-loopback AI endpoints carrying an API key must use https://",
        );
    }

    let requested_model = req
        .get("model")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(m) = requested_model {
        let (_, clean_m) = split_runtime_prefixed_model(m);
        if is_forbidden_model_alias(clean_m) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid AI model: provider or locality aliases cannot be used as model identifiers",
            );
        }
    }

    let res = match provider_type {
        "openai" => {
            if let Some(m) = requested_model {
                if !is_openai_model_id(m) {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        format!("Model '{m}' is not compatible with provider 'openai'"),
                    );
                }
            }
            let model = requested_model.unwrap_or_else(|| {
                if ALLOWED_AI_MODELS.contains(&ps.default_model.as_str())
                    && is_openai_model_id(&ps.default_model)
                {
                    ps.default_model.as_str()
                } else {
                    "gpt-6.1-sol"
                }
            });
            if !ALLOWED_AI_MODELS.contains(&model) || !is_openai_model_id(model) {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid AI model");
            }
            call_openai_compatible_api(
                "https://api.openai.com",
                &ps.openai_api_key,
                model,
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
        "anthropic" => {
            if let Some(m) = requested_model {
                if !is_anthropic_model_id(m) {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        format!("Model '{m}' is not compatible with provider 'anthropic'"),
                    );
                }
            }
            let model = requested_model.unwrap_or_else(|| {
                if ALLOWED_AI_MODELS.contains(&ps.default_model.as_str())
                    && is_anthropic_model_id(&ps.default_model)
                {
                    ps.default_model.as_str()
                } else {
                    "claude-sonnet-5-5"
                }
            });
            if !ALLOWED_AI_MODELS.contains(&model) || !is_anthropic_model_id(model) {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid AI model");
            }
            if !ps.anthropic_endpoint.trim().is_empty()
                && is_self_target_ai_endpoint(&ps.anthropic_endpoint)
            {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "AI_SELF_TARGET_REJECTED",
                    "AI endpoint cannot target the AetherFlow API server itself",
                );
            }
            call_anthropic_api(
                &ps.anthropic_endpoint,
                &ps.anthropic_api_key,
                model,
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
        "localai" | "lm-studio" | "ollama" | "anthropic-local" => {
            let local_runtime = infer_local_runtime(explicit_local_rt, &ps);
            let local_model = if let Some(m) = requested_model {
                let (_, clean_m) = split_runtime_prefixed_model(m);
                clean_m
            } else if !ps.local_model.is_empty() {
                ps.local_model.as_str()
            } else if !is_forbidden_model_alias(&ps.default_model)
                && !ALLOWED_AI_MODELS.contains(&ps.default_model.as_str())
            {
                ps.default_model.as_str()
            } else {
                "qwen2.5-coder:7b"
            };
            if !is_valid_local_model_id(local_model) {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid local AI model identifier",
                );
            }
            match local_runtime {
                "anthropic-local" => {
                    let ep = if !ps.anthropic_endpoint.trim().is_empty() {
                        ps.anthropic_endpoint.trim().to_string()
                    } else {
                        DEFAULT_ANTHROPIC_LOCAL_ENDPOINT.to_string()
                    };
                    if is_self_target_ai_endpoint(&ep) {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AI_SELF_TARGET_REJECTED",
                            "AI endpoint cannot target the AetherFlow API server itself",
                        );
                    }
                    call_anthropic_api(
                        &ep,
                        "",
                        local_model,
                        "",
                        &[],
                        "Reply with the exact word: SUCCESS",
                    )
                    .await
                }
                "ollama" => {
                    let ep = if !ps.ollama_endpoint.trim().is_empty() {
                        ps.ollama_endpoint.trim().to_string()
                    } else {
                        "http://localhost:11434".to_string()
                    };
                    if is_self_target_ai_endpoint(&ep) {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AI_SELF_TARGET_REJECTED",
                            "AI endpoint cannot target the AetherFlow API server itself",
                        );
                    }
                    call_openai_compatible_api(
                        &ep,
                        "",
                        local_model,
                        "",
                        &[],
                        "Reply with the exact word: SUCCESS",
                    )
                    .await
                }
                _ => {
                    let ep = if !ps.lm_studio_endpoint.trim().is_empty() {
                        ps.lm_studio_endpoint.trim().to_string()
                    } else {
                        "http://localhost:1234".to_string()
                    };
                    if is_self_target_ai_endpoint(&ep) {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AI_SELF_TARGET_REJECTED",
                            "AI endpoint cannot target the AetherFlow API server itself",
                        );
                    }
                    call_openai_compatible_api(
                        &ep,
                        "",
                        local_model,
                        "",
                        &[],
                        "Reply with the exact word: SUCCESS",
                    )
                    .await
                }
            }
        }
        _ => {
            if let Some(m) = requested_model {
                if !is_valid_gemini_model_id(m) {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        format!("Model '{m}' is not compatible with provider 'gemini'"),
                    );
                }
            }
            let model = requested_model.unwrap_or_else(|| {
                if ALLOWED_AI_MODELS.contains(&ps.default_model.as_str())
                    && is_valid_gemini_model_id(&ps.default_model)
                {
                    ps.default_model.as_str()
                } else {
                    "gemini-4-argon"
                }
            });
            if !ALLOWED_AI_MODELS.contains(&model) || !is_valid_gemini_model_id(model) {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid AI model");
            }
            call_gemini_api(
                &ps.gemini_api_key,
                model,
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
    };

    match res {
        Ok(_) => Json(serde_json::json!({
            "message": format!("{} connection successful", provider_type),
        }))
        .into_response(),
        Err(e) => api_error(
            StatusCode::BAD_GATEWAY,
            "AI_CONNECTION_FAILED",
            format!(
                "Connection test failed: {}",
                af_services::redact_secrets(&e.to_string())
            ),
        ),
    }
}
