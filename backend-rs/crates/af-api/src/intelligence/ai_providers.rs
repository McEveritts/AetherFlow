use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};
use std::env;

pub(super) static ALLOWED_AI_MODELS: &[&str] = &[
    "gemini-4-argon",
    "gemini-4-carbon",
    "gemini-4-neon",
    "gemini-4-hydrogen",
    "gemini-3.1-pro-preview",
    "gemini-3-flash-preview",
    "gemini-3.1-flash-lite-preview",
    "gemini-3-pro-image-preview",
    "gemini-3.1-flash-image-preview",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
    "gpt-6-astra",
    "gpt-6.2-astra",
    "gpt-6.1-sol",
    "gpt-6.2-sol",
    "gpt-6.1-terra",
    "gpt-6-luna",
    "gpt-4o",
    "gpt-4o-mini",
    "o3",
    "claude-fable-5-1",
    "claude-opus-5-6",
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
    "claude-sonnet-4-5",
    "claude-opus-4-6",
];

static FORBIDDEN_MODEL_ALIASES: &[&str] = &[
    "lm-studio",
    "ollama",
    "anthropic-local",
    "localai",
    "local-test",
    "local",
    "gemini",
    "openai",
    "anthropic",
];

pub(crate) fn is_forbidden_model_alias(model_id: &str) -> bool {
    let trimmed = model_id.trim();
    trimmed.is_empty()
        || FORBIDDEN_MODEL_ALIASES
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(trimmed))
}

pub(crate) fn is_valid_local_model_id(model_id: &str) -> bool {
    let trimmed = model_id.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 128
        && !is_forbidden_model_alias(trimmed)
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/' | '@'))
}

pub(super) fn is_valid_gemini_model_id(model_id: &str) -> bool {
    let trimmed = model_id.trim();
    trimmed.starts_with("gemini-")
        && trimmed.len() <= 128
        && !trimmed.contains("..")
        && !is_forbidden_model_alias(trimmed)
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn build_versioned_endpoint_url(validated_base: &str, v1_subpath: &str) -> String {
    let trimmed = validated_base.trim_end_matches('/');
    let without_v1 = trimmed
        .strip_suffix("/v1")
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    let clean_subpath = v1_subpath.trim_start_matches('/');
    format!("{without_v1}/v1/{clean_subpath}")
}

pub(super) fn split_runtime_prefixed_model(raw: &str) -> (Option<&'static str>, &str) {
    let trimmed = raw.trim();
    for runtime in ["lm-studio", "ollama", "anthropic-local"] {
        if let Some(rest) = trimmed.strip_prefix(runtime) {
            if let Some(model_part) = rest.strip_prefix(':') {
                let model_trimmed = model_part.trim();
                if !model_trimmed.is_empty() {
                    return (Some(runtime), model_trimmed);
                }
            }
        }
    }
    (None, trimmed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    #[serde(rename = "type")]
    pub action_type: String,
    pub action_id: i64,
    pub title: String,
    pub description: String,
    pub danger_level: String,
    pub impact: String,
}

#[derive(Debug, Clone)]
pub struct ProviderSettings {
    pub gemini_api_key: String,
    pub openai_api_key: String,
    pub anthropic_api_key: String,
    pub anthropic_endpoint: String,
    pub lm_studio_endpoint: String,
    pub ollama_endpoint: String,
    pub default_model: String,
    pub local_provider: String,
    pub local_model: String,
    pub system_prompt: String,
}

pub(super) fn select_gemini_model_from_setting(raw_ai_model: Option<&str>) -> String {
    if let Some(m) = raw_ai_model.map(str::trim).filter(|s| !s.is_empty()) {
        if is_valid_gemini_model_id(m) {
            return m.to_string();
        }
    }
    "gemini-2.5-flash".to_string()
}

pub(super) fn resolve_configured_gemini_model() -> String {
    let configured = af_db::get_read_conn().ok().and_then(|conn| {
        conn.query_row(
            "SELECT COALESCE(ai_model, '') FROM settings WHERE id = 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()
    });
    select_gemini_model_from_setting(configured.as_deref())
}

pub fn resolve_provider_settings() -> ProviderSettings {
    let mut ps = ProviderSettings {
        gemini_api_key: String::new(),
        openai_api_key: String::new(),
        anthropic_api_key: String::new(),
        anthropic_endpoint: String::new(),
        lm_studio_endpoint: String::new(),
        ollama_endpoint: String::new(),
        default_model: "gemini-4-argon".to_string(),
        local_provider: String::new(),
        local_model: String::new(),
        system_prompt: "You are FlowAI, a helpful server assistant.".to_string(),
    };

    match af_db::get_read_conn() {
        Ok(conn) => {
            if let Err(err) = conn
                .query_row(
                    "SELECT COALESCE(gemini_api_key, ''), COALESCE(openai_api_key, ''), COALESCE(anthropic_api_key, ''), \
                     COALESCE(anthropic_endpoint, ''), COALESCE(lm_studio_endpoint, ''), COALESCE(ollama_endpoint, ''), \
                     COALESCE(ai_model, ''), COALESCE(system_prompt, ''), \
                     COALESCE(local_provider, ''), COALESCE(local_model, '') FROM settings WHERE id = 1",
                    [],
                    |r| {
                        ps.gemini_api_key = r.get(0)?;
                        ps.openai_api_key = r.get(1)?;
                        ps.anthropic_api_key = r.get(2)?;
                        ps.anthropic_endpoint = r.get(3)?;
                        ps.lm_studio_endpoint = r.get(4)?;
                        ps.ollama_endpoint = r.get(5)?;
                        let m: String = r.get(6)?;
                        let trimmed_m = m.trim();
                        if !trimmed_m.is_empty() {
                            let (prefixed_rt, clean_m) = split_runtime_prefixed_model(trimmed_m);
                            if let Some(rt) = prefixed_rt {
                                ps.local_provider = rt.to_string();
                                ps.default_model = clean_m.to_string();
                                if !is_forbidden_model_alias(clean_m) {
                                    ps.local_model = clean_m.to_string();
                                }
                            } else if matches!(trimmed_m, "lm-studio" | "ollama" | "anthropic-local") {
                                ps.local_provider = trimmed_m.to_string();
                                ps.default_model = trimmed_m.to_string();
                            } else {
                                ps.default_model = clean_m.to_string();
                                if !ALLOWED_AI_MODELS.contains(&clean_m)
                                    && is_valid_local_model_id(clean_m)
                                {
                                    ps.local_model = clean_m.to_string();
                                }
                            }
                        }
                        let sp: String = r.get(7)?;
                        if !sp.is_empty() {
                            ps.system_prompt = sp;
                        }
                        let local_provider: String = r.get(8)?;
                        let local_model: String = r.get(9)?;
                        if is_valid_local_model_id(local_model.trim()) {
                            ps.local_model = local_model.trim().to_owned();
                        }
                        if !ALLOWED_AI_MODELS.contains(&ps.default_model.as_str())
                            && matches!(
                                local_provider.trim(),
                                "lm-studio" | "ollama" | "anthropic-local"
                            )
                        {
                            ps.local_provider = local_provider.trim().to_owned();
                        }
                        Ok(())
                    },
                )
                .optional()
            {
                tracing::warn!(%err, "Failed to read AI provider settings from SQLite; falling back to defaults/env");
            }
        }
        Err(err) => {
            tracing::warn!(%err, "SQLite unavailable when reading AI provider settings; falling back to defaults/env");
        }
    }

    if !ps.gemini_api_key.is_empty() {
        ps.gemini_api_key = af_db::decrypt_key(&ps.gemini_api_key).unwrap_or_default();
    }
    if !ps.openai_api_key.is_empty() {
        ps.openai_api_key = af_db::decrypt_key(&ps.openai_api_key).unwrap_or_default();
    }
    if !ps.anthropic_api_key.is_empty() {
        ps.anthropic_api_key = af_db::decrypt_key(&ps.anthropic_api_key).unwrap_or_default();
    }

    if ps.gemini_api_key.is_empty() {
        ps.gemini_api_key = env::var("GEMINI_API_KEY").unwrap_or_default();
    }
    if ps.openai_api_key.is_empty() {
        ps.openai_api_key = env::var("OPENAI_API_KEY").unwrap_or_default();
    }
    if ps.anthropic_api_key.is_empty() {
        ps.anthropic_api_key = env::var("ANTHROPIC_API_KEY").unwrap_or_default();
    }
    if ps.ollama_endpoint.trim().is_empty() {
        ps.ollama_endpoint = env::var("OLLAMA_ENDPOINT")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default();
    }
    if ps.lm_studio_endpoint.trim().is_empty() {
        ps.lm_studio_endpoint = env::var("LM_STUDIO_ENDPOINT")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default();
    }

    ps
}

fn sanitize_chat_history_role(raw_role: &str) -> &'static str {
    match raw_role.trim().to_ascii_lowercase().as_str() {
        "assistant" | "model" => "assistant",
        _ => "user",
    }
}

pub(super) fn sanitize_chat_history(history: Vec<ChatMessage>) -> Vec<ChatMessage> {
    history
        .into_iter()
        .map(|mut msg| {
            msg.role = sanitize_chat_history_role(&msg.role).to_string();
            msg
        })
        .collect()
}

pub(super) fn infer_local_runtime(provider_hint: &str, ps: &ProviderSettings) -> &'static str {
    match provider_hint.trim() {
        "ollama" => return "ollama",
        "lm-studio" => return "lm-studio",
        "anthropic-local" => return "anthropic-local",
        _ => {}
    }
    match ps.local_provider.as_str() {
        "ollama" => return "ollama",
        "lm-studio" => return "lm-studio",
        "anthropic-local" => return "anthropic-local",
        _ => {}
    }
    let anthropic_ep = ps.anthropic_endpoint.trim();
    if !anthropic_ep.is_empty() && anthropic_ep != "https://api.anthropic.com" {
        return "anthropic-local";
    }
    let ollama_ep = ps.ollama_endpoint.trim();
    let lm_ep = ps.lm_studio_endpoint.trim();
    if !ollama_ep.is_empty()
        && ollama_ep != "http://localhost:11434"
        && (lm_ep.is_empty() || lm_ep == "http://localhost:1234")
    {
        return "ollama";
    }
    "lm-studio"
}

pub(super) fn resolve_provider(provider_hint: &str, model_id: &str) -> &'static str {
    match provider_hint.trim() {
        "gemini" => return "gemini",
        "openai" => return "openai",
        "anthropic" => return "anthropic",
        "localai" | "lm-studio" | "ollama" | "anthropic-local" => return "localai",
        _ => {}
    }
    if model_id.starts_with("gemini") {
        "gemini"
    } else if model_id.starts_with("gpt")
        || model_id == "o3"
        || model_id.starts_with("o3-")
        || model_id.starts_with("o4-")
    {
        "openai"
    } else if model_id.starts_with("claude") {
        "anthropic"
    } else if !ALLOWED_AI_MODELS.contains(&model_id) && is_valid_local_model_id(model_id) {
        "localai"
    } else {
        "gemini"
    }
}

const MAX_AI_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

async fn read_bounded_ai_response_bytes(mut resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > MAX_AI_RESPONSE_BYTES as u64 {
            anyhow::bail!(
                "AI response payload exceeds {} byte limit",
                MAX_AI_RESPONSE_BYTES
            );
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len().saturating_add(chunk.len()) > MAX_AI_RESPONSE_BYTES {
            anyhow::bail!(
                "AI response payload exceeds {} byte limit",
                MAX_AI_RESPONSE_BYTES
            );
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

pub(super) async fn call_gemini_api(
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    let clean_model = model_name.trim();
    if !is_valid_gemini_model_id(clean_model) {
        anyhow::bail!("Invalid Gemini model identifier '{}'", clean_model);
    }
    if api_key.trim().is_empty() {
        anyhow::bail!("gemini API key not configured. Set it in Settings \u{2192} FlowAI Engine");
    }
    let client = af_services::streaming_http_client_builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()?;

    let mut contents = Vec::new();
    for hm in history {
        let role = if sanitize_chat_history_role(&hm.role) == "assistant" {
            "model"
        } else {
            "user"
        };
        contents.push(serde_json::json!({
            "role": role,
            "parts": [{ "text": hm.text }],
        }));
    }
    contents.push(serde_json::json!({
        "role": "user",
        "parts": [{ "text": message }],
    }));

    let mut body = serde_json::json!({ "contents": contents });
    if !system_prompt.trim().is_empty() {
        body["systemInstruction"] = serde_json::json!({
            "parts": [{ "text": system_prompt }]
        });
    }

    let send_for_model = |m: &str| {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
            m
        );
        client
            .post(url)
            .header("x-goog-api-key", api_key.trim())
            .json(&body)
            .send()
    };

    let mut resp = send_for_model(clean_model).await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND && clean_model == "gemini-4-argon" {
        resp = send_for_model("gemini-2.5-pro").await?;
    }

    let status = resp.status();
    let raw_bytes = read_bounded_ai_response_bytes(resp).await?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&raw_bytes);
        anyhow::bail!("gemini API error ({}): {}", status, text);
    }

    let val: serde_json::Value = serde_json::from_slice(&raw_bytes)?;
    let mut out = String::new();
    if let Some(parts) = val
        .pointer("/candidates/0/content/parts")
        .and_then(|v| v.as_array())
    {
        for p in parts {
            if let Some(t) = p.get("text").and_then(|v| v.as_str()) {
                out.push_str(t);
            }
        }
    }
    Ok(out)
}

pub(super) fn ai_endpoint_origin_tuple(raw: &str) -> Option<(String, String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = url::Url::parse(trimmed).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed.port_or_known_default()?;
    Some((parsed.scheme().to_ascii_lowercase(), host, port))
}

pub(super) fn is_loopback_ai_endpoint(raw: &str) -> bool {
    let Ok(parsed) = url::Url::parse(raw.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

pub(super) async fn call_openai_compatible_api(
    endpoint: &str,
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    if is_forbidden_model_alias(model_name) {
        anyhow::bail!(
            "Invalid AI model identifier '{}': provider or locality aliases cannot be sent as inference model IDs",
            model_name.trim()
        );
    }
    let client = af_services::streaming_http_client_builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut messages = Vec::new();
    if !system_prompt.trim().is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": system_prompt }));
    }
    for hm in history {
        let safe_role = sanitize_chat_history_role(&hm.role);
        messages.push(serde_json::json!({ "role": safe_role, "content": hm.text }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": message }));

    let endpoint = af_services::validate_server_url(endpoint)
        .map_err(|error| anyhow::anyhow!("Invalid AI endpoint: {error}"))?;
    if !api_key.trim().is_empty()
        && !endpoint.starts_with("https://")
        && !is_loopback_ai_endpoint(&endpoint)
    {
        anyhow::bail!("Non-loopback AI endpoints carrying an API key must use https://");
    }
    let url = build_versioned_endpoint_url(&endpoint, "chat/completions");
    let mut req = client.post(&url).json(&serde_json::json!({
        "model": model_name.trim(),
        "messages": messages,
    }));
    if !api_key.trim().is_empty() {
        req = req.bearer_auth(api_key);
    }
    let resp = req.send().await?;
    let status = resp.status();
    let raw_bytes = read_bounded_ai_response_bytes(resp).await?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&raw_bytes);
        anyhow::bail!("openai API error ({}): {}", status, text);
    }
    let val: serde_json::Value = serde_json::from_slice(&raw_bytes)?;
    let content = val
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(content)
}

pub(super) async fn call_anthropic_api(
    endpoint: &str,
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    if is_forbidden_model_alias(model_name) {
        anyhow::bail!(
            "Invalid AI model identifier '{}': provider or locality aliases cannot be sent as inference model IDs",
            model_name.trim()
        );
    }
    let base_raw = if endpoint.trim().is_empty() {
        "https://api.anthropic.com"
    } else {
        endpoint.trim().trim_end_matches('/')
    };
    let base = af_services::validate_server_url(base_raw)
        .map_err(|error| anyhow::anyhow!("Invalid AI endpoint: {error}"))?;
    if !api_key.trim().is_empty()
        && !base.starts_with("https://")
        && !is_loopback_ai_endpoint(&base)
    {
        anyhow::bail!("Non-loopback AI endpoints carrying an API key must use https://");
    }
    if base == "https://api.anthropic.com" && api_key.trim().is_empty() {
        anyhow::bail!(
            "anthropic API key not configured. Set it in Settings \u{2192} FlowAI Engine"
        );
    }
    let client = af_services::streaming_http_client_builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut messages = Vec::new();
    for hm in history {
        let safe_role = sanitize_chat_history_role(&hm.role);
        messages.push(serde_json::json!({ "role": safe_role, "content": hm.text }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": message }));

    let mut body = serde_json::json!({
        "model": model_name.trim(),
        "messages": messages,
        "max_tokens": 4096,
    });
    if !system_prompt.trim().is_empty() {
        body["system"] = serde_json::Value::String(system_prompt.to_string());
    }

    let url = build_versioned_endpoint_url(&base, "messages");
    let mut req = client
        .post(&url)
        .header("anthropic-version", "2023-06-01")
        .json(&body);
    if !api_key.trim().is_empty() {
        req = req.header("x-api-key", api_key);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let raw_bytes = read_bounded_ai_response_bytes(resp).await?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&raw_bytes);
        anyhow::bail!("anthropic API error ({}): {}", status, text);
    }
    let val: serde_json::Value = serde_json::from_slice(&raw_bytes)?;
    let mut out = String::new();
    if let Some(arr) = val.get("content").and_then(|v| v.as_array()) {
        for block in arr {
            if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                    out.push_str(t);
                }
            }
        }
    }
    Ok(out)
}

pub(crate) fn clean_json_fence(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("```json") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("```") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_suffix("```") {
        s = rest.to_string();
    }
    s.trim().to_string()
}

pub(crate) async fn call_configured_ai(
    ps: &ProviderSettings,
    system_prompt: &str,
    message: &str,
) -> anyhow::Result<String> {
    let provider = resolve_provider(&ps.local_provider, &ps.default_model);
    match provider {
        "openai" if !ps.openai_api_key.is_empty() => {
            call_openai_compatible_api(
                "https://api.openai.com",
                &ps.openai_api_key,
                &ps.default_model,
                system_prompt,
                &[],
                message,
            )
            .await
        }
        "anthropic" if !ps.anthropic_api_key.is_empty() => {
            call_anthropic_api(
                &ps.anthropic_endpoint,
                &ps.anthropic_api_key,
                &ps.default_model,
                system_prompt,
                &[],
                message,
            )
            .await
        }
        "localai" => {
            let local_model = if !ps.local_model.is_empty() {
                ps.local_model.as_str()
            } else if !is_forbidden_model_alias(&ps.default_model) {
                ps.default_model.as_str()
            } else {
                anyhow::bail!("Local AI model identifier is not configured");
            };
            let runtime = infer_local_runtime(&ps.local_provider, ps);
            match runtime {
                "anthropic-local" => {
                    let ep = if ps.anthropic_endpoint.is_empty() {
                        "http://localhost:8080".to_string()
                    } else {
                        ps.anthropic_endpoint.clone()
                    };
                    call_anthropic_api(
                        &ep,
                        &ps.anthropic_api_key,
                        local_model,
                        system_prompt,
                        &[],
                        message,
                    )
                    .await
                }
                "ollama" => {
                    let ep = if ps.ollama_endpoint.is_empty() {
                        "http://localhost:11434".to_string()
                    } else {
                        ps.ollama_endpoint.clone()
                    };
                    call_openai_compatible_api(&ep, "", local_model, system_prompt, &[], message)
                        .await
                }
                _ => {
                    let ep = if ps.lm_studio_endpoint.is_empty() {
                        "http://localhost:1234".to_string()
                    } else {
                        ps.lm_studio_endpoint.clone()
                    };
                    call_openai_compatible_api(&ep, "", local_model, system_prompt, &[], message)
                        .await
                }
            }
        }
        _ => {
            if !ps.gemini_api_key.is_empty() {
                let model = if is_valid_gemini_model_id(&ps.default_model) {
                    ps.default_model.as_str()
                } else {
                    "gemini-2.5-flash"
                };
                call_gemini_api(&ps.gemini_api_key, model, system_prompt, &[], message).await
            } else if !ps.openai_api_key.is_empty() {
                call_openai_compatible_api(
                    "https://api.openai.com",
                    &ps.openai_api_key,
                    "gpt-6.1-sol",
                    system_prompt,
                    &[],
                    message,
                )
                .await
            } else if !ps.anthropic_api_key.is_empty() {
                call_anthropic_api(
                    &ps.anthropic_endpoint,
                    &ps.anthropic_api_key,
                    "claude-sonnet-5-5",
                    system_prompt,
                    &[],
                    message,
                )
                .await
            } else {
                anyhow::bail!("No AI provider API key configured")
            }
        }
    }
}
