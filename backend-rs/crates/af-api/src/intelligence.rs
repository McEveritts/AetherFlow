use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::{Path, Query, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{Duration, Utc};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::{Path as StdPath, PathBuf};
use std::process::Command;
use std::sync::Mutex;

#[cfg(test)]
mod audit_tests {
    use super::*;

    struct ScanFixture(PathBuf);

    impl ScanFixture {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("af-mediaflow-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(path.join("library/nested")).unwrap();
            std::fs::create_dir_all(path.join("library-other")).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for ScanFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn mediaflow_paths_enforce_canonical_root_boundaries() {
        let fixture = ScanFixture::new();
        let root = fixture.0.join("library");
        let roots = vec![root.clone()];
        assert_eq!(validate_mediaflow_directory(&root, &roots).unwrap(), root);
        assert!(validate_mediaflow_directory(&root.join("nested"), &roots).is_ok());
        for path in [root.join("../library-other"), fixture.0.join("library-other")] {
            assert_eq!(validate_mediaflow_directory(&path, &roots).unwrap_err().0, StatusCode::FORBIDDEN);
        }
        assert_eq!(validate_mediaflow_directory(&root, &[]).unwrap_err().0, StatusCode::FORBIDDEN);
        assert_eq!(validate_mediaflow_directory(&root.join("missing"), &roots).unwrap_err().0, StatusCode::BAD_REQUEST);
        std::fs::write(root.join("video.mp4"), []).unwrap();
        assert_eq!(validate_mediaflow_directory(&root.join("video.mp4"), &roots).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn mediaflow_collection_filters_hidden_and_non_video_files() {
        let fixture = ScanFixture::new();
        let root = fixture.0.join("library");
        std::fs::create_dir(root.join(".mediaflow_trash")).unwrap();
        for name in ["nested/movie.MKV", "notes.txt", ".hidden.mp4", ".mediaflow_trash/deleted.mp4"] {
            std::fs::write(root.join(name), []).unwrap();
        }
        let mut files = Vec::new();
        collect_mediaflow_files(&root, &root, &mut files);
        assert_eq!(files, vec![root.join("nested/movie.MKV")]);
    }

    #[cfg(unix)]
    #[test]
    fn mediaflow_rejects_symlink_escapes_and_skips_cycles() {
        let fixture = ScanFixture::new();
        let root = fixture.0.join("library");
        let outside = fixture.0.join("library-other");
        std::fs::write(outside.join("secret.mp4"), []).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.mp4"), root.join("linked.mp4")).unwrap();
        std::os::unix::fs::symlink(&root, root.join("nested/cycle")).unwrap();
        assert_eq!(validate_mediaflow_directory(&root.join("escape"), &[root.clone()]).unwrap_err().0, StatusCode::FORBIDDEN);
        let mut files = Vec::new();
        collect_mediaflow_files(&root, &root, &mut files);
        assert!(files.is_empty());
    }

    #[test]
    fn wireguard_dump_uses_all_interface_column_offsets_without_secrets() {
        let dump = "wg0\tprivate-secret\tpublic-key\t51820\toff\nwg0\tpeer-key\tpreshared-secret\t192.0.2.1:1234\t10.0.0.2/32\t123\t456\t789\t25\nwg1\tother-private\tother-public\t51821\toff\nwg1\tother-peer\tother-psk\t(none)\t10.1.0.2/32\t0\t0\t0\toff\n";
        let status = parse_wireguard_dump(dump).unwrap();
        assert_eq!(status["interface"], "wg0");
        assert_eq!(status["public_key"], "public-key");
        assert_eq!(status["listen_port"], "51820");
        assert_eq!(status["peers"].as_array().unwrap().len(), 1);
        assert_eq!(status["peers"][0], serde_json::json!({
            "public_key": "peer-key", "endpoint": "192.0.2.1:1234",
            "allowed_ips": "10.0.0.2/32", "latest_handshake": "123",
            "transfer_rx": "456", "transfer_tx": "789",
        }));
        assert!(!status.to_string().contains("secret"));
    }

    #[test]
    fn wireguard_dump_handles_empty_interfaces_and_malformed_rows() {
        assert!(parse_wireguard_dump("").is_none());
        assert!(parse_wireguard_dump("invalid\trow").is_none());
        let status = parse_wireguard_dump("wg0\tprivate\tpublic\t51820\toff\nwg0\ttruncated\n").unwrap();
        assert_eq!(status["peers"], serde_json::json!([]));
    }

    #[test]
    fn tailscale_status_preserves_frontend_fields_and_real_peer_data() {
        let raw = serde_json::json!({
            "BackendState": "Running", "MagicDNSSuffix": "tail.example",
            "Self": {"ID": "self-id", "HostName": "server", "DNSName": "server.tail.example.",
                "TailscaleIPs": ["100.64.0.1"], "OS": "linux", "Online": true},
            "Peer": {"peer-key": {"HostName": "laptop", "TailscaleIPs": ["100.64.0.2"],
                "Online": true, "ExitNode": true, "Tags": ["tag:media"]}},
        });
        let status = tailscale_status_value(&raw);
        assert_eq!(status["backend_state"], "Running");
        assert_eq!(status["magic_dns"], true);
        assert_eq!(status["self"]["hostname"], "server");
        assert_eq!(status["self"]["tailscale_ip"], "100.64.0.1");
        assert_eq!(status["peers"][0]["id"], "peer-key");
        assert_eq!(status["peers"][0]["online"], true);
        assert_eq!(status["peers"][0]["exit_node"], true);
        assert_eq!(status["peers"][0]["tags"], serde_json::json!(["tag:media"]));
        let stopped = tailscale_status_value(&serde_json::json!({}));
        assert_eq!(stopped["backend_state"], "Stopped");
        assert_eq!(stopped["peers"], serde_json::json!([]));
    }

    #[test]
    fn audit_log_fallback_reads_singular_detail_column() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE admin_audit_log (id INTEGER PRIMARY KEY, created_at TEXT, action TEXT, target_type TEXT, detail TEXT); INSERT INTO admin_audit_log VALUES (1, '2026-10-31', 'update', 'system', 'channel stable'), (2, NULL, NULL, NULL, NULL);").unwrap();
        let mut stmt = conn.prepare(AUDIT_LOG_FALLBACK_SQL).unwrap();
        let rows: Vec<(String, String)> = stmt.query_map([2], |row| Ok((row.get(1)?, row.get(3)?)))
            .unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(rows, vec![("event".to_string(), "".to_string()), ("update".to_string(), "channel stable".to_string())]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. FlowAI Multi-Provider Chat, Support & Connection Test (`backend/api/ai.go`)
// ─────────────────────────────────────────────────────────────────────────────

static ALLOWED_AI_MODELS: &[&str] = &[
    "gemini-4-argon",
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
    "gpt-6.1-sol",
    "gpt-6.1-terra",
    "gpt-6-luna",
    "claude-fable-5-1",
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
    "lm-studio",
    "ollama",
    "anthropic-local",
];

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
    pub system_prompt: String,
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
        system_prompt: "You are FlowAI, a helpful server assistant.".to_string(),
    };

    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.query_row(
            "SELECT COALESCE(gemini_api_key, ''), COALESCE(openai_api_key, ''), COALESCE(anthropic_api_key, ''), \
             COALESCE(anthropic_endpoint, ''), COALESCE(lm_studio_endpoint, ''), COALESCE(ollama_endpoint, ''), \
             COALESCE(ai_model, ''), COALESCE(system_prompt, '') FROM settings WHERE id = 1",
            [],
            |r| {
                ps.gemini_api_key = r.get(0)?;
                ps.openai_api_key = r.get(1)?;
                ps.anthropic_api_key = r.get(2)?;
                ps.anthropic_endpoint = r.get(3)?;
                ps.lm_studio_endpoint = r.get(4)?;
                ps.ollama_endpoint = r.get(5)?;
                let m: String = r.get(6)?;
                if !m.is_empty() {
                    ps.default_model = m;
                }
                let sp: String = r.get(7)?;
                if !sp.is_empty() {
                    ps.system_prompt = sp;
                }
                Ok(())
            },
        );
    }

    if !ps.gemini_api_key.is_empty() {
        if let Ok(dec) = af_db::decrypt_key(&ps.gemini_api_key) {
            ps.gemini_api_key = dec;
        }
    }
    if !ps.openai_api_key.is_empty() {
        if let Ok(dec) = af_db::decrypt_key(&ps.openai_api_key) {
            ps.openai_api_key = dec;
        }
    }
    if !ps.anthropic_api_key.is_empty() {
        if let Ok(dec) = af_db::decrypt_key(&ps.anthropic_api_key) {
            ps.anthropic_api_key = dec;
        }
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

    ps
}

fn resolve_provider(provider_hint: &str, model_id: &str) -> &'static str {
    match provider_hint.trim() {
        "gemini" => return "gemini",
        "openai" => return "openai",
        "anthropic" => return "anthropic",
        "localai" => return "localai",
        _ => {}
    }
    if model_id.starts_with("gemini") {
        "gemini"
    } else if model_id.starts_with("gpt") {
        "openai"
    } else if model_id.starts_with("claude") {
        "anthropic"
    } else if model_id == "lm-studio" || model_id == "ollama" || model_id == "anthropic-local" {
        "localai"
    } else {
        "gemini"
    }
}

pub fn get_system_metrics_context() -> String {
    let m = af_hardware::get_system_metrics_core();
    let mut sb = String::from("=== CURRENT SYSTEM METRICS ===\n");
    sb.push_str(&format!("CPU Usage: {:.1}%\n", m.cpu_usage));
    sb.push_str(&format!("CPU Frequency: {:.0} MHz\n", m.cpu_freq_mhz));
    if let (Some(&used), Some(&total)) = (m.memory.get("used"), m.memory.get("total")) {
        let pct = if total > 0.0 { (used / total) * 100.0 } else { 0.0 };
        sb.push_str(&format!("Memory: {:.2} / {:.2} GB ({:.1}%)\n", used, total, pct));
    }
    for disk in &m.disks {
        sb.push_str(&format!(
            "Disk {} ({}): {:.1} / {:.1} GB ({:.1}% used)\n",
            disk.mount_point, disk.device, disk.used_gb, disk.total_gb, disk.used_pct
        ));
    }
    sb.push_str(&format!("Uptime: {}\n", m.uptime));
    if m.load_average.len() >= 3 {
        sb.push_str(&format!(
            "Load Average: {:.2} / {:.2} / {:.2}\n",
            m.load_average[0], m.load_average[1], m.load_average[2]
        ));
    }
    sb.push_str("=== END METRICS ===\n");
    sb
}

async fn call_gemini_api(
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    if api_key.trim().is_empty() {
        anyhow::bail!("gemini API key not configured. Set it in Settings → FlowAI Engine");
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()?;

    let mut contents = Vec::new();
    for hm in history {
        let role = if hm.role == "assistant" { "model" } else { "user" };
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
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            m, api_key
        );
        client.post(url).json(&body).send()
    };

    let mut resp = send_for_model(model_name).await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND && model_name == "gemini-4-argon" {
        resp = send_for_model("gemini-2.5-pro").await?;
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("gemini API error ({}): {}", status, text);
    }

    let val: serde_json::Value = resp.json().await?;
    let mut out = String::new();
    if let Some(parts) = val.pointer("/candidates/0/content/parts").and_then(|v| v.as_array()) {
        for p in parts {
            if let Some(t) = p.get("text").and_then(|v| v.as_str()) {
                out.push_str(t);
            }
        }
    }
    Ok(out)
}

async fn call_openai_compatible_api(
    endpoint: &str,
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut messages = Vec::new();
    if !system_prompt.trim().is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": system_prompt }));
    }
    for hm in history {
        messages.push(serde_json::json!({ "role": hm.role, "content": hm.text }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": message }));

    let url = format!("{}/v1/chat/completions", endpoint.trim_end_matches('/'));
    let mut req = client.post(&url).json(&serde_json::json!({
        "model": model_name,
        "messages": messages,
    }));
    if !api_key.is_empty() {
        req = req.bearer_auth(api_key);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("openai API error ({}): {}", status, text);
    }
    let val: serde_json::Value = resp.json().await?;
    let content = val
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(content)
}

async fn call_anthropic_api(
    endpoint: &str,
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    if api_key.trim().is_empty() {
        anyhow::bail!("anthropic API key not configured. Set it in Settings → FlowAI Engine");
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut messages = Vec::new();
    for hm in history {
        messages.push(serde_json::json!({ "role": hm.role, "content": hm.text }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": message }));

    let base = if endpoint.trim().is_empty() {
        "https://api.anthropic.com"
    } else {
        endpoint.trim().trim_end_matches('/')
    };
    let mut body = serde_json::json!({
        "model": model_name,
        "messages": messages,
        "max_tokens": 4096,
    });
    if !system_prompt.trim().is_empty() {
        body["system"] = serde_json::Value::String(system_prompt.to_string());
    }

    let resp = client
        .post(format!("{}/v1/messages", base))
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("anthropic API error ({}): {}", status, text);
    }
    let val: serde_json::Value = resp.json().await?;
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

fn extract_service_target(message: &str) -> &'static str {
    let lower = message.to_lowercase();
    for svc in [
        "apache2", "apache", "aetherflow-api", "aetherflow-runner", "nginx", "postgres",
        "postgresql", "redis", "qbittorrent", "qui", "autobrr", "sonarr", "radarr", "lidarr",
        "prowlarr", "plex", "jellyfin", "emby", "threadfin", "dispatcharr", "transmission",
        "deluge", "jackett", "wireguard", "tailscale", "traefik", "duplicati", "filebot",
        "listenarr", "notifiarr", "novnc", "pyload", "quassel", "requestrr", "seedcross",
        "unmanic", "x2go",
    ] {
        if lower.contains(svc) {
            return svc;
        }
    }
    "target service"
}

fn extract_proposed_action(ai_reply: &str, user_message: &str) -> Option<ProposedAction> {
    let combined = format!("{} {}", ai_reply, user_message).to_lowercase();
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
        (
            &["delete", "remove", "uninstall", "purge"],
            "critical",
            "Delete",
            "Data associated with this service may be permanently lost.",
        ),
        (
            &["update", "upgrade", "patch"],
            "warn",
            "Update",
            "Service will restart after update. Configuration may change.",
        ),
    ];

    for (keywords, classification, verb, impact) in specs {
        for kw in *keywords {
            if combined.contains(kw) {
                let target = extract_service_target(user_message);
                let title = format!("{} {}", verb, target);
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
    None
}

async fn run_chat_session(
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
    let ai_model = if model_override.trim().is_empty() {
        ps.default_model.clone()
    } else {
        model_override.trim().to_string()
    };

    if !ALLOWED_AI_MODELS.contains(&ai_model.as_str()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid AI model. Check settings for available models.",
        );
    }

    let provider_type = resolve_provider(provider_hint, &ai_model);
    let prompt = if !system_prompt_override.is_empty() {
        system_prompt_override.to_string()
    } else if user.as_ref().map(|u| u.role == "admin").unwrap_or(false) {
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
                    "AI provider initialization failed: openai API key not configured. Set it in Settings → FlowAI Engine"
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
            let endpoint = match ai_model.as_str() {
                "ollama" if !ps.ollama_endpoint.is_empty() => ps.ollama_endpoint.clone(),
                "ollama" => "http://localhost:11434".to_string(),
                "anthropic-local" if !ps.anthropic_endpoint.is_empty() => {
                    ps.anthropic_endpoint.clone()
                }
                "anthropic-local" => "http://localhost:8080".to_string(),
                _ if !ps.lm_studio_endpoint.is_empty() => ps.lm_studio_endpoint.clone(),
                _ => "http://localhost:1234".to_string(),
            };
            call_openai_compatible_api(&endpoint, "", &ai_model, &prompt, &history, &message).await
        }
        _ => call_gemini_api(&ps.gemini_api_key, &ai_model, &prompt, &history, &message).await,
    };

    let reply_text = match result {
        Ok(t) if !t.trim().is_empty() => t,
        Ok(_) => "I received an empty response. Please try again.".to_string(),
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Generation error: {}", e),
            );
        }
    };

    if let Some(mut proposal) = extract_proposed_action(&reply_text, &message) {
        let (action_id, needs_approval) = af_db::queue_action(
            &proposal.danger_level,
            "FlowAI",
            &proposal.title,
            &proposal.description,
        );
        if needs_approval {
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
                &format!("classification={} title={}", proposal.danger_level, proposal.title),
                ip,
                ua,
            );
            return Json(serde_json::json!({
                "reply": reply_text,
                "proposed_action": proposal,
            }))
            .into_response();
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
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "message is required");
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
    let history: Vec<ChatMessage> = body
        .get("history")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    run_chat_session(user, &ip, &ua, "", &model, &provider, history, message).await
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
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "message is required");
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
    let history: Vec<ChatMessage> = body
        .get("history")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let ps = resolve_provider_settings();
    let support_prompt = format!(
        "{}\n\nYou are in SUPPORT MODE. The user is troubleshooting a server issue. Use the following live system data to help diagnose problems:\n\n{}\nAnalyze the above data in context of the user's question.",
        ps.system_prompt,
        get_system_metrics_context()
    );

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

pub async fn test_ai_connection(
    axum::Extension(user): axum::Extension<AuthUser>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if user.role != "admin" {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Admin access required",
        );
    }
    let mut ps = resolve_provider_settings();
    let provider_type = req
        .get("provider")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("gemini");

    if let Some(k) = req
        .get("gemini_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****"))
    {
        ps.gemini_api_key = k.to_string();
    }
    if let Some(k) = req
        .get("openai_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****"))
    {
        ps.openai_api_key = k.to_string();
    }
    if let Some(k) = req
        .get("anthropic_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****"))
    {
        ps.anthropic_api_key = k.to_string();
    }
    if let Some(ep) = req
        .get("endpoint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        ps.lm_studio_endpoint = clean_ep.clone();
        ps.ollama_endpoint = clean_ep;
    }

    let res = match provider_type {
        "openai" => {
            call_openai_compatible_api(
                "https://api.openai.com",
                &ps.openai_api_key,
                "gpt-6.1-sol",
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
        "anthropic" => {
            call_anthropic_api(
                &ps.anthropic_endpoint,
                &ps.anthropic_api_key,
                "claude-sonnet-5-5",
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
        "localai" => {
            let ep = if !ps.lm_studio_endpoint.is_empty() {
                ps.lm_studio_endpoint.clone()
            } else {
                "http://localhost:1234".to_string()
            };
            call_openai_compatible_api(
                &ep,
                "",
                "local-test",
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
        _ => {
            call_gemini_api(
                &ps.gemini_api_key,
                "gemini-4-argon",
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
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            format!("Connection test failed: {}", e),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Metadata Enricher, Bandwidth, Predictions & MediaFlow
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct EnricherState {
    scanning: bool,
    progress: f64,
    total: usize,
    done: usize,
    processed: usize,
    results: Vec<serde_json::Value>,
    last_err: String,
}

static ENRICHER_STATE: Lazy<Mutex<EnricherState>> =
    Lazy::new(|| Mutex::new(EnricherState::default()));

static MEDIA_EXTENSIONS: &[&str] = &[
    ".mkv", ".mp4", ".avi", ".mov", ".m4v", ".wmv", ".flv", ".webm", ".ts", ".srt", ".ass", ".ssa",
    ".sub", ".vtt", ".flac", ".mp3", ".aac", ".ogg", ".opus",
];

fn clean_json_fence(raw: &str) -> String {
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

async fn call_configured_ai(
    ps: &ProviderSettings,
    system_prompt: &str,
    message: &str,
) -> anyhow::Result<String> {
    let provider = resolve_provider("", &ps.default_model);
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
            let ep = if ps.default_model == "ollama" {
                if ps.ollama_endpoint.is_empty() {
                    "http://localhost:11434".to_string()
                } else {
                    ps.ollama_endpoint.clone()
                }
            } else if ps.lm_studio_endpoint.is_empty() {
                "http://localhost:1234".to_string()
            } else {
                ps.lm_studio_endpoint.clone()
            };
            call_openai_compatible_api(&ep, "", &ps.default_model, system_prompt, &[], message)
                .await
        }
        _ => {
            if !ps.gemini_api_key.is_empty() {
                let model = if ps.default_model.starts_with("gemini") {
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

fn collect_files_recursive(dir: &StdPath, allowed_exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        if file_name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_files_recursive(&path, allowed_exts, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let dot_ext = format!(".{}", ext.to_lowercase());
            if allowed_exts.iter().any(|&a| a == dot_ext) {
                out.push(path);
            }
        }
    }
}

fn parse_filename_metadata(filename: &str) -> (String, String, String, String, Vec<String>) {
    static YEAR_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"\b(19\d{2}|20\d{2})\b").unwrap());
    static QUALITY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"(?i)\b(2160p|4k|1080p|720p|480p|bluray|blu-ray|web-dl|webdl|webrip|remux|hdtv)\b",
        )
        .unwrap()
    });
    static CODEC_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?i)\b(hevc|x265|h\.?265|av1|x264|h\.?264|10bit|hdr10|dv)\b").unwrap()
    });

    let stem = StdPath::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);

    let year = YEAR_RE
        .find(stem)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let mut quality_parts: Vec<String> = Vec::new();
    for m in QUALITY_RE.find_iter(stem) {
        let tok = m.as_str();
        let norm = match tok.to_lowercase().as_str() {
            "4k" | "2160p" => "2160p".to_string(),
            "1080p" => "1080p".to_string(),
            "720p" => "720p".to_string(),
            "480p" => "480p".to_string(),
            "bluray" | "blu-ray" => "BluRay".to_string(),
            "web-dl" | "webdl" => "WEB-DL".to_string(),
            "webrip" => "WEBRip".to_string(),
            "remux" => "Remux".to_string(),
            "hdtv" => "HDTV".to_string(),
            other => other.to_uppercase(),
        };
        if !quality_parts.contains(&norm) {
            quality_parts.push(norm);
        }
    }
    for m in CODEC_RE.find_iter(stem) {
        let tok = m.as_str().to_uppercase().replace('.', "");
        let norm = if tok == "X265" || tok == "H265" {
            "HEVC".to_string()
        } else if tok == "X264" {
            "H264".to_string()
        } else {
            tok
        };
        if !quality_parts.contains(&norm) {
            quality_parts.push(norm);
        }
    }
    let quality = if quality_parts.is_empty() {
        "Unknown".to_string()
    } else {
        quality_parts.join(" ")
    };

    // Extract clean title up to the year or quality token
    let mut cutoff_idx = stem.len();
    if let Some(m) = YEAR_RE.find(stem) {
        if m.start() > 0 {
            cutoff_idx = cutoff_idx.min(m.start());
        }
    }
    if let Some(m) = QUALITY_RE.find(stem) {
        if m.start() > 0 {
            cutoff_idx = cutoff_idx.min(m.start());
        }
    }
    let raw_title = &stem[..cutoff_idx];
    let cleaned_title = raw_title
        .replace(['.', '_', '-'], " ")
        .replace(['[', ']', '(', ')'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let title = if cleaned_title.is_empty() {
        stem.replace(['.', '_'], " ").trim().to_string()
    } else {
        cleaned_title
    };

    let lower = stem.to_lowercase();
    let language = if lower.contains("japanese") || lower.contains(".jpn.") || lower.contains("dual")
    {
        "ja".to_string()
    } else if lower.contains("spanish") || lower.contains(".spa.") {
        "es".to_string()
    } else if lower.contains("french") || lower.contains(".fre.") {
        "fr".to_string()
    } else if lower.contains("german") || lower.contains(".ger.") {
        "de".to_string()
    } else {
        "en".to_string()
    };

    let mut subs = Vec::new();
    if lower.contains("sub") || lower.contains("multi") {
        subs.push("en".to_string());
    }

    (title, year, language, quality, subs)
}

fn upsert_media_metadata_row(
    file_path: &str,
    filename: &str,
    title: &str,
    year: &str,
    language: &str,
    quality: &str,
    subtitles: &[String],
) -> Option<serde_json::Value> {
    let Ok(conn) = af_db::get_conn() else {
        return None;
    };
    let subs_json = serde_json::to_string(subtitles).unwrap_or_else(|_| "[]".to_string());
    let now_str = Utc::now().to_rfc3339();

    let updated = conn
        .execute(
            "UPDATE media_metadata SET filename = ?2, title = ?3, year = ?4, language = ?5, quality = ?6, subtitles_json = ?7, enriched_at = ?8 WHERE file_path = ?1",
            params![file_path, filename, title, year, language, quality, subs_json, now_str],
        )
        .unwrap_or(0);

    if updated == 0 {
        let _ = conn.execute(
            "INSERT INTO media_metadata (file_path, filename, title, year, language, quality, subtitles_json, enriched_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![file_path, filename, title, year, language, quality, subs_json, now_str],
        );
    }

    let id = conn
        .query_row(
            "SELECT id FROM media_metadata WHERE file_path = ?1 ORDER BY id DESC LIMIT 1",
            params![file_path],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0);

    Some(serde_json::json!({
        "id": id,
        "file_path": file_path,
        "filename": filename,
        "title": title,
        "year": year,
        "language": language,
        "quality": quality,
        "subtitles_json": subs_json,
        "enriched_at": now_str,
    }))
}

pub async fn metadata_scan(Json(req): Json<serde_json::Value>) -> Response {
    let raw_path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").trim();
    if raw_path.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "path is required");
    }
    if raw_path.contains("..") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Path traversal not allowed",
        );
    }
    let allowed_roots = mediaflow_library_roots();
    let clean_path = match validate_mediaflow_directory(&PathBuf::from(raw_path), &allowed_roots) {
        Ok(path) => path,
        Err((status, message)) => return api_error(status, "INVALID_SCAN_PATH", message),
    };

    {
        let st = ENRICHER_STATE.lock().unwrap();
        if st.scanning {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "A scan is already in progress",
            );
        }
    }

    let mut media_files = Vec::new();
    collect_files_recursive(&clean_path, MEDIA_EXTENSIONS, &mut media_files);
    let total_files = media_files.len();

    if let Ok(mut st) = ENRICHER_STATE.lock() {
        st.scanning = true;
        st.progress = 0.0;
        st.total = total_files;
        st.done = 0;
        st.processed = 0;
        st.results.clear();
        st.last_err.clear();
    }

    let ps = resolve_provider_settings();
    let has_gemini_key = !ps.gemini_api_key.is_empty();

    // First pass: deterministically parse filenames and persist immediately so results
    // and progress are immediately available even before optional AI enrichment completes.
    let mut enriched_items = Vec::with_capacity(total_files);
    for (idx, path) in media_files.iter().enumerate() {
        let file_path_str = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let (title, year, language, quality, subs) = parse_filename_metadata(&filename);
        if let Some(row) = upsert_media_metadata_row(
            &file_path_str,
            &filename,
            &title,
            &year,
            &language,
            &quality,
            &subs,
        ) {
            enriched_items.push(row);
        }
        if let Ok(mut st) = ENRICHER_STATE.lock() {
            st.done = idx + 1;
            st.processed = idx + 1;
            st.progress = if total_files > 0 {
                ((idx + 1) as f64 / total_files as f64) * 100.0
            } else {
                100.0
            };
        }
    }

    if let Ok(mut st) = ENRICHER_STATE.lock() {
        st.results = enriched_items;
        st.progress = 100.0;
        if !has_gemini_key || media_files.is_empty() {
            st.scanning = false;
        }
    }

    if has_gemini_key && !media_files.is_empty() {
        let api_key = ps.gemini_api_key.clone();
        tokio::spawn(async move {
            let batch_size = 10usize;
            let total = media_files.len();
            let mut updated_results = Vec::new();

            for (start, chunk) in media_files.chunks(batch_size).enumerate() {
                let filenames: Vec<String> = chunk
                    .iter()
                    .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()))
                    .collect();
                let prompt = format!(
                    "Parse these media filenames and extract structured metadata. Return a JSON array where each element has: \"filename\", \"title\", \"year\", \"language\" (ISO 639-1), \"quality\" (e.g., 1080p BluRay), \"subtitles\" (array of likely subtitle languages). Only return valid JSON, no markdown.\n\nFilenames:\n{}",
                    filenames.join("\n")
                );
                if let Ok(resp_text) =
                    call_gemini_api(&api_key, "gemini-2.0-flash", "", &[], &prompt).await
                {
                    let cleaned = clean_json_fence(&resp_text);
                    if let Ok(parsed_arr) = serde_json::from_str::<Vec<serde_json::Value>>(&cleaned)
                    {
                        for (i, item) in parsed_arr.iter().enumerate() {
                            if let Some(full_path) = chunk.get(i) {
                                let fp_str = full_path.to_string_lossy().to_string();
                                let fname = full_path
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("");
                                let (def_title, def_year, def_lang, def_qual, def_subs) =
                                    parse_filename_metadata(fname);
                                let title = item
                                    .get("title")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_title);
                                let year = item
                                    .get("year")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_year);
                                let language = item
                                    .get("language")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_lang);
                                let quality = item
                                    .get("quality")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_qual);
                                let subs: Vec<String> = item
                                    .get("subtitles")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or(def_subs);
                                if let Some(row) = upsert_media_metadata_row(
                                    &fp_str, fname, title, year, language, quality, &subs,
                                ) {
                                    updated_results.push(row);
                                }
                            }
                        }
                    }
                }
                let done_count = ((start + 1) * batch_size).min(total);
                if let Ok(mut st) = ENRICHER_STATE.lock() {
                    st.done = done_count;
                    st.processed = done_count;
                    st.progress = (done_count as f64 / total as f64) * 100.0;
                    if !updated_results.is_empty() {
                        st.results = updated_results.clone();
                    }
                }
            }

            if let Ok(mut st) = ENRICHER_STATE.lock() {
                st.scanning = false;
                st.progress = 100.0;
            }
        });
    }

    Json(serde_json::json!({
        "message": "Metadata enrichment scan started",
        "path": raw_path,
        "total": total_files,
    }))
    .into_response()
}

pub async fn metadata_status() -> Response {
    let st = ENRICHER_STATE.lock().unwrap();
    Json(serde_json::json!({
        "scanning": st.scanning,
        "progress": st.progress,
        "total": st.total,
        "done": st.done,
        "processed": st.processed,
        "results": st.results,
        "error": st.last_err,
    }))
    .into_response()
}

pub async fn metadata_results() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!([])).into_response();
    };
    let mut results = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, file_path, filename, COALESCE(title, ''), COALESCE(year, ''), \
         COALESCE(language, ''), COALESCE(quality, ''), COALESCE(subtitles_json, '[]'), COALESCE(enriched_at, '') \
         FROM media_metadata ORDER BY enriched_at DESC, id DESC LIMIT 200",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "file_path": r.get::<_, String>(1)?,
                "filename": r.get::<_, String>(2)?,
                "title": r.get::<_, String>(3)?,
                "year": r.get::<_, String>(4)?,
                "language": r.get::<_, String>(5)?,
                "quality": r.get::<_, String>(6)?,
                "subtitles_json": r.get::<_, String>(7)?,
                "enriched_at": r.get::<_, String>(8)?,
            }))
        }) {
            for item in rows.flatten() {
                results.push(item);
            }
        }
    }
    Json(results).into_response()
}

pub async fn bandwidth_analyze() -> Response {
    let ps = resolve_provider_settings();
    let m = af_hardware::get_system_metrics_core();
    let active_services = af_services::get_active_services();
    let streaming = af_services::get_streaming_dashboard(7, true);
    let active_streams = streaming.live_summary.active_streams;
    let active_transcodes = streaming.live_summary.transcode_count;

    let mem_used = m.memory.get("used").copied().unwrap_or(0.0);
    let mem_total = m.memory.get("total").copied().unwrap_or(0.0);
    let mem_pct = if mem_total > 0.0 {
        (mem_used / mem_total) * 100.0
    } else {
        0.0
    };
    let disk_read_bps = m.disk_io.get("read_bytes_sec").copied().unwrap_or(0.0);
    let disk_write_bps = m.disk_io.get("write_bytes_sec").copied().unwrap_or(0.0);
    let disk_io_mb_s = (disk_read_bps + disk_write_bps) / (1024.0 * 1024.0);

    // Dynamic bandwidth calculation scaled by CPU, disk I/O, and active media streams
    let base_down_kbps: i64 = 102_400; // 100 MB/s baseline
    let base_up_kbps: i64 = 51_200; // 50 MB/s baseline

    let load_factor = if m.cpu_usage > 85.0 || disk_io_mb_s > 250.0 {
        0.45
    } else if m.cpu_usage > 65.0 || active_transcodes > 0 {
        0.70
    } else if m.cpu_usage < 25.0 && active_streams == 0 {
        1.25
    } else {
        1.0
    };

    let stream_headroom_kbps = (active_streams as i64) * 6_000 + (active_transcodes as i64) * 8_000;
    let recommended_download_kbps =
        (((base_down_kbps as f64) * load_factor) as i64 - stream_headroom_kbps).max(10_240);
    let recommended_upload_kbps =
        (((base_up_kbps as f64) * load_factor) as i64 - stream_headroom_kbps).max(5_120);

    let swarm_health = if m.cpu_usage > 85.0 || mem_pct > 90.0 || disk_io_mb_s > 250.0 {
        "congested"
    } else if m.cpu_usage < 25.0 && active_streams == 0 {
        "underutilized"
    } else {
        "healthy"
    };

    let mut suggestions = vec![
        "Maintain 20% egress headroom for Jellyfin direct-stream spikes".to_string(),
        "Enable alternative speed limits during active transcoding sessions".to_string(),
    ];
    if active_streams > 0 {
        suggestions.push(format!(
            "Reserved {} kbps egress headroom for {} active media stream(s)",
            stream_headroom_kbps, active_streams
        ));
    }
    if disk_io_mb_s > 100.0 {
        suggestions.push(format!(
            "Disk I/O throughput is {:.1} MB/s; throttle concurrent torrent writes to reduce seek contention",
            disk_io_mb_s
        ));
    }

    let prompt = format!(
        "Analyze the current server state and recommend optimal torrent bandwidth limits.\n\n{}\n\nActive Streams: {} (Transcodes: {})\nDisk I/O: {:.2} MB/s\n\nReturn a JSON object with these exact fields:\n- \"recommended_upload_kbps\": integer (in KB/s)\n- \"recommended_download_kbps\": integer (in KB/s)\n- \"reasoning\": string (1-2 sentences explaining why)\n- \"confidence\": float (0.0-1.0)\n- \"swarm_health\": string (\"healthy\", \"congested\", or \"underutilized\")\n- \"suggestions\": array of strings (2-3 actionable tips)\n\nOnly return valid JSON, no markdown fences.",
        get_system_metrics_context(),
        active_streams,
        active_transcodes,
        disk_io_mb_s
    );

    if let Ok(ai_text) = call_configured_ai(
        &ps,
        "You are an expert network traffic engineer for a media server running torrent clients alongside streaming services (Plex/Jellyfin).",
        &prompt,
    )
    .await
    {
        let cleaned = clean_json_fence(&ai_text);
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cleaned) {
            if parsed.get("recommended_upload_kbps").is_some()
                && parsed.get("recommended_download_kbps").is_some()
            {
                return Json(parsed).into_response();
            }
        }
    }

    Json(serde_json::json!({
        "recommended_upload_kbps": recommended_upload_kbps,
        "recommended_download_kbps": recommended_download_kbps,
        "reasoning": format!(
            "Evaluated live CPU load ({:.1}%), memory utilization ({:.1}%), disk I/O ({:.1} MB/s), and {} active service(s) / {} active stream(s).",
            m.cpu_usage,
            mem_pct,
            disk_io_mb_s,
            active_services.len(),
            active_streams
        ),
        "confidence": 0.89,
        "swarm_health": swarm_health,
        "suggestions": suggestions,
    }))
    .into_response()
}

pub async fn bandwidth_apply(Json(req): Json<serde_json::Value>) -> Response {
    let upload_kbps = req.get("upload_kbps").and_then(|v| v.as_i64()).unwrap_or(0);
    let download_kbps = req
        .get("download_kbps")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let payload = serde_json::json!({
        "method": "session-set",
        "arguments": {
            "alt-speed-down": download_kbps,
            "alt-speed-up": upload_kbps,
            "alt-speed-enabled": true,
        }
    });

    match client
        .post("http://127.0.0.1:9091/transmission/rpc")
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status != reqwest::StatusCode::OK {
                return api_error(
                    StatusCode::BAD_GATEWAY,
                    "BAD_GATEWAY",
                    "Torrent daemon rejected RPC request",
                );
            }
            Json(serde_json::json!({
                "message": "Limits applied successfully to Torrent engine via RPC",
                "upload_kbps": upload_kbps,
                "download_kbps": download_kbps,
                "rpc_response": text,
            }))
            .into_response()
        }
        Err(_) => api_error(
            StatusCode::GATEWAY_TIMEOUT,
            "GATEWAY_TIMEOUT",
            "Torrent daemon RPC timeout or unreachable",
        ),
    }
}

fn compute_linear_slope(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 2 {
        return 0.0;
    }
    let nf = n as f64;
    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;
    for (i, &v) in values.iter().enumerate() {
        let x = i as f64;
        sum_x += x;
        sum_y += v;
        sum_xy += x * v;
        sum_x2 += x * x;
    }
    let denom = nf * sum_x2 - sum_x * sum_x;
    if denom.abs() < 1e-12 {
        return 0.0;
    }
    (nf * sum_xy - sum_x * sum_y) / denom
}

fn classify_metric_trend(slope: f64, avg_val: f64, max_val: f64, crit_threshold: f64) -> &'static str {
    if max_val >= crit_threshold || avg_val >= crit_threshold * 0.95 {
        "critical"
    } else if slope > 0.05 {
        "increasing"
    } else if slope < -0.05 {
        "decreasing"
    } else {
        "stable"
    }
}

async fn build_resource_predictions(invoke_ai: bool) -> serde_json::Value {
    let m = af_hardware::get_system_metrics_core();
    let disk_pct = m.disks.first().map(|d| d.used_pct).unwrap_or(0.0);
    let disk_free_gb = m
        .disks
        .first()
        .map(|d| (d.total_gb - d.used_gb).max(0.0))
        .unwrap_or(100.0);

    #[derive(Clone)]
    struct HistPoint {
        timestamp: String,
        cpu_avg: f64,
        mem_used_gb: f64,
        mem_total_gb: f64,
        disk_read_bps: f64,
        disk_write_bps: f64,
        net_rx_bytes: i64,
        net_tx_bytes: i64,
        load_avg_1: f64,
        active_conns: i64,
    }

    let mut history: Vec<HistPoint> = Vec::new();
    if let Ok(conn) = af_db::get_conn() {
        let cutoff = (Utc::now() - Duration::days(30))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT COALESCE(CAST(timestamp AS TEXT), ''), COALESCE(cpu_avg, 0), COALESCE(mem_used_gb, 0), COALESCE(mem_total_gb, 0), \
             COALESCE(disk_read_bps, 0), COALESCE(disk_write_bps, 0), COALESCE(net_rx_bytes, 0), COALESCE(net_tx_bytes, 0), \
             COALESCE(load_avg_1, 0), COALESCE(active_conns, 0) \
             FROM metrics_history WHERE timestamp >= ?1 ORDER BY timestamp ASC LIMIT 2000",
        ) {
            if let Ok(rows) = stmt.query_map(params![cutoff], |r| {
                Ok(HistPoint {
                    timestamp: r.get(0)?,
                    cpu_avg: r.get(1)?,
                    mem_used_gb: r.get(2)?,
                    mem_total_gb: r.get(3)?,
                    disk_read_bps: r.get(4)?,
                    disk_write_bps: r.get(5)?,
                    net_rx_bytes: r.get(6)?,
                    net_tx_bytes: r.get(7)?,
                    load_avg_1: r.get(8)?,
                    active_conns: r.get(9)?,
                })
            }) {
                for pt in rows.flatten() {
                    history.push(pt);
                }
            }
        }
    }

    let mut cpu_vals = Vec::with_capacity(history.len().max(1));
    let mut mem_pcts = Vec::with_capacity(history.len().max(1));
    let mut disk_writes = Vec::with_capacity(history.len().max(1));
    let mut net_totals = Vec::with_capacity(history.len().max(1));
    let mut anomalies: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if history.is_empty() {
        cpu_vals.push(m.cpu_usage);
        let used = m.memory.get("used").copied().unwrap_or(0.0);
        let total = m.memory.get("total").copied().unwrap_or(0.0);
        mem_pcts.push(if total > 0.0 {
            (used / total) * 100.0
        } else {
            0.0
        });
        disk_writes.push(m.disk_io.get("write_bytes_sec").copied().unwrap_or(0.0));
        net_totals.push(
            (m.total_net_bytes.get("rx").copied().unwrap_or(0)
                + m.total_net_bytes.get("tx").copied().unwrap_or(0)) as f64,
        );
    } else {
        for pt in &history {
            cpu_vals.push(pt.cpu_avg);
            let mp = if pt.mem_total_gb > 0.0 {
                (pt.mem_used_gb / pt.mem_total_gb) * 100.0
            } else {
                0.0
            };
            mem_pcts.push(mp);
            disk_writes.push(pt.disk_write_bps);
            net_totals.push((pt.net_rx_bytes.saturating_add(pt.net_tx_bytes)) as f64);
        }
    }

    let n = cpu_vals.len() as f64;
    let cpu_avg = cpu_vals.iter().sum::<f64>() / n;
    let cpu_max = cpu_vals.iter().copied().fold(0.0_f64, f64::max);
    let mem_avg = mem_pcts.iter().sum::<f64>() / n;
    let mem_max = mem_pcts.iter().copied().fold(0.0_f64, f64::max);
    let disk_write_avg = disk_writes.iter().sum::<f64>() / n;
    let load_avg = if history.is_empty() {
        m.load_average.first().copied().unwrap_or(0.0)
    } else {
        history.iter().map(|h| h.load_avg_1).sum::<f64>() / (history.len() as f64)
    };

    let cpu_slope = compute_linear_slope(&cpu_vals);
    let mem_slope = compute_linear_slope(&mem_pcts);
    let disk_io_slope = compute_linear_slope(&disk_writes);
    let net_slope = compute_linear_slope(&net_totals);

    let cpu_trend = classify_metric_trend(cpu_slope, cpu_avg, cpu_max, 90.0);
    let memory_trend = classify_metric_trend(mem_slope, mem_avg, mem_max, 92.0);
    let disk_trend = if disk_pct >= 92.0 {
        "critical"
    } else if disk_pct > 80.0 || disk_io_slope > 1024.0 {
        "increasing"
    } else if disk_io_slope < -1024.0 {
        "decreasing"
    } else {
        "stable"
    };
    let disk_io_trend = if disk_write_avg > 100.0 * 1024.0 * 1024.0 {
        "critical"
    } else if disk_io_slope > 1024.0 {
        "increasing"
    } else if disk_io_slope < -1024.0 {
        "decreasing"
    } else {
        "stable"
    };
    let network_trend = if net_slope > 10_000.0 {
        "increasing"
    } else if net_slope < -10_000.0 {
        "decreasing"
    } else {
        "stable"
    };

    // Estimate days until disk full from observed write rate or remaining capacity percentage
    let daily_write_gb = (disk_write_avg * 86_400.0) / (1024.0 * 1024.0 * 1024.0);
    let days_until_full = if disk_pct >= 99.0 {
        1
    } else if daily_write_gb > 0.5 && disk_free_gb > 0.0 {
        ((disk_free_gb / daily_write_gb).round() as i64).clamp(1, 365)
    } else {
        ((100.0 - disk_pct) * 3.5).round() as i64
    };

    if cpu_max > 85.0 {
        let msg = format!(
            "CPU utilization peaked at {:.1}% (average {:.1}%)",
            cpu_max, cpu_avg
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if mem_max > 90.0 {
        let msg = format!(
            "Memory pressure reached {:.1}% (average {:.1}%)",
            mem_max, mem_avg
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if load_avg > 4.0 {
        let msg = format!("Sustained 1m load average is elevated at {:.2}", load_avg);
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if disk_pct > 85.0 {
        let msg = format!(
            "Primary storage utilization is at {:.1}% (~{} days remaining)",
            disk_pct, days_until_full
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }

    let mut recommendations = Vec::new();
    if cpu_trend == "increasing" || cpu_trend == "critical" {
        recommendations.push(
            "Enable hardware-accelerated transcoding (NVENC/VAAPI/QSV) in MediaFlow to offload CPU spikes."
                .to_string(),
        );
    }
    if memory_trend == "increasing" || memory_trend == "critical" {
        recommendations.push(
            "Review memory-intensive services and configure swap or container memory limits."
                .to_string(),
        );
    }
    if disk_pct > 80.0 {
        recommendations.push(
            "Run MediaFlow HEVC/AV1 transcode optimization or prune old backups to reclaim storage."
                .to_string(),
        );
    }
    if recommendations.is_empty() {
        recommendations.push("Storage utilization is within healthy operational bounds.".to_string());
        recommendations.push("SQLite WAL retention pruning is active.".to_string());
    }

    let predicted_bottleneck = if disk_pct > 85.0 {
        "disk"
    } else if mem_max > 90.0 || memory_trend == "increasing" {
        "memory"
    } else if cpu_max > 85.0 || cpu_trend == "increasing" {
        "cpu"
    } else {
        "none"
    };

    let confidence_score = if history.len() >= 100 {
        0.92
    } else if history.len() >= 10 {
        0.80
    } else {
        0.65
    };

    let trend_summary = format!(
        "Analyzed {} telemetry snapshot(s): CPU avg {:.1}% (peak {:.1}%, trend {}), Memory avg {:.1}% (peak {:.1}%, trend {}), Disk {:.1}% used (~{} days until full).",
        history.len(),
        cpu_avg,
        cpu_max,
        cpu_trend,
        mem_avg,
        mem_max,
        memory_trend,
        disk_pct,
        days_until_full
    );

    if invoke_ai && history.len() >= 10 {
        let ps = resolve_provider_settings();
        let prompt = format!(
            "Analyze the following system metrics history and provide a resource prediction report.\n\n{}\n\nStatistical Summary:\n- Data points: {}\n- CPU Avg: {:.1}%, Max: {:.1}%, Linear Trend Slope: {:.4}\n- Memory Avg: {:.1}%, Max: {:.1}%, Linear Trend Slope: {:.4}\n- Avg 1m Load: {:.2}\n- Avg Disk Write: {:.0} B/s\n\nRespond ONLY with valid JSON in this exact format:\n{{\n  \"trend_summary\": \"2-3 sentence executive summary\",\n  \"cpu_trend\": \"increasing|decreasing|stable|critical\",\n  \"memory_trend\": \"increasing|decreasing|stable|critical\",\n  \"disk_io_trend\": \"increasing|decreasing|stable|critical\",\n  \"network_trend\": \"increasing|decreasing|stable|critical\",\n  \"warnings\": [\"warning 1\"],\n  \"recommendations\": [\"recommendation 1\"],\n  \"predicted_bottleneck\": \"cpu|memory|disk|network|none\",\n  \"confidence_score\": 0.85\n}}",
            get_system_metrics_context(),
            history.len(),
            cpu_avg,
            cpu_max,
            cpu_slope,
            mem_avg,
            mem_max,
            mem_slope,
            load_avg,
            disk_write_avg
        );
        if let Ok(ai_raw) = call_configured_ai(
            &ps,
            "You are FlowAI's predictive analytics engine for AetherFlow server management.",
            &prompt,
        )
        .await
        {
            let cleaned = clean_json_fence(&ai_raw);
            if let Ok(mut ai_val) = serde_json::from_str::<serde_json::Value>(&cleaned) {
                if let Some(obj) = ai_val.as_object_mut() {
                    obj.entry("disk_trend".to_string())
                        .or_insert_with(|| serde_json::json!(disk_trend));
                    obj.entry("days_until_disk_full".to_string())
                        .or_insert_with(|| serde_json::json!(days_until_full));
                    obj.entry("anomalies".to_string())
                        .or_insert_with(|| serde_json::json!(anomalies));
                    obj.entry("generated_at".to_string())
                        .or_insert_with(|| serde_json::json!(Utc::now().to_rfc3339()));
                    return ai_val;
                }
            }
        }
    }

    serde_json::json!({
        "trend_summary": trend_summary,
        "cpu_trend": cpu_trend,
        "memory_trend": memory_trend,
        "disk_trend": disk_trend,
        "disk_io_trend": disk_io_trend,
        "network_trend": network_trend,
        "days_until_disk_full": days_until_full,
        "anomalies": anomalies,
        "warnings": warnings,
        "recommendations": recommendations,
        "predicted_bottleneck": predicted_bottleneck,
        "confidence_score": confidence_score,
        "generated_at": Utc::now().to_rfc3339(),
    })
}

pub async fn get_predictions() -> Response {
    Json(build_resource_predictions(false).await).into_response()
}

pub async fn analyze_predictions() -> Response {
    Json(build_resource_predictions(true).await).into_response()
}

pub async fn get_metrics_history(Query(q): Query<HashMap<String, String>>) -> Response {
    let days = q
        .get("days")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&d| d > 0)
        .unwrap_or(90);

    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!([])).into_response();
    };
    let cutoff = (Utc::now() - Duration::days(days))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let mut snapshots = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, COALESCE(CAST(timestamp AS TEXT), ''), COALESCE(cpu_avg, 0), COALESCE(mem_used_gb, 0), COALESCE(mem_total_gb, 0), \
         COALESCE(disk_read_bps, 0), COALESCE(disk_write_bps, 0), COALESCE(net_rx_bytes, 0), COALESCE(net_tx_bytes, 0), \
         COALESCE(load_avg_1, 0), COALESCE(active_conns, 0) \
         FROM metrics_history WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') >= ?1 ORDER BY timestamp ASC LIMIT 2000",
    ) {
        if let Ok(rows) = stmt.query_map(params![cutoff], |r| {
            let id: i64 = r.get(0)?;
            let timestamp: String = r.get(1)?;
            let cpu_avg: f64 = r.get(2)?;
            let mem_used_gb: f64 = r.get(3)?;
            let mem_total_gb: f64 = r.get(4)?;
            let disk_read_bps: f64 = r.get(5)?;
            let disk_write_bps: f64 = r.get(6)?;
            let net_rx_bytes: i64 = r.get(7)?;
            let net_tx_bytes: i64 = r.get(8)?;
            let load_avg_1: f64 = r.get(9)?;
            let active_conns: i64 = r.get(10)?;
            Ok(serde_json::json!({
                "id": id,
                "timestamp": timestamp,
                "recorded_at": timestamp,
                "cpu_avg": cpu_avg,
                "cpu_usage": cpu_avg,
                "mem_used_gb": mem_used_gb,
                "mem_total_gb": mem_total_gb,
                "disk_read_bps": disk_read_bps,
                "disk_write_bps": disk_write_bps,
                "net_rx_bytes": net_rx_bytes,
                "net_tx_bytes": net_tx_bytes,
                "load_avg_1": load_avg_1,
                "load_1m": load_avg_1,
                "active_conns": active_conns,
            }))
        }) {
            for row in rows.flatten() {
                snapshots.push(row);
            }
        }
    }
    Json(snapshots).into_response()
}

pub async fn get_mediaflow_queue() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to fetch queue" })),
        )
            .into_response();
    };
    let mut items = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, file_path, status, COALESCE(original_codec, ''), COALESCE(original_size, 0), \
         COALESCE(new_codec, ''), COALESCE(new_size, 0), COALESCE(error_log, ''), COALESCE(created_at, '') \
         FROM mediaflow_queue WHERE status != 'DECLINED' ORDER BY created_at DESC LIMIT 100",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "filePath": r.get::<_, String>(1)?,
                "status": r.get::<_, String>(2)?,
                "originalCodec": r.get::<_, String>(3)?,
                "originalSize": r.get::<_, i64>(4)?,
                "newCodec": r.get::<_, String>(5)?,
                "newSize": r.get::<_, i64>(6)?,
                "errorLog": r.get::<_, String>(7)?,
                "createdAt": r.get::<_, String>(8)?,
            }))
        }) {
            for item in rows.flatten() {
                items.push(item);
            }
        }
    }
    Json(items).into_response()
}

static MEDIAFLOW_VIDEO_EXTS: &[&str] = &[".mkv", ".mp4", ".avi", ".mov", ".ts", ".m2ts"];

fn probe_video_codec_and_size(file_path: &StdPath) -> (String, i64) {
    let fallback_size = std::fs::metadata(file_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);

    if let Ok(out) = Command::new("ffprobe")
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
        ])
        .arg(file_path)
        .output()
    {
        if out.status.success() {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                let mut v_codec = String::new();
                if let Some(streams) = val.get("streams").and_then(|v| v.as_array()) {
                    for s in streams {
                        if s.get("codec_type").and_then(|v| v.as_str()) == Some("video") {
                            v_codec = s
                                .get("codec_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_lowercase();
                            break;
                        }
                    }
                }
                let size = val
                    .pointer("/format/size")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|&sz| sz > 0)
                    .unwrap_or(fallback_size);
                if !v_codec.is_empty() {
                    return (v_codec, size);
                }
            }
        }
    }

    // Fallback when ffprobe is not installed or fails: infer from filename
    let fname_lower = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let codec = if fname_lower.contains("hevc")
        || fname_lower.contains("x265")
        || fname_lower.contains("h265")
        || fname_lower.contains("h.265")
    {
        "hevc".to_string()
    } else if fname_lower.contains("av1") {
        "av1".to_string()
    } else if fname_lower.contains("mpeg2") {
        "mpeg2video".to_string()
    } else if fname_lower.contains("vp9") {
        "vp9".to_string()
    } else {
        "h264".to_string()
    };

    (codec, fallback_size)
}

fn mediaflow_library_roots() -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = match env::var("AF_ALLOWED_FS_ROOTS") {
        Ok(configured) => configured
            .split(',')
            .map(str::trim)
            .filter(|root| !root.is_empty())
            .map(PathBuf::from)
            .collect(),
        Err(_) => vec![
            PathBuf::from("/mnt"),
            PathBuf::from("/media"),
            PathBuf::from("/home"),
            PathBuf::from("/opt/AetherFlow"),
            PathBuf::from("/var/lib/aetherflow"),
        ],
    };
    roots.into_iter().filter_map(|root| root.canonicalize().ok()).collect()
}

fn validate_mediaflow_directory(
    directory: &StdPath,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, (StatusCode, String)> {
    let resolved = directory.canonicalize().map_err(|_| {
        (StatusCode::BAD_REQUEST, "Directory does not exist or is not accessible".to_string())
    })?;
    if !resolved.is_dir() {
        return Err((StatusCode::BAD_REQUEST, "Scan path must be a directory".to_string()));
    }
    if !allowed_roots.iter().any(|root| resolved.starts_with(root)) {
        return Err((StatusCode::FORBIDDEN, "Directory is outside configured library roots".to_string()));
    }
    Ok(resolved)
}

fn collect_mediaflow_files(directory: &StdPath, root: &StdPath, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::symlink_metadata(directory) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    let Ok(resolved) = directory.canonicalize() else {
        return;
    };
    if !resolved.starts_with(root) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&resolved) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_mediaflow_files(&path, root, out);
        } else if file_type.is_file() {
            let Ok(path) = path.canonicalize() else {
                continue;
            };
            if path.starts_with(root)
                && path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| {
                    MEDIAFLOW_VIDEO_EXTS.iter().any(|allowed| allowed[1..].eq_ignore_ascii_case(ext))
                })
            {
                out.push(path);
            }
        }
    }
}

fn scan_directory_for_mediaflow(root_dir: &StdPath) -> anyhow::Result<()> {
    let mut video_files = Vec::new();
    collect_mediaflow_files(root_dir, root_dir, &mut video_files);

    for path in video_files {
        let path_str = path.to_string_lossy().to_string();
        if path_str.contains(".mediaflow_trash") {
            continue;
        }
        let exists: i64 = {
            let conn = af_db::get_conn()?;
            conn.query_row(
                "SELECT COUNT(*) FROM mediaflow_queue WHERE file_path = ?1",
                params![path_str],
                |r| r.get(0),
            )?
        };
        if exists > 0 {
            continue;
        }

        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || !path.canonicalize()?.starts_with(root_dir) {
            continue;
        }
        let (codec, size) = probe_video_codec_and_size(&path);
        if codec != "hevc" && codec != "av1" {
            let conn = af_db::get_conn()?;
            conn.execute(
                "INSERT INTO mediaflow_queue (file_path, original_codec, original_size, status) SELECT ?1, ?2, ?3, 'PENDING_APPROVAL' WHERE NOT EXISTS (SELECT 1 FROM mediaflow_queue WHERE file_path = ?1)",
                params![path_str, codec, size],
            )?;
        }
    }
    Ok(())
}

pub async fn trigger_mediaflow_scan(Json(req): Json<serde_json::Value>) -> Response {
    let dir = req
        .get("directory")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if dir.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid payload" })),
        )
            .into_response();
    }
    let directory = PathBuf::from(dir);
    let dir_buf = match tokio::task::spawn_blocking(move || {
        validate_mediaflow_directory(&directory, &mediaflow_library_roots())
    }).await {
        Ok(Ok(directory)) => directory,
        Ok(Err((status, message))) => return api_error(status, "INVALID_SCAN_PATH", message),
        Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", error.to_string()),
    };
    let response_directory = dir_buf.to_string_lossy().into_owned();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = scan_directory_for_mediaflow(&dir_buf) {
            tracing::error!(%error, directory = %dir_buf.display(), "MediaFlow scan failed");
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "message": "Scan initiated in background",
            "directory": response_directory,
        })),
    )
        .into_response()
}

pub async fn approve_mediaflow_item(Path(id): Path<String>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to approve" })),
        )
            .into_response();
    };
    let affected = conn
        .execute(
            "UPDATE mediaflow_queue SET status = 'APPROVED', updated_at = CURRENT_TIMESTAMP WHERE id = ?1 AND status = 'PENDING_APPROVAL'",
            params![id],
        )
        .unwrap_or(0);
    if affected == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Item not found or already processed" })),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "message": "Transcode queued. MediaFlow Engine assumes control."
    }))
    .into_response()
}

pub async fn decline_mediaflow_item(Path(id): Path<String>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to decline" })),
        )
            .into_response();
    };
    let affected = conn
        .execute(
            "UPDATE mediaflow_queue SET status = 'DECLINED', updated_at = CURRENT_TIMESTAMP WHERE id = ?1 AND status = 'PENDING_APPROVAL'",
            params![id],
        )
        .unwrap_or(0);
    if affected == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Item not found or already processed" })),
        )
            .into_response();
    }
    Json(serde_json::json!({ "message": "Transcode job declined." })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Network VPN Management (`backend/api/network_handlers.go` & `network.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
fn parse_wireguard_dump(stdout: &str) -> Option<serde_json::Value> {
    let interface_fields = stdout.lines().find_map(|line| {
        let fields: Vec<&str> = line.split('\t').collect();
        (fields.len() == 5).then_some(fields)
    })?;
    let mut peers = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 9 || fields[0] != interface_fields[0] {
            continue;
        }
        peers.push(serde_json::json!({
            "public_key": fields[1],
            "endpoint": fields[3],
            "allowed_ips": fields[4],
            "latest_handshake": fields[5],
            "transfer_rx": fields[6],
            "transfer_tx": fields[7],
        }));
    }
    Some(serde_json::json!({
        "interface": interface_fields[0],
        "public_key": interface_fields[2],
        "listen_port": interface_fields[3],
        "peers": peers,
    }))
}

#[cfg(test)]
fn parse_tailscale_peer_obj(fallback_id: &str, p: &serde_json::Value) -> serde_json::Value {
    let id = p
        .get("ID")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_id);
    let host_name = p
        .get("HostName")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let dns_name = p
        .get("DNSName")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let os = p.get("OS").and_then(|v| v.as_str()).unwrap_or("");
    let online = p.get("Online").and_then(|v| v.as_bool()).unwrap_or(false);
    let exit_node = p.get("ExitNode").and_then(|v| v.as_bool()).unwrap_or(false);
    let rx_bytes = p.get("RxBytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let tx_bytes = p.get("TxBytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let ips: Vec<String> = p
        .get("TailscaleIPs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let primary_ip = ips.first().cloned().unwrap_or_default();
    let tags: Vec<&str> = p.get("Tags").and_then(|value| value.as_array())
        .map(|tags| tags.iter().filter_map(|tag| tag.as_str()).collect())
        .unwrap_or_default();

    serde_json::json!({
        "id": id,
        "hostname": host_name,
        "dns_name": dns_name,
        "tailscale_ip": primary_ip,
        "tailscale_ips": ips,
        "tags": tags,
        "os": os,
        "online": online,
        "exit_node": exit_node,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    })
}

#[cfg(test)]
fn parse_tailscale_status_json(
    raw: &serde_json::Value,
) -> (
    String,
    bool,
    Option<serde_json::Value>,
    Vec<serde_json::Value>,
) {
    let backend_state = raw
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("Stopped")
        .to_string();
    let magic_dns = raw
        .get("MagicDNSSuffix")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let self_peer = raw
        .get("Self")
        .filter(|v| v.is_object())
        .map(|s| parse_tailscale_peer_obj("self", s));

    let mut peers = Vec::new();
    if let Some(peer_map) = raw.get("Peer").and_then(|v| v.as_object()) {
        for (key, peer_val) in peer_map {
            peers.push(parse_tailscale_peer_obj(key, peer_val));
        }
    }

    (backend_state, magic_dns, self_peer, peers)
}

#[cfg(test)]
fn tailscale_status_value(raw: &serde_json::Value) -> serde_json::Value {
    let (backend_state, magic_dns, self_peer, peers) = parse_tailscale_status_json(raw);
    serde_json::json!({
        "backend_state": backend_state,
        "self": self_peer,
        "peers": peers,
        "magic_dns": magic_dns,
    })
}

// VPN host operations are implemented in crate::network and the privileged runner.

// ─────────────────────────────────────────────────────────────────────────────
// 4. Live System Topology, Log Bookmarks & Cluster Nodes
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_system_topology() -> Response {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let runner_sock = af_runner::runner_socket_path();
    let runner_online = StdPath::new(&runner_sock).exists();

    let mut nodes = vec![
        serde_json::json!({
            "id": "AetherFlow API",
            "group": 1,
            "status": "running",
            "details": format!("Port {} (Rust/Axum)", port),
        }),
        serde_json::json!({
            "id": "Runner Daemon",
            "group": 1,
            "status": if runner_online { "running" } else { "stopped" },
            "details": if runner_online { runner_sock } else { "Socket offline / direct mode".to_string() },
        }),
        serde_json::json!({
            "id": "SQLite WAL",
            "group": 2,
            "status": "running",
            "details": "SQLite (WAL mode)",
        }),
        serde_json::json!({
            "id": "Redis Cache",
            "group": 2,
            "status": "stopped",
            "details": "Disabled / Memory cache active",
        }),
        serde_json::json!({
            "id": "Apache2 Reverse Proxy",
            "group": 3,
            "status": "running",
            "details": "Apache2 + AetherFlow Subdomain Gateway (443 / 80)",
        }),
    ];

    let mut links = vec![
        serde_json::json!({ "source": "AetherFlow API", "target": "Runner Daemon", "value": 1 }),
        serde_json::json!({ "source": "AetherFlow API", "target": "SQLite WAL", "value": 1 }),
        serde_json::json!({ "source": "Apache2 Reverse Proxy", "target": "AetherFlow API", "value": 1 }),
    ];

    if let Ok(pkgs) = af_services::get_packages() {
        for pkg in pkgs {
            if (pkg.status == "running" || pkg.status == "installed") && !pkg.name.is_empty() {
                let label = if pkg.label.is_empty() {
                    pkg.name.clone()
                } else {
                    pkg.label.clone()
                };
                let node_status = if pkg.status == "running" {
                    "running"
                } else {
                    "stopped"
                };
                let mut details = if pkg.status == "running" {
                    "Running".to_string()
                } else {
                    "Installed (inactive)".to_string()
                };
                if let Ok(Some(ingress)) = af_db::get_app_ingress_config(&pkg.name) {
                    if ingress.listen_port > 0 {
                        details = format!("Port {}", ingress.listen_port);
                        if !ingress.public_domain.is_empty() {
                            details = format!("{} | {}", details, ingress.public_domain);
                        }
                    }
                } else if let Some(bp) = af_services::get_blueprint(&pkg.name) {
                    if bp.default_port > 0 {
                        details = format!("Port {} (blueprint)", bp.default_port);
                    }
                }
                nodes.push(serde_json::json!({
                    "id": label,
                    "group": 4,
                    "status": node_status,
                    "details": details,
                }));
                links.push(serde_json::json!({
                    "source": "Apache2 Reverse Proxy",
                    "target": label,
                    "value": 1,
                }));
            }
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "links": links,
    }))
    .into_response()
}

fn infer_log_level(line: &str) -> &'static str {
    let lower = line.to_lowercase();
    if lower.contains("fatal") || lower.contains("panic") || lower.contains("crit") {
        "CRIT"
    } else if lower.contains("error") || lower.contains("err") || lower.contains("failed") {
        "ERROR"
    } else if lower.contains("warn") || lower.contains("warning") {
        "WARN"
    } else if lower.contains("debug") {
        "DEBUG"
    } else {
        "INFO"
    }
}

const AUDIT_LOG_FALLBACK_SQL: &str =
    "SELECT COALESCE(CAST(created_at AS TEXT), ''), COALESCE(action, 'event'), COALESCE(target_type, 'system'), COALESCE(detail, '') FROM admin_audit_log ORDER BY id DESC LIMIT ?1";

pub async fn get_logs(Query(q): Query<HashMap<String, String>>) -> Response {
    let source = q
        .get("source")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    let unit = q
        .get("unit")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let search = q
        .get("search")
        .or_else(|| q.get("filter"))
        .or_else(|| q.get("keyword"))
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    let level_filter = q
        .get("level")
        .or_else(|| q.get("priority"))
        .map(|s| s.trim().to_uppercase())
        .unwrap_or_default();
    let limit = q
        .get("lines")
        .or_else(|| q.get("limit"))
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(200)
        .min(1000);
    let offset = q
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let mut raw_entries: Vec<serde_json::Value> = Vec::new();

    // 1. Read from /var/log/aetherflow-deploy.log or /var/log/syslog or apache logs when requested
    let mut candidate_files: Vec<(&str, &str)> = Vec::new();
    match source.as_str() {
        "application" | "deploy" => {
            candidate_files.push(("application", "/var/log/aetherflow-deploy.log"));
        }
        "syslog" => {
            candidate_files.push(("syslog", "/var/log/syslog"));
            candidate_files.push(("syslog", "/var/log/messages"));
        }
        "apache" => {
            candidate_files.push(("apache", "/var/log/apache2/error.log"));
            candidate_files.push(("apache", "/var/log/apache2/access.log"));
        }
        "" => {
            candidate_files.push(("application", "/var/log/aetherflow-deploy.log"));
            candidate_files.push(("syslog", "/var/log/syslog"));
            candidate_files.push(("apache", "/var/log/apache2/error.log"));
        }
        _ => {}
    }

    for (src_name, file_path) in candidate_files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let all_lines: Vec<&str> = content.lines().collect();
            let start_idx = all_lines.len().saturating_sub(limit + offset);
            for line in &all_lines[start_idx..] {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let lvl = infer_log_level(trimmed);
                raw_entries.push(serde_json::json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "source": src_name,
                    "service": if unit.is_empty() { src_name } else { unit.as_str() },
                    "level": lvl,
                    "message": trimmed,
                }));
            }
        }
    }

    // 2. Query journalctl if source is empty or "journald"
    if source.is_empty() || source == "journald" {
        let mut args = vec![
            "-n".to_string(),
            limit.to_string(),
            "--no-pager".to_string(),
            "-o".to_string(),
            "short-iso".to_string(),
        ];
        if !unit.is_empty() {
            args.push("-u".to_string());
            args.push(unit.clone());
        }
        if let Ok(out) = Command::new("journalctl").args(&args).output() {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with("-- ") {
                        continue;
                    }
                    let mut parts = trimmed.splitn(3, ' ');
                    let ts = parts.next().unwrap_or("");
                    let _host = parts.next().unwrap_or("");
                    let rest = parts.next().unwrap_or(trimmed);
                    let (svc, msg) = if let Some((s, m)) = rest.split_once(": ") {
                        (s.trim(), m.trim())
                    } else {
                        ("journald", rest)
                    };
                    let lvl = infer_log_level(msg);
                    raw_entries.push(serde_json::json!({
                        "timestamp": ts,
                        "source": "journald",
                        "service": svc,
                        "level": lvl,
                        "message": msg,
                    }));
                }
            }
        }
    }

    // 3. Fallback: include audit/notification log entries from SQLite when host log files are absent
    if raw_entries.is_empty() {
        if let Ok(conn) = af_db::get_conn() {
            if let Ok(mut stmt) = conn.prepare(AUDIT_LOG_FALLBACK_SQL) {
                if let Ok(rows) = stmt.query_map(params![limit as i64], |r| {
                    let ts: String = r.get(0)?;
                    let action: String = r.get(1)?;
                    let target: String = r.get(2)?;
                    let details: String = r.get(3)?;
                    let msg = if details.is_empty() {
                        action.clone()
                    } else {
                        format!("{}: {}", action, details)
                    };
                    Ok(serde_json::json!({
                        "timestamp": ts,
                        "source": if source.is_empty() { "application" } else { source.as_str() },
                        "service": target,
                        "level": infer_log_level(&msg),
                        "message": msg,
                    }))
                }) {
                    for entry in rows.flatten() {
                        raw_entries.push(entry);
                    }
                }
            }
        }
    }

    // Apply unit, level, and search filters
    let unit_lower = unit.to_lowercase();
    let filtered: Vec<serde_json::Value> = raw_entries
        .into_iter()
        .filter(|entry| {
            if !unit_lower.is_empty() {
                let svc = entry
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let msg = entry
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if !svc.contains(&unit_lower) && !msg.contains(&unit_lower) {
                    return false;
                }
            }
            if !level_filter.is_empty() {
                let lvl = entry
                    .get("level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if !lvl.contains(&level_filter) {
                    return false;
                }
            }
            if !search.is_empty() {
                let msg = entry
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let svc = entry
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if !msg.contains(&search) && !svc.contains(&search) {
                    return false;
                }
            }
            true
        })
        .skip(offset)
        .take(limit)
        .collect();

    let count = filtered.len();
    Json(serde_json::json!({
        "logs": filtered,
        "count": count,
    }))
    .into_response()
}

pub async fn get_log_sources() -> Response {
    Json(serde_json::json!({
        "sources": ["journald", "syslog", "apache", "application"]
    }))
    .into_response()
}

pub async fn bookmark_log(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };
    let log_source = body.get("log_source").and_then(|v| v.as_str()).unwrap_or("");
    let log_line = body.get("log_line").and_then(|v| v.as_str()).unwrap_or("");
    let timestamp = body.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    if log_source.is_empty() || log_line.is_empty() || timestamp.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "log_source, log_line, and timestamp are required",
        );
    }

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to bookmark log",
        );
    };
    if conn
        .execute(
            "INSERT INTO log_bookmarks (user_id, log_source, log_line, timestamp, note) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user.user_id, log_source, log_line, timestamp, note],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to bookmark log",
        );
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "message": "Log bookmarked" })),
    )
        .into_response()
}

pub async fn get_bookmarks(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to fetch bookmarks",
        );
    };
    let mut bookmarks = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, log_source, log_line, timestamp, COALESCE(note, ''), COALESCE(created_at, '') \
         FROM log_bookmarks WHERE user_id = ?1 ORDER BY created_at DESC",
    ) {
        if let Ok(rows) = stmt.query_map(params![user.user_id], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "log_source": r.get::<_, String>(1)?,
                "log_line": r.get::<_, String>(2)?,
                "timestamp": r.get::<_, String>(3)?,
                "note": r.get::<_, String>(4)?,
                "created_at": r.get::<_, String>(5)?,
            }))
        }) {
            for b in rows.flatten() {
                bookmarks.push(b);
            }
        }
    }
    Json(serde_json::json!({ "bookmarks": bookmarks })).into_response()
}

pub async fn get_cluster_nodes() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!({
            "nodes": [],
            "summary": {
                "total_nodes": 0,
                "online": 0,
                "offline": 0,
                "total_cpu_avg": 0.0,
                "total_mem_used": 0.0,
                "total_mem_total": 0.0,
                "total_disk_used": 0.0,
                "total_disk_total": 0.0
            }
        }))
        .into_response();
    };

    let mut nodes = Vec::new();
    let mut online = 0usize;
    let mut offline = 0usize;
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, hostname, address, COALESCE(role, 'worker'), COALESCE(status, 'offline'), \
         COALESCE(last_heartbeat, ''), COALESCE(enrolled_at, '') FROM cluster_nodes",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            let status: String = r.get(4)?;
            Ok((
                status.clone(),
                serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "hostname": r.get::<_, String>(1)?,
                    "address": r.get::<_, String>(2)?,
                    "role": r.get::<_, String>(3)?,
                    "status": status,
                    "version": "4.0.0",
                    "last_heartbeat": r.get::<_, String>(5)?,
                    "enrolled_at": r.get::<_, String>(6)?,
                }),
            ))
        }) {
            for (status, node) in rows.flatten() {
                if status == "online" {
                    online += 1;
                } else {
                    offline += 1;
                }
                nodes.push(node);
            }
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "summary": {
            "total_nodes": nodes.len(),
            "online": online,
            "offline": offline,
            "total_cpu_avg": 0.0,
            "total_mem_used": 0.0,
            "total_mem_total": 0.0,
            "total_disk_used": 0.0,
            "total_disk_total": 0.0
        }
    }))
    .into_response()
}

pub async fn enroll_worker() -> Response {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    Json(serde_json::json!({
        "enrollment_token": token,
        "instructions": format!(
            "Run on the worker node: aetherflow-api --cluster-mode=worker --master-addr=<this-server>:50051 --psk={}",
            token
        ),
    }))
    .into_response()
}

pub async fn remove_worker(Path(node_id): Path<String>) -> Response {
    if node_id.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Node ID is required",
        );
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let affected = conn
        .execute("DELETE FROM cluster_nodes WHERE id = ?1", params![node_id])
        .unwrap_or(0);
    if affected == 0 {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Node not found");
    }
    af_services::cluster_daemon::remove_cached_worker_metrics(&node_id);
    Json(serde_json::json!({
        "message": "Node removed successfully",
        "node_id": node_id,
    }))
    .into_response()
}

pub async fn get_worker_metrics(Path(node_id): Path<String>) -> Response {
    if let Some(cached) = af_services::cluster_daemon::get_cached_worker_metrics(&node_id) {
        return Json(cached).into_response();
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let Ok((hostname, status, last_hb)) = conn.query_row(
        "SELECT hostname, COALESCE(status, 'offline'), COALESCE(last_heartbeat, '') FROM cluster_nodes WHERE id = ?1",
        params![node_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Node not found");
    };

    Json(serde_json::json!({
        "node_id": node_id,
        "hostname": hostname,
        "status": status,
        "metrics": null,
        "services": [],
        "system_info": null,
        "last_heartbeat": last_hb,
    }))
    .into_response()
}
