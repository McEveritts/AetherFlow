use super::models::{EmbyAdapterError, EmbyServerConfig};
use super::{EMBY_DEFAULT_NAME, EMBY_DEFAULT_URL, EMBY_PROVIDER_ID};
use axum::http::{header, StatusCode};
use once_cell::sync::Lazy;
use reqwest::Client;
use rusqlite::OptionalExtension;
use std::env;
use std::time::Duration;

static EMBY_HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    af_services::streaming_http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(16)
        .build()
        .expect("guarded Emby HTTP client")
});

pub(super) fn resolve_default_emby_url_from(
    env_url: Option<&str>,
    ingress: Option<&af_models::AppIngressConfig>,
    base_domain: &str,
) -> String {
    if let Some(trimmed) = env_url
        .map(|raw| raw.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
    {
        return trimmed.to_string();
    }
    if let Some(cfg) = ingress {
        let dom = cfg.public_domain.trim();
        if !dom.is_empty() && cfg.external_access_enabled {
            let scheme = if cfg.tls_enabled { "https" } else { "http" };
            return format!("{scheme}://{dom}");
        }
        if cfg.listen_port > 0 {
            return format!("http://127.0.0.1:{}", cfg.listen_port);
        }
    }
    let base_dom = base_domain.trim();
    if !base_dom.is_empty() {
        return format!("https://emby.{}", base_dom);
    }
    EMBY_DEFAULT_URL.to_string()
}

pub fn resolve_default_emby_url() -> String {
    let env_url = env::var("EMBY_URL").ok();
    let ingress = af_db::get_app_ingress_config(EMBY_PROVIDER_ID)
        .ok()
        .flatten();
    let base_dom = af_services::resolve_base_domain();
    resolve_default_emby_url_from(env_url.as_deref(), ingress.as_ref(), &base_dom)
}

pub fn get_stored_emby_config() -> EmbyServerConfig {
    let mut cfg = EmbyServerConfig {
        provider: EMBY_PROVIDER_ID.to_string(),
        name: EMBY_DEFAULT_NAME.to_string(),
        url: resolve_default_emby_url(),
        api_key: env::var("EMBY_API_KEY")
            .unwrap_or_default()
            .trim()
            .to_string(),
        enabled: false,
        expected_server_id: String::new(),
    };

    match af_db::get_conn() {
        Ok(conn) => match conn
            .query_row(
                "SELECT name, url, api_key, enabled, COALESCE(server_id, '') FROM streaming_servers WHERE provider = 'emby'",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, bool>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
        {
            Ok(Some((db_name, db_url, db_key, db_enabled, db_srv_id))) => {
                if !db_name.trim().is_empty() {
                    cfg.name = db_name.trim().to_string();
                }
                if !db_url.trim().is_empty() {
                    cfg.url = db_url.trim().trim_end_matches('/').to_string();
                }
                cfg.enabled = db_enabled;
                cfg.expected_server_id = db_srv_id.trim().to_string();
                if !db_key.is_empty() {
                    match af_db::decrypt_key(&db_key) {
                        Ok(dec) if !dec.is_empty() => cfg.api_key = dec,
                        _ if !db_key.starts_with("enc:v1:") => cfg.api_key = db_key,
                        _ => {
                            tracing::warn!(
                                "failed to decrypt stored Emby API key; refusing ciphertext fallback"
                            );
                            cfg.api_key.clear();
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to load stored Emby server configuration");
            }
        },
        Err(error) => {
            tracing::warn!(%error, "database unavailable while loading stored Emby configuration");
        }
    }

    cfg
}

pub fn validate_emby_server_url(raw_url: &str) -> Result<String, EmbyAdapterError> {
    let clean = af_services::validate_server_url(raw_url)
        .map_err(|e| EmbyAdapterError::InvalidUrl(e.to_string()))?;
    let parsed = url::Url::parse(&clean)
        .map_err(|_| EmbyAdapterError::InvalidUrl("Invalid server URL format".to_string()))?;
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || !host.contains(':') {
        // Additional defense-in-depth check on path segments (prevent path traversal in base URL)
        if parsed.path().contains("..") || parsed.path().contains('\\') {
            return Err(EmbyAdapterError::InvalidUrl(
                "URL path must not contain traversal sequences".to_string(),
            ));
        }
    }
    Ok(clean.trim_end_matches('/').to_string())
}

pub fn sanitize_emby_token(api_key: &str) -> String {
    api_key
        .chars()
        .filter(|&c| c != '"' && c != '\r' && c != '\n' && (c as u32) >= 0x20)
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn mask_emby_api_key(api_key: &str) -> String {
    let clean = sanitize_emby_token(api_key);
    let char_count = clean.chars().count();
    if char_count > 4 {
        let tail: String = clean
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("****{}", tail)
    } else if !clean.is_empty() {
        "****".to_string()
    } else {
        String::new()
    }
}

fn build_emby_authorization_header(clean_token: &str) -> String {
    format!(
        "Emby Client=\"AetherFlow\", Device=\"Nexus\", DeviceId=\"aetherflow-nexus\", Version=\"4.0\", Token=\"{}\"",
        clean_token
    )
}

pub(super) async fn do_emby_request(
    method: reqwest::Method,
    full_url: &str,
    api_key: &str,
    json_body: Option<serde_json::Value>,
    timeout: Duration,
    max_bytes: usize,
) -> Result<(Vec<u8>, StatusCode, String), EmbyAdapterError> {
    let mut req = EMBY_HTTP_CLIENT
        .request(method, full_url)
        .timeout(timeout)
        .header(header::ACCEPT, "application/json");

    let clean_token = sanitize_emby_token(api_key);
    if !clean_token.is_empty() {
        let auth_val = build_emby_authorization_header(&clean_token);
        req = req
            .header("X-Emby-Token", &clean_token)
            .header("X-Emby-Authorization", &auth_val)
            .header(header::AUTHORIZATION, auth_val);
    }

    if let Some(body) = json_body {
        req = req.json(&body);
    }

    let mut resp = req
        .send()
        .await
        .map_err(|e| EmbyAdapterError::Transport(e.to_string()))?;

    let status = resp.status();
    if status.is_redirection() {
        return Err(EmbyAdapterError::Transport(format!(
            "Upstream redirect (HTTP {}) is disallowed",
            status.as_u16()
        )));
    }

    if let Some(content_len) = resp.content_length() {
        if content_len > max_bytes as u64 {
            return Err(EmbyAdapterError::PayloadTooLarge {
                limit_bytes: max_bytes,
            });
        }
    }

    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| EmbyAdapterError::Transport(e.to_string()))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(EmbyAdapterError::PayloadTooLarge {
                limit_bytes: max_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok((body, status, content_type))
}
