use super::models::{sanitize_emby_token, PlexServerConfig};
use rusqlite::{params, OptionalExtension};
use std::env;

fn resolve_default_jellyfin_url() -> String {
    if let Ok(env_url) = env::var("JELLYFIN_URL") {
        let trimmed = env_url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(Some(cfg)) = af_db::get_app_ingress_config("jellyfin") {
        let dom = cfg.public_domain.trim();
        if !dom.is_empty() && cfg.external_access_enabled {
            return format!("https://{}", dom);
        }
        if cfg.listen_port > 0 {
            return format!("http://127.0.0.1:{}", cfg.listen_port);
        }
    }
    let base_dom = af_services::resolve_base_domain();
    if !base_dom.is_empty() {
        return format!("https://jellyfin.{}", base_dom);
    }
    "http://127.0.0.1:8096".to_string()
}

pub(super) fn try_get_stored_jellyfin_config() -> anyhow::Result<(String, String, String, bool)> {
    let mut name = "Jellyfin".to_string();
    let mut server_url = resolve_default_jellyfin_url();
    let mut raw_api_key = env::var("JELLYFIN_API_KEY")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut enabled = true;

    let conn = af_db::get_conn()?;
    if let Some((db_name, db_url, db_key, db_enabled)) = conn
        .query_row(
            "SELECT name, url, api_key, enabled FROM streaming_servers WHERE provider = 'jellyfin'",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            },
        )
        .optional()?
    {
        if !db_name.trim().is_empty() {
            name = db_name.trim().to_string();
        }
        if !db_url.trim().is_empty() {
            server_url = db_url.trim().trim_end_matches('/').to_string();
        }
        enabled = db_enabled;
        if !db_key.is_empty() {
            match af_db::decrypt_key(&db_key) {
                Ok(dec) if !dec.is_empty() => raw_api_key = dec,
                _ if !db_key.starts_with("enc:v1:") => raw_api_key = db_key,
                _ => {
                    tracing::warn!(
                        "failed to decrypt stored Jellyfin API key; refusing ciphertext fallback"
                    );
                    raw_api_key.clear();
                }
            }
        }
    }

    Ok((name, server_url, raw_api_key, enabled))
}

pub fn get_stored_jellyfin_config() -> (String, String, String, bool) {
    match try_get_stored_jellyfin_config() {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::warn!(%error, "failed to load stored Jellyfin configuration; using defaults");
            (
                "Jellyfin".to_string(),
                resolve_default_jellyfin_url(),
                env::var("JELLYFIN_API_KEY")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                true,
            )
        }
    }
}

pub(super) fn try_get_stored_emby_config_fail_closed(
) -> anyhow::Result<crate::streaming_emby::EmbyServerConfig> {
    let mut cfg = crate::streaming_emby::EmbyServerConfig {
        provider: crate::streaming_emby::EMBY_PROVIDER_ID.to_string(),
        name: crate::streaming_emby::EMBY_DEFAULT_NAME.to_string(),
        url: crate::streaming_emby::resolve_default_emby_url(),
        api_key: env::var("EMBY_API_KEY")
            .unwrap_or_default()
            .trim()
            .to_string(),
        enabled: false,
        expected_server_id: String::new(),
    };
    if cfg.api_key.starts_with("enc:v1:") {
        tracing::warn!("refusing undecrypted Emby ciphertext API key from environment");
        cfg.api_key.clear();
    }

    let conn = af_db::get_conn()?;
    if let Some((db_name, db_url, db_key, db_enabled, db_srv_id)) = conn
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
        .optional()?
    {
        if !db_name.trim().is_empty() {
            cfg.name = db_name.trim().to_string();
        }
        if !db_url.trim().is_empty() {
            cfg.url = db_url.trim().trim_end_matches('/').to_string();
        }
        cfg.enabled = db_enabled;
        cfg.expected_server_id = db_srv_id.trim().to_string();
        if !db_key.is_empty() {
            if db_key.starts_with("enc:v1:") {
                match af_db::decrypt_key(&db_key) {
                    Ok(dec) if !dec.trim().is_empty() && !dec.starts_with("enc:v1:") => {
                        cfg.api_key = dec;
                    }
                    _ => {
                        tracing::warn!(
                            "stored Emby encrypted API key could not be decrypted; failing closed"
                        );
                        cfg.api_key.clear();
                    }
                }
            } else {
                cfg.api_key = db_key;
            }
        }
    }

    Ok(cfg)
}

pub fn get_stored_emby_config_fail_closed() -> crate::streaming_emby::EmbyServerConfig {
    match try_get_stored_emby_config_fail_closed() {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::warn!(%error, "failed to load stored Emby configuration; failing closed");
            crate::streaming_emby::EmbyServerConfig {
                provider: crate::streaming_emby::EMBY_PROVIDER_ID.to_string(),
                name: crate::streaming_emby::EMBY_DEFAULT_NAME.to_string(),
                url: crate::streaming_emby::resolve_default_emby_url(),
                api_key: String::new(),
                enabled: false,
                expected_server_id: String::new(),
            }
        }
    }
}

pub(super) fn try_get_stored_plex_config_fail_closed() -> anyhow::Result<PlexServerConfig> {
    let default_url = env::var("PLEX_URL")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:32400".to_string());
    let env_token = env::var("PLEX_TOKEN")
        .ok()
        .map(|s| sanitize_emby_token(&s))
        .unwrap_or_default();

    let mut cfg = PlexServerConfig {
        name: "Plex Media Server".to_string(),
        url: default_url,
        api_key: env_token,
        enabled: true,
        expected_server_id: String::new(),
    };

    let conn = af_db::get_conn()?;
    if let Some((name, url, raw_key, enabled, server_id)) = conn
        .query_row(
            "SELECT COALESCE(NULLIF(TRIM(name), ''), 'Plex Media Server'), \
                    COALESCE(NULLIF(TRIM(url), ''), 'http://127.0.0.1:32400'), \
                    COALESCE(api_key, ''), \
                    COALESCE(enabled, 1), \
                    COALESCE(server_id, '') \
             FROM streaming_servers WHERE provider = 'plex' LIMIT 1",
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
        .optional()?
    {
        cfg.name = name;
        cfg.url = url.trim_end_matches('/').to_string();
        cfg.enabled = enabled;
        cfg.expected_server_id = server_id;
        if raw_key.starts_with("enc:v1:") {
            match af_db::decrypt_key(&raw_key) {
                Ok(dec) if !dec.trim().is_empty() && !dec.starts_with("enc:v1:") => {
                    cfg.api_key = sanitize_emby_token(&dec);
                }
                _ => {
                    tracing::warn!(
                        "stored Plex encrypted API token could not be decrypted; failing closed"
                    );
                    cfg.api_key.clear();
                }
            }
        } else if !raw_key.trim().is_empty() {
            cfg.api_key = sanitize_emby_token(&raw_key);
        } else {
            cfg.api_key.clear();
        }
    }

    Ok(cfg)
}

pub fn get_stored_plex_config_fail_closed() -> PlexServerConfig {
    match try_get_stored_plex_config_fail_closed() {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::warn!(%error, "failed to load stored Plex configuration; failing closed");
            let default_url = env::var("PLEX_URL")
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "http://127.0.0.1:32400".to_string());
            PlexServerConfig {
                name: "Plex Media Server".to_string(),
                url: default_url,
                api_key: String::new(),
                enabled: true,
                expected_server_id: String::new(),
            }
        }
    }
}

pub(super) fn try_get_stored_provider_config(
    provider: &str,
) -> anyhow::Result<(String, String, String, bool)> {
    if provider == "jellyfin" {
        try_get_stored_jellyfin_config()
    } else if provider == "plex" {
        let config = try_get_stored_plex_config_fail_closed()?;
        Ok((config.name, config.url, config.api_key, config.enabled))
    } else {
        let config = try_get_stored_emby_config_fail_closed()?;
        Ok((config.name, config.url, config.api_key, config.enabled))
    }
}

pub(super) fn query_stored_provider_server_id(
    conn: &rusqlite::Connection,
    provider: &str,
) -> rusqlite::Result<String> {
    Ok(conn
        .query_row(
            "SELECT COALESCE(server_id, '') FROM streaming_servers WHERE provider = ?1",
            params![provider.trim()],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_default()
        .trim()
        .to_string())
}

pub(super) fn query_reconnect_window_secs(conn: &rusqlite::Connection) -> rusqlite::Result<i64> {
    Ok(conn
        .query_row(
            "SELECT COALESCE(reconnect_window_secs, 0) FROM streaming_tracking_policies WHERE id = 1",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0)
        .clamp(0, 300))
}

pub(super) fn persist_verified_monitor_source(
    conn: &rusqlite::Connection,
    provider: &str,
    server_url: &str,
    server_id: &str,
) -> anyhow::Result<String> {
    if server_id.trim().is_empty() {
        anyhow::bail!("Missing provider server identity");
    }
    let changed = conn.execute(
        "UPDATE streaming_servers SET server_id=CASE WHEN COALESCE(server_id,'')='' THEN ?3 ELSE server_id END WHERE provider=?1 AND RTRIM(url,'/')=RTRIM(?2,'/') AND enabled=1 AND (COALESCE(server_id,'')='' OR LOWER(server_id)=LOWER(?3))",
        params![provider, server_url, server_id],
    )?;
    if changed != 1 {
        anyhow::bail!("Provider source changed; verify server configuration");
    }
    Ok(query_stored_provider_server_id(conn, provider)?)
}

pub(super) fn persist_verified_source_with_key(
    conn: &rusqlite::Connection,
    provider: &str,
    url: &str,
    key: &str,
    server_id: &str,
) -> anyhow::Result<String> {
    let transaction =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let stored_key: String = transaction.query_row(
        "SELECT api_key FROM streaming_servers WHERE provider=?1 AND RTRIM(url,'/')=RTRIM(?2,'/') AND enabled=1",
        params![provider, url],
        |row| row.get(0),
    )?;
    let plaintext = if stored_key.starts_with("enc:v1:") {
        af_db::decrypt_key(&stored_key)?
    } else {
        stored_key
    };
    anyhow::ensure!(
        !key.is_empty() && plaintext == key,
        "Provider credentials changed during verification"
    );
    let identity = persist_verified_monitor_source(&transaction, provider, url, server_id)?;
    transaction.commit()?;
    Ok(identity)
}
