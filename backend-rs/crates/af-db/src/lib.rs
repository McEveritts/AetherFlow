mod retained_ingress;
pub use retained_ingress::{
    archive_app_ingress_config, archive_app_ingress_config_for_lifecycle,
    get_reserved_ports_excluding, get_retained_app_ingress_config, list_reserved_ports_excluding,
    load_lifecycle_ingress, plan_lifecycle_ingress, synchronize_lifecycle_ingress,
};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use af_models::AppIngressConfig;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::RngCore;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod streaming;

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM Secret Encryption
// ─────────────────────────────────────────────────────────────────────────────

const CIPHERTEXT_PREFIX: &str = "enc:v1:";

static AES_MASTER_KEY: Lazy<RwLock<Option<[u8; 32]>>> = Lazy::new(|| RwLock::new(None));

pub fn parse_aes_key_bytes(raw: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut arr = [0u8; 32];
        for (idx, dst) in arr.iter_mut().enumerate() {
            let hex_pair = &trimmed[idx * 2..idx * 2 + 2];
            *dst = u8::from_str_radix(hex_pair, 16)?;
        }
        return Ok(arr);
    }
    if let Ok(decoded) = BASE64_STD.decode(trimmed) {
        if decoded.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            return Ok(arr);
        }
    }
    if trimmed.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(trimmed.as_bytes());
        return Ok(arr);
    }
    if raw.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw.as_bytes());
        return Ok(arr);
    }
    anyhow::bail!(
        "FATAL: AES_MASTER_KEY must decode to 32 bytes (32-byte raw, base64, or 64-char hex). Got {} chars.",
        trimmed.len()
    )
}

fn aes_key_candidate_env_files() -> Vec<std::path::PathBuf> {
    if env::var("AETHERFLOW_SKIP_ENV_FILES").as_deref() == Ok("1") {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    if let Some(explicit_path) = env::var("AETHERFLOW_ENV_FILE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        candidates.push(std::path::PathBuf::from(explicit_path));
    }
    let default_env = std::path::PathBuf::from("/etc/aetherflow/aetherflow.env");
    if !candidates.iter().any(|p| p == &default_env) {
        candidates.push(default_env);
    }
    candidates
}

pub fn resolve_runtime_aes_key() -> Option<[u8; 32]> {
    {
        let guard = AES_MASTER_KEY.read().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = *guard {
            return Some(key);
        }
    }
    if let Ok(raw) = env::var("AES_MASTER_KEY") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if let Ok(key) = parse_aes_key_bytes(trimmed) {
                return Some(key);
            }
        }
    }
    for env_file in aes_key_candidate_env_files() {
        if let Some(clean) = read_last_aes_key_from_env_file(&env_file) {
            if let Ok(key) = parse_aes_key_bytes(&clean) {
                return Some(key);
            }
        }
    }
    None
}

fn read_last_aes_key_from_env_file(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    if let Some(parent) = path.parent() {
        let pmeta = fs::symlink_metadata(parent).ok()?;
        if pmeta.file_type().is_symlink() || !pmeta.is_dir() {
            return None;
        }
    }
    let lmeta = fs::symlink_metadata(path).ok()?;
    if lmeta.file_type().is_symlink() || !lmeta.is_file() {
        return None;
    }
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = opts.open(path).ok()?;
    let fmeta = file.metadata().ok()?;
    if !fmeta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if lmeta.dev() != fmeta.dev() || lmeta.ino() != fmeta.ino() {
            return None;
        }
    }
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents).ok()?;
    let mut last_raw: Option<String> = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some(val) = stripped.strip_prefix("AES_MASTER_KEY=") {
            let clean = val.trim().trim_matches('"').trim_matches('\'');
            if !clean.is_empty() {
                last_raw = Some(clean.to_string());
            }
        }
    }
    last_raw
}

fn encrypt_with_key(plaintext: &str, key: &[u8; 32]) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("aes cipher creation failed: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("gcm encryption failed: {}", e))?;
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(format!(
        "{}{}",
        CIPHERTEXT_PREFIX,
        BASE64_STD.encode(combined)
    ))
}

fn decrypt_with_key(payload: &str, key: &[u8; 32]) -> anyhow::Result<String> {
    let data = BASE64_STD
        .decode(payload)
        .map_err(|e| anyhow::anyhow!("versioned ciphertext base64 decode failed: {}", e))?;
    if data.len() < 12 {
        anyhow::bail!("ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("aes cipher creation failed: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("gcm decryption failed: {}", e))?;
    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("invalid utf8: {}", e))
}

pub fn encrypt_secret_if_configured(plaintext: &str) -> anyhow::Result<String> {
    match resolve_runtime_aes_key() {
        Some(key) => encrypt_with_key(plaintext, &key),
        None => Ok(plaintext.to_string()),
    }
}

pub fn decrypt_secret_if_needed(value: &str) -> anyhow::Result<String> {
    if let Some(payload) = value.strip_prefix(CIPHERTEXT_PREFIX) {
        let key = resolve_runtime_aes_key().ok_or_else(|| {
            anyhow::anyhow!("AES_MASTER_KEY is required to decrypt enc:v1: secret")
        })?;
        return decrypt_with_key(payload, &key);
    }
    Ok(value.to_string())
}

/// Initializes the AES-256-GCM master key from `AES_MASTER_KEY` (or `AETHERFLOW_ENV_FILE`).
pub fn init_aes_key() -> anyhow::Result<()> {
    let mut raw = env::var("AES_MASTER_KEY")
        .unwrap_or_default()
        .trim()
        .to_string();
    if raw.is_empty() {
        for candidate in aes_key_candidate_env_files() {
            if let Some(from_file) = read_last_aes_key_from_env_file(&candidate) {
                raw = from_file;
                break;
            }
        }
    }
    if raw.is_empty() {
        let af_env = env::var("AETHERFLOW_ENV").unwrap_or_default();
        let is_production = af_env.trim().eq_ignore_ascii_case("production")
            || af_env.trim().eq_ignore_ascii_case("release");
        if is_production {
            anyhow::bail!(
                "FATAL: AES_MASTER_KEY is required in production (AETHERFLOW_ENV=production). \
                 Set a 32-byte key (raw, hex, or base64-encoded) to enable API key encryption."
            );
        }
        tracing::info!(
            "WARNING: AES_MASTER_KEY not set. API key encryption is disabled (dev/test mode only)."
        );
        *AES_MASTER_KEY.write().unwrap_or_else(|e| e.into_inner()) = None;
        return Ok(());
    }

    let key_bytes = parse_aes_key_bytes(&raw)?;

    *AES_MASTER_KEY.write().unwrap_or_else(|e| e.into_inner()) = Some(key_bytes);
    tracing::info!("AES-256-GCM encryption key loaded successfully.");
    Ok(())
}

pub fn is_encryption_enabled() -> bool {
    AES_MASTER_KEY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

/// Encrypts plaintext using AES-256-GCM with a 12-byte random nonce, returning
/// `"enc:v1:<base64(nonce || ciphertext)>"` — byte-for-byte compatible with Go's `EncryptKey`.
pub fn encrypt_key(plaintext: &str) -> anyhow::Result<String> {
    let key_opt = *AES_MASTER_KEY.read().unwrap_or_else(|e| e.into_inner());
    let Some(key) = key_opt else {
        return Ok(plaintext.to_string());
    };
    encrypt_with_key(plaintext, &key)
}

/// Decrypts a versioned `"enc:v1:<base64>"` string produced by Go or Rust.
pub fn decrypt_key(encoded: &str) -> anyhow::Result<String> {
    let key_opt = *AES_MASTER_KEY.read().unwrap_or_else(|e| e.into_inner());
    let Some(key) = key_opt else {
        anyhow::ensure!(
            !encoded.starts_with(CIPHERTEXT_PREFIX),
            "AES_MASTER_KEY is required to decrypt enc:v1: secret"
        );
        return Ok(encoded.to_string());
    };

    if let Some(payload) = encoded.strip_prefix(CIPHERTEXT_PREFIX) {
        return decrypt_with_key(payload, &key);
    }

    anyhow::bail!("ciphertext tampered or missing required version prefix")
}

pub const SECRET_MASK: &str = "••••••••";

fn is_notification_secret_field_name(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "bot_token"
            | "token"
            | "webhook_url"
            | "password"
            | "smtp_password"
            | "pass"
            | "secret"
            | "api_key"
            | "apikey"
            | "auth_token"
            | "access_token"
            | "bearer_token"
            | "signing_secret"
            | "authorization"
            | "client_secret"
    )
}

fn is_notification_secret_header_name(header_name: &str, value: &str) -> bool {
    let lower = header_name.trim().to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    ) {
        return true;
    }
    if ["token", "secret", "key", "pass", "auth", "signature"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }
    let trimmed = value.trim();
    trimmed.starts_with(CIPHERTEXT_PREFIX)
        || trimmed
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("bearer "))
        || trimmed
            .get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case("basic "))
        || trimmed
            .get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case("token "))
}

fn url_contains_userinfo(raw: &str) -> bool {
    let trimmed = raw.trim();
    let Some(scheme_sep) = trimmed.find("://") else {
        return false;
    };
    let rest = &trimmed[scheme_sep + 3..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

fn is_url_field_secret(channel_type: &str, key: &str, value: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    if lower != "url" && lower != "endpoint" && !lower.ends_with("_url") {
        return false;
    }
    if lower == "webhook_url" {
        return true;
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.starts_with(CIPHERTEXT_PREFIX)
        || url_contains_userinfo(trimmed)
        || (lower == "url" && channel_type.trim().eq_ignore_ascii_case("webhook"))
}

fn encrypt_notification_value_in_place(
    channel_type: &str,
    val: &mut serde_json::Value,
    in_headers_map: bool,
) -> anyhow::Result<usize> {
    let mut encrypted_count = 0usize;
    let Some(obj) = val.as_object_mut() else {
        return Ok(0);
    };
    for (key, field_val) in obj.iter_mut() {
        let key_lower = key.trim().to_ascii_lowercase();
        if !in_headers_map && (key_lower == "headers" || key_lower == "custom_headers") {
            encrypted_count += encrypt_notification_value_in_place(channel_type, field_val, true)?;
            continue;
        }
        if field_val.is_object() {
            encrypted_count += encrypt_notification_value_in_place(channel_type, field_val, false)?;
            continue;
        }
        let Some(raw_str) = field_val.as_str() else {
            continue;
        };
        let trimmed = raw_str.trim();
        if trimmed.is_empty() || trimmed == SECRET_MASK || trimmed.starts_with(CIPHERTEXT_PREFIX) {
            continue;
        }
        let should_encrypt = if in_headers_map {
            is_notification_secret_header_name(key, trimmed)
        } else {
            is_notification_secret_field_name(key)
                || is_url_field_secret(channel_type, key, trimmed)
        };
        if should_encrypt {
            let enc = encrypt_key(trimmed)?;
            if enc != raw_str {
                encrypted_count += 1;
            }
            *field_val = serde_json::Value::String(enc);
        }
    }
    Ok(encrypted_count)
}

fn decrypt_notification_secret_str(raw: &str) -> anyhow::Result<String> {
    if raw.starts_with(CIPHERTEXT_PREFIX) {
        if is_encryption_enabled() {
            return decrypt_key(raw);
        }
        return decrypt_secret_if_needed(raw);
    }
    Ok(raw.to_string())
}

fn decrypt_notification_value_in_place(
    channel_type: &str,
    val: &mut serde_json::Value,
    in_headers_map: bool,
) -> anyhow::Result<()> {
    let Some(obj) = val.as_object_mut() else {
        return Ok(());
    };
    for (key, field_val) in obj.iter_mut() {
        let key_lower = key.trim().to_ascii_lowercase();
        if !in_headers_map && (key_lower == "headers" || key_lower == "custom_headers") {
            decrypt_notification_value_in_place(channel_type, field_val, true)?;
            continue;
        }
        if field_val.is_object() {
            decrypt_notification_value_in_place(channel_type, field_val, false)?;
            continue;
        }
        let Some(raw_str) = field_val.as_str() else {
            continue;
        };
        let should_decrypt = raw_str.starts_with(CIPHERTEXT_PREFIX)
            || (in_headers_map && is_notification_secret_header_name(key, raw_str))
            || is_notification_secret_field_name(key)
            || is_url_field_secret(channel_type, key, raw_str);
        if should_decrypt && raw_str.starts_with(CIPHERTEXT_PREFIX) {
            let dec = decrypt_notification_secret_str(raw_str)?;
            *field_val = serde_json::Value::String(dec);
        }
    }
    Ok(())
}

fn mask_notification_value_in_place(
    channel_type: &str,
    val: &mut serde_json::Value,
    in_headers_map: bool,
) {
    let Some(obj) = val.as_object_mut() else {
        return;
    };
    for (key, field_val) in obj.iter_mut() {
        let key_lower = key.trim().to_ascii_lowercase();
        if !in_headers_map && (key_lower == "headers" || key_lower == "custom_headers") {
            mask_notification_value_in_place(channel_type, field_val, true);
            continue;
        }
        if field_val.is_object() {
            mask_notification_value_in_place(channel_type, field_val, false);
            continue;
        }
        let Some(raw_str) = field_val.as_str() else {
            continue;
        };
        let trimmed = raw_str.trim();
        if trimmed.is_empty() {
            continue;
        }
        let should_mask = trimmed.starts_with(CIPHERTEXT_PREFIX)
            || (in_headers_map && is_notification_secret_header_name(key, trimmed))
            || is_notification_secret_field_name(key)
            || is_url_field_secret(channel_type, key, trimmed);
        if should_mask {
            *field_val = serde_json::Value::String(SECRET_MASK.to_string());
        }
    }
}

/// Encrypts secret fields inside a `notification_channels.config` JSON value using `encrypt_key`.
pub fn encrypt_notification_channel_config_value(
    channel_type: &str,
    config: &serde_json::Value,
) -> anyhow::Result<(serde_json::Value, usize)> {
    let mut cloned = config.clone();
    let count = encrypt_notification_value_in_place(channel_type, &mut cloned, false)?;
    Ok((cloned, count))
}

/// Encrypts secret fields inside a serialized `notification_channels.config` JSON string.
pub fn encrypt_notification_channel_config_str(
    channel_type: &str,
    raw_config: &str,
) -> anyhow::Result<(String, usize)> {
    let parsed: serde_json::Value = serde_json::from_str(raw_config)
        .map_err(|e| anyhow::anyhow!("invalid notification channel config JSON: {e}"))?;
    let (encrypted, count) = encrypt_notification_channel_config_value(channel_type, &parsed)?;
    Ok((encrypted.to_string(), count))
}

/// Decrypts `enc:v1:` secret fields inside a `notification_channels.config` JSON string at dispatch time.
pub fn decrypt_notification_channel_config_str(
    channel_type: &str,
    raw_config: &str,
) -> anyhow::Result<serde_json::Value> {
    let mut parsed: serde_json::Value = serde_json::from_str(raw_config)
        .map_err(|e| anyhow::anyhow!("invalid notification channel config JSON: {e}"))?;
    decrypt_notification_value_in_place(channel_type, &mut parsed, false)?;
    Ok(parsed)
}

/// Masks secret fields inside `notification_channels.config` as `"••••••••"` for API responses.
pub fn mask_notification_channel_config_str(
    channel_type: &str,
    raw_config: &str,
) -> serde_json::Value {
    let mut parsed: serde_json::Value =
        serde_json::from_str(raw_config).unwrap_or_else(|_| serde_json::json!({}));
    mask_notification_value_in_place(channel_type, &mut parsed, false);
    parsed
}

/// Migrates any unprefixed plaintext secrets in `settings`, `users`, and `streaming_servers` to `enc:v1:` format.
pub fn migrate_legacy_secrets() -> anyhow::Result<()> {
    if !is_encryption_enabled() {
        return Ok(());
    }
    let conn = get_conn()?;
    let tx = rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)?;
    let mut migrated = 0usize;

    let has_table = |name: &str| -> rusqlite::Result<bool> {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            params![name],
            |r| r.get(0),
        )
    };
    let has_column = |table: &str, col: &str| -> rusqlite::Result<bool> {
        tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1)"),
            params![col],
            |r| r.get(0),
        )
    };

    if has_table("settings")? {
        for col in ["gemini_api_key", "openai_api_key", "anthropic_api_key"] {
            if !has_column("settings", col)? {
                continue;
            }
            let raw: Option<String> = tx
                .query_row(
                    &format!("SELECT COALESCE({col}, '') FROM settings WHERE id = 1"),
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(val) = raw {
                if !val.is_empty() && !val.starts_with(CIPHERTEXT_PREFIX) {
                    let enc = encrypt_key(&val)?;
                    tx.execute(
                        &format!("UPDATE settings SET {col} = ?1 WHERE id = 1"),
                        params![enc],
                    )?;
                    migrated += 1;
                }
            }
        }
    }

    if has_table("users")? && has_column("users", "totp_secret")? {
        let rows: Vec<(i64, String)> = {
            let mut stmt =
                tx.prepare("SELECT id, COALESCE(totp_secret, '') FROM users WHERE COALESCE(totp_secret, '') != ''")?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut batch = Vec::new();
        for (uid, raw) in rows {
            if !raw.is_empty() && !raw.starts_with(CIPHERTEXT_PREFIX) {
                let enc = encrypt_key(&raw)?;
                batch.push(serde_json::json!({ "id": uid, "enc": enc }));
            }
        }
        if !batch.is_empty() {
            let payload = serde_json::Value::Array(batch.clone()).to_string();
            tx.execute(
                "UPDATE users
                 SET totp_secret = (
                     SELECT json_extract(value, '$.enc')
                     FROM json_each(?1)
                     WHERE CAST(json_extract(value, '$.id') AS INTEGER) = users.id
                 )
                 WHERE id IN (
                     SELECT CAST(json_extract(value, '$.id') AS INTEGER)
                     FROM json_each(?1)
                 )",
                params![payload],
            )?;
            migrated += batch.len();
        }
    }

    if has_table("streaming_servers")? && has_column("streaming_servers", "api_key")? {
        let rows: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT provider, COALESCE(api_key, '') FROM streaming_servers WHERE COALESCE(api_key, '') != ''",
            )?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut batch = Vec::new();
        for (provider, raw) in rows {
            if !raw.is_empty() && !raw.starts_with(CIPHERTEXT_PREFIX) {
                let enc = encrypt_key(&raw)?;
                batch.push(serde_json::json!({ "provider": provider, "enc": enc }));
            }
        }
        if !batch.is_empty() {
            let payload = serde_json::Value::Array(batch.clone()).to_string();
            tx.execute(
                "UPDATE streaming_servers
                 SET api_key = (
                     SELECT json_extract(value, '$.enc')
                     FROM json_each(?1)
                     WHERE json_extract(value, '$.provider') = streaming_servers.provider
                 )
                 WHERE provider IN (
                     SELECT json_extract(value, '$.provider')
                     FROM json_each(?1)
                 )",
                params![payload],
            )?;
            migrated += batch.len();
        }
    }

    if has_table("notification_channels")? && has_column("notification_channels", "config")? {
        let rows: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, COALESCE(type, ''), COALESCE(config, '') FROM notification_channels WHERE COALESCE(config, '') != ''",
            )?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (channel_id, channel_type, raw_cfg) in rows {
            if let Ok((encrypted_cfg, count)) =
                encrypt_notification_channel_config_str(&channel_type, &raw_cfg)
            {
                if count > 0 && encrypted_cfg != raw_cfg {
                    tx.execute(
                        "UPDATE notification_channels SET config = ?1 WHERE id = ?2",
                        params![encrypted_cfg, channel_id],
                    )?;
                    migrated += count;
                }
            }
        }
    }

    tx.commit()?;
    if migrated > 0 {
        tracing::info!(
            "[crypto] Successfully migrated {migrated} legacy secret(s) to enc:v1: format"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite Connection Pool, WAL PRAGMAs & Schema Migrations
// ─────────────────────────────────────────────────────────────────────────────

static DB_POOL: Lazy<RwLock<Option<Pool<SqliteConnectionManager>>>> =
    Lazy::new(|| RwLock::new(None));
static DB_READ_POOL: Lazy<RwLock<Option<Pool<SqliteConnectionManager>>>> =
    Lazy::new(|| RwLock::new(None));
static DB_PATH_RESOLVED: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

pub fn try_resolve_db_path() -> anyhow::Result<String> {
    let default_fallback = env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .map(|exe_dir| exe_dir.join("data/aetherflow.sqlite"))
        })
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "aetherflow.sqlite".to_string());

    let resolved = af_models::try_resolve_active_db_path_from_env(None, &default_fallback)
        .map_err(|err| anyhow::anyhow!(err))?;
    let resolved_str = resolved.to_string_lossy().into_owned();
    if resolved_str != ":memory:" && !resolved_str.starts_with("file:") {
        if let Some(parent) = resolved.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
    }
    Ok(resolved_str)
}

pub fn resolve_db_path() -> String {
    let default_fallback = env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .map(|exe_dir| exe_dir.join("data/aetherflow.sqlite"))
        })
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "aetherflow.sqlite".to_string());

    let resolved = af_models::resolve_active_db_path_from_env(None, &default_fallback);
    let resolved_str = resolved.to_string_lossy().into_owned();
    if resolved_str != ":memory:" && !resolved_str.starts_with("file:") {
        if let Some(parent) = resolved.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
    }
    resolved_str
}

pub fn get_db_path() -> String {
    let current = DB_PATH_RESOLVED
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if !current.is_empty() {
        return current;
    }
    resolve_db_path()
}

pub fn get_conn() -> anyhow::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    let pool = DB_POOL
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Database pool not initialized"))?;
    pool.get()
        .map_err(|e| anyhow::anyhow!("Failed to acquire SQLite connection: {}", e))
}

/// Bounded, read-only WAL connections. The writer remains a pool of one.
/// Private in-memory test databases must use their original connection.
pub fn get_read_conn() -> anyhow::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    let pool = DB_READ_POOL
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match pool {
        Some(pool) => pool.get().map_err(Into::into),
        None => get_conn(),
    }
}

fn build_read_pool(db_path: &str) -> anyhow::Result<Pool<SqliteConnectionManager>> {
    let manager = SqliteConnectionManager::file(db_path)
        .with_flags(OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)
        .with_init(|conn| {
            conn.busy_timeout(Duration::from_millis(750))?;
            conn.execute_batch(
                "PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA cache_size=-8000;",
            )
        });
    Ok(Pool::builder()
        .max_size(8)
        .min_idle(Some(1))
        .connection_timeout(Duration::from_secs(2))
        .build(manager)?)
}

fn apply_pragmas(conn: &Connection) {
    let pragmas = [
        "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=NORMAL;",
        "PRAGMA busy_timeout=5000;",
        "PRAGMA cache_size=-64000;",
        "PRAGMA foreign_keys=ON;",
        "PRAGMA temp_store=MEMORY;",
        "PRAGMA mmap_size=268435456;",
    ];
    for p in pragmas {
        if let Err(e) = conn.execute_batch(p) {
            tracing::warn!(pragma = p, error = %e, "PRAGMA execution warning");
        }
    }
}

fn run_atomic_migration_tx<F, R>(conn: &Connection, f: F) -> anyhow::Result<R>
where
    F: FnOnce(&Connection) -> anyhow::Result<R>,
{
    if conn.is_autocommit() {
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    } else {
        conn.execute_batch("SAVEPOINT af_migrate;")?;
        match f(conn) {
            Ok(out) => {
                conn.execute_batch("RELEASE SAVEPOINT af_migrate;")?;
                Ok(out)
            }
            Err(err) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT af_migrate; RELEASE SAVEPOINT af_migrate;",
                );
                Err(err)
            }
        }
    }
}

fn migrate(
    conn: &Connection,
    version: i32,
    description: &str,
    stmts: &[&str],
) -> anyhow::Result<()> {
    run_atomic_migration_tx(conn, |tx_conn| {
        let count: i32 = tx_conn.query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        if count > 0 {
            return Ok(());
        }

        for stmt in stmts {
            if let Err(err) = tx_conn.execute_batch(stmt) {
                let msg = err.to_string().to_ascii_lowercase();
                if msg.contains("duplicate column name") || msg.contains("already exists") {
                    tracing::info!(version, "migration DDL already applied");
                    continue;
                }
                tracing::error!(version, error = %err, "migration failed");
                return Err(err.into());
            }
        }

        tx_conn.execute(
            "INSERT INTO schema_versions (version, description) VALUES (?1, ?2)",
            params![version, description],
        )?;
        tracing::info!(version, description, "migration applied");
        Ok(())
    })
}

pub fn init_db() -> anyhow::Result<()> {
    let db_path = try_resolve_db_path()?;
    if db_path != ":memory:" && !db_path.starts_with("file:") {
        if let Some(parent) = Path::new(&db_path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
    }

    let manager = if db_path == ":memory:" {
        SqliteConnectionManager::memory()
    } else {
        SqliteConnectionManager::file(&db_path)
    }
    .with_init(|c| {
        apply_pragmas(c);
        Ok(())
    });

    // Constrain pool to 1 writer connection matching Go's `DB.SetMaxOpenConns(1)`
    let pool = Pool::builder()
        .max_size(1)
        .connection_timeout(Duration::from_secs(5))
        .build(manager)?;
    let conn = pool.get()?;
    apply_pragmas(&conn);

    // Core tables
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            ai_model TEXT DEFAULT 'gemini-4-argon',
            system_prompt TEXT DEFAULT 'You are FlowAI, a highly intelligent infrastructure assistant connected to a sovereign Rust + WebAssembly aetherflow-api environment. Always prioritize safe and performant configurations.',
            language TEXT DEFAULT 'en',
            timezone TEXT DEFAULT 'UTC',
            update_channel TEXT DEFAULT 'stable',
            default_dashboard TEXT DEFAULT 'overview',
            setup_completed BOOLEAN DEFAULT 0,
            gemini_api_key TEXT DEFAULT '',
            openai_api_key TEXT DEFAULT '',
            lm_studio_endpoint TEXT DEFAULT '',
            ollama_endpoint TEXT DEFAULT '',
            anthropic_api_key TEXT DEFAULT '',
            anthropic_endpoint TEXT DEFAULT '',
            local_provider TEXT DEFAULT '',
            local_model TEXT DEFAULT '',
            base_domain TEXT DEFAULT '',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT DEFAULT '',
            google_id TEXT DEFAULT '',
            email TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS cluster_nodes (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            address TEXT NOT NULL,
            psk_hash TEXT NOT NULL,
            role TEXT DEFAULT 'worker',
            status TEXT DEFAULT 'offline',
            last_heartbeat DATETIME,
            enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS oidc_clients (
            id TEXT PRIMARY KEY,
            client_secret_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (
            app_name TEXT PRIMARY KEY,
            config_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oidc_auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT DEFAULT 'openid profile email',
            code_challenge TEXT DEFAULT '',
            code_challenge_method TEXT DEFAULT '',
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            scope TEXT DEFAULT 'openid profile email',
            expires_at DATETIME NOT NULL,
            revoked BOOLEAN DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS oidc_device_codes (
            device_code TEXT PRIMARY KEY,
            user_code TEXT NOT NULL,
            client_id TEXT NOT NULL,
            scope TEXT DEFAULT 'openid profile email',
            user_id INTEGER,
            expires_at DATETIME NOT NULL,
            status TEXT DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS log_bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            log_source TEXT NOT NULL,
            log_line TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            note TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            level TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            read BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notification_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            condition_type TEXT NOT NULL,
            condition_value TEXT NOT NULL,
            level TEXT DEFAULT 'warning',
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notification_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            config TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_quotas (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            quota_bytes INTEGER DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'manual',
            billing_provider TEXT DEFAULT '',
            billing_external_id TEXT DEFAULT '',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fileshare_objects (
            storage_root TEXT NOT NULL,
            directory TEXT NOT NULL,
            filename TEXT NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id),
            size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
            PRIMARY KEY(storage_root, directory, filename)
        );
        CREATE INDEX IF NOT EXISTS idx_fileshare_objects_user ON fileshare_objects(user_id);

        CREATE TABLE IF NOT EXISTS billing_webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            event_id TEXT NOT NULL,
            event_type TEXT DEFAULT '',
            username TEXT DEFAULT '',
            quota_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'received',
            error TEXT DEFAULT '',
            payload TEXT NOT NULL,
            processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(provider, event_id)
        );

        CREATE TABLE IF NOT EXISTS app_updates (
            package_name TEXT PRIMARY KEY,
            installed_version TEXT DEFAULT '',
            latest_version TEXT DEFAULT '',
            update_available BOOLEAN DEFAULT 0,
            update_url TEXT DEFAULT '',
            checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_error TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS media_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            title TEXT DEFAULT '',
            year TEXT DEFAULT '',
            language TEXT DEFAULT '',
            quality TEXT DEFAULT '',
            subtitles_json TEXT DEFAULT '[]',
            enriched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_avg REAL DEFAULT 0,
            mem_used_gb REAL DEFAULT 0,
            mem_total_gb REAL DEFAULT 0,
            disk_read_bps REAL DEFAULT 0,
            disk_write_bps REAL DEFAULT 0,
            net_rx_bytes INTEGER DEFAULT 0,
            net_tx_bytes INTEGER DEFAULT 0,
            load_avg_1 REAL DEFAULT 0,
            active_conns INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS schema_versions (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )?;

    // All 19 versioned migrations matching `backend/db/db.go`
    migrate(
        &conn,
        1,
        "Add setup_completed to settings",
        &["ALTER TABLE settings ADD COLUMN setup_completed BOOLEAN DEFAULT 0;"],
    )?;
    migrate(
        &conn,
        2,
        "Add gemini_api_key to settings",
        &["ALTER TABLE settings ADD COLUMN gemini_api_key TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        3,
        "Add password_hash to users",
        &["ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        4,
        "Add backup scheduling columns to settings",
        &[
            "ALTER TABLE settings ADD COLUMN backup_schedule_mode TEXT DEFAULT 'manual';",
            "ALTER TABLE settings ADD COLUMN backup_optimal_window TEXT DEFAULT '';",
        ],
    )?;
    migrate(
        &conn,
        5,
        "v3.1.0 Gold — performance indexes",
        &[
            "CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, read);",
            "CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_metrics_history_ts_id ON metrics_history(timestamp DESC, id DESC);",
            "CREATE INDEX IF NOT EXISTS idx_metrics_history_norm_ts_id ON metrics_history(replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC);",
            "CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_login_history_created ON login_history(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_client ON oidc_auth_codes(client_id);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_expires ON oidc_auth_codes(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_refresh_client ON oidc_refresh_tokens(client_id);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_expires ON oidc_device_codes(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status);",
            "CREATE INDEX IF NOT EXISTS idx_billing_provider_event ON billing_webhook_events(provider, event_id);",
            "CREATE INDEX IF NOT EXISTS idx_log_bookmarks_user ON log_bookmarks(user_id);",
        ],
    )?;
    migrate(
        &conn,
        6,
        "Persist smart backup next run time",
        &["ALTER TABLE settings ADD COLUMN backup_next_run_at TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        7,
        "Add OIDC consent persistence",
        &[
            r#"CREATE TABLE IF NOT EXISTS oidc_consents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, client_id)
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_oidc_consents_user_client ON oidc_consents(user_id, client_id);",
        ],
    )?;
    migrate(
        &conn,
        8,
        "Add active sessions table for session tracking",
        &[
            r#"CREATE TABLE IF NOT EXISTS active_sessions (
                jti TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                ip_address TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                expires_at DATETIME NOT NULL,
                last_active DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_active_sessions_user ON active_sessions(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_active_sessions_expires ON active_sessions(expires_at);",
        ],
    )?;
    migrate(
        &conn,
        9,
        "Add pending_actions table for approval gates",
        &[
            r#"CREATE TABLE IF NOT EXISTS pending_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                classification TEXT NOT NULL DEFAULT 'warn',
                source TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                resolved_by TEXT,
                execution_log TEXT
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_pending_actions_status ON pending_actions(status);",
        ],
    )?;
    migrate(
        &conn,
        10,
        "Add notification_delivery_log for delivery tracking",
        &[
            r#"CREATE TABLE IF NOT EXISTS notification_delivery_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL,
                channel_type TEXT NOT NULL,
                notification_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_delivery_log_channel ON notification_delivery_log(channel_id);",
            "CREATE INDEX IF NOT EXISTS idx_delivery_log_status ON notification_delivery_log(status);",
        ],
    )?;
    migrate(
        &conn,
        11,
        "Add admin audit trail for accountability",
        &[
            r#"CREATE TABLE IF NOT EXISTS admin_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT '',
                target_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_audit_log_user ON admin_audit_log(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON admin_audit_log(action);",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_created ON admin_audit_log(created_at);",
        ],
    )?;
    migrate(
        &conn,
        12,
        "Add OpenAI and Local AI provider config",
        &[
            "ALTER TABLE settings ADD COLUMN openai_api_key TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN lm_studio_endpoint TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN ollama_endpoint TEXT DEFAULT '';",
        ],
    )?;
    migrate(
        &conn,
        13,
        "Add Anthropic API provider config",
        &[
            "ALTER TABLE settings ADD COLUMN anthropic_api_key TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN anthropic_endpoint TEXT DEFAULT '';",
        ],
    )?;
    migrate(
        &conn,
        14,
        "Add TOTP 2FA columns to users",
        &[
            "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT '';",
            "ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;",
        ],
    )?;
    migrate(
        &conn,
        15,
        "Add recovery_codes table for 2FA backup codes",
        &[r#"CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"#],
    )?;
    migrate(
        &conn,
        16,
        "Add mediaflow queue for hwaccel transcoding",
        &[
            r#"CREATE TABLE IF NOT EXISTS mediaflow_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'PENDING_APPROVAL',
                original_codec TEXT DEFAULT '',
                original_size INTEGER DEFAULT 0,
                new_codec TEXT DEFAULT '',
                new_size INTEGER DEFAULT 0,
                error_log TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_mediaflow_status ON mediaflow_queue(status);",
        ],
    )?;
    migrate(
        &conn,
        17,
        "Add app_ingress_configs table for persistent ingress routing",
        &[
            r#"CREATE TABLE IF NOT EXISTS app_ingress_configs (
                app_name TEXT PRIMARY KEY,
                public_domain TEXT DEFAULT '',
                external_access_enabled BOOLEAN DEFAULT 0,
                listen_port INTEGER DEFAULT 0,
                tls_enabled BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ingress_configs_app_name ON app_ingress_configs(app_name);",
        ],
    )?;
    migrate(
        &conn,
        18,
        "Add base_domain to settings for automatic app subdomain provisioning",
        &["ALTER TABLE settings ADD COLUMN base_domain TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        19,
        "Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables",
        &[
            r#"CREATE TABLE IF NOT EXISTS streaming_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL DEFAULT 'Jellyfin',
                url TEXT NOT NULL DEFAULT 'http://127.0.0.1:8096',
                api_key TEXT NOT NULL DEFAULT '',
                enabled BOOLEAN DEFAULT 1,
                server_id TEXT DEFAULT '',
                server_version TEXT DEFAULT '',
                last_connected_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            r#"CREATE TABLE IF NOT EXISTS streaming_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT UNIQUE NOT NULL,
                provider TEXT NOT NULL DEFAULT 'jellyfin',
                server_name TEXT NOT NULL DEFAULT 'Jellyfin',
                user_id TEXT NOT NULL DEFAULT '',
                user_name TEXT NOT NULL DEFAULT '',
                client_name TEXT NOT NULL DEFAULT '',
                device_name TEXT NOT NULL DEFAULT '',
                device_id TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                item_id TEXT NOT NULL DEFAULT '',
                item_name TEXT NOT NULL DEFAULT '',
                item_type TEXT NOT NULL DEFAULT 'Movie',
                series_name TEXT NOT NULL DEFAULT '',
                series_id TEXT NOT NULL DEFAULT '',
                season_number INTEGER DEFAULT 0,
                episode_number INTEGER DEFAULT 0,
                production_year INTEGER DEFAULT 0,
                play_method TEXT NOT NULL DEFAULT 'DirectPlay',
                container TEXT NOT NULL DEFAULT '',
                video_codec TEXT NOT NULL DEFAULT '',
                video_resolution TEXT NOT NULL DEFAULT '',
                audio_codec TEXT NOT NULL DEFAULT '',
                audio_channels INTEGER DEFAULT 0,
                subtitle_codec TEXT NOT NULL DEFAULT '',
                hw_accel TEXT NOT NULL DEFAULT '',
                transcode_reasons TEXT NOT NULL DEFAULT '',
                bitrate_bps INTEGER DEFAULT 0,
                duration_secs INTEGER DEFAULT 0,
                watched_secs INTEGER DEFAULT 0,
                data_used_bytes INTEGER DEFAULT 0,
                completion_pct REAL DEFAULT 0,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                ended_at DATETIME,
                is_active BOOLEAN DEFAULT 0
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_provider ON streaming_history(provider);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_started ON streaming_history(started_at);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_last_seen ON streaming_history(last_seen_at DESC, id DESC);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_user ON streaming_history(user_name);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_item ON streaming_history(item_id);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_active ON streaming_history(provider, is_active);",
            r#"CREATE TABLE IF NOT EXISTS streaming_bandwidth_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                provider TEXT NOT NULL DEFAULT 'jellyfin',
                active_streams INTEGER DEFAULT 0,
                direct_play_count INTEGER DEFAULT 0,
                direct_stream_count INTEGER DEFAULT 0,
                transcode_count INTEGER DEFAULT 0,
                total_bitrate_bps INTEGER DEFAULT 0,
                bytes_delta INTEGER DEFAULT 0
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_streaming_bw_timestamp ON streaming_bandwidth_samples(timestamp);",
        ],
    )?;

    streaming::migrate_history(&conn, &db_path)?;
    migrate(
        &conn,
        21,
        "Add plugins_registry table for Rust plugin platform lifecycle state",
        &[
            r#"CREATE TABLE IF NOT EXISTS plugins_registry (
                plugin_id TEXT PRIMARY KEY,
                enabled BOOLEAN NOT NULL DEFAULT 0,
                allocated_port INTEGER NOT NULL DEFAULT 0,
                token_epoch INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'stopped',
                last_health_at DATETIME,
                last_error TEXT NOT NULL DEFAULT '',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_plugins_registry_enabled ON plugins_registry(enabled);",
        ],
    )?;

    migrate(&conn, 22, "Persist MFA replay guards and OIDC nonces", &[
        "ALTER TABLE users ADD COLUMN last_totp_step INTEGER NOT NULL DEFAULT -1;",
        "ALTER TABLE oidc_auth_codes ADD COLUMN nonce TEXT NOT NULL DEFAULT '';",
        "CREATE TABLE IF NOT EXISTS mfa_challenges (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL);",
        "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expiry ON mfa_challenges(expires_at);",
        "CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);",
    ])?;

    let security_migration: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_versions WHERE version = 22",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        security_migration == 1,
        "Security schema migration v22 failed"
    );

    // Singleton settings row & model normalization
    migrate(
        &conn,
        23,
        "Persist installed local AI model and runtime separately",
        &[
            "ALTER TABLE settings ADD COLUMN local_provider TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN local_model TEXT DEFAULT '';",
        ],
    )?;
    let local_settings_migration: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_versions WHERE version = 23",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        local_settings_migration == 1,
        "Local AI settings migration v23 failed"
    );

    ensure_security_schema_invariants(&conn)?;
    ensure_notification_schema_invariants(&conn)?;
    ensure_pending_actions_schema_invariants(&conn)?;

    let _ = conn.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)", []);
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'gemini-4-argon' WHERE id = 1 AND ai_model IN ('gemini-3.8-flash', 'gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-3.1-pro-preview', 'gemini-3-flash-preview', 'gemini-3.1-flash-lite-preview', 'gemini-3-pro-image-preview', 'gemini-3.1-flash-image-preview')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'gpt-6.1-sol' WHERE id = 1 AND ai_model IN ('gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-5.4', 'gpt-5.4-mini')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'claude-opus-5-5' WHERE id = 1 AND ai_model IN ('claude-opus', 'claude-opus-4.5', 'claude-opus-4.6', 'claude-4-5-opus')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'claude-sonnet-5-5' WHERE id = 1 AND ai_model IN ('claude-sonnet-4.5', 'claude-sonnet-4.6', 'claude-4-6-sonnet')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'claude-haiku-5-5' WHERE id = 1 AND ai_model IN ('claude-4-6-haiku')",
        [],
    );

    let _ = conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_metrics_history_ts_id ON metrics_history(timestamp DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_metrics_history_norm_ts_id ON metrics_history(replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC);",
    );

    let env_domain = env::var("AETHERFLOW_BASE_DOMAIN")
        .or_else(|_| env::var("AETHERFLOW_DOMAIN"))
        .map(|dom| normalize_base_domain(&dom))
        .unwrap_or_default();
    if !env_domain.is_empty() {
        let _ = conn.execute(
            "UPDATE settings SET base_domain = ?1 WHERE id = 1 AND COALESCE(base_domain, '') = ''",
            params![env_domain],
        );
    }

    drop(conn);
    let read_pool = if db_path == ":memory:" || db_path.contains("mode=memory") {
        None
    } else {
        Some(build_read_pool(&db_path)?)
    };
    *DB_PATH_RESOLVED.write().unwrap_or_else(|e| e.into_inner()) = db_path.clone();
    *DB_POOL.write().unwrap_or_else(|e| e.into_inner()) = Some(pool);
    *DB_READ_POOL.write().unwrap_or_else(|e| e.into_inner()) = read_pool;
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        map.clear();
    }
    invalidate_ingress_cache();
    get_base_domain();

    tracing::info!(path = %db_path, "SQLite WAL database connected");
    Ok(())
}

fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    column_ddl: &str,
) -> anyhow::Result<()> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name.eq_ignore_ascii_case(column));
    if !exists {
        let alter = format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, column_ddl);
        conn.execute(&alter, [])?;
    }
    Ok(())
}

fn ensure_security_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    ensure_column(
        conn,
        "users",
        "sessions_revoked_after",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "active_sessions",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "oidc_refresh_tokens",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "mfa_challenges",
        "credential_ver",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "revoked_tokens",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "revoked_tokens",
        "user_id",
        "INTEGER NOT NULL DEFAULT 0",
    )?;

    let existing_index_sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_oidc_device_codes_user_code'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let needs_unique_index = match existing_index_sql {
        Some(sql) => !sql.to_ascii_uppercase().contains("UNIQUE"),
        None => true,
    };
    if needs_unique_index {
        conn.execute_batch(
            "DELETE FROM oidc_device_codes
             WHERE rowid NOT IN (
                 SELECT MAX(rowid) FROM oidc_device_codes GROUP BY user_code
             );
             DROP INDEX IF EXISTS idx_oidc_device_codes_user_code;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);",
        )?;
    }
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_active_sessions_family ON active_sessions(family_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mediaflow_file_path ON mediaflow_queue(file_path)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_oidc_refresh_family ON oidc_refresh_tokens(family_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_revoked_tokens_family ON revoked_tokens(family_id)",
        [],
    )?;
    Ok(())
}

fn ensure_notification_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    run_atomic_migration_tx(conn, |tx_conn| {
        tx_conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS notification_reads (
                notification_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (notification_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_notification_reads_user_notification
                ON notification_reads(user_id, notification_id);",
        )?;
        Ok(())
    })
}

fn ensure_pending_actions_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    ensure_column(conn, "pending_actions", "job_unit", "TEXT")?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pending_actions_job_unit ON pending_actions(job_unit)",
        [],
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-User Notification Read State Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserNotificationRow {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_id: Option<i64>,
    pub level: String,
    pub title: String,
    pub message: String,
    pub read: bool,
    pub created_at: String,
}

pub const UNREAD_NOTIFICATIONS_COUNT_FOR_USER_SQL: &str = "
    SELECT COUNT(*)
    FROM notifications n
    LEFT JOIN notification_reads nr
        ON nr.notification_id = n.id AND nr.user_id = ?1
    WHERE (n.user_id = ?1 OR n.user_id IS NULL)
      AND CASE
            WHEN n.user_id IS NULL THEN (COALESCE(n.read, 0) = 0 AND nr.notification_id IS NULL)
            ELSE COALESCE(n.read, 0) = 0
          END
";

pub const LIST_NOTIFICATIONS_FOR_USER_SQL: &str = "
    SELECT
        n.id,
        n.user_id,
        n.level,
        n.title,
        n.message,
        CASE
            WHEN n.user_id IS NULL THEN (COALESCE(n.read, 0) != 0 OR nr.notification_id IS NOT NULL)
            ELSE COALESCE(n.read, 0) != 0
        END AS effective_read,
        COALESCE(CAST(n.created_at AS TEXT), '')
    FROM notifications n
    LEFT JOIN notification_reads nr
        ON nr.notification_id = n.id AND nr.user_id = ?1
    WHERE (n.user_id = ?1 OR n.user_id IS NULL)
    ORDER BY n.created_at DESC, n.id DESC
    LIMIT ?2 OFFSET ?3
";

/// Marks a single notification read for `user_id`.
///
/// User-owned rows (`user_id = ?`) update `notifications.read = 1`.
/// Broadcast rows (`user_id IS NULL`) record `(notification_id, user_id)` in `notification_reads`
/// without mutating `notifications.read`, preserving unread state for other users.
pub fn mark_notification_read_for_user(user_id: i64, notification_id: i64) -> anyhow::Result<bool> {
    let conn = get_conn()?;
    mark_notification_read_for_user_with_conn(&conn, user_id, notification_id)
}

pub fn mark_notification_read_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
    notification_id: i64,
) -> anyhow::Result<bool> {
    run_atomic_migration_tx(conn, |tx_conn| {
        let owner_id: Option<Option<i64>> = tx_conn
            .query_row(
                "SELECT user_id FROM notifications WHERE id = ?1",
                params![notification_id],
                |r| r.get(0),
            )
            .optional()?;
        match owner_id {
            None => Ok(false),
            Some(Some(owner)) if owner != user_id => Ok(false),
            Some(Some(_)) => {
                tx_conn.execute(
                    "UPDATE notifications SET read = 1 WHERE id = ?1 AND user_id = ?2",
                    params![notification_id, user_id],
                )?;
                Ok(true)
            }
            Some(None) => {
                tx_conn.execute(
                    "INSERT OR IGNORE INTO notification_reads (notification_id, user_id) VALUES (?1, ?2)",
                    params![notification_id, user_id],
                )?;
                Ok(true)
            }
        }
    })
}

/// Dismisses all unread notifications visible to `user_id`.
///
/// User-owned rows (`user_id = ?`) are marked `read = 1`; broadcast rows (`user_id IS NULL`)
/// are recorded in `notification_reads` for `user_id` without mutating `notifications.read`.
/// Returns the number of notifications newly marked read for `user_id`.
pub fn dismiss_all_notifications_for_user(user_id: i64) -> anyhow::Result<usize> {
    let conn = get_conn()?;
    dismiss_all_notifications_for_user_with_conn(&conn, user_id)
}

pub fn dismiss_all_notifications_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
) -> anyhow::Result<usize> {
    run_atomic_migration_tx(conn, |tx_conn| {
        let owned_updated = tx_conn.execute(
            "UPDATE notifications SET read = 1 WHERE user_id = ?1 AND COALESCE(read, 0) = 0",
            params![user_id],
        )?;
        let broadcast_inserted = tx_conn.execute(
            "INSERT OR IGNORE INTO notification_reads (notification_id, user_id)
             SELECT n.id, ?1
             FROM notifications n
             LEFT JOIN notification_reads nr
                 ON nr.notification_id = n.id AND nr.user_id = ?1
             WHERE n.user_id IS NULL
               AND COALESCE(n.read, 0) = 0
               AND nr.notification_id IS NULL",
            params![user_id],
        )?;
        Ok(owned_updated + broadcast_inserted)
    })
}

pub fn count_unread_notifications_for_user(user_id: i64) -> anyhow::Result<i64> {
    let conn = get_read_conn()?;
    count_unread_notifications_for_user_with_conn(&conn, user_id)
}

pub fn count_unread_notifications_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
) -> anyhow::Result<i64> {
    let unread: i64 = conn.query_row(
        UNREAD_NOTIFICATIONS_COUNT_FOR_USER_SQL,
        params![user_id],
        |r| r.get(0),
    )?;
    Ok(unread)
}

pub fn list_notifications_for_user(
    user_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<UserNotificationRow>, i64)> {
    let conn = get_read_conn()?;
    list_notifications_for_user_with_conn(&conn, user_id, limit, offset)
}

pub fn list_notifications_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<UserNotificationRow>, i64)> {
    let unread = count_unread_notifications_for_user_with_conn(conn, user_id)?;
    let mut stmt = conn.prepare(LIST_NOTIFICATIONS_FOR_USER_SQL)?;
    let rows = stmt.query_map(params![user_id, limit.clamp(1, 200), offset.max(0)], |r| {
        Ok(UserNotificationRow {
            id: r.get(0)?,
            user_id: r.get(1)?,
            level: r.get(2)?,
            title: r.get(3)?,
            message: r.get(4)?,
            read: r.get(5)?,
            created_at: r.get(6)?,
        })
    })?;
    let mut list = Vec::new();
    for row in rows {
        list.push(row?);
    }
    Ok((list, unread))
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Check & Data Pruning
// ─────────────────────────────────────────────────────────────────────────────

pub fn db_readiness_check() -> anyhow::Result<i64> {
    let start = Instant::now();
    let conn = get_read_conn()?;
    let _: Option<i32> = conn
        .query_row("SELECT 1 FROM users LIMIT 1", [], |row| row.get(0))
        .optional()?;
    Ok(start.elapsed().as_millis() as i64)
}

pub fn db_health_check() -> anyhow::Result<serde_json::Value> {
    let start = Instant::now();
    let conn = get_read_conn()?;
    let _: Option<i32> = conn
        .query_row("SELECT 1 FROM users LIMIT 1", [], |row| row.get(0))
        .optional()?;
    let latency_ms = start.elapsed().as_millis() as i64;

    let tables = [
        "users",
        "active_sessions",
        "oidc_clients",
        "notifications",
        "metrics_history",
    ];
    let mut counts = HashMap::new();
    for tbl in tables {
        let query_sql = format!("SELECT COUNT(*) FROM {}", tbl);
        if let Ok(cnt) = conn.query_row(&query_sql, [], |row| row.get::<_, i64>(0)) {
            counts.insert(tbl.to_string(), cnt);
        }
    }

    // A WAL frame occupies its database page plus a 24-byte frame header.
    // Measuring the file avoids a checkpoint on the writer connection.
    let path: String = conn.query_row("PRAGMA database_list", [], |row| row.get(2))?;
    let page_size: u64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let wal_pages = if path.is_empty() {
        0
    } else {
        match fs::metadata(format!("{path}-wal")) {
            Ok(wal) => wal.len().saturating_sub(32) / (page_size + 24),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        }
    };

    Ok(serde_json::json!({
        "status": "healthy",
        "latency_ms": latency_ms,
        "table_counts": counts,
        "wal_pages": wal_pages,
    }))
}

pub const PRUNE_METRICS_HISTORY_SQL: &str =
    "DELETE FROM metrics_history WHERE julianday(timestamp) < julianday('now', '-90 days')";

pub fn has_unexpired_active_session(
    conn: &Connection,
    jti: &str,
    user_id: i64,
    now: i64,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE jti = ?1 AND user_id = ?2 AND unixepoch(expires_at, 'auto') > ?3)",
        params![jti, user_id, now],
        |row| row.get(0),
    )
}

pub fn prune_expired_active_sessions(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM active_sessions WHERE unixepoch(expires_at, 'auto') <= ?1",
        params![now],
    )
}

pub fn prune_expired_data() {
    let Ok(conn) = get_conn() else {
        return;
    };
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let param_queries = [
        // Retain used = 1 authorization-code tombstones until expires_at for RFC 6749 §4.1.2 reuse detection.
        "DELETE FROM oidc_auth_codes WHERE expires_at < ?1",
        "DELETE FROM oidc_device_codes WHERE expires_at < ?1",
        "DELETE FROM oidc_refresh_tokens WHERE expires_at < ?1",
    ];
    for query_sql in param_queries {
        let _ = conn.execute(query_sql, params![now_rfc3339]);
    }
    let _ = prune_expired_active_sessions(&conn, now.timestamp());
    let _ = conn.execute(
        "DELETE FROM mfa_challenges WHERE expires_at <= ?1",
        params![now.timestamp()],
    );

    let static_queries = [
        "DELETE FROM revoked_tokens WHERE expires_at IS NOT NULL AND TRIM(expires_at) != '' AND datetime(expires_at) IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        PRUNE_METRICS_HISTORY_SQL,
        "DELETE FROM login_history WHERE replace(CAST(created_at AS TEXT), 'T', ' ') < datetime('now', '-90 days')",
        "DELETE FROM streaming_bandwidth_samples WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') < datetime('now', '-90 days')",
    ];
    for query_sql in static_queries {
        let _ = conn.execute(query_sql, []);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// App Ingress Configs & Base Domain
// ─────────────────────────────────────────────────────────────────────────────

struct IngressCache {
    generation: u64,
    configs: Option<Vec<AppIngressConfig>>,
    configs_at: Option<Instant>,
    base_domain: String,
    base_domain_at: Option<Instant>,
}

static INGRESS_CACHE: Lazy<RwLock<IngressCache>> = Lazy::new(|| {
    RwLock::new(IngressCache {
        generation: 0,
        configs: None,
        configs_at: None,
        base_domain: String::new(),
        base_domain_at: None,
    })
});

const INGRESS_CACHE_TTL: Duration = Duration::from_secs(5);

// This hint only sends possible subdomains to authoritative resolution. A
// fingerprint match never grants access.
static BASE_DOMAIN_HINT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn base_domain_fingerprint(domain: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    domain.hash(&mut hasher);
    hasher.finish().max(1)
}

/// A routing hint for passing requests to the control plane. Host validation
/// still compares the complete authority before accepting a request.
pub fn maybe_cached_control_plane_host(host: &str) -> bool {
    let hint = BASE_DOMAIN_HINT.load(std::sync::atomic::Ordering::Acquire);
    if hint == 0 {
        return false;
    }
    base_domain_fingerprint(host) == hint
        || host.split_once('.').is_some_and(|(label, suffix)| {
            matches!(label, "www" | "direct" | "aetherflow")
                && base_domain_fingerprint(suffix) == hint
        })
}

pub fn cached_base_domain() -> Option<String> {
    let cache = INGRESS_CACHE.try_read().ok()?;
    cache
        .base_domain_at
        .filter(|at| at.elapsed() < INGRESS_CACHE_TTL)?;
    Some(cache.base_domain.clone())
}

pub fn matches_cached_ingress_subdomain(host: &str) -> bool {
    let hint = BASE_DOMAIN_HINT.load(std::sync::atomic::Ordering::Acquire);
    hint != 0
        && host.match_indices('.').any(|(offset, _)| {
            base_domain_fingerprint(&host[offset + 1..]) == hint
                && !matches!(&host[..offset], "www" | "direct" | "aetherflow")
        })
}

pub fn invalidate_ingress_cache() {
    if let Ok(mut guard) = INGRESS_CACHE.write() {
        guard.generation = guard.generation.wrapping_add(1);
        guard.configs = None;
        guard.configs_at = None;
        guard.base_domain.clear();
        guard.base_domain_at = None;
    }
}

pub fn normalize_base_domain(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    if let Some((host, _)) = s.split_once('/') {
        s = host.to_string();
    }
    if let Some((host, _)) = s.split_once(':') {
        s = host.to_string();
    }
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    s = s.trim_matches('.').to_string();
    if s.is_empty()
        || s == "localhost"
        || s == "aether.local"
        || s.ends_with(".local")
        || !s.contains('.')
    {
        return String::new();
    }
    s
}

pub fn get_base_domain() -> String {
    if let Ok(guard) = INGRESS_CACHE.read() {
        if let Some(at) = guard.base_domain_at {
            if at.elapsed() < INGRESS_CACHE_TTL {
                return guard.base_domain.clone();
            }
        }
    }
    let generation = INGRESS_CACHE
        .read()
        .map(|cache| cache.generation)
        .unwrap_or(0);
    let domain = get_read_conn()
        .ok()
        .and_then(|c| {
            c.query_row(
                "SELECT COALESCE(base_domain, '') FROM settings WHERE id = 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
        })
        .map(|d| normalize_base_domain(&d))
        .unwrap_or_default();

    if let Ok(mut guard) = INGRESS_CACHE.write() {
        if guard.generation == generation {
            guard.base_domain = domain.clone();
            guard.base_domain_at = Some(Instant::now());
            BASE_DOMAIN_HINT.store(
                if domain.is_empty() {
                    0
                } else {
                    base_domain_fingerprint(&domain)
                },
                std::sync::atomic::Ordering::Release,
            );
        }
    }
    domain
}

pub fn set_base_domain(domain: &str) -> anyhow::Result<()> {
    let norm = normalize_base_domain(domain);
    let conn = get_conn()?;
    conn.execute(
        "UPDATE settings SET base_domain = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        params![norm],
    )?;
    drop(conn);
    invalidate_ingress_cache();
    get_base_domain();
    Ok(())
}

fn parse_sqlite_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").map(|ndt| ndt.and_utc())
        })
        .unwrap_or_else(|_| Utc::now())
}

pub fn get_all_app_ingress_configs() -> anyhow::Result<Vec<AppIngressConfig>> {
    let generation = INGRESS_CACHE
        .read()
        .map(|guard| guard.generation)
        .unwrap_or(0);
    if let Ok(guard) = INGRESS_CACHE.read() {
        if let (Some(ref cfgs), Some(at)) = (&guard.configs, guard.configs_at) {
            if at.elapsed() < INGRESS_CACHE_TTL {
                return Ok(cfgs.clone());
            }
        }
    }

    let conn = get_read_conn()?;
    let mut stmt = conn.prepare(
        "SELECT app_name, public_domain, external_access_enabled, listen_port, tls_enabled, \
         COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '') \
         FROM app_ingress_configs ORDER BY app_name ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let created_raw: String = r.get(5)?;
        let updated_raw: String = r.get(6)?;
        Ok(AppIngressConfig {
            app_name: r.get(0)?,
            public_domain: r.get(1)?,
            external_access_enabled: r.get(2)?,
            listen_port: r.get(3)?,
            tls_enabled: r.get(4)?,
            created_at: parse_sqlite_dt(&created_raw),
            updated_at: parse_sqlite_dt(&updated_raw),
        })
    })?;

    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }

    if let Ok(mut guard) = INGRESS_CACHE.write() {
        if guard.generation == generation {
            guard.configs = Some(result.clone());
            guard.configs_at = Some(Instant::now());
        }
    }
    Ok(result)
}

pub fn has_retained_app_ingress_config(app: &str) -> anyhow::Result<bool> {
    let conn = get_read_conn()?;
    let table_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='retained_app_ingress_configs')",
        [], |row| row.get(0),
    )?;
    if !table_exists {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM retained_app_ingress_configs WHERE app_name = ?1)",
        [app],
        |row| row.get(0),
    )?)
}

pub fn get_app_ingress_config(app_name: &str) -> anyhow::Result<Option<AppIngressConfig>> {
    let all = get_all_app_ingress_configs()?;
    Ok(all.into_iter().find(|c| c.app_name == app_name))
}

pub fn set_app_ingress_config(cfg: &AppIngressConfig) -> anyhow::Result<()> {
    let mut conn = get_conn()?;
    retained_ingress::set_config(&mut conn, cfg, None)?;
    invalidate_ingress_cache();
    Ok(())
}

pub fn set_app_ingress_config_for_lifecycle(
    cfg: &AppIngressConfig,
    job_id: &str,
    action: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(action, "install" | "reinstall" | "update"),
        "Invalid ingress lifecycle action"
    );
    anyhow::ensure!(
        !job_id.is_empty(),
        "Ingress lifecycle job identity is required"
    );
    let mut conn = get_conn()?;
    retained_ingress::set_config(&mut conn, cfg, Some((job_id, action)))?;
    invalidate_ingress_cache();
    Ok(())
}

fn write_app_ingress_config(conn: &Connection, cfg: &AppIngressConfig) -> anyhow::Result<()> {
    if cfg.listen_port > 0 {
        let reserved = retained_ingress::list_reserved_ports_excluding(conn, &cfg.app_name)?;
        anyhow::ensure!(
            !reserved.contains(&cfg.listen_port),
            "Listen port {} is already reserved by another application",
            cfg.listen_port
        );
    }
    conn.execute(
        r#"
        INSERT INTO app_ingress_configs (app_name, public_domain, external_access_enabled, listen_port, tls_enabled, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
        ON CONFLICT(app_name) DO UPDATE SET
            public_domain = excluded.public_domain,
            external_access_enabled = excluded.external_access_enabled,
            listen_port = CASE WHEN excluded.listen_port > 0 THEN excluded.listen_port ELSE app_ingress_configs.listen_port END,
            tls_enabled = excluded.tls_enabled,
            updated_at = CURRENT_TIMESTAMP
        "#,
        params![
            cfg.app_name,
            cfg.public_domain,
            cfg.external_access_enabled,
            cfg.listen_port,
            cfg.tls_enabled,
        ],
    )?;
    Ok(())
}

pub fn delete_app_ingress_config(app_name: &str) -> anyhow::Result<()> {
    let conn = get_conn()?;
    conn.execute(
        "DELETE FROM app_ingress_configs WHERE app_name = ?1",
        params![app_name],
    )?;
    invalidate_ingress_cache();
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin Audit Trail
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub detail: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: String,
}

#[allow(clippy::too_many_arguments)]
pub fn record_audit(
    user_id: i64,
    username: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    detail: &str,
    ip_address: &str,
    user_agent: &str,
) {
    if let Ok(conn) = get_conn() {
        let _ = conn.execute(
            "INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail, ip_address, user_agent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                user_id,
                username,
                action,
                target_type,
                target_id,
                detail,
                ip_address,
                user_agent
            ],
        );
    }
}

pub fn query_audit_log(
    mut limit: i64,
    offset: i64,
    action: &str,
    username: &str,
) -> anyhow::Result<(Vec<AuditEntry>, i64)> {
    if limit <= 0 || limit > 200 {
        limit = 50;
    }
    let conn = get_read_conn()?;
    let mut where_sql = String::from("WHERE 1=1");
    let mut bind_vals: Vec<String> = Vec::new();
    if !action.is_empty() {
        bind_vals.push(action.to_string());
        where_sql.push_str(&format!(" AND action = ?{}", bind_vals.len()));
    }
    if !username.is_empty() {
        bind_vals.push(username.to_string());
        where_sql.push_str(&format!(" AND username = ?{}", bind_vals.len()));
    }

    let count_sql = format!("SELECT COUNT(*) FROM admin_audit_log {}", where_sql);
    let total: i64 = match bind_vals.len() {
        0 => conn.query_row(&count_sql, [], |r| r.get(0))?,
        1 => conn.query_row(&count_sql, params![bind_vals[0]], |r| r.get(0))?,
        _ => conn.query_row(&count_sql, params![bind_vals[0], bind_vals[1]], |r| {
            r.get(0)
        })?,
    };

    let list_sql = format!(
        "SELECT id, user_id, username, action, target_type, target_id, detail, ip_address, user_agent, COALESCE(CAST(created_at AS TEXT), '') \
         FROM admin_audit_log {} ORDER BY created_at DESC LIMIT {} OFFSET {}",
        where_sql,
        limit,
        offset.max(0)
    );

    let mut stmt = conn.prepare(&list_sql)?;
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<AuditEntry> {
        Ok(AuditEntry {
            id: r.get(0)?,
            user_id: r.get(1)?,
            username: r.get(2)?,
            action: r.get(3)?,
            target_type: r.get(4)?,
            target_id: r.get(5)?,
            detail: r.get(6)?,
            ip_address: r.get(7)?,
            user_agent: r.get(8)?,
            created_at: r.get(9)?,
        })
    };

    let mut entries = Vec::new();
    match bind_vals.len() {
        0 => {
            for row in stmt.query_map([], map_row)? {
                entries.push(row?);
            }
        }
        1 => {
            for row in stmt.query_map(params![bind_vals[0]], map_row)? {
                entries.push(row?);
            }
        }
        _ => {
            for row in stmt.query_map(params![bind_vals[0], bind_vals[1]], map_row)? {
                entries.push(row?);
            }
        }
    }

    Ok((entries, total))
}

// ─────────────────────────────────────────────────────────────────────────────
// Action Approval Gates
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PendingAction {
    pub id: i64,
    pub classification: String,
    pub source: String,
    pub action: String,
    pub reason: String,
    pub status: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub job_unit: Option<String>,
}

fn pending_actions_has_job_unit(conn: &Connection) -> bool {
    conn.prepare("PRAGMA table_info(pending_actions)")
        .and_then(|mut stmt| {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name.eq_ignore_ascii_case("job_unit") {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .unwrap_or(false)
}

fn pending_action_select_columns(conn: &Connection) -> &'static str {
    if pending_actions_has_job_unit(conn) {
        "id, COALESCE(classification, 'warn'), COALESCE(source, ''), COALESCE(action, ''), COALESCE(reason, ''), COALESCE(status, 'pending'), COALESCE(CAST(created_at AS TEXT), ''), CAST(resolved_at AS TEXT), resolved_by, execution_log, NULLIF(TRIM(COALESCE(job_unit, '')), '')"
    } else {
        "id, COALESCE(classification, 'warn'), COALESCE(source, ''), COALESCE(action, ''), COALESCE(reason, ''), COALESCE(status, 'pending'), COALESCE(CAST(created_at AS TEXT), ''), CAST(resolved_at AS TEXT), resolved_by, execution_log, NULL"
    }
}

fn map_pending_action_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PendingAction> {
    Ok(PendingAction {
        id: r.get(0)?,
        classification: r.get(1)?,
        source: r.get(2)?,
        action: r.get(3)?,
        reason: r.get(4)?,
        status: r.get(5)?,
        created_at: r.get(6)?,
        resolved_at: r.get(7).ok().flatten(),
        resolved_by: r.get(8).ok().flatten(),
        execution_log: r.get(9).ok().flatten(),
        job_unit: r.get(10).ok().flatten(),
    })
}

pub fn queue_action(classification: &str, source: &str, action: &str, reason: &str) -> (i64, bool) {
    if classification == "safe" {
        return (0, false);
    }
    let Ok(conn) = get_conn() else {
        return (0, true);
    };
    match conn.execute(
        "INSERT INTO pending_actions (classification, source, action, reason, status) VALUES (?1, ?2, ?3, ?4, 'pending')",
        params![classification, source, action, reason],
    ) {
        Ok(_) => (conn.last_insert_rowid(), true),
        Err(_) => (0, true),
    }
}

pub fn mark_action_executed(action_id: i64, execution_log: &str) {
    if let Ok(conn) = get_conn() {
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE pending_actions SET status = 'executed', resolved_at = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
            params![now, execution_log, action_id],
        );
    }
}

pub fn mark_action_failed(action_id: i64, execution_log: &str) {
    if let Ok(conn) = get_conn() {
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE pending_actions SET status = 'failed', resolved_at = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
            params![now, execution_log, action_id],
        );
    }
}

pub fn mark_action_queued(
    action_id: i64,
    job_unit: &str,
    execution_log: &str,
) -> anyhow::Result<PendingAction> {
    let conn = get_conn()?;
    mark_action_queued_with_connection(&conn, action_id, job_unit, execution_log)
}

fn mark_action_queued_with_connection(
    conn: &Connection,
    action_id: i64,
    job_unit: &str,
    execution_log: &str,
) -> anyhow::Result<PendingAction> {
    let unit = job_unit.trim();
    anyhow::ensure!(!unit.is_empty(), "job_unit is required to queue an action");
    let changed = conn.execute(
        "UPDATE pending_actions SET status = 'queued', job_unit = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
        params![unit, execution_log, action_id],
    )?;
    if changed == 0 {
        anyhow::bail!("Action not found or not awaiting deferred queue persistence");
    }
    get_pending_action_by_id_with_connection(conn, action_id)?
        .ok_or_else(|| anyhow::anyhow!("Action disappeared after queueing"))
}

pub fn mark_action_unavailable(
    action_id: i64,
    job_unit: Option<&str>,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    let conn = get_conn()?;
    mark_action_unavailable_with_connection(&conn, action_id, job_unit, execution_log)
}

fn mark_action_unavailable_with_connection(
    conn: &Connection,
    action_id: i64,
    job_unit: Option<&str>,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    let now = Utc::now().to_rfc3339();
    let normalized_unit = job_unit.map(str::trim).filter(|u| !u.is_empty());
    if let Some(unit) = normalized_unit {
        conn.execute(
            "UPDATE pending_actions SET status = 'unavailable', resolved_at = ?1, execution_log = ?2, job_unit = COALESCE(NULLIF(TRIM(COALESCE(job_unit, '')), ''), ?3) \
             WHERE id = ?4 AND status IN ('approved', 'queued') AND COALESCE(TRIM(job_unit), '') IN ('', ?3)",
            params![now, execution_log, unit, action_id],
        )?;
    } else {
        conn.execute(
            "UPDATE pending_actions SET status = 'unavailable', resolved_at = ?1, execution_log = ?2 \
             WHERE id = ?3 AND status IN ('approved', 'queued')",
            params![now, execution_log, action_id],
        )?;
    }
    get_pending_action_by_id_with_connection(conn, action_id)
}

pub fn finalize_queued_action_by_id(
    action_id: i64,
    expected_job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    let conn = get_conn()?;
    finalize_queued_action_by_id_with_connection(
        &conn,
        action_id,
        expected_job_unit,
        final_status,
        execution_log,
    )
}

fn finalize_queued_action_by_id_with_connection(
    conn: &Connection,
    action_id: i64,
    expected_job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    anyhow::ensure!(
        matches!(final_status, "executed" | "failed" | "unavailable"),
        "Invalid final action status"
    );
    let unit = expected_job_unit.trim();
    anyhow::ensure!(!unit.is_empty(), "expected_job_unit is required");
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE pending_actions SET status = ?1, resolved_at = ?2, execution_log = ?3 \
         WHERE id = ?4 AND status IN ('approved', 'queued') AND job_unit = ?5",
        params![final_status, now, execution_log, action_id, unit],
    )?;
    get_pending_action_by_id_with_connection(conn, action_id)
}

pub fn finalize_queued_action_by_job_unit(
    job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<usize> {
    let conn = get_conn()?;
    finalize_queued_action_by_job_unit_with_connection(&conn, job_unit, final_status, execution_log)
}

fn finalize_queued_action_by_job_unit_with_connection(
    conn: &Connection,
    job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<usize> {
    anyhow::ensure!(
        matches!(final_status, "executed" | "failed" | "unavailable"),
        "Invalid final action status"
    );
    let unit = job_unit.trim();
    anyhow::ensure!(!unit.is_empty(), "job_unit is required");
    if !pending_actions_has_job_unit(conn) {
        return Ok(0);
    }
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE pending_actions SET status = ?1, resolved_at = ?2, execution_log = ?3 \
         WHERE job_unit = ?4 AND status IN ('approved', 'queued')",
        params![final_status, now, execution_log, unit],
    )?;
    Ok(changed)
}

pub fn list_queued_actions_with_receipts(limit: i64) -> anyhow::Result<Vec<PendingAction>> {
    let conn = get_read_conn()?;
    list_queued_actions_with_receipts_with_connection(&conn, limit)
}

fn list_queued_actions_with_receipts_with_connection(
    conn: &Connection,
    limit: i64,
) -> anyhow::Result<Vec<PendingAction>> {
    if !pending_actions_has_job_unit(conn) {
        return Ok(Vec::new());
    }
    let limit = limit.clamp(1, 100);
    let cols = pending_action_select_columns(conn);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM pending_actions WHERE status = 'queued' AND NULLIF(TRIM(COALESCE(job_unit, '')), '') IS NOT NULL ORDER BY created_at DESC, id DESC LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![limit], map_pending_action_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn list_audit_entries(
    limit: i64,
    offset: i64,
    action: &str,
    username: &str,
) -> anyhow::Result<(Vec<AuditEntry>, i64)> {
    query_audit_log(limit, offset, action, username)
}

pub fn list_pending_actions(mut limit: i64, offset: i64) -> anyhow::Result<Vec<PendingAction>> {
    if limit <= 0 {
        limit = 50;
    } else if limit > 500 {
        limit = 500;
    }
    let conn = get_read_conn()?;
    let cols = pending_action_select_columns(&conn);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM pending_actions ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
    ))?;
    let rows = stmt.query_map(params![limit, offset.max(0)], map_pending_action_row)?;
    let mut actions = Vec::new();
    for r in rows {
        actions.push(r?);
    }
    Ok(actions)
}

pub fn query_pending_actions(
    status_filter: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<PendingAction>, i64)> {
    let conn = get_read_conn()?;
    query_pending_actions_with_connection(&conn, status_filter, limit, offset)
}

fn query_pending_actions_with_connection(
    conn: &Connection,
    status_filter: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<PendingAction>, i64)> {
    let limit = if limit <= 0 { 50 } else { limit.clamp(1, 500) };
    let offset = offset.max(0);
    let predicate = match status_filter {
        "all" | "" => "1 = 1",
        "pending" => "COALESCE(status, 'pending') = 'pending'",
        "approved_history" => {
            "COALESCE(status, 'pending') IN ('approved', 'queued', 'executed', 'failed', 'unavailable')"
        }
        "approved" | "queued" | "rejected" | "executed" | "failed" | "unavailable" => {
            "COALESCE(status, 'pending') = ?"
        }
        _ => anyhow::bail!("Invalid status filter"),
    };
    let mut bindings = Vec::<rusqlite::types::Value>::new();
    if predicate.ends_with("= ?") {
        bindings.push(status_filter.to_owned().into());
    }
    let total = conn.query_row(
        &format!("SELECT COUNT(*) FROM pending_actions WHERE {predicate}"),
        rusqlite::params_from_iter(bindings.iter()),
        |row| row.get::<_, i64>(0),
    )?;
    bindings.push(limit.into());
    bindings.push(offset.into());
    let cols = pending_action_select_columns(conn);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM pending_actions WHERE {predicate} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
    ))?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(bindings.iter()),
        map_pending_action_row,
    )?;
    Ok((rows.collect::<rusqlite::Result<Vec<_>>>()?, total))
}

pub fn get_pending_action_by_id(action_id: i64) -> anyhow::Result<Option<PendingAction>> {
    let conn = get_read_conn()?;
    get_pending_action_by_id_with_connection(&conn, action_id)
}

fn get_pending_action_by_id_with_connection(
    conn: &Connection,
    action_id: i64,
) -> anyhow::Result<Option<PendingAction>> {
    let cols = pending_action_select_columns(conn);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM pending_actions WHERE id = ?1",
    ))?;
    let res = stmt.query_row(params![action_id], map_pending_action_row);
    match res {
        Ok(action) => Ok(Some(action)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn resolve_action(
    action_id: i64,
    new_status: &str,
    resolved_by: &str,
) -> anyhow::Result<PendingAction> {
    let conn = get_conn()?;
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE pending_actions SET status = ?1, resolved_at = ?2, resolved_by = ?3 WHERE id = ?4 AND status = 'pending'",
        params![new_status, now, resolved_by, action_id],
    )?;
    if changed == 0 {
        anyhow::bail!("Action not found or already resolved");
    }
    get_pending_action_by_id_with_connection(&conn, action_id)?
        .ok_or_else(|| anyhow::anyhow!("Action disappeared after resolve"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Session Revocation, 2FA Pending & MFA Challenge Store
// ─────────────────────────────────────────────────────────────────────────────

static TOKEN_BLACKLIST: Lazy<Mutex<HashMap<String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PENDING_2FA_CACHE: Lazy<Mutex<HashMap<i64, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn ensure_revoked_tokens_table(conn: &Connection) -> bool {
    if conn
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                family_id TEXT NOT NULL DEFAULT '',
                user_id INTEGER NOT NULL DEFAULT 0
            );",
        )
        .is_err()
    {
        return false;
    }
    let _ = ensure_column(
        conn,
        "revoked_tokens",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    );
    let _ = ensure_column(
        conn,
        "revoked_tokens",
        "user_id",
        "INTEGER NOT NULL DEFAULT 0",
    );
    true
}

pub fn cache_revoked_token(jti: &str, ttl: Duration) {
    if jti.is_empty() {
        return;
    }
    let ttl = ttl.max(Duration::from_secs(8160));
    let exp = Instant::now() + ttl;
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        map.retain(|_, v| *v > Instant::now());
        map.insert(jti.to_string(), exp);
    }
}

pub fn revoke_token_in_tx(conn: &Connection, jti: &str, ttl: Duration) -> anyhow::Result<()> {
    if jti.is_empty() {
        return Ok(());
    }
    let ttl = ttl.max(Duration::from_secs(8160));
    if !ensure_revoked_tokens_table(conn) {
        anyhow::bail!("failed to ensure revoked_tokens table");
    }
    let mut family_id = String::new();
    let mut user_id = 0i64;
    if let Ok(Some((fam, uid))) = conn
        .query_row(
            "SELECT COALESCE(family_id, ''), user_id FROM active_sessions WHERE jti = ?1",
            params![jti],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
    {
        family_id = if fam.trim().is_empty() {
            jti.to_string()
        } else {
            fam
        };
        user_id = uid;
    } else if let Ok(Some((fam, uid))) = conn
        .query_row(
            "SELECT COALESCE(family_id, ''), COALESCE(user_id, 0) FROM revoked_tokens WHERE jti = ?1",
            params![jti],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
    {
        family_id = fam;
        user_id = uid;
    }
    let exp_rfc3339 = (Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64)).to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, family_id, user_id) VALUES (?1, ?2, ?3, ?4)",
        params![jti, exp_rfc3339, family_id, user_id],
    )?;
    let _ = conn.execute("DELETE FROM active_sessions WHERE jti = ?1", params![jti]);
    Ok(())
}

/// Atomically marks `jti` as revoked inside an active `BEGIN IMMEDIATE` transaction
/// ONLY if it is not currently revoked. Returns `Ok(true)` exclusively for the single
/// winning caller that consumed `jti`.
pub fn try_consume_session_jti_in_tx(
    conn: &Connection,
    jti: &str,
    ttl: Duration,
) -> anyhow::Result<bool> {
    if jti.is_empty() {
        return Ok(false);
    }
    let ttl = ttl.max(Duration::from_secs(8160));
    if token_revocation_status_with_conn(conn, jti)? {
        return Ok(false);
    }
    let _ = conn.execute("DELETE FROM revoked_tokens WHERE jti = ?1", params![jti]);
    let exp_rfc3339 = (Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64)).to_rfc3339();
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?1, ?2)",
        params![jti, exp_rfc3339],
    )?;
    Ok(inserted == 1)
}

pub fn record_revoked_token_lineage_in_tx(
    conn: &Connection,
    jti: &str,
    family_id: &str,
    user_id: i64,
) -> anyhow::Result<()> {
    if jti.is_empty() || family_id.trim().is_empty() {
        return Ok(());
    }
    match conn.execute(
        "UPDATE revoked_tokens SET family_id = ?1, user_id = ?2 WHERE jti = ?3",
        params![family_id.trim(), user_id, jti],
    ) {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("family_id") || e.to_string().contains("user_id") => {
            let _ = ensure_column(
                conn,
                "revoked_tokens",
                "family_id",
                "TEXT NOT NULL DEFAULT ''",
            );
            let _ = ensure_column(
                conn,
                "revoked_tokens",
                "user_id",
                "INTEGER NOT NULL DEFAULT 0",
            );
            conn.execute(
                "UPDATE revoked_tokens SET family_id = ?1, user_id = ?2 WHERE jti = ?3",
                params![family_id.trim(), user_id, jti],
            )?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

pub fn resolve_revoked_token_family_in_tx(
    conn: &Connection,
    jti: &str,
    user_id: i64,
) -> anyhow::Result<Option<String>> {
    if jti.is_empty() {
        return Ok(None);
    }
    let query = || {
        conn.query_row(
            "SELECT COALESCE(family_id, '') FROM revoked_tokens \
             WHERE jti = ?1 AND (COALESCE(user_id, 0) = 0 OR user_id = ?2) LIMIT 1",
            params![jti, user_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    };
    let fam: Option<String> = match query() {
        Ok(v) => v,
        Err(e) if e.to_string().contains("family_id") || e.to_string().contains("user_id") => None,
        Err(e) => return Err(e.into()),
    };
    Ok(fam.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

pub fn revoke_token(jti: &str, ttl: Duration) -> anyhow::Result<()> {
    if jti.is_empty() {
        return Ok(());
    }
    // Refresh accepts a token for 7200s after exp (900s), plus 60s clock skew tolerance = 8160s.
    let ttl = ttl.max(Duration::from_secs(8160));
    let conn = get_conn()?;
    revoke_token_in_tx(&conn, jti, ttl)?;
    let _ = conn.execute(
        "DELETE FROM revoked_tokens WHERE expires_at IS NOT NULL AND TRIM(expires_at) != '' AND datetime(expires_at) IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        [],
    );
    cache_revoked_token(jti, ttl);
    Ok(())
}

/// Errors are distinct from a confirmed revocation so rotation grace cannot mask a DB failure.
pub fn token_revocation_status(jti: &str) -> anyhow::Result<bool> {
    if jti.is_empty() {
        return Ok(true);
    }
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        if let Some(&exp) = map.get(jti) {
            if exp > Instant::now() {
                return Ok(true);
            }
            map.remove(jti);
        }
    }
    let conn = get_read_conn()?;
    token_revocation_status_with_conn(&conn, jti)
}

fn parse_revocation_expiry_utc(raw: &str) -> anyhow::Result<DateTime<Utc>> {
    let trimmed = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        return Ok(naive.and_utc());
    }
    anyhow::bail!("invalid revoked_tokens.expires_at timestamp: {}", trimmed)
}

pub fn token_revocation_status_with_conn(conn: &Connection, jti: &str) -> anyhow::Result<bool> {
    let expiry: Option<String> = conn
        .query_row(
            "SELECT expires_at FROM revoked_tokens WHERE jti = ?1",
            params![jti],
            |r| r.get(0),
        )
        .optional()?;
    match expiry {
        None => Ok(false),
        Some(expiry) => Ok(parse_revocation_expiry_utc(&expiry)? > Utc::now()),
    }
}

pub fn is_token_revoked(jti: &str) -> bool {
    token_revocation_status(jti).unwrap_or(true)
}

pub fn store_2fa_pending(user_id: i64, secret: &str, ttl: Duration) {
    if let Ok(mut map) = PENDING_2FA_CACHE.lock() {
        let now = Instant::now();
        map.retain(|_, (_, expires)| *expires > now);
        map.insert(user_id, (secret.to_string(), now + ttl));
    }
}

pub fn get_2fa_pending(user_id: i64) -> Option<String> {
    let mut map = PENDING_2FA_CACHE.lock().ok()?;
    if let Some((secret, exp)) = map.get(&user_id) {
        if *exp > Instant::now() {
            return Some(secret.clone());
        }
        map.remove(&user_id);
    }
    None
}

pub fn delete_2fa_pending(user_id: i64) {
    if let Ok(mut map) = PENDING_2FA_CACHE.lock() {
        map.remove(&user_id);
    }
}

pub const MAX_MFA_ATTEMPTS: i64 = 5;

pub fn store_mfa_challenge_in_tx(
    conn: &Connection,
    token: &str,
    user_id: i64,
    credential_ver: i64,
    ttl: Duration,
) -> anyhow::Result<()> {
    let now = Utc::now().timestamp();
    let exp = now + ttl.as_secs().min(300) as i64;
    conn.execute(
        "DELETE FROM mfa_challenges WHERE expires_at <= ?1",
        params![now],
    )?;
    match conn.execute(
        "INSERT INTO mfa_challenges (token, user_id, credential_ver, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token, user_id, credential_ver, exp],
    ) {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("credential_ver") => {
            ensure_column(
                conn,
                "mfa_challenges",
                "credential_ver",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            conn.execute(
                "INSERT INTO mfa_challenges (token, user_id, credential_ver, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![token, user_id, credential_ver, exp],
            )?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

pub fn store_mfa_challenge(token: &str, user_id: i64, ttl: Duration) -> anyhow::Result<()> {
    let conn = get_conn()?;
    let ver: i64 = conn
        .query_row(
            "SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    store_mfa_challenge_in_tx(&conn, token, user_id, ver, ttl)
}

pub fn delete_user_mfa_challenges_in_tx(conn: &Connection, user_id: i64) -> anyhow::Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'mfa_challenges'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if exists {
        conn.execute(
            "DELETE FROM mfa_challenges WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    Ok(())
}

/// Call within the same write transaction as factor verification and consumption.
/// Failed verification must commit this attempt; successful consumption must commit with the factor.
pub fn begin_mfa_attempt_with_epoch(
    conn: &Connection,
    token: &str,
) -> anyhow::Result<Option<(i64, i64)>> {
    let now = Utc::now().timestamp();
    match conn
        .query_row(
            "UPDATE mfa_challenges SET attempts = attempts + 1 \
             WHERE token = ?1 AND attempts < ?2 AND expires_at > ?3 \
             RETURNING user_id, COALESCE(credential_ver, 0)",
            params![token, MAX_MFA_ATTEMPTS, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
    {
        Ok(res) => Ok(res),
        Err(e) if e.to_string().contains("credential_ver") => Ok(conn
            .query_row(
                "UPDATE mfa_challenges SET attempts = attempts + 1 \
                 WHERE token = ?1 AND attempts < ?2 AND expires_at > ?3 \
                 RETURNING user_id",
                params![token, MAX_MFA_ATTEMPTS, now],
                |r| Ok((r.get(0)?, 0i64)),
            )
            .optional()?),
        Err(e) => Err(e.into()),
    }
}

pub fn begin_mfa_attempt(conn: &Connection, token: &str) -> anyhow::Result<Option<i64>> {
    Ok(begin_mfa_attempt_with_epoch(conn, token)?.map(|(uid, _)| uid))
}

pub fn consume_mfa_challenge_with_epoch(
    conn: &Connection,
    token: &str,
    user_id: i64,
    credential_ver: i64,
) -> anyhow::Result<bool> {
    let now = Utc::now().timestamp();
    match conn
        .query_row(
            "DELETE FROM mfa_challenges \
             WHERE token = ?1 AND user_id = ?2 AND COALESCE(credential_ver, 0) = ?3 \
               AND attempts <= ?4 AND expires_at > ?5 \
             RETURNING user_id",
            params![token, user_id, credential_ver, MAX_MFA_ATTEMPTS, now],
            |r| r.get::<_, i64>(0),
        )
        .optional()
    {
        Ok(consumed) => Ok(consumed == Some(user_id)),
        Err(e) if e.to_string().contains("credential_ver") => {
            if credential_ver != 0 {
                return Ok(false);
            }
            consume_mfa_challenge(conn, token, user_id)
        }
        Err(e) => Err(e.into()),
    }
}

pub fn consume_mfa_challenge(conn: &Connection, token: &str, user_id: i64) -> anyhow::Result<bool> {
    let consumed: Option<i64> = conn
        .query_row(
            "DELETE FROM mfa_challenges WHERE token = ?1 AND user_id = ?2 AND attempts <= ?3 AND expires_at > ?4 RETURNING user_id",
            params![token, user_id, MAX_MFA_ATTEMPTS, Utc::now().timestamp()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(consumed == Some(user_id))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) static TEST_DB_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn bundled_sqlite_includes_wal_security_fix() {
        assert!(
            rusqlite::version_number() >= 3_054_000,
            "bundled SQLite must include the RUSTSEC-2026-0459 WAL fix; found {}",
            rusqlite::version()
        );
    }

    #[test]
    fn sqlite_preserves_checked_unsigned_integer_conversions() {
        let connection = Connection::open_in_memory().unwrap();
        let maximum = connection
            .query_row("SELECT ?1", [i64::MAX], |row| row.get::<_, u64>(0))
            .unwrap();
        assert_eq!(maximum, i64::MAX as u64);
        let offset = connection
            .query_row("SELECT 42", [], |row| row.get::<_, usize>(0))
            .unwrap();
        assert_eq!(offset, 42);
        assert!(connection
            .query_row("SELECT -1", [], |row| row.get::<_, u64>(0))
            .is_err());
    }

    #[test]
    fn revocation_query_distinguishes_absent_revoked_and_database_errors() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let conn = Connection::open_in_memory().unwrap();
        assert!(token_revocation_status_with_conn(&conn, "session").is_err());
        conn.execute_batch(
            "CREATE TABLE revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);",
        )
        .unwrap();
        assert!(!token_revocation_status_with_conn(&conn, "absent").unwrap());
        for (jti, expiry) in [
            (
                "active",
                (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            ),
            (
                "expired",
                (Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
            ),
            ("bad-date", "invalid".into()),
        ] {
            conn.execute(
                "INSERT INTO revoked_tokens VALUES (?1, ?2)",
                params![jti, expiry],
            )
            .unwrap();
        }
        assert!(token_revocation_status_with_conn(&conn, "active").unwrap());
        assert!(!token_revocation_status_with_conn(&conn, "expired").unwrap());
        assert!(token_revocation_status_with_conn(&conn, "bad-date").is_err());
        conn.execute_batch("DROP TABLE revoked_tokens;").unwrap();
        assert!(token_revocation_status_with_conn(&conn, "absent").is_err());
    }

    #[test]
    fn bounded_read_pool_works_while_writer_is_held_and_cannot_write() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = std::env::temp_dir().join(format!(
            "af-read-pool-{}-{}.sqlite",
            std::process::id(),
            rand::random::<u64>()
        ));
        let writer_pool = Pool::builder()
            .max_size(1)
            .build(SqliteConnectionManager::file(&path))
            .unwrap();
        let writer = writer_pool.get().unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE example (id INTEGER); INSERT INTO example VALUES (1); BEGIN IMMEDIATE; INSERT INTO example VALUES (2);").unwrap();
        let readers = build_read_pool(path.to_str().unwrap()).unwrap();
        let reader = readers.get().unwrap();
        let count: i64 = reader
            .query_row("SELECT COUNT(*) FROM example", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 1,
            "Reader sees committed WAL snapshot while writer is busy"
        );
        assert!(reader
            .execute("INSERT INTO example VALUES (3)", [])
            .is_err());
        assert_eq!(readers.max_size(), 8);
        writer.execute_batch("ROLLBACK;").unwrap();
        drop(reader);
        drop(readers);
        drop(writer);
        drop(writer_pool);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_decrypt_key_requires_master_key_for_ciphertext() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let encrypted = encrypt_with_key("fixture-secret", &[1; 32]).unwrap();
        let previous = AES_MASTER_KEY
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let encrypted_result = decrypt_key(&encrypted);
        let plaintext_result = decrypt_key("local-development-key");
        *AES_MASTER_KEY.write().unwrap_or_else(|e| e.into_inner()) = previous;

        let error = encrypted_result.unwrap_err().to_string();
        assert!(error.contains("AES_MASTER_KEY is required"));
        assert!(!error.contains(&encrypted));
        assert_eq!(plaintext_result.unwrap(), "local-development-key");
    }

    #[test]
    fn test_aes_gcm_roundtrip_and_format() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("AES_MASTER_KEY", "a".repeat(32));
        init_aes_key().unwrap();
        assert!(is_encryption_enabled());

        let encrypted = encrypt_key("my-secret-gemini-key").unwrap();
        assert!(encrypted.starts_with("enc:v1:"));
        let decrypted = decrypt_key(&encrypted).unwrap();
        assert_eq!(decrypted, "my-secret-gemini-key");
    }

    #[test]
    fn test_sqlite_migrations_and_settings_singleton() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("DB_PATH", ":memory:");
        init_db().unwrap();
        let health = db_health_check().unwrap();
        assert_eq!(health["status"], "healthy");

        {
            let conn = get_conn().unwrap();
            let migration_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM schema_versions WHERE version IN (20, 21, 22)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(migration_count, 3);
            let retired_runtime_tables: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='billing_webhook_cursors'", [], |row| row.get(0)
            ).unwrap();
            assert_eq!(retired_runtime_tables, 0);
            let provenance_column_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('streaming_history') WHERE name = 'provenance'",
                [],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(provenance_column_count, 1);
            conn.query_row("SELECT COUNT(*) FROM plugins_registry", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        }

        for new_status in ["approved", "rejected"] {
            let action_id = {
                let conn = get_conn().unwrap();
                conn.execute(
                    "INSERT INTO pending_actions (source, action, reason) VALUES ('audit', 'test', 'connection regression')",
                    [],
                )
                .unwrap();
                conn.last_insert_rowid()
            };
            let action = resolve_action(action_id, new_status, "audit-admin").unwrap();
            assert_eq!(action.status, new_status);
            assert_eq!(action.resolved_by.as_deref(), Some("audit-admin"));
            assert!(action.resolved_at.is_some());
            assert!(resolve_action(action_id, new_status, "audit-admin").is_err());
        }
    }

    #[test]
    fn test_round3_64hex_aes_key_schema24_and_revoked_lineage_epoch_mfa() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let hex_key: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
        let parsed = parse_aes_key_bytes(&hex_key).expect("64-char hex AES key must decode");
        assert_eq!(parsed[0], 0x00);
        assert_eq!(parsed[1], 0x01);
        assert!(parse_aes_key_bytes(&hex_key[..16]).is_err());
        assert!(parse_aes_key_bytes(&"z".repeat(64)).is_err());

        env::set_var("AES_MASTER_KEY", &hex_key);
        init_aes_key().unwrap();
        let ct = encrypt_key("hex-key-secret-value").unwrap();
        assert!(ct.starts_with("enc:v1:"));
        assert_eq!(decrypt_key(&ct).unwrap(), "hex-key-secret-value");

        env::set_var("DB_PATH", ":memory:");
        init_db().unwrap();
        let conn = get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 24, "MAX(schema_versions.version) must remain 24");

        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (777, 'r3_db_user', 'user')",
            [],
        )
        .unwrap();

        revoke_token_in_tx(&conn, "r3-jti-1", Duration::from_secs(600)).unwrap();
        record_revoked_token_lineage_in_tx(&conn, "r3-jti-1", "r3-family-99", 777).unwrap();
        assert_eq!(
            resolve_revoked_token_family_in_tx(&conn, "r3-jti-1", 777)
                .unwrap()
                .as_deref(),
            Some("r3-family-99")
        );

        store_mfa_challenge_in_tx(&conn, "r3-mfa-tok", 777, 10, Duration::from_secs(300)).unwrap();
        let (_, ver) = begin_mfa_attempt_with_epoch(&conn, "r3-mfa-tok")
            .unwrap()
            .expect("challenge must exist");
        assert_eq!(ver, 10);
        assert!(!consume_mfa_challenge_with_epoch(&conn, "r3-mfa-tok", 777, 11).unwrap());
        assert!(consume_mfa_challenge_with_epoch(&conn, "r3-mfa-tok", 777, 10).unwrap());
    }

    #[test]
    fn test_round7_migrate_legacy_secrets_encrypts_settings_totp_and_streaming() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("AES_MASTER_KEY", "c".repeat(64));
        init_aes_key().unwrap();
        env::set_var("DB_PATH", ":memory:");
        init_db().unwrap();

        {
            let conn = get_conn().unwrap();
            conn.execute(
                "UPDATE settings SET gemini_api_key = 'plain-gemini', openai_api_key = 'plain-openai', anthropic_api_key = 'plain-anthropic' WHERE id = 1",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (id, username, role, totp_secret, totp_enabled) VALUES (888, 'r7_mfa_user', 'admin', 'JBSWY3DPEHPK3PXP', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'JF', 'http://127.0.0.1:8096', 'plain-jf-api-key', 1)",
                [],
            )
            .unwrap();
        }

        migrate_legacy_secrets().expect("migrate_legacy_secrets must succeed");

        let conn = get_conn().unwrap();
        let (gem, oai, ant): (String, String, String) = conn
            .query_row(
                "SELECT gemini_api_key, openai_api_key, anthropic_api_key FROM settings WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(gem.starts_with("enc:v1:"));
        assert!(oai.starts_with("enc:v1:"));
        assert!(ant.starts_with("enc:v1:"));
        assert_eq!(decrypt_key(&gem).unwrap(), "plain-gemini");
        assert_eq!(decrypt_key(&oai).unwrap(), "plain-openai");
        assert_eq!(decrypt_key(&ant).unwrap(), "plain-anthropic");

        let totp_enc: String = conn
            .query_row("SELECT totp_secret FROM users WHERE id = 888", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(totp_enc.starts_with("enc:v1:"));
        assert_eq!(decrypt_key(&totp_enc).unwrap(), "JBSWY3DPEHPK3PXP");

        let stream_enc: String = conn
            .query_row(
                "SELECT api_key FROM streaming_servers WHERE provider = 'jellyfin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stream_enc.starts_with("enc:v1:"));
        assert_eq!(decrypt_key(&stream_enc).unwrap(), "plain-jf-api-key");
    }

    #[test]
    fn test_round8_env_file_aes_fallback_and_rfc3339_prune_expired_data() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let env_path = std::env::temp_dir().join(format!(
            "af_r8_env_file_{}_{}.env",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::write(&env_path, format!("AES_MASTER_KEY={}\n", "e".repeat(64))).unwrap();
        env::remove_var("AES_MASTER_KEY");
        env::set_var("AETHERFLOW_ENV_FILE", &env_path);
        init_aes_key().expect("init_aes_key must load AES_MASTER_KEY from AETHERFLOW_ENV_FILE");
        let ct = encrypt_key("r8-env-secret").unwrap();
        assert!(
            ct.starts_with("enc:v1:"),
            "expected AES-256-GCM ciphertext prefix enc:v1:, got {ct}"
        );
        assert_eq!(decrypt_key(&ct).unwrap(), "r8-env-secret");
        env::remove_var("AETHERFLOW_ENV_FILE");
        let _ = std::fs::remove_file(&env_path);
        env::set_var("AES_MASTER_KEY", "c".repeat(64));
        init_aes_key().unwrap();

        env::set_var("DB_PATH", ":memory:");
        init_db().unwrap();
        let now_rfc3339 = Utc::now().to_rfc3339();
        {
            let conn = get_conn().unwrap();
            conn.execute(
                "INSERT INTO login_history (user_id, ip_address, user_agent, created_at) \
                 VALUES (1, '10.0.0.1', 'ua-old', '2020-01-01T00:00:00+00:00'), \
                        (1, '10.0.0.2', 'ua-fresh', ?1)",
                params![now_rfc3339],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO metrics_history (cpu_avg, timestamp) \
                 VALUES (1.0, '2020-01-01T00:00:00+00:00'), \
                        (2.0, ?1)",
                params![now_rfc3339],
            )
            .unwrap();
        }
        prune_expired_data();
        let conn = get_conn().unwrap();
        let login_rem: Vec<String> = conn
            .prepare("SELECT user_agent FROM login_history")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(login_rem, vec!["ua-fresh".to_string()]);
        let metrics_cnt: i64 = conn
            .query_row("SELECT COUNT(*) FROM metrics_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(metrics_cnt, 1);

        let future_exp = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        let past_exp = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        conn.execute(
            "INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, expires_at, used) \
             VALUES ('live-used-tombstone', 'cid', 1, 'https://app.example/cb', 'openid', ?1, 1), \
                    ('expired-used-code', 'cid', 1, 'https://app.example/cb', 'openid', ?2, 1)",
            params![future_exp, past_exp],
        )
        .unwrap();
        drop(conn);
        prune_expired_data();
        let conn = get_conn().unwrap();
        let remaining_codes: Vec<String> = conn
            .prepare("SELECT code FROM oidc_auth_codes")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(remaining_codes, vec!["live-used-tombstone".to_string()]);
    }

    #[test]
    fn test_init_aes_key_requires_key_when_aetherflow_env_production() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let prev_aes = env::var("AES_MASTER_KEY").ok();
        let prev_af_env = env::var("AETHERFLOW_ENV").ok();
        let prev_gin = env::var("GIN_MODE").ok();
        let prev_skip = env::var("AETHERFLOW_SKIP_ENV_FILES").ok();

        env::remove_var("AES_MASTER_KEY");
        env::remove_var("GIN_MODE");
        env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
        env::set_var("AETHERFLOW_ENV", "production");

        let err = init_aes_key()
            .expect_err("AETHERFLOW_ENV=production without AES_MASTER_KEY must fail closed");
        assert!(err
            .to_string()
            .contains("AES_MASTER_KEY is required in production"));
        assert!(!err.to_string().contains("GIN_MODE"));

        env::set_var("AETHERFLOW_ENV", "disposable-guest-lifecycle-drill");
        env::set_var("GIN_MODE", "release");
        init_aes_key().expect(
            "legacy GIN_MODE=release must be ignored when AETHERFLOW_ENV is non-production",
        );

        match prev_aes {
            Some(v) => env::set_var("AES_MASTER_KEY", v),
            None => env::remove_var("AES_MASTER_KEY"),
        }
        match prev_af_env {
            Some(v) => env::set_var("AETHERFLOW_ENV", v),
            None => env::remove_var("AETHERFLOW_ENV"),
        }
        match prev_gin {
            Some(v) => env::set_var("GIN_MODE", v),
            None => env::remove_var("GIN_MODE"),
        }
        match prev_skip {
            Some(v) => env::set_var("AETHERFLOW_SKIP_ENV_FILES", v),
            None => env::remove_var("AETHERFLOW_SKIP_ENV_FILES"),
        }
    }

    #[test]
    fn test_aes_key_candidate_env_files_includes_default_fallback() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        struct EnvGuard {
            prev_skip: Option<String>,
            prev_file: Option<String>,
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.prev_skip {
                    Some(v) => env::set_var("AETHERFLOW_SKIP_ENV_FILES", v),
                    None => env::remove_var("AETHERFLOW_SKIP_ENV_FILES"),
                }
                match &self.prev_file {
                    Some(v) => env::set_var("AETHERFLOW_ENV_FILE", v),
                    None => env::remove_var("AETHERFLOW_ENV_FILE"),
                }
            }
        }
        let _env_guard = EnvGuard {
            prev_skip: env::var("AETHERFLOW_SKIP_ENV_FILES").ok(),
            prev_file: env::var("AETHERFLOW_ENV_FILE").ok(),
        };

        env::remove_var("AETHERFLOW_SKIP_ENV_FILES");
        env::remove_var("AETHERFLOW_ENV_FILE");
        let default_only = aes_key_candidate_env_files();
        assert_eq!(
            default_only,
            vec![std::path::PathBuf::from("/etc/aetherflow/aetherflow.env")]
        );

        env::set_var("AETHERFLOW_ENV_FILE", "/tmp/custom-af.env");
        let with_explicit = aes_key_candidate_env_files();
        assert_eq!(
            with_explicit,
            vec![
                std::path::PathBuf::from("/tmp/custom-af.env"),
                std::path::PathBuf::from("/etc/aetherflow/aetherflow.env"),
            ]
        );

        env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
        assert!(aes_key_candidate_env_files().is_empty());
    }

    #[test]
    fn test_migrate_is_atomic_on_mid_migration_failure() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_versions (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();

        let err = migrate(
            &conn,
            99,
            "failing partial migration",
            &[
                "CREATE TABLE atomic_test_table (id INTEGER PRIMARY KEY);",
                "THIS IS NOT VALID SQL;",
            ],
        )
        .expect_err("invalid second statement must fail migration");
        assert!(!err.to_string().is_empty());
        assert!(
            conn.is_autocommit(),
            "connection must not stay in transaction"
        );

        let table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='atomic_test_table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            table_exists, 0,
            "first DDL statement must be rolled back when later statement fails"
        );
        let version_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_versions WHERE version = 99",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version_exists, 0);

        // Now apply a valid migration and verify idempotent re-run
        migrate(
            &conn,
            99,
            "valid atomic migration",
            &["CREATE TABLE atomic_test_table (id INTEGER PRIMARY KEY);"],
        )
        .unwrap();
        migrate(
            &conn,
            99,
            "valid atomic migration",
            &["THIS WOULD FAIL IF RE-EXECUTED;"],
        )
        .unwrap();
        let version_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_versions WHERE version = 99",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version_count, 1);
    }

    #[test]
    fn test_system_prompt_default_updated_to_rust_wasm() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("DB_PATH", ":memory:");
        init_db().unwrap();
        let conn = get_conn().unwrap();
        let prompt: String = conn
            .query_row("SELECT system_prompt FROM settings WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(prompt.contains("sovereign Rust + WebAssembly aetherflow-api environment"));
        assert!(!prompt.contains("Next.js"));
    }

    #[test]
    fn test_per_user_broadcast_notification_reads_isolate_users() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("DB_PATH", ":memory:");
        init_db().unwrap();
        let conn = get_conn().unwrap();

        // Seed two broadcast notifications (user_id IS NULL) and one owned per user
        conn.execute(
            "INSERT INTO notifications (id, user_id, level, title, message, read)
             VALUES (1, NULL, 'info', 'Broadcast A', 'Hello all', 0),
                    (2, NULL, 'warning', 'Broadcast B', 'Maintenance', 0),
                    (3, 1, 'info', 'User 1 private', 'Only 1', 0),
                    (4, 2, 'error', 'User 2 private', 'Only 2', 0)",
            [],
        )
        .unwrap();

        assert_eq!(
            count_unread_notifications_for_user_with_conn(&conn, 1).unwrap(),
            3
        );
        assert_eq!(
            count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
            3
        );

        // User 1 cannot mark User 2's private notification read
        assert!(!mark_notification_read_for_user_with_conn(&conn, 1, 4).unwrap());
        assert!(!mark_notification_read_for_user_with_conn(&conn, 1, 999).unwrap());

        // User 1 marks Broadcast A (id=1) read: notifications.read MUST stay 0!
        assert!(mark_notification_read_for_user_with_conn(&conn, 1, 1).unwrap());
        let broadcast_global_read: bool = conn
            .query_row("SELECT read FROM notifications WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            !broadcast_global_read,
            "marking broadcast notification read for user 1 must NOT mutate notifications.read"
        );

        assert_eq!(
            count_unread_notifications_for_user_with_conn(&conn, 1).unwrap(),
            2
        );
        assert_eq!(
            count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
            3
        );

        let (u1_list, u1_unread) = list_notifications_for_user_with_conn(&conn, 1, 50, 0).unwrap();
        assert_eq!(u1_unread, 2);
        assert_eq!(u1_list.len(), 3);
        let u1_b1 = u1_list.iter().find(|n| n.id == 1).unwrap();
        assert!(u1_b1.read);

        let (u2_list, u2_unread) = list_notifications_for_user_with_conn(&conn, 2, 50, 0).unwrap();
        assert_eq!(u2_unread, 3);
        let u2_b1 = u2_list.iter().find(|n| n.id == 1).unwrap();
        assert!(!u2_b1.read, "Broadcast A must remain unread for user 2");

        // User 1 dismisses all remaining unread (Broadcast B id=2 + private id=3)
        let dismissed_u1 = dismiss_all_notifications_for_user_with_conn(&conn, 1).unwrap();
        assert_eq!(dismissed_u1, 2);
        assert_eq!(
            dismiss_all_notifications_for_user_with_conn(&conn, 1).unwrap(),
            0
        );
        assert_eq!(
            count_unread_notifications_for_user_with_conn(&conn, 1).unwrap(),
            0
        );

        // User 2 still has all 3 unread (both broadcasts + User 2 private)!
        assert_eq!(
            count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
            3
        );
        let dismissed_u2 = dismiss_all_notifications_for_user_with_conn(&conn, 2).unwrap();
        assert_eq!(dismissed_u2, 3);
        assert_eq!(
            count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
            0
        );
    }
}

#[cfg(test)]
mod pending_action_query_tests {
    use super::*;
    use crate::tests::TEST_DB_MUTEX;

    fn connection() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE pending_actions (
                id INTEGER PRIMARY KEY, classification TEXT, source TEXT, action TEXT,
                reason TEXT, status TEXT, created_at TEXT, resolved_at TEXT,
                resolved_by TEXT, execution_log TEXT
            );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn status_filter_precedes_pagination_and_counts_all_matching_rows() {
        let conn = connection();
        conn.execute(
            "INSERT INTO pending_actions (id, action, status, created_at) VALUES (1, 'older-pending', 'pending', '2020-01-01')",
            [],
        )
        .unwrap();
        for id in 2..=506 {
            conn.execute(
                "INSERT INTO pending_actions (id, action, status, created_at) VALUES (?1, 'newer-executed', 'executed', '2026-01-01')",
                params![id],
            )
            .unwrap();
        }
        let (pending, total) =
            query_pending_actions_with_connection(&conn, "pending", 50, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, 1);
        assert_eq!(pending[0].action, "older-pending");
        let (history, total) =
            query_pending_actions_with_connection(&conn, "approved_history", 50, 0).unwrap();
        assert_eq!(total, 505);
        assert_eq!(history.len(), 50);
        assert_eq!(history[0].id, 506);
        assert_eq!(history[49].id, 457);
        let (last_page, total) =
            query_pending_actions_with_connection(&conn, "approved_history", 50, 500).unwrap();
        assert_eq!(total, 505);
        assert_eq!(
            last_page.iter().map(|action| action.id).collect::<Vec<_>>(),
            vec![6, 5, 4, 3, 2]
        );
        for filter in ["all", ""] {
            let (actions, total) =
                query_pending_actions_with_connection(&conn, filter, 1000, -1).unwrap();
            assert_eq!(total, 506);
            assert_eq!(actions.len(), 500);
        }
        assert_eq!(
            query_pending_actions_with_connection(&conn, "executed", 0, 0)
                .unwrap()
                .0
                .len(),
            50
        );
        assert!(query_pending_actions_with_connection(&conn, "unknown", 50, 0).is_err());
    }

    #[test]
    fn null_status_is_pending_and_history_includes_only_approved_outcomes() {
        let conn = connection();
        for (id, status) in [
            None,
            Some("approved"),
            Some("rejected"),
            Some("executed"),
            Some("failed"),
        ]
        .into_iter()
        .enumerate()
        {
            conn.execute(
                "INSERT INTO pending_actions (id, status) VALUES (?1, ?2)",
                params![id as i64, status],
            )
            .unwrap();
        }
        let (pending, total) =
            query_pending_actions_with_connection(&conn, "pending", 50, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(pending[0].status, "pending");
        let (history, total) =
            query_pending_actions_with_connection(&conn, "approved_history", 50, 0).unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            history.iter().map(|action| action.id).collect::<Vec<_>>(),
            vec![4, 3, 1]
        );
        for filter in ["approved", "rejected", "executed", "failed"] {
            let (actions, total) =
                query_pending_actions_with_connection(&conn, filter, 1, 0).unwrap();
            assert_eq!(total, 1);
            assert_eq!(actions[0].status, filter);
        }
        let (actions, total) =
            query_pending_actions_with_connection(&conn, "pending", 50, 1).unwrap();
        assert_eq!(total, 1);
        assert!(actions.is_empty());
    }

    #[test]
    fn deferred_restart_receipt_schema_upgrade_preserves_rows_and_history_filters() {
        let conn = connection();
        conn.execute(
            "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at) \
             VALUES (1, 'warn', 'FlowAI', 'restart:sonarr', 'legacy row', 'executed', '2026-01-01')",
            [],
        )
        .unwrap();
        // Legacy table without job_unit still reads cleanly.
        let legacy = get_pending_action_by_id_with_connection(&conn, 1)
            .unwrap()
            .unwrap();
        assert_eq!(legacy.status, "executed");
        assert_eq!(legacy.job_unit, None);

        // Invariant upgrade adds job_unit without modifying existing rows.
        ensure_pending_actions_schema_invariants(&conn).unwrap();
        ensure_pending_actions_schema_invariants(&conn).unwrap();
        let preserved = get_pending_action_by_id_with_connection(&conn, 1)
            .unwrap()
            .unwrap();
        assert_eq!(preserved.action, "restart:sonarr");
        assert_eq!(preserved.status, "executed");
        assert_eq!(preserved.job_unit, None);

        for (id, status, unit) in [
            (2, "approved", None),
            (3, "queued", Some("aetherflow-self-update-restart-aetherflow-api-0123456789abcdef.service")),
            (4, "unavailable", Some("aetherflow-self-update-restart-aetherflow-runner-fedcba9876543210.service")),
            (5, "rejected", None),
            (6, "pending", None),
        ] {
            conn.execute(
                "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at, job_unit) \
                 VALUES (?1, 'critical', 'FlowAI', 'restart_service:aetherflow-api:systemd', 'test', ?2, '2026-01-02', ?3)",
                params![id, status, unit],
            )
            .unwrap();
        }

        let (history, total) =
            query_pending_actions_with_connection(&conn, "approved_history", 50, 0).unwrap();
        assert_eq!(total, 4);
        assert_eq!(
            history.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![4, 3, 2, 1]
        );

        let (queued, q_total) =
            query_pending_actions_with_connection(&conn, "queued", 50, 0).unwrap();
        assert_eq!(q_total, 1);
        assert_eq!(queued[0].id, 3);
        assert_eq!(
            queued[0].job_unit.as_deref(),
            Some("aetherflow-self-update-restart-aetherflow-api-0123456789abcdef.service")
        );

        let (unavail, u_total) =
            query_pending_actions_with_connection(&conn, "unavailable", 50, 0).unwrap();
        assert_eq!(u_total, 1);
        assert_eq!(unavail[0].id, 4);

        let tracked = list_queued_actions_with_receipts_with_connection(&conn, 50).unwrap();
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].id, 3);
    }

    #[test]
    fn deferred_restart_receipt_transitions_guard_against_mismatches_and_replays() {
        let conn = connection();
        ensure_pending_actions_schema_invariants(&conn).unwrap();
        conn.execute(
            "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at) \
             VALUES (10, 'critical', 'FlowAI', 'restart_service:aetherflow-api:systemd', 'recycle', 'approved', '2026-01-03')",
            [],
        )
        .unwrap();

        let unit = "aetherflow-self-update-restart-aetherflow-api-abcdef0123456789.service";
        let queued =
            mark_action_queued_with_connection(&conn, 10, unit, "queued for restart").unwrap();
        assert_eq!(queued.status, "queued");
        assert_eq!(queued.job_unit.as_deref(), Some(unit));

        // Second queue attempt on an already-queued row is rejected.
        assert!(mark_action_queued_with_connection(&conn, 10, unit, "duplicate").is_err());

        // Mismatched receipt cannot finalize the action.
        let wrong = finalize_queued_action_by_id_with_connection(
            &conn,
            10,
            "aetherflow-self-update-restart-aetherflow-api-ffffffffffffffff.service",
            "executed",
            "wrong receipt",
        )
        .unwrap()
        .unwrap();
        assert_eq!(wrong.status, "queued");

        // Matching receipt finalizes atomically by job_unit.
        let changed = finalize_queued_action_by_job_unit_with_connection(
            &conn,
            unit,
            "executed",
            "confirmed via durable receipt",
        )
        .unwrap();
        assert_eq!(changed, 1);
        let done = get_pending_action_by_id_with_connection(&conn, 10)
            .unwrap()
            .unwrap();
        assert_eq!(done.status, "executed");
        assert_eq!(done.job_unit.as_deref(), Some(unit));
        assert_eq!(
            done.execution_log.as_deref(),
            Some("confirmed via durable receipt")
        );

        // Terminal row cannot be overwritten back to failed or unavailable.
        let repeat = finalize_queued_action_by_job_unit_with_connection(
            &conn,
            unit,
            "failed",
            "stale failure",
        )
        .unwrap();
        assert_eq!(repeat, 0);
        assert_eq!(
            get_pending_action_by_id_with_connection(&conn, 10)
                .unwrap()
                .unwrap()
                .status,
            "executed"
        );
    }

    #[test]
    fn test_wal_readiness_check_succeeds_during_active_writer_lock() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let dir = env::temp_dir().join(format!("af-db-wal-ready-{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("aetherflow.sqlite");
        let prev_af = env::var("AF_DB_PATH").ok();
        let prev_db = env::var("DB_PATH").ok();
        let prev_af2 = env::var("AETHERFLOW_DB_PATH").ok();
        env::set_var("AF_DB_PATH", &db_file);
        env::set_var("DB_PATH", &db_file);
        env::set_var("AETHERFLOW_DB_PATH", &db_file);

        init_db().unwrap();
        let writer = get_conn().unwrap();
        writer.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('committed', 'hash', 'user')",
            [],
        ).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        writer
            .execute(
                "INSERT INTO users (username, password_hash, role) VALUES ('alice', 'hash', 'admin')",
                [],
            )
            .unwrap();

        let latency = db_readiness_check()
            .expect("read-only WAL readiness check must not stall on active writer lock");
        assert!(latency < 1000);
        let health =
            db_health_check().expect("read-only WAL health check must not stall on writer lock");
        assert_eq!(health["status"], "healthy");
        assert!(health["wal_pages"].as_u64().unwrap() > 0);

        writer.execute_batch("ROLLBACK").unwrap();
        drop(writer);
        match prev_af {
            Some(v) => env::set_var("AF_DB_PATH", v),
            None => env::remove_var("AF_DB_PATH"),
        }
        match prev_db {
            Some(v) => env::set_var("DB_PATH", v),
            None => env::remove_var("DB_PATH"),
        }
        match prev_af2 {
            Some(v) => env::set_var("AETHERFLOW_DB_PATH", v),
            None => env::remove_var("AETHERFLOW_DB_PATH"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_notification_channel_secret_encryption_migration_and_masking() {
        let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let dir = env::temp_dir().join(format!("af-db-notif-enc-{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("aetherflow.sqlite");
        let prev_af = env::var("AF_DB_PATH").ok();
        let prev_aes = env::var("AES_MASTER_KEY").ok();
        env::set_var("AF_DB_PATH", &db_file);
        env::set_var(
            "AES_MASTER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        init_aes_key().unwrap();
        init_db().unwrap();

        {
            let conn = get_conn().unwrap();
            conn.execute(
                "INSERT INTO notification_channels (name, type, config, enabled) VALUES (?1, ?2, ?3, 1)",
                params![
                    "tg",
                    "telegram",
                    r#"{"bot_token":"123456:ABC-DEF","chat_id":"-1001"}"#
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO notification_channels (name, type, config, enabled) VALUES (?1, ?2, ?3, 1)",
                params![
                    "hook",
                    "webhook",
                    r#"{"webhook_url":"https://hooks.example.com/sec","headers":{"Authorization":"Bearer tok123","Content-Type":"application/json"},"password":"smtp-secret"}"#
                ],
            )
            .unwrap();
        }

        migrate_legacy_secrets().unwrap();

        let conn = get_conn().unwrap();
        let (tg_type, tg_cfg): (String, String) = conn
            .query_row(
                "SELECT type, config FROM notification_channels WHERE name = 'tg'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(!tg_cfg.contains("123456:ABC-DEF"));
        assert!(tg_cfg.contains("enc:v1:"));
        let tg_masked = mask_notification_channel_config_str(&tg_type, &tg_cfg);
        assert_eq!(tg_masked["bot_token"], SECRET_MASK);
        assert_eq!(tg_masked["chat_id"], "-1001");
        let tg_dec = decrypt_notification_channel_config_str(&tg_type, &tg_cfg).unwrap();
        assert_eq!(tg_dec["bot_token"], "123456:ABC-DEF");

        let (hk_type, hk_cfg): (String, String) = conn
            .query_row(
                "SELECT type, config FROM notification_channels WHERE name = 'hook'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(!hk_cfg.contains("https://hooks.example.com/sec"));
        assert!(!hk_cfg.contains("Bearer tok123"));
        assert!(!hk_cfg.contains("smtp-secret"));
        let hk_masked = mask_notification_channel_config_str(&hk_type, &hk_cfg);
        assert_eq!(hk_masked["webhook_url"], SECRET_MASK);
        assert_eq!(hk_masked["password"], SECRET_MASK);
        assert_eq!(hk_masked["headers"]["Authorization"], SECRET_MASK);
        assert_eq!(hk_masked["headers"]["Content-Type"], "application/json");
        let hk_dec = decrypt_notification_channel_config_str(&hk_type, &hk_cfg).unwrap();
        assert_eq!(hk_dec["webhook_url"], "https://hooks.example.com/sec");
        assert_eq!(hk_dec["headers"]["Authorization"], "Bearer tok123");
        assert_eq!(hk_dec["password"], "smtp-secret");

        drop(conn);
        match prev_af {
            Some(v) => env::set_var("AF_DB_PATH", v),
            None => env::remove_var("AF_DB_PATH"),
        }
        match prev_aes {
            Some(v) => env::set_var("AES_MASTER_KEY", v),
            None => {
                env::remove_var("AES_MASTER_KEY");
                let _ = init_aes_key();
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
