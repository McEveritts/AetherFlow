use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use std::env;
use std::fs;
use std::path::Path;
use std::sync::RwLock;

use crate::pool::get_conn;
use af_models::secret_zeroize::{SecretBytes, SecretString};

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM Secret Encryption
// ─────────────────────────────────────────────────────────────────────────────

const CIPHERTEXT_PREFIX: &str = "enc:v1:";

const AES_KEY_BYTES: usize = 32;

/// Process-wide AES-256-GCM master key. Held in a zeroize-on-drop [`SecretBytes`] (`SEC-05`) so
/// replacing or clearing the key wipes the previous key's full `0..capacity` allocation.
pub(crate) static AES_MASTER_KEY: Lazy<RwLock<Option<SecretBytes>>> =
    Lazy::new(|| RwLock::new(None));

/// Parses `AES_MASTER_KEY` (64-char hex, base64, or 32-byte raw) directly into a zeroizing
/// buffer. Intermediate decode buffers are wrapped too, so no plaintext key copy outlives the call.
pub(crate) fn parse_aes_key_secret(raw: &str) -> anyhow::Result<SecretBytes> {
    let trimmed = raw.trim();
    if trimmed.len() == AES_KEY_BYTES * 2 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut key = Vec::with_capacity(AES_KEY_BYTES);
        for idx in 0..AES_KEY_BYTES {
            let hex_pair = &trimmed[idx * 2..idx * 2 + 2];
            match u8::from_str_radix(hex_pair, 16) {
                Ok(byte) => key.push(byte),
                Err(err) => {
                    drop(SecretBytes::new(key));
                    return Err(err.into());
                }
            }
        }
        return Ok(SecretBytes::new(key));
    }
    if let Ok(decoded) = BASE64_STD.decode(trimmed) {
        let decoded = SecretBytes::new(decoded);
        if decoded.len() == AES_KEY_BYTES {
            return Ok(decoded);
        }
    }
    if trimmed.len() == AES_KEY_BYTES {
        return Ok(SecretBytes::from(trimmed.as_bytes()));
    }
    if raw.len() == AES_KEY_BYTES {
        return Ok(SecretBytes::from(raw.as_bytes()));
    }
    anyhow::bail!(
        "FATAL: AES_MASTER_KEY must decode to 32 bytes (32-byte raw, base64, or 64-char hex). Got {} chars.",
        trimmed.len()
    )
}

/// Backwards-compatible fixed-array parser. Prefer [`parse_aes_key_secret`] internally: the
/// returned array is a plain copy that the caller is responsible for wiping.
pub fn parse_aes_key_bytes(raw: &str) -> anyhow::Result<[u8; 32]> {
    let key = parse_aes_key_secret(raw)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(key.expose_secret());
    Ok(arr)
}

pub(crate) fn aes_key_candidate_env_files() -> Vec<std::path::PathBuf> {
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

/// Resolves the active AES-256-GCM key into a zeroize-on-drop buffer (`SEC-05`).
pub fn resolve_runtime_aes_key() -> Option<SecretBytes> {
    {
        let guard = AES_MASTER_KEY.read().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = guard.as_ref() {
            return Some(key.clone());
        }
    }
    if let Ok(raw) = env::var("AES_MASTER_KEY") {
        let raw = SecretString::new(raw);
        let trimmed = raw.expose_secret().trim();
        if !trimmed.is_empty() {
            if let Ok(key) = parse_aes_key_secret(trimmed) {
                return Some(key);
            }
        }
    }
    for env_file in aes_key_candidate_env_files() {
        if let Some(clean) = read_last_aes_key_from_env_file(&env_file) {
            if let Ok(key) = parse_aes_key_secret(clean.expose_secret()) {
                return Some(key);
            }
        }
    }
    None
}

fn read_last_aes_key_from_env_file(path: &Path) -> Option<SecretString> {
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
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = opts.open(path).ok()?;
    let fmeta = file.metadata().ok()?;
    if !fmeta.is_file() || fmeta.len() > 65_536 {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if lmeta.dev() != fmeta.dev() || lmeta.ino() != fmeta.ino() {
            return None;
        }
    }
    // The env file holds the master key: keep the whole buffer zeroize-on-drop.
    let mut buf = String::with_capacity(usize::try_from(fmeta.len()).unwrap_or(0) + 1);
    let read_res =
        std::io::Read::read_to_string(&mut std::io::Read::take(&mut file, 65_537), &mut buf);
    let too_large = buf.len() > 65_536;
    let contents = SecretString::new(buf);
    if read_res.is_err() || too_large {
        return None;
    }
    let contents = contents.expose_secret();
    let mut last_raw: Option<SecretString> = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some(val) = stripped.strip_prefix("AES_MASTER_KEY=") {
            let clean = val.trim().trim_matches('"').trim_matches('\'');
            if !clean.is_empty() {
                last_raw = Some(SecretString::from(clean));
            }
        }
    }
    last_raw
}

pub(crate) fn encrypt_with_key(plaintext: &str, key: &[u8]) -> anyhow::Result<String> {
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

fn decrypt_with_key(payload: &str, key: &[u8]) -> anyhow::Result<String> {
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
    String::from_utf8(plaintext).map_err(|e| {
        // Wipe the rejected plaintext rather than dropping it unzeroized.
        drop(SecretBytes::new(e.into_bytes()));
        anyhow::anyhow!("invalid utf8 in decrypted secret")
    })
}

pub fn encrypt_secret_if_configured(plaintext: &str) -> anyhow::Result<String> {
    match resolve_runtime_aes_key() {
        Some(key) => encrypt_with_key(plaintext, key.expose_secret()),
        None => Ok(plaintext.to_string()),
    }
}

pub fn decrypt_secret_if_needed(value: &str) -> anyhow::Result<String> {
    if let Some(payload) = value.strip_prefix(CIPHERTEXT_PREFIX) {
        let key = resolve_runtime_aes_key().ok_or_else(|| {
            anyhow::anyhow!("AES_MASTER_KEY is required to decrypt enc:v1: secret")
        })?;
        return decrypt_with_key(payload, key.expose_secret());
    }
    Ok(value.to_string())
}

/// Initializes the AES-256-GCM master key from `AES_MASTER_KEY` (or `AETHERFLOW_ENV_FILE`).
pub fn init_aes_key() -> anyhow::Result<()> {
    let env_raw = SecretString::new(env::var("AES_MASTER_KEY").unwrap_or_default());
    let mut raw = SecretString::from(env_raw.expose_secret().trim());
    drop(env_raw);
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

    let key_bytes = parse_aes_key_secret(raw.expose_secret())?;
    drop(raw);

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
    // Borrow the key under the read guard instead of copying it onto the stack.
    let guard = AES_MASTER_KEY.read().unwrap_or_else(|e| e.into_inner());
    let Some(key) = guard.as_ref() else {
        return Ok(plaintext.to_string());
    };
    encrypt_with_key(plaintext, key.expose_secret())
}

/// Decrypts a versioned `"enc:v1:<base64>"` string produced by Go or Rust.
pub fn decrypt_key(encoded: &str) -> anyhow::Result<String> {
    let guard = AES_MASTER_KEY.read().unwrap_or_else(|e| e.into_inner());
    let Some(key) = guard.as_ref() else {
        anyhow::ensure!(
            !encoded.starts_with(CIPHERTEXT_PREFIX),
            "AES_MASTER_KEY is required to decrypt enc:v1: secret"
        );
        return Ok(encoded.to_string());
    };

    if let Some(payload) = encoded.strip_prefix(CIPHERTEXT_PREFIX) {
        return decrypt_with_key(payload, key.expose_secret());
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

#[cfg(test)]
mod secret_key_zeroize_tests {
    use super::*;

    #[test]
    fn sec05_parse_aes_key_secret_matches_legacy_parser_and_is_redacted() {
        let hex_key = "0123456789abcdef".repeat(4);
        let b64_key = BASE64_STD.encode([7u8; 32]);
        let raw_key = "0123456789abcdef0123456789abcdef";
        for candidate in [hex_key.as_str(), b64_key.as_str(), raw_key] {
            let secret = parse_aes_key_secret(candidate).unwrap();
            assert_eq!(secret.len(), 32);
            assert_eq!(
                secret.expose_secret(),
                &parse_aes_key_bytes(candidate).unwrap()[..]
            );
            assert_eq!(format!("{secret:?}"), "[REDACTED]");
        }
        let err = parse_aes_key_secret("too-short-key")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("too-short-key"), "{err}");
    }

    #[test]
    fn sec05_encrypt_decrypt_roundtrip_with_borrowed_secret_key() {
        let key = parse_aes_key_secret(&"ab".repeat(32)).unwrap();
        let sealed = encrypt_with_key("api-key-plaintext", key.expose_secret()).unwrap();
        assert!(sealed.starts_with(CIPHERTEXT_PREFIX));
        let payload = sealed.strip_prefix(CIPHERTEXT_PREFIX).unwrap();
        assert_eq!(
            decrypt_with_key(payload, key.expose_secret()).unwrap(),
            "api-key-plaintext"
        );
        let wrong = parse_aes_key_secret(&"cd".repeat(32)).unwrap();
        assert!(decrypt_with_key(payload, wrong.expose_secret()).is_err());
    }

    #[test]
    fn sec05_env_file_key_is_returned_in_redacted_secret_string() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("af-db-aes-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aetherflow.env");
        let key = "fedcba9876543210".repeat(4);
        fs::write(
            &path,
            format!("# comment\nAES_MASTER_KEY=old\nexport AES_MASTER_KEY=\"{key}\"\n"),
        )
        .unwrap();
        let found = read_last_aes_key_from_env_file(&path).expect("key line");
        assert_eq!(found.expose_secret(), key);
        assert!(!format!("{found:?}").contains("fedcba"));
        let _ = fs::remove_dir_all(&dir);
    }
}
