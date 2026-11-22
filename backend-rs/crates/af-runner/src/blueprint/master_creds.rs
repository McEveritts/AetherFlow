use super::fs_mutators::read_metadata_config;
use crate::resolve_runner_fs_path as resolve_config_path;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{env, path::PathBuf};

pub const MASTER_CREDS_SYSTEM_KEY: &str = "master_credentials";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MasterCreds {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ha1: String,
}

pub fn master_ha1(username: &str, password: &str) -> Result<String, String> {
    let digest = af_models::md5::md5_digest(
        format!("{username}:Welcome to AetherFlow:{password}").as_bytes(),
    );
    Ok(hex::encode(digest))
}

fn pbkdf2_hmac_sha512_block1(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    // HMAC-SHA512 block size is 128 bytes
    let mut key_block = [0u8; 128];
    if password.len() > 128 {
        let hashed = Sha512::digest(password);
        key_block[..64].copy_from_slice(&hashed);
    } else {
        key_block[..password.len()].copy_from_slice(password);
    }

    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_base = Sha512::new();
    inner_base.update(ipad);
    let mut outer_base = Sha512::new();
    outer_base.update(opad);

    // U_1 = HMAC-SHA512(password, salt || INT_32_BE(1))
    let mut inner = inner_base.clone();
    inner.update(salt);
    inner.update(1u32.to_be_bytes());
    let inner_hash = inner.finalize();

    let mut outer = outer_base.clone();
    outer.update(inner_hash);
    let mut u: [u8; 64] = outer.finalize().into();
    let mut dk = u;

    for _ in 1..iterations {
        let mut i_ctx = inner_base.clone();
        i_ctx.update(u);
        let i_out = i_ctx.finalize();

        let mut o_ctx = outer_base.clone();
        o_ctx.update(i_out);
        u = o_ctx.finalize().into();

        for (d_byte, u_byte) in dk.iter_mut().zip(u.iter()) {
            *d_byte ^= *u_byte;
        }
    }

    dk
}

/// Generates qBittorrent's `WebUI\Password_PBKDF2` format:
/// `"@ByteArray(<base64-16B-salt>:<base64-64B-PBKDF2-HMAC-SHA512-100000>)"`
pub fn generate_qbittorrent_pbkdf2(password: &str) -> String {
    let entropy = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
    let salt = &Sha256::digest(
        [
            entropy[0].as_bytes().as_slice(),
            entropy[1].as_bytes().as_slice(),
        ]
        .concat(),
    )[..16];
    let dk = pbkdf2_hmac_sha512_block1(password.as_bytes(), salt, 100_000);
    let salt_b64 = BASE64_STD.encode(salt);
    let dk_b64 = BASE64_STD.encode(dk);
    format!("\"@ByteArray({}:{})\"", salt_b64, dk_b64)
}

fn default_master_cred_paths() -> Vec<PathBuf> {
    vec![resolve_config_path("/var/lib/aetherflow/.master.creds")]
}

pub fn master_cred_paths() -> Vec<PathBuf> {
    if let Ok(custom) = env::var("AETHERFLOW_MASTER_CREDS_FILE") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return vec![PathBuf::from(trimmed)];
        }
    }
    default_master_cred_paths()
}

fn decode_stored_master_creds(creds: MasterCreds) -> Option<(String, String, String)> {
    let user = creds.username.trim().to_string();
    if user.is_empty() || creds.password.trim().is_empty() {
        return None;
    }
    let password = af_db::decrypt_secret_if_needed(creds.password.trim()).ok()?;
    if password.is_empty() || password == "adminadmin" {
        return None;
    }
    let ha1 = match load_install_master_conf() {
        Some((loaded_user, loaded_password, loaded_ha1))
            if loaded_user == user && loaded_password == password =>
        {
            loaded_ha1
        }
        _ => master_ha1(&user, &password).ok()?,
    };
    Some((user, password, ha1))
}

fn hmac_sha256_bytes(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut block_key = [0u8; 64];
    if key.len() > 64 {
        let hashed = Sha256::digest(key);
        block_key[..32].copy_from_slice(&hashed);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_digest);
    out
}

/// Derives a domain-separated, irreversible 32-hex-character WebUI password for
/// applications that store cleartext passwords in their local INI/TOML configs
/// (such as SABnzbd), preventing recovery of the shared provisioning secret.
pub fn derive_app_webui_password(app_id: &str, master_pass: &str) -> String {
    let msg = format!("aetherflow:{}:webui:v1", app_id.trim().to_ascii_lowercase());
    let digest = hmac_sha256_bytes(master_pass.as_bytes(), msg.as_bytes());
    hex::encode(&digest[..16])
}

/// Loads `(username, password, ha1)` from the master credentials file, the installer
/// conf, or a previously encrypted `system_config` row.
pub fn load_master_credentials() -> (String, String, String) {
    load_master_credentials_with(|| {
        let conn = af_db::get_conn().ok()?;
        database_master_credentials(&conn)
    })
}

pub(super) fn load_master_credentials_with(
    load_database: impl FnOnce() -> Option<(String, String, String)>,
) -> (String, String, String) {
    let mut read_paths = master_cred_paths();
    if env::var("AETHERFLOW_MASTER_CREDS_FILE")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        read_paths.push(resolve_config_path(
            "/opt/AetherFlow/backend/data/.master.creds",
        ));
    }
    for path in read_paths {
        if let Ok(data) = crate::read_confined_text(&path, &["aetherflow"]) {
            if let Ok(creds) = serde_json::from_str::<MasterCreds>(&data) {
                if let Some(decoded) = decode_stored_master_creds(creds) {
                    return decoded;
                }
            }
        }
    }
    if let Some(from_conf) = load_install_master_conf() {
        return from_conf;
    }
    load_database().unwrap_or_default()
}

pub(super) fn database_master_credentials(conn: &Connection) -> Option<(String, String, String)> {
    let raw: String = conn
        .query_row(
            "SELECT value FROM system_config WHERE key = ?1",
            params![MASTER_CREDS_SYSTEM_KEY],
            |row| row.get(0),
        )
        .ok()?;
    let decrypted = af_db::decrypt_secret_if_needed(&raw)
        .or_else(|_| af_db::decrypt_key(&raw))
        .ok()?;
    decode_stored_master_creds(serde_json::from_str::<MasterCreds>(&decrypted).ok()?)
}

fn load_install_master_conf() -> Option<(String, String, String)> {
    let text = read_metadata_config(resolve_config_path("/install/.aetherflow.conf")).ok()?;
    let mut username = String::new();
    let mut password = String::new();
    let mut ha1 = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let val = value
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .to_string();
        match key.trim() {
            "username" => username = val,
            "passwd" => password = val,
            "ha1pass" => ha1 = val,
            _ => {}
        }
    }
    if username.is_empty() || password.is_empty() {
        return None;
    }
    if ha1.len() != 32 || !ha1.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        ha1 = master_ha1(&username, &password).ok()?;
    }
    Some((username, password, ha1))
}
