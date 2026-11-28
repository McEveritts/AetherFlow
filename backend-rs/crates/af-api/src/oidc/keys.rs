use crate::auth::blocking_response;
use af_models::secret_zeroize::SecretBytes;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use once_cell::sync::Lazy;
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{PrivateKey, PublicKey};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path as StdPath, PathBuf};

struct OsCryptoRng;

impl rsa::rand_core::TryRng for OsCryptoRng {
    type Error = std::io::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand::rngs::OsRng
            .try_fill_bytes(dst)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

impl rsa::rand_core::TryCryptoRng for OsCryptoRng {}

// ─────────────────────────────────────────────────────────────────────────────
// OIDC RSA-2048 Key Management
// ─────────────────────────────────────────────────────────────────────────────

pub struct OidcKeyMaterial {
    pub kid: String,
    pub n_b64: String,
    pub e_b64: String,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}

pub(super) static OIDC_KEYS: Lazy<Option<OidcKeyMaterial>> = Lazy::new(load_or_generate_oidc_key);

pub(super) fn oidc_server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": "server_error" })),
    )
        .into_response()
}

pub(super) fn oidc_key_path(override_path: Option<&str>, state_directory: Option<&str>) -> PathBuf {
    if let Some(path) = override_path.map(str::trim).filter(|s| !s.is_empty()) {
        return PathBuf::from(path);
    }
    let state = state_directory
        .and_then(|s| s.split(':').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/var/lib/aetherflow");
    PathBuf::from(state).join("oidc_rsa.pem")
}

fn resolve_oidc_key_path() -> PathBuf {
    oidc_key_path(
        env::var("OIDC_KEY_PATH").ok().as_deref(),
        env::var("STATE_DIRECTORY").ok().as_deref(),
    )
}

fn compute_key_id(pub_key: &PublicKey) -> String {
    if let Ok(der) = pub_key.to_pkcs1_der() {
        let mut hasher = Sha256::new();
        hasher.update(der.as_bytes());
        let digest = hasher.finalize();
        return hex::encode(&digest[..8]);
    }
    "aetherflow-oidc-1".to_string()
}

fn build_material_from_private_key(
    priv_key: &PrivateKey,
    pem_str: &str,
) -> Option<OidcKeyMaterial> {
    let pub_key = PublicKey::from(priv_key);
    let kid = compute_key_id(&pub_key);
    let n_b64 = URL_SAFE_NO_PAD.encode(pub_key.n().as_ref().to_be_bytes_trimmed_vartime());
    let e_b64 = URL_SAFE_NO_PAD.encode(pub_key.e().to_be_bytes_trimmed_vartime());
    let encoding_key = EncodingKey::from_rsa_pem(pem_str.as_bytes()).ok()?;
    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).ok()?;
    Some(OidcKeyMaterial {
        kid,
        n_b64,
        e_b64,
        encoding_key,
        decoding_key,
    })
}

fn load_or_generate_oidc_key() -> Option<OidcKeyMaterial> {
    let path = resolve_oidc_key_path();
    match load_or_generate_oidc_key_at(&path) {
        Ok(material) => Some(material),
        Err(err) => {
            tracing::error!(path = %path.display(), error = %err, "OIDC signing disabled: cannot load persistent key");
            None
        }
    }
}

pub(super) fn read_oidc_key(path: &StdPath) -> anyhow::Result<OidcKeyMaterial> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "OIDC key must be a regular file"
        );
        anyhow::ensure!(
            file.metadata()?.permissions().mode() & 0o077 == 0,
            "OIDC key permissions must be 0600 or stricter"
        );
        read_oidc_material(file)
    }
    #[cfg(not(unix))]
    read_oidc_material(options.open(path)?)
}

/// Upper bound for an on-disk OIDC RSA PEM (a 2048-bit PKCS#1 PEM is ~1.7 KiB).
const MAX_OIDC_PEM_BYTES: u64 = 64 * 1024;

fn read_oidc_material(file: fs::File) -> anyhow::Result<OidcKeyMaterial> {
    let pem = read_oidc_pem(file)?;
    let pem_str = std::str::from_utf8(pem.expose_secret())
        .map_err(|_| anyhow::anyhow!("OIDC key must be UTF-8 PEM"))?;
    let private_key = PrivateKey::from_pkcs1_pem(pem_str)?;
    build_material_from_private_key(&private_key, pem_str)
        .ok_or_else(|| anyhow::anyhow!("Invalid OIDC signing key"))
}

/// Reads the private-key PEM into a zeroize-on-drop buffer (`SEC-05`).
///
/// The buffer is pre-sized from file metadata so reading does not reallocate (which would leave
/// an unzeroized copy behind), and it is wrapped before any error is propagated so partial reads
/// are wiped too.
fn read_oidc_pem(mut file: fs::File) -> anyhow::Result<SecretBytes> {
    let declared = file.metadata()?.len();
    anyhow::ensure!(
        declared <= MAX_OIDC_PEM_BYTES,
        "OIDC key file exceeds {MAX_OIDC_PEM_BYTES} bytes"
    );
    let mut raw = Vec::with_capacity(declared as usize + 1);
    let read_res = (&mut file)
        .take(MAX_OIDC_PEM_BYTES + 1)
        .read_to_end(&mut raw);
    let pem = SecretBytes::new(raw);
    read_res?;
    anyhow::ensure!(
        pem.len() as u64 <= MAX_OIDC_PEM_BYTES,
        "OIDC key file exceeds {MAX_OIDC_PEM_BYTES} bytes"
    );
    Ok(pem)
}

pub(super) fn load_or_generate_oidc_key_at(path: &StdPath) -> anyhow::Result<OidcKeyMaterial> {
    match read_oidc_key(path) {
        Ok(material) => return Ok(material),
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
        Err(err) => return Err(err),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| StdPath::new("."));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        if let Ok(meta) = fs::symlink_metadata(parent) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                anyhow::bail!(
                    "OIDC key parent directory {} is a symlink or non-directory",
                    parent.display()
                );
            }
        } else {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(parent)?;
    }
    let private_key = PrivateKey::new(&mut OsCryptoRng, 2048)?;
    let pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    // Write and fsync a private file, then publish it without replacing another process's key.
    let temporary = parent.join(format!(".oidc-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> anyhow::Result<OidcKeyMaterial> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(pem.as_bytes())?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                fs::File::open(parent)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        read_oidc_key(path)
    })();
    let _ = fs::remove_file(&temporary);
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Host Authority, Issuer Resolution, Discovery & JWKS
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn is_valid_host_authority(raw_host: &str) -> bool {
    let trimmed = raw_host.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('@')
    {
        return false;
    }
    if trimmed.starts_with('[') {
        let Some((ipv6, rest)) = trimmed.strip_prefix('[').and_then(|s| s.split_once(']')) else {
            return false;
        };
        if ipv6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        return rest.is_empty()
            || rest
                .strip_prefix(':')
                .is_some_and(|p| p.parse::<u16>().is_ok());
    }
    let (host, port) = trimmed
        .split_once(':')
        .map_or((trimmed, None), |(h, p)| (h, Some(p)));
    if let Some(p) = port {
        if p.parse::<u16>().is_err() {
            return false;
        }
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

pub(crate) fn is_loopback_authority(authority: &str) -> bool {
    let trimmed = authority.trim();
    if trimmed.is_empty() {
        return false;
    }
    let host_only = if let Some(rest) = trimmed.strip_prefix('[') {
        let Some((v6, after)) = rest.split_once(']') else {
            return false;
        };
        if !after.is_empty()
            && !after
                .strip_prefix(':')
                .is_some_and(|p| p.parse::<u16>().is_ok())
        {
            return false;
        }
        v6
    } else if let Some((h, port)) = trimmed.rsplit_once(':') {
        if trimmed.matches(':').count() == 1 && port.parse::<u16>().is_ok() {
            h
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    host_only.eq_ignore_ascii_case("localhost") || host_only == "127.0.0.1" || host_only == "::1"
}

fn configured_allowed_hosts() -> Vec<String> {
    env::var("ALLOWED_HOSTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn is_allowed_request_host(host: &str) -> bool {
    is_valid_host_authority(host) && crate::middlewares::is_trusted_request_host(host)
}

pub fn get_base_url_for_peer(headers: &HeaderMap, peer_ip: Option<std::net::IpAddr>) -> String {
    if let Ok(public_url) = env::var("PUBLIC_URL") {
        let trimmed = public_url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let trust_forwarded = match peer_ip {
        Some(ip) => crate::ws::is_trusted_proxy_peer(ip),
        None => env::var("TRUST_PROXY_HEADERS")
            .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
            .unwrap_or(false),
    };

    let forwarded_host = if trust_forwarded {
        headers
            .get("X-Forwarded-Host")
            .and_then(|v| v.to_str().ok())
            .and_then(|raw| raw.split(',').next())
            .map(str::trim)
            .filter(|h| is_allowed_request_host(h))
    } else {
        None
    };

    let host = forwarded_host
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|h| is_allowed_request_host(h))
        })
        .unwrap_or("localhost:8080");

    let has_forwarded_host = headers.contains_key("X-Forwarded-Host");
    let proto = if trust_forwarded && (forwarded_host.is_some() || !has_forwarded_host) {
        headers
            .get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|raw| raw.split(',').next())
            .map(str::trim)
            .and_then(|first| {
                if first.eq_ignore_ascii_case("http") {
                    Some("http")
                } else if first.eq_ignore_ascii_case("https") {
                    Some("https")
                } else {
                    None
                }
            })
            .unwrap_or("https")
    } else {
        "https"
    };

    format!("{}://{}", proto, host)
}

pub fn get_base_url(headers: &HeaderMap) -> String {
    get_base_url_for_peer(headers, None)
}

pub fn get_oidc_issuer_for_peer(headers: &HeaderMap, peer_ip: Option<std::net::IpAddr>) -> String {
    if let Ok(issuer) = env::var("OIDC_ISSUER") {
        if !issuer.trim().is_empty() {
            return issuer.trim().trim_end_matches('/').to_string();
        }
    }
    get_base_url_for_peer(headers, peer_ip)
}

pub(super) fn is_accepted_oidc_issuer(
    token_iss: &str,
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
) -> bool {
    let normalized = token_iss.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return false;
    }
    if let Ok(cfg_iss) = env::var("OIDC_ISSUER") {
        let cfg_trimmed = cfg_iss.trim().trim_end_matches('/');
        if !cfg_trimmed.is_empty() {
            return af_models::constant_time_eq(normalized.as_bytes(), cfg_trimmed.as_bytes());
        }
    }
    if normalized == get_oidc_issuer_for_peer(headers, peer_ip) {
        return true;
    }
    if let Ok(pub_url) = env::var("PUBLIC_URL") {
        let pub_trimmed = pub_url.trim().trim_end_matches('/');
        if !pub_trimmed.is_empty() && normalized == pub_trimmed {
            return true;
        }
    }
    let Ok(parsed) = url::Url::parse(normalized) else {
        return false;
    };
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return false;
    }
    let Some(host_str) = parsed.host_str() else {
        return false;
    };
    let authority = match parsed.port() {
        Some(p) => format!("{}:{}", host_str, p),
        None => host_str.to_string(),
    };
    match parsed.scheme() {
        "https" => is_allowed_request_host(&authority),
        "http" => {
            is_loopback_authority(&authority)
                && (configured_allowed_hosts().is_empty() || is_allowed_request_host(&authority))
        }
        _ => false,
    }
}

pub async fn oidc_discovery(
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    headers: HeaderMap,
) -> Response {
    let issuer = get_oidc_issuer_for_peer(&headers, peer_ip);
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/api/v1/public/oidc/authorize", issuer),
        "device_authorization_endpoint": format!("{}/api/v1/public/oidc/device/authorize", issuer),
        "token_endpoint": format!("{}/api/v1/public/oidc/token", issuer),
        "userinfo_endpoint": format!("{}/api/v1/public/oidc/userinfo", issuer),
        "jwks_uri": format!("{}/api/v1/public/oidc/jwks", issuer),
        "revocation_endpoint": format!("{}/api/v1/public/oidc/revoke", issuer),
        "introspection_endpoint": format!("{}/api/v1/public/oidc/introspect", issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email", "picture", "role"],
        "code_challenge_methods_supported": ["S256"]
    }))
    .into_response()
}

pub async fn oidc_jwks() -> Response {
    blocking_response(oidc_jwks_blocking).await
}

fn oidc_jwks_blocking() -> Response {
    let Some(keys) = OIDC_KEYS.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "OIDC keys not initialized" })),
        )
            .into_response();
    };

    Json(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": keys.kid,
            "alg": "RS256",
            "n": keys.n_b64,
            "e": keys.e_b64,
        }]
    }))
    .into_response()
}

#[cfg(test)]
mod pem_zeroize_tests {
    use super::*;

    fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
        let dir = env::temp_dir().join(format!("af-oidc-pem-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn sec05_oidc_pem_is_read_into_redacted_secret_bytes() {
        let body = concat!(
            "-----BEGIN ",
            "RSA PRIVATE KEY-----\nMIIEtestfixture\n-----END ",
            "RSA PRIVATE KEY-----\n"
        )
        .as_bytes();
        let path = temp_file("k.pem", body);
        let pem = read_oidc_pem(fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(pem.expose_secret(), body);
        assert_eq!(format!("{pem:?}"), "[REDACTED]");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn sec05_oidc_pem_rejects_oversized_files() {
        let path = temp_file("big.pem", &vec![b'A'; (MAX_OIDC_PEM_BYTES + 1) as usize]);
        let err = read_oidc_pem(fs::File::open(&path).unwrap()).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
