use super::manifest::{discover_plugins, is_valid_plugin_id};
use super::registry::try_read_registry_state;
use super::types::{
    PluginTokenClaims, ValidatedPluginManifest, ACTIVE_PLUGIN_JTIS, ACTIVE_PROCESSES,
};
use super::{
    DEFAULT_PLUGIN_TOKEN_TTL_SECS, MAX_PLUGIN_TOKEN_TTL_SECS, PLUGIN_TOKEN_AUDIENCE,
    PLUGIN_TOKEN_ISSUER, PLUGIN_TOKEN_TYP,
};
use crate::auth::jwt_secret_bytes;
use chrono::Utc;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use sha2::Sha256;
use std::time::Duration;
use uuid::Uuid;

fn plugin_signing_key() -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&jwt_secret_bytes())
        .expect("HMAC accepts arbitrary key length");
    mac.update(b"aetherflow-plugin-token-v1");
    mac.finalize().into_bytes().to_vec()
}

pub fn mint_scoped_plugin_token(
    manifest: &ValidatedPluginManifest,
    requested_ttl_secs: Option<i64>,
) -> Result<(String, PluginTokenClaims), String> {
    let reg = try_read_registry_state(&manifest.id)?;
    if !reg.enabled && reg.status != "running" {
        return Err(format!(
            "Plugin '{}' must be enabled before minting a scoped runtime token",
            manifest.id
        ));
    }

    let (token, claims) = sign_plugin_token(manifest, reg.token_epoch, requested_ttl_secs, None)?;
    if let Ok(mut map) = ACTIVE_PLUGIN_JTIS.lock() {
        let jtis = map.entry(manifest.id.clone()).or_default();
        jtis.retain(|_, expiry| *expiry >= claims.iat);
        jtis.insert(claims.jti.clone(), claims.exp);
    }
    Ok((token, claims))
}

pub(super) fn sign_plugin_token(
    manifest: &ValidatedPluginManifest,
    epoch: i64,
    requested_ttl_secs: Option<i64>,
    runtime_id: Option<Uuid>,
) -> Result<(String, PluginTokenClaims), String> {
    let now = Utc::now().timestamp();
    let ttl = requested_ttl_secs
        .unwrap_or(DEFAULT_PLUGIN_TOKEN_TTL_SECS)
        .clamp(30, MAX_PLUGIN_TOKEN_TTL_SECS);
    let exp = now + ttl;
    let jti = match runtime_id {
        Some(id) => format!("plg-runtime:{id}:{}", Uuid::new_v4()),
        None => format!("plg-{}-{}", manifest.id, Uuid::new_v4()),
    };

    let claims = PluginTokenClaims {
        typ: PLUGIN_TOKEN_TYP.to_string(),
        iss: PLUGIN_TOKEN_ISSUER.to_string(),
        aud: PLUGIN_TOKEN_AUDIENCE.to_string(),
        sub: format!("plugin:{}", manifest.id),
        plugin_id: manifest.id.clone(),
        jti,
        iat: now,
        exp,
        epoch,
        scopes: manifest.granted_scopes.clone(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&plugin_signing_key()),
    )
    .map_err(|e| format!("Failed to encode plugin token: {}", e))?;

    Ok((token, claims))
}

pub fn decode_and_verify_plugin_token(token: &str) -> Result<PluginTokenClaims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[PLUGIN_TOKEN_AUDIENCE]);
    validation.leeway = 0;

    let data = decode::<PluginTokenClaims>(
        token,
        &DecodingKey::from_secret(&plugin_signing_key()),
        &validation,
    )
    .map_err(|e| format!("Invalid plugin token signature or expiry: {}", e))?;

    let mut claims = data.claims;
    if claims.typ != PLUGIN_TOKEN_TYP
        || claims.iss != PLUGIN_TOKEN_ISSUER
        || claims.aud != PLUGIN_TOKEN_AUDIENCE
    {
        return Err("Token is not a valid AetherFlow plugin token".to_string());
    }
    if !is_valid_plugin_id(&claims.plugin_id) {
        return Err("Invalid plugin_id in token".to_string());
    }
    if let Some(runtime_jti) = claims.jti.strip_prefix("plg-runtime:") {
        let run = runtime_jti
            .split_once(':')
            .and_then(|(id, _)| Uuid::parse_str(id).ok());
        let active = ACTIVE_PROCESSES
            .lock()
            .ok()
            .and_then(|processes| processes.get(&claims.plugin_id).map(|p| p.runtime_id));
        if run.is_none() || run != active {
            return Err("Managed plugin process is no longer active".to_string());
        }
    }
    if af_db::is_token_revoked(&claims.jti) {
        return Err("Plugin token has been revoked".to_string());
    }

    let reg = try_read_registry_state(&claims.plugin_id)?;
    if !reg.enabled || reg.status == "stopped" || reg.token_epoch != claims.epoch {
        return Err(
            "Plugin token is no longer active for the current plugin lifecycle epoch".to_string(),
        );
    }

    let (manifests, _) = discover_plugins();
    let live_manifest = manifests
        .into_iter()
        .find(|m| m.id == claims.plugin_id)
        .ok_or_else(|| "Plugin manifest is unavailable".to_string())?;
    claims
        .scopes
        .retain(|scope| live_manifest.granted_scopes.contains(scope));

    Ok(claims)
}

pub fn revoke_all_tokens_for_plugin(plugin_id: &str) {
    let jtis = ACTIVE_PLUGIN_JTIS
        .lock()
        .ok()
        .and_then(|mut map| map.remove(plugin_id));
    for (jti, _) in jtis.into_iter().flatten() {
        let _ = af_db::revoke_token(
            &jti,
            Duration::from_secs(MAX_PLUGIN_TOKEN_TTL_SECS as u64 + 60),
        );
    }
}
