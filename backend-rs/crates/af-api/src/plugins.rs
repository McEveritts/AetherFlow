mod handlers;
mod lifecycle;
mod manifest;
mod proxy;
mod registry;
mod tokens;
mod types;

#[cfg(test)]
pub(crate) mod tests;

const MAX_PLUGIN_PROXY_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const DEFAULT_PLUGIN_TOKEN_TTL_SECS: i64 = 300; // 5 minutes
const MAX_PLUGIN_TOKEN_TTL_SECS: i64 = 900; // 15 minutes
pub const PLUGIN_TOKEN_ISSUER: &str = "aetherflow-plugin";
pub const PLUGIN_TOKEN_TYP: &str = "plugin";
pub const PLUGIN_TOKEN_AUDIENCE: &str = "aetherflow-plugin-api";

pub use handlers::{
    control_plugin_handler, list_plugins_handler, mint_plugin_token_handler,
    serve_plugin_ui_handler, MintPluginTokenRequest, PluginControlRequest,
};
pub use lifecycle::{
    probe_plugin_health, reconcile_managed_plugins_on_startup, restart_plugin_instance_with_port,
    shutdown_managed_plugins, start_plugin_instance, start_plugin_instance_with_port,
    stop_plugin_instance,
};
pub use manifest::{
    discover_plugins, discover_plugins_in_dir, is_plugin_request_denied, is_route_default_denied,
    is_valid_plugin_id, normalize_scope_entry, plugin_claims_allow_request, route_pattern_matches,
    validate_plugin_manifest, validate_relative_plugin_subpath,
};
pub(crate) use proxy::ProxiedPluginResponse;
pub use proxy::{proxy_plugin_root_handler, proxy_plugin_wildcard_handler};
#[allow(unused_imports)]
pub(crate) use registry::update_registry_state;
pub use tokens::{
    decode_and_verify_plugin_token, mint_scoped_plugin_token, revoke_all_tokens_for_plugin,
};
pub use types::{
    PluginBackendSpec, PluginFrontendSpec, PluginLifecycleError, PluginLifecycleHooks,
    PluginRegistryState, PluginRuntimeView, PluginScopeRule, PluginTokenClaims, RawPluginManifest,
    RawScopeEntry, ValidatedPluginManifest,
};
