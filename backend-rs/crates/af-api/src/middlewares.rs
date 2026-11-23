mod host_resolution;
mod host_validation;
mod proxy_helpers;
mod rate_limit;
mod subdomain_proxy;

#[cfg(test)]
#[path = "middlewares_security_regressions.rs"]
mod security_regressions;
#[cfg(test)]
mod tests;

pub use host_resolution::resolve_app_target_for_host;
pub use host_validation::host_validation_middleware;
pub(crate) use host_validation::{is_trusted_request_host, ValidatedRequestHost};
#[allow(unused_imports)]
pub(crate) use proxy_helpers::upstream_uses_tls;
pub use rate_limit::{
    ai_rate_limit_middleware, auth_rate_limit_middleware, oidc_rate_limit_middleware,
    quota_upload_guard_middleware,
};
pub use subdomain_proxy::app_subdomain_proxy_middleware;

#[cfg(test)]
use host_resolution::PROXY_RESOLVE_LIMIT;
#[cfg(test)]
use host_validation::is_host_trusted;
#[cfg(test)]
use proxy_helpers::{
    canonical_forwarded_headers, is_private_or_loopback_ip, is_unauth_local_lan_ip,
    librespeed_tls_client, unauth_local_lan_enabled,
};
#[cfg(test)]
use rate_limit::{is_rate_limit_disabled_for_env, SlidingWindowLimiter, RATE_LIMIT_KEY_CAPACITY};
