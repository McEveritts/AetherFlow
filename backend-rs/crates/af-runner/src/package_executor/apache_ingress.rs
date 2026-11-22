use super::*;

mod blueprint_config;
mod librespeed_tls;
mod vhost_render;

use blueprint_config::validate_regular_config_candidate;
pub use blueprint_config::{
    apply_runner_blueprint_app_config, collect_blueprint_target_paths,
    try_apply_runner_blueprint_app_config,
};
#[cfg(test)]
pub(super) use blueprint_config::{
    apply_runner_blueprint_app_config_changes, load_runner_blueprint_ingress,
    try_apply_runner_blueprint_app_config_with_ingress,
};
pub(crate) use blueprint_config::{
    apply_runner_blueprint_in_background, RunnerBlueprintConfigChanges,
};

#[cfg(test)]
pub(super) use librespeed_tls::parse_librespeed_root_tls_flag;
use librespeed_tls::validate_librespeed_apache_ca_cert;
pub use librespeed_tls::{
    librespeed_runner_settings_tls_config, librespeed_runner_settings_tls_enabled,
    try_librespeed_runner_settings_tls_config, LibreSpeedUpstreamTlsConfig,
};

#[cfg(test)]
pub(super) use vhost_render::{
    apache_bcrypt_entry, apache_tls_pair, ensure_apache_htpasswd_with, external_auth_policy,
    render_or_update_runner_apache_vhost, render_or_update_runner_apache_vhost_with_ca,
    ACME_HTTP_EXEMPTION, ACME_REWRITE_GUARD, APACHE_HTPASSWD,
};
pub(crate) use vhost_render::{
    apache_upstream_tls, render_managed_apache_vhost, update_legacy_apache_vhost,
};
pub use vhost_render::{check_domain_tls_ready, requires_external_app_auth, GATEWAY_APP_HEADER};
use vhost_render::{
    extract_runner_apache_custom_blocks, read_runner_apache_vhost, runner_apache_directory_exists,
    update_legacy_apache_vhost_with_blocks, verify_runner_apache_configtest,
};
