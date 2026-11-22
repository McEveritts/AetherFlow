mod extractors_media;
mod extractors_services;
mod handlers;
mod parsers;
mod rclone;

pub use af_models::app_metadata::normalize_app_slug as normalize_runner_app_name;
pub use af_models::AppRuntimeMeta;
pub use extractors_services::{
    extract_app_runtime_meta_local, extract_app_runtime_meta_local_until,
};
#[cfg(test)]
pub(super) use handlers::{
    dispatcharr_credentials_command, DispatcharrCredentialsRequest, DISPATCHARR_ADMIN_SCRIPT,
};
pub(super) use handlers::{
    handle_app_meta, handle_dispatcharr_credentials, handle_package_version_probe,
};
pub use handlers::{probe_package_version_via_runner, PackageVersionProbeRunnerRequest};
#[cfg(test)]
pub(super) use parsers::dispatcharr_runtime_port;
pub(super) use parsers::{app_metadata_users, resolve_runner_fs_path};
pub use parsers::{query_app_metadata_sqlite, read_app_metadata_config};
pub use rclone::{
    extract_rclone_runtime_api_port_for_root, parse_rclone_env_api_port, parse_rclone_port_value,
    parse_rclone_unit_ports, rclone_extra_reserved_ports, rclone_secondary_port_update_for_root,
    read_rclone_unit_text_for_root, RcloneUnitPorts,
};
