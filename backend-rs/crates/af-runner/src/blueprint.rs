//! Native application configuration shared by the API and privileged runner.

mod apply;
mod fs_mutators;
mod master_creds;
mod native_specs;

#[cfg(test)]
use apply::service_units_changed;
pub use apply::{apply_host_config, has_config_root};
pub(crate) use apply::{
    apply_host_config_with_state, blueprint_base_domain, is_transmission_config_alias,
    reload_changed_units, run_systemctl, with_transmission_stopped,
};
pub use fs_mutators::{
    backup_config_file, extract_ini_value, extract_xml_tag_text, mutate_dispatcharr_port,
    mutate_ini_key, mutate_json_key, mutate_pihole_toml, mutate_systemd_aspnetcore_urls,
    mutate_xml_element, mutate_yaml_section_key, read_metadata_config, read_xml_element,
    write_file_atomic, write_file_atomic_mode,
};
pub(crate) use fs_mutators::{
    mutate_systemd_port, mutate_transmission_whitelist, open_mutation_file,
};
pub use master_creds::{
    derive_app_webui_password, generate_qbittorrent_pbkdf2, load_master_credentials,
    master_cred_paths, master_ha1, MasterCreds, MASTER_CREDS_SYSTEM_KEY,
};
pub(crate) use native_specs::TRANSMISSION_CONFIG_PATHS;
pub use native_specs::{inject_arr_download_client_routes, native_app_spec, NativeAppSpec};

#[cfg(test)]
mod tests;
