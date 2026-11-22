use super::*;

mod catalog;
mod lifecycle;
mod rclone_helpers;
mod readiness_and_fetch;
mod steps_files_services;
mod steps_system;

pub use catalog::{resolve_threadfin_sha256_override, resolve_threadfin_target_version};
pub(crate) use catalog::recipe_version_file_logical_path;
pub(super) use catalog::{recipe_mutable_state_dirs, recipe_primary_apt_package};

pub use rclone_helpers::{
    detect_rclone_exec_start, detect_rclone_exec_start_for_root, detect_rclone_separate_api_port,
    detect_rclone_separate_api_port_for_root,
};
pub(crate) use rclone_helpers::{
    resolve_and_reserve_rclone_api_port, resolve_and_reserve_rclone_api_port_with,
};
use rclone_helpers::{rclone_unit_path, read_rclone_env};

/// Verified declarative recipes. LegacyBashFallback remains the default engine
/// unless AETHERFLOW_ENABLE_RUST_PACKAGES=1 opts in to the Rust engine.
pub(super) static BUILTIN_DECLARATIVE_RECIPES: Lazy<HashMap<String, DeclarativePackageRecipe>> =
    Lazy::new(|| {
        let mut map = HashMap::new();
        for recipe in [
            catalog::build_fail2ban_recipe(),
            catalog::build_quassel_recipe(),
            catalog::build_threadfin_recipe(),
            catalog::build_znc_recipe(),
            catalog::build_xrdp_recipe(),
            catalog::build_x2go_recipe(),
            catalog::build_netdata_recipe(),
            catalog::build_mergerfs_recipe(),
            catalog::build_rclone_recipe(),
        ] {
            recipe
                .validate()
                .expect("built-in declarative package recipe failed validation");
            map.insert(recipe.package_id.clone(), recipe);
        }
        map
    });

/// Returns the built-in declarative recipe for `pkg_id`, if that package has been migrated
/// and verified for full parity. Unported or deferred recipes return `None` and automatically
/// fall back to the legacy Bash scripts in `packages/package/{install,remove,update}/*`.
pub fn get_declarative_recipe(pkg_id: &str) -> Option<DeclarativePackageRecipe> {
    BUILTIN_DECLARATIVE_RECIPES
        .get(pkg_id.trim().to_lowercase().as_str())
        .cloned()
}

/// Lists all package IDs currently supported by the native Rust declarative executor.
pub fn list_declarative_recipe_ids() -> Vec<String> {
    let mut ids: Vec<String> = BUILTIN_DECLARATIVE_RECIPES.keys().cloned().collect();
    ids.sort();
    ids
}

/// Pure helper evaluating engine selection given explicit gate flags (`rust_enabled`, `force_bash`).
pub fn select_package_engine_with_flags(
    pkg_id: &str,
    rust_enabled: bool,
    force_bash: bool,
) -> PackageEngineMode {
    if rust_enabled && !force_bash && get_declarative_recipe(pkg_id).is_some() {
        PackageEngineMode::DeclarativeRust
    } else {
        PackageEngineMode::LegacyBashFallback
    }
}

/// Returns `true` when the native Rust package engine is enabled via
/// `AETHERFLOW_ENABLE_RUST_PACKAGES` and not overridden by `AETHERFLOW_FORCE_BASH_PACKAGES`.
pub fn is_rust_package_engine_enabled() -> bool {
    let rust_enabled = env::var("AETHERFLOW_ENABLE_RUST_PACKAGES")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_bash = env::var("AETHERFLOW_FORCE_BASH_PACKAGES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    rust_enabled && !force_bash
}

/// Determines whether `pkg_id` will execute via [`PackageEngineMode::DeclarativeRust`] or
/// [`PackageEngineMode::LegacyBashFallback`].
///
/// Default gate: `AETHERFLOW_ENABLE_RUST_PACKAGES` defaults to OFF (`false`).
/// Override gate: `AETHERFLOW_FORCE_BASH_PACKAGES=1` forces all packages through legacy Bash scripts.
pub fn select_package_engine(pkg_id: &str) -> PackageEngineMode {
    let rust_enabled = env::var("AETHERFLOW_ENABLE_RUST_PACKAGES")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_bash = env::var("AETHERFLOW_FORCE_BASH_PACKAGES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    select_package_engine_with_flags(pkg_id, rust_enabled, force_bash)
}

/// Typed declarative marketplace package executor.
pub struct DeclarativePackageExecutor<R: CommandRunner = TokioCommandRunner> {
    pub env_cfg: PackageExecutionEnv,
    pub runner: R,
}

impl DeclarativePackageExecutor<TokioCommandRunner> {
    pub fn new(env_cfg: PackageExecutionEnv) -> Self {
        Self {
            env_cfg,
            runner: TokioCommandRunner::default(),
        }
    }
}

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    pub fn with_runner(env_cfg: PackageExecutionEnv, runner: R) -> Self {
        Self { env_cfg, runner }
    }
}
