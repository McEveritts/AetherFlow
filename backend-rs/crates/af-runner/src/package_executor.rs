//! Typed Declarative Package Installation, Update & Removal Engine (`af-runner::package_executor`).
//!
//! Provides a Rust-native, security-bounded marketplace lifecycle engine integrated into
//! `af-runner`'s `/v1/package` stream dispatcher, with automatic fallback to legacy Bash
//! scripts (`packages/package/{install,remove,update}/*`) for recipes not yet migrated.
//!
//! ## Core Design Principles
//! 1. **Conservative Security Boundaries**:
//!    - Zero arbitrary shell evaluation (`bash -c` / `sh -c`) in declarative recipes.
//!    - Strict allowlists for identifiers (`SAFE_PKG_ID`), usernames (`SAFE_USERNAME`),
//!      systemd unit names (`SAFE_SERVICE_NAME`), APT package names (`SAFE_APT_PKG_NAME`),
//!      and managed filesystem prefixes (`/etc/`, `/var/lib/`, `/var/log/`, `/var/run/`, `/opt/`,
//!      `/usr/local/bin/`, `/install/`).
//!    - Path traversal (`..`) and root-level destructive mutations are rejected at validation time.
//! 2. **Dependency & State Locking**:
//!    - Process-wide serialization via `PACKAGE_MUTEX` + cross-process advisory lock file
//!      (`${LOCK_DIR}/.af-package-executor.flock`) + per-package in-flight guard (`ACTIVE_CANCELLATIONS`)
//!      so concurrent Marketplace or CLI requests never collide on `/var/lib/dpkg/lock-frontend`.
//!    - Completion lockfile (`/install/.<pkg>.lock`) is written **only** as the final step of
//!      `install`/`update` after all steps and sandboxing succeed, and removed on `remove`.
//! 3. **Artifact Verification**:
//!    - Remote and local artifacts are verified against minimum size bounds (`min_size_bytes`)
//!      to detect truncated/HTML 404 responses, optional SHA-256 digests (`expected_sha256` or
//!      release `.sha256` sidecars), and archive format magic bytes before extraction/installation.
//! 4. **Structured Progress & Wire Compatibility**:
//!    - Emits structured [`PackageProgressEvent`] values and formats lines as
//!      `[PROGRESS:<pct>] <message>` plus timestamped `[INFO]`/`[WARN]`/`[ERROR]` lines compatible
//!      with both the legacy Go scanner and the Rust
//!      `consume_package_output` consumer.
//! 5. **Explicit Failure, Cancellation & Rollback Recovery**:
//!    - Every file mutation (`WriteTemplateFile`, `WriteSystemdUnit`, `InstallBinary`, `ExtractTarGz`)
//!      records a `.bak-af` backup or newly-created path in a [`RollbackJournal`].
//!    - If any step fails or is cancelled via [`cancel_package_execution`], the executor runs
//!      compensating rollback actions in reverse order, restores `.bak-af` backups, removes
//!      newly created files, cleans up temporary artifacts, and preserves the pre-operation lock state.

#[cfg(test)]
#[path = "teardown_regressions.rs"]
mod teardown_regressions;

use crate::package_lifecycle::snapshot_policy::{
    configured_max_snapshot_bytes, ensure_snapshot_free_space, snapshot_filesystem_capacity,
    SnapshotBudget, SNAPSHOT_RESERVE_BYTES,
};
use crate::{resolve_package_script_path, SAFE_PKG_ID, SAFE_SERVICE_NAME, SAFE_USERNAME};
use af_models::PackageRunnerRequest;
use chrono::Utc;
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tar::Archive;
use tokio::process::Command;

mod apache_ingress;
mod command_env;
mod declarative_recipes;
mod helpers;
mod legacy_readiness;
mod model;
mod policy;
mod rollback;
mod stream_dispatch;
mod validation;

pub use apache_ingress::*;
#[cfg(test)]
use apache_ingress::{
    apache_bcrypt_entry, apache_tls_pair, apply_runner_blueprint_app_config_changes,
    ensure_apache_htpasswd_with, external_auth_policy, load_runner_blueprint_ingress,
    parse_librespeed_root_tls_flag, render_or_update_runner_apache_vhost,
    render_or_update_runner_apache_vhost_with_ca,
    try_apply_runner_blueprint_app_config_with_ingress, ACME_HTTP_EXEMPTION, ACME_REWRITE_GUARD,
    APACHE_HTPASSWD,
};
pub(crate) use apache_ingress::{
    apache_upstream_tls, apply_runner_blueprint_in_background,
    apply_runner_blueprint_in_background_with_ingress, render_managed_apache_vhost,
    update_legacy_apache_vhost, RunnerBlueprintConfigChanges,
};

pub use command_env::*;

pub use declarative_recipes::*;
#[allow(unused_imports)]
pub(crate) use declarative_recipes::{
    recipe_version_file_logical_path, resolve_and_reserve_rclone_api_port,
    resolve_and_reserve_rclone_api_port_with,
};

#[cfg(test)]
use helpers::resolve_master_credentials;
pub use helpers::*;
use helpers::{
    add_missing_rclone_env_aliases, append_log_line, apply_sandbox_in_root_with_journal,
    escape_systemd_env_quoted, extract_binaries_from_targz, format_znc_major_minor,
    interpolate_template, is_downgrade_allowed, is_semver_strictly_greater, merge_ini_settings,
    step_progress_meta, trigger_certbot_sync_best_effort, update_preserved_rclone_env_pass,
    update_preserved_template_port,
};
pub(crate) use helpers::{
    ensure_package_sandbox_dropin_under_root_with_journal, package_request_deletes_data,
    try_resolve_master_credentials,
};

pub(crate) use legacy_readiness::*;

pub use model::*;

pub use policy::*;
use policy::{
    ALLOWED_MANAGED_PREFIXES, FORBIDDEN_EXACT_PATHS, MAX_COMMAND_OUTPUT_BYTES, PROGRESS_LINE_RE,
    SHARED_SYSTEM_CHOWN_PATHS, SSH_PORT_LINE_RE,
};
pub(crate) use policy::{RCLONE_BIN, RCLONE_BIN_OWNER, RCLONE_ENV, RCLONE_LEGACY_ENV};

pub(crate) use rollback::{
    acquire_package_mutex_with_cancel, wait_for_cancellation, CrossProcessLockGuard,
    RollbackJournal,
};
#[cfg(test)]
use rollback::{
    copy_dir_snapshot_recursive, open_new_private_file, write_file_atomic_with_mode, RollbackEntry,
};
use rollback::{
    create_dir_all_0755, set_path_mode, write_file_atomic_with_file_owner,
    write_file_atomic_with_mode_bounded,
};

use stream_dispatch::resolve_package_lock_name;
pub use stream_dispatch::*;
#[allow(unused_imports)]
pub(crate) use stream_dispatch::{
    apply_legacy_package_environment, configure_legacy_rclone_api_port_env,
    format_exit_failure_diagnostics,
};

pub use validation::*;
use validation::{normalize_unit_filename, validate_step};
#[allow(unused_imports)]
pub(crate) use validation::{
    probe_host_for_bind_address, resolve_bind_address, validate_path_ancestors_with_lstat,
};

#[cfg(test)]
mod tests;
