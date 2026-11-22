//! Shared inspection for explicit package purge eligibility, retained-removal
//! provenance, and fail-closed handling of ambiguous markerless state.
//!
//! Used by `af-cli`, `af-api`, and `af-runner` so dry-run planning, API
//! admission, and direct runner execution share one confined ownership model.

use crate::package_executor::{
    get_declarative_recipe, DeclarativeStep, RCLONE_BIN, RCLONE_BIN_OWNER, RCLONE_ENV,
    RCLONE_LEGACY_ENV,
};
use af_models::{
    inspect_package_receipts, inspect_receipt_file, read_receipt_file_bounded,
    resolve_package_fs_root, resolve_package_lock_name, resolve_path_for_fs_root,
    PackageReceiptStatus, MAX_PACKAGE_RECEIPT_BYTES,
};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

const RCLONE_MANAGED_CONF_HEADER: &str = "# AetherFlow managed rclone configuration";
const DISPATCHARR_DATA_OWNER_PREFIX: &str = "aetherflow-dispatcharr-data-v1:";

/// Classification of whether an explicit package purge (`--purge` / `delete_data=true`)
/// is permitted, skipped, or refused fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackagePurgeEligibility {
    /// Active canonical (`/install/.<pkg>.lock`) or legacy Swizzin receipt exists.
    Installed,
    /// Install lock is gone, but AetherFlow-owned retained state is positively proved
    /// (canonical `.retained` receipt, durable DB retention/ingress record, or verified
    /// AetherFlow ownership marker).
    RetainedProven,
    /// Install lock is gone and no AetherFlow ownership proof exists, yet package-specific
    /// markerless state exists on disk. Purge MUST refuse fail-closed to avoid deleting
    /// unmanaged distribution packages or unverified pre-fix state.
    AmbiguousMarkerless,
    /// Package is neither installed nor retained nor present as ambiguous markerless state.
    NotPresent,
}

/// Complete confined inspection result for explicit package purge evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePurgeInspection {
    pub package_id: String,
    pub eligibility: PackagePurgeEligibility,
    pub receipt_status: PackageReceiptStatus,
    pub ownership_evidence: Vec<String>,
    pub ambiguous_paths: Vec<String>,
    pub legacy_remove_job_id: Option<String>,
}

impl PackagePurgeInspection {
    /// Returns `true` when explicit purge is allowed to proceed (active install or
    /// positively proved AetherFlow retained installation).
    pub fn allows_purge(&self) -> bool {
        matches!(
            self.eligibility,
            PackagePurgeEligibility::Installed | PackagePurgeEligibility::RetainedProven
        )
    }

    /// Returns `true` when purge is targeting a recognized retained installation
    /// whose install lock has already been removed.
    pub fn is_retained_purge(&self) -> bool {
        self.eligibility == PackagePurgeEligibility::RetainedProven
    }
}

/// Resolves candidate AetherFlow SQLite database paths strictly confined to
/// `explicit_root` (or `AETHERFLOW_FS_ROOT` / `AETHERFLOW_INSTALL_ROOT`) when set.
pub fn candidate_package_sqlite_dbs(explicit_root: Option<&Path>) -> Vec<PathBuf> {
    let fs_root = resolve_package_fs_root(explicit_root);
    let mut candidate_dbs = Vec::new();
    let mut push_unique = |path: PathBuf| {
        if path.as_os_str().is_empty()
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            return;
        }
        if let Some(ref root) = fs_root {
            if !path.starts_with(root) {
                return;
            }
        }
        if !candidate_dbs.contains(&path) {
            candidate_dbs.push(path);
        }
    };

    if let Some(ref root) = fs_root {
        let conf = af_release::resolve_release_manager_conf_for_root(Some(root));
        if let Ok(cfg) =
            af_release::ReleaseConfig::load_for_root_from_process_env(Some(root), conf.as_deref())
        {
            if let Ok(resolved) = af_release::config::try_resolve_db_path(&cfg, None) {
                if resolved.path.starts_with(root) {
                    push_unique(resolved.path);
                }
            }
        }
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Ok(db_env) = env::var(key) {
                let trimmed = db_env.trim();
                if !trimmed.is_empty() && trimmed != ":memory:" && !trimmed.starts_with("file:") {
                    let p = PathBuf::from(trimmed);
                    if p.starts_with(root) {
                        push_unique(p);
                    }
                }
            }
        }
        push_unique(root.join("var/lib/aetherflow/aetherflow.sqlite"));
        push_unique(root.join("opt/AetherFlow/backend/data/aetherflow.sqlite"));
        push_unique(root.join("data/aetherflow.sqlite"));
    } else {
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Ok(db_env) = env::var(key) {
                let trimmed = db_env.trim();
                if !trimmed.is_empty() && trimmed != ":memory:" && !trimmed.starts_with("file:") {
                    push_unique(PathBuf::from(trimmed));
                }
            }
        }
        if let Ok(data_dir) = env::var("DATA_DIR") {
            let trimmed = data_dir.trim();
            if !trimmed.is_empty() {
                push_unique(PathBuf::from(trimmed).join("aetherflow.sqlite"));
            }
        }
        let conf = af_release::resolve_release_manager_conf_for_root(None);
        if let Ok(cfg) =
            af_release::ReleaseConfig::load_for_root_from_process_env(None, conf.as_deref())
        {
            if let Ok(resolved) = af_release::config::try_resolve_db_path(&cfg, None) {
                push_unique(resolved.path);
            }
        }
        push_unique(PathBuf::from("/var/lib/aetherflow/aetherflow.sqlite"));
        push_unique(PathBuf::from(
            "/opt/AetherFlow/backend/data/aetherflow.sqlite",
        ));
        push_unique(PathBuf::from("data/aetherflow.sqlite"));
    }

    candidate_dbs
}

/// Inspects purge eligibility for `pkg_id` using filesystem state confined to
/// `explicit_root` (or env fs-root) and candidate SQLite databases inside that root.
pub fn inspect_package_purge_state(
    pkg_id: &str,
    explicit_lock_file: Option<&str>,
    explicit_root: Option<&Path>,
) -> Result<PackagePurgeInspection, String> {
    inspect_package_purge_state_with_conn(pkg_id, explicit_lock_file, explicit_root, None)
}

/// Inspects purge eligibility for `pkg_id`, optionally reusing an existing SQLite
/// connection (such as the API pool's connection, including in-memory test DBs).
pub fn inspect_package_purge_state_with_conn(
    pkg_id: &str,
    explicit_lock_file: Option<&str>,
    explicit_root: Option<&Path>,
    db_conn: Option<&Connection>,
) -> Result<PackagePurgeInspection, String> {
    let trimmed_pkg = pkg_id.trim();
    if trimmed_pkg.is_empty() {
        return Err("Package identifier is required for purge inspection".to_string());
    }
    let fs_root = resolve_package_fs_root(explicit_root);
    let receipt_status = inspect_package_receipts(trimmed_pkg, explicit_lock_file, explicit_root)?;

    if receipt_status.has_any_receipt() {
        let mut evidence = Vec::new();
        if receipt_status.canonical_installed {
            evidence.push(format!(
                "install_lock:{}",
                receipt_status.canonical_path.display()
            ));
        }
        if receipt_status.legacy_receipt_present {
            if let Some(ref legacy) = receipt_status.legacy_path {
                evidence.push(format!("legacy_install_lock:{}", legacy.display()));
            }
        }
        return Ok(PackagePurgeInspection {
            package_id: trimmed_pkg.to_string(),
            eligibility: PackagePurgeEligibility::Installed,
            receipt_status,
            ownership_evidence: evidence,
            ambiguous_paths: Vec::new(),
            legacy_remove_job_id: None,
        });
    }

    let mut evidence: Vec<String> = Vec::new();
    let mut legacy_remove_job_id: Option<String> = None;

    // 1. Canonical retained-removal receipt (already verified for ownership & symlink safety)
    if receipt_status.has_retained_receipt() {
        evidence.push(format!(
            "retained_receipt:{}",
            receipt_status.retained_path.display()
        ));
    }

    // 2. Durable SQLite provenance (retained_app_ingress_configs + lifecycle retention_state)
    if let Some(conn) = db_conn {
        inspect_db_retention_evidence(conn, trimmed_pkg, &mut evidence, &mut legacy_remove_job_id);
    } else {
        for db_path in candidate_package_sqlite_dbs(explicit_root) {
            if !matches!(inspect_receipt_file(&db_path, fs_root.as_deref()), Ok(true)) {
                continue;
            }
            if let Ok(conn) = Connection::open_with_flags(
                &db_path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            ) {
                let _ = conn.busy_timeout(std::time::Duration::from_secs(2));
                inspect_db_retention_evidence(
                    &conn,
                    trimmed_pkg,
                    &mut evidence,
                    &mut legacy_remove_job_id,
                );
            }
        }
    }

    // 3. Package-specific AetherFlow ownership markers & owned backup archives on disk
    if evidence.is_empty() {
        collect_disk_ownership_evidence(trimmed_pkg, fs_root.as_deref(), &mut evidence)?;
    }

    dedup_preserve_order(&mut evidence);
    if !evidence.is_empty() {
        return Ok(PackagePurgeInspection {
            package_id: trimmed_pkg.to_string(),
            eligibility: PackagePurgeEligibility::RetainedProven,
            receipt_status,
            ownership_evidence: evidence,
            ambiguous_paths: Vec::new(),
            legacy_remove_job_id,
        });
    }

    // 4. No AetherFlow ownership proof exists: detect whether package-specific markerless
    //    state is present on disk so we fail closed instead of silently skipping or deleting.
    let ambiguous_paths = collect_ambiguous_markerless_paths(trimmed_pkg, fs_root.as_deref())?;
    if !ambiguous_paths.is_empty() {
        return Ok(PackagePurgeInspection {
            package_id: trimmed_pkg.to_string(),
            eligibility: PackagePurgeEligibility::AmbiguousMarkerless,
            receipt_status,
            ownership_evidence: Vec::new(),
            ambiguous_paths,
            legacy_remove_job_id,
        });
    }

    Ok(PackagePurgeInspection {
        package_id: trimmed_pkg.to_string(),
        eligibility: PackagePurgeEligibility::NotPresent,
        receipt_status,
        ownership_evidence: Vec::new(),
        ambiguous_paths: Vec::new(),
        legacy_remove_job_id,
    })
}

/// Formats a clear fail-closed diagnostic when explicit purge encounters
/// markerless package state without AetherFlow ownership proof.
pub fn format_ambiguous_purge_error(inspection: &PackagePurgeInspection) -> String {
    let paths_display = if inspection.ambiguous_paths.is_empty() {
        "(unverified markerless state)".to_string()
    } else {
        inspection.ambiguous_paths.join(", ")
    };
    let history_note = match inspection.legacy_remove_job_id.as_deref() {
        Some(job_id) => format!(
            " An older lifecycle removal record (job '{job_id}') predates retention tracking and cannot confirm whether this state belongs to AetherFlow."
        ),
        None => String::new(),
    };
    format!(
        "Refusing to purge '{}': no active install receipt ({}) or AetherFlow retained-ownership receipt/record exists, but markerless package state was found at [{}].{} Inspect and remove unmanaged files manually, or reinstall '{}' via AetherFlow before purging.",
        inspection.package_id,
        inspection.receipt_status.canonical_path.display(),
        paths_display,
        history_note,
        inspection.package_id
    )
}

fn dedup_preserve_order(items: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    items.retain(|item| seen.insert(item.clone()));
}

fn inspect_db_retention_evidence(
    conn: &Connection,
    pkg_id: &str,
    evidence: &mut Vec<String>,
    legacy_remove_job_id: &mut Option<String>,
) {
    let lock_alias = resolve_package_lock_name(pkg_id);

    // 1. retained_app_ingress_configs row (written exclusively on AetherFlow retained remove)
    let has_retained_ingress: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='retained_app_ingress_configs')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);
    if has_retained_ingress {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT app_name, config_json FROM retained_app_ingress_configs \
             WHERE LOWER(app_name)=LOWER(?1) OR LOWER(app_name)=LOWER(?2) LIMIT 1",
        ) {
            if let Ok(mut rows) = stmt.query(params![pkg_id, lock_alias]) {
                if let Ok(Some(row)) = rows.next() {
                    let app_name: String = row.get(0).unwrap_or_else(|_| pkg_id.to_string());
                    let raw_json: String = row.get(1).unwrap_or_default();
                    let port_suffix = serde_json::from_str::<serde_json::Value>(&raw_json)
                        .ok()
                        .and_then(|v| {
                            v.get("listenPort")
                                .or_else(|| v.get("listen_port"))
                                .and_then(|p| p.as_i64())
                        })
                        .filter(|p| *p > 0)
                        .map(|p| format!(" (port {p})"))
                        .unwrap_or_default();
                    evidence.push(format!("retained_ingress_config:{app_name}{port_suffix}"));
                }
            }
        }
    }

    // 2. Durable lifecycle history / job retention state
    if let Ok(Some(rec)) = af_release::lifecycle::query_package_retention_history(conn, pkg_id) {
        if rec.action == "remove" && rec.status == "completed" {
            if rec.retention_state == af_release::lifecycle::RETENTION_STATE_RETAINED {
                evidence.push(format!(
                    "lifecycle_retention_record:job={} (retention_state=retained)",
                    rec.job_id
                ));
            } else if rec.retention_state.is_empty() && legacy_remove_job_id.is_none() {
                *legacy_remove_job_id = Some(rec.job_id);
            }
        }
    }
}

fn package_backup_aliases(pkg_id: &str) -> Vec<String> {
    let lower = pkg_id.trim().to_ascii_lowercase();
    let lock_name = resolve_package_lock_name(&lower).to_string();
    let mut names = vec![lower.clone()];
    if !lock_name.is_empty() && !names.contains(&lock_name) {
        names.push(lock_name);
    }
    match lower.as_str() {
        "paperless-ngx" => names.push("paperless".to_string()),
        "uptimekuma" => names.push("uptime-kuma".to_string()),
        "transmission-daemon" => names.push("transmission".to_string()),
        _ => {}
    }
    names
}

fn check_confined_ancestors_exist(path: &Path, fs_root: Option<&Path>) -> Result<bool, String> {
    if path.as_os_str().is_empty() {
        return Ok(false);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "path contains forbidden parent traversal: {}",
            path.display()
        ));
    }
    if fs_root.is_some_and(|root| !path.starts_with(root)) {
        return Err(format!(
            "path is outside the filesystem root: {}",
            path.display()
        ));
    }
    let ancestors: Vec<_> = path
        .ancestors()
        .skip(1)
        .filter(|parent| !parent.as_os_str().is_empty())
        .collect();
    for ancestor in ancestors.into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "path ancestor is not a regular directory (symlink): {}",
                    ancestor.display()
                ));
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "path ancestor is not a directory: {}",
                    ancestor.display()
                ));
            }
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(format!("cannot inspect {}: {}", path.display(), err));
            }
        }
    }
    Ok(true)
}

fn confined_entry_exists(path: &Path, fs_root: Option<&Path>) -> Result<bool, String> {
    if !check_confined_ancestors_exist(path, fs_root)? {
        return Ok(false);
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("cannot inspect {}: {}", path.display(), err)),
    }
}

fn confined_regular_file_read(
    path: &Path,
    fs_root: Option<&Path>,
) -> Result<Option<String>, String> {
    match read_receipt_file_bounded(path, fs_root, MAX_PACKAGE_RECEIPT_BYTES) {
        Ok(content) => Ok(content),
        // Non-regular / symlink markers on arbitrary disk locations are never valid ownership proof.
        Err(_) => Ok(None),
    }
}

fn scan_owned_af_backup_archives(
    parent_logical: &str,
    stem: &str,
    accepted_owners: &[String],
    fs_root: Option<&Path>,
    evidence: &mut Vec<String>,
) {
    let parent = resolve_path_for_fs_root(parent_logical, fs_root);
    if !matches!(check_confined_ancestors_exist(&parent, fs_root), Ok(true)) {
        return;
    }
    let Ok(parent_meta) = fs::symlink_metadata(&parent) else {
        return;
    };
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return;
    }
    let prefix = format!("{stem}.af-backup.");
    let Ok(entries) = fs::read_dir(&parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(&prefix) {
            continue;
        }
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        let owner_path = entry.path().join(".af-archive-owner");
        if let Ok(Some(raw)) = confined_regular_file_read(&owner_path, fs_root) {
            let owner = raw.trim().to_ascii_lowercase();
            if accepted_owners.iter().any(|allowed| allowed == &owner) {
                evidence.push(format!("owned_archive:{}", entry.path().display()));
            }
        }
    }
}

fn inspect_dispatcharr_data_owner(fs_root: Option<&Path>) -> Option<PathBuf> {
    let data_dir = resolve_path_for_fs_root("/var/lib/dispatcharr", fs_root);
    let owner_path = data_dir.join(".aetherflow-data-owner");
    if !matches!(
        check_confined_ancestors_exist(&owner_path, fs_root),
        Ok(true)
    ) {
        return None;
    }
    let dir_meta = fs::symlink_metadata(&data_dir).ok()?;
    if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
        return None;
    }
    let file_meta = fs::symlink_metadata(&owner_path).ok()?;
    if file_meta.file_type().is_symlink() || !file_meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file_meta.nlink() != 1
            || (file_meta.mode() & 0o022) != 0
            || (dir_meta.mode() & 0o022) != 0
        {
            return None;
        }
    }
    let raw = confined_regular_file_read(&owner_path, fs_root).ok()??;
    let trimmed = raw.trim();
    let expected_logical = format!("{DISPATCHARR_DATA_OWNER_PREFIX}/var/lib/dispatcharr");
    let expected_rooted = format!("{DISPATCHARR_DATA_OWNER_PREFIX}{}", data_dir.display());
    if trimmed == expected_logical || trimmed == expected_rooted {
        Some(owner_path)
    } else {
        None
    }
}

fn collect_disk_ownership_evidence(
    pkg_id: &str,
    fs_root: Option<&Path>,
    evidence: &mut Vec<String>,
) -> Result<(), String> {
    let lower = pkg_id.trim().to_ascii_lowercase();
    let aliases = package_backup_aliases(&lower);

    // Package-specific AetherFlow ownership markers
    match lower.as_str() {
        "rclone" => {
            let owner_marker = resolve_path_for_fs_root(RCLONE_BIN_OWNER, fs_root);
            if let Some(raw) = confined_regular_file_read(&owner_marker, fs_root)? {
                if raw.trim() == "rclone" {
                    evidence.push(format!("rclone_owner_marker:{}", owner_marker.display()));
                }
            }
            let legacy_env = resolve_path_for_fs_root(RCLONE_LEGACY_ENV, fs_root);
            if matches!(inspect_receipt_file(&legacy_env, fs_root), Ok(true)) {
                evidence.push(format!("aetherflow_rclone_env:{}", legacy_env.display()));
            }
            let conf_path = resolve_path_for_fs_root("/etc/rclone/rclone.conf", fs_root);
            if let Some(raw) = confined_regular_file_read(&conf_path, fs_root)? {
                let first_non_empty = raw.lines().map(str::trim).find(|line| !line.is_empty());
                if first_non_empty.is_some_and(|line| line.starts_with(RCLONE_MANAGED_CONF_HEADER))
                {
                    evidence.push(format!("aetherflow_rclone_conf:{}", conf_path.display()));
                }
            }
            scan_owned_af_backup_archives(
                "/opt/AetherFlow/apps/rclone",
                "rclone",
                &aliases,
                fs_root,
                evidence,
            );
            scan_owned_af_backup_archives("/usr/bin", "rclone", &aliases, fs_root, evidence);
        }
        "dispatcharr" => {
            if let Some(owner_path) = inspect_dispatcharr_data_owner(fs_root) {
                evidence.push(format!("dispatcharr_data_owner:{}", owner_path.display()));
            }
        }
        "nextcloud" => {
            let marker = resolve_path_for_fs_root(
                "/opt/AetherFlow/logs/nextcloud_database_owner.json",
                fs_root,
            );
            if matches!(inspect_receipt_file(&marker, fs_root), Ok(true)) {
                evidence.push(format!("nextcloud_db_owner:{}", marker.display()));
            }
        }
        "fail2ban" => {
            let marker =
                resolve_path_for_fs_root("/etc/fail2ban/jail.d/10-aetherflow.local", fs_root);
            if matches!(inspect_receipt_file(&marker, fs_root), Ok(true)) {
                evidence.push(format!("fail2ban_aetherflow_jail:{}", marker.display()));
            }
        }
        "librespeed" => {
            for logical in [
                "/etc/aetherflow/librespeed/settings.toml",
                "/etc/aetherflow/librespeed-proxy-token.conf",
            ] {
                let marker = resolve_path_for_fs_root(logical, fs_root);
                if matches!(inspect_receipt_file(&marker, fs_root), Ok(true)) {
                    evidence.push(format!("librespeed_aetherflow_config:{}", marker.display()));
                }
            }
        }
        _ => {}
    }

    // Owned <target>.af-backup.*/.af-archive-owner directories for common package runtime paths
    for stem in &aliases {
        for parent in ["/opt", "/var/lib", "/etc", "/usr/local/bin", "/usr/bin"] {
            scan_owned_af_backup_archives(parent, stem, &aliases, fs_root, evidence);
        }
        let app_parent = format!("/opt/AetherFlow/apps/{stem}");
        scan_owned_af_backup_archives(&app_parent, stem, &aliases, fs_root, evidence);
    }

    Ok(())
}

fn is_shared_or_excluded_root(logical: &str) -> bool {
    let trimmed = logical.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return true;
    }
    if trimmed == "/mnt" || trimmed.starts_with("/mnt/") {
        return true;
    }
    matches!(
        trimmed,
        "/etc"
            | "/etc/aetherflow"
            | "/etc/systemd"
            | "/etc/systemd/system"
            | "/etc/nginx"
            | "/etc/apache2"
            | "/var"
            | "/var/lib"
            | "/var/log"
            | "/var/backups"
            | "/opt"
            | "/opt/AetherFlow"
            | "/opt/AetherFlow/apps"
            | "/usr"
            | "/usr/bin"
            | "/usr/local"
            | "/usr/local/bin"
            | "/tmp"
            | "/run"
    )
}

fn collect_ambiguous_markerless_paths(
    pkg_id: &str,
    fs_root: Option<&Path>,
) -> Result<Vec<String>, String> {
    let lower = pkg_id.trim().to_ascii_lowercase();
    let mut candidate_logical_paths: Vec<String> = Vec::new();

    if lower == "rclone" {
        // Strictly scoped to the exact paths that RemoveRcloneFiles deletes on purge.
        // Deliberately excludes /etc/rclone directory itself (so /etc/rclone/custom.conf
        // is untouched), /usr/bin/rclone, /usr/local/bin/rclone, /etc/aetherflow/aetherflow.env,
        // /mnt/remote/*, and unowned foreign backup directories.
        candidate_logical_paths.extend([
            "/etc/rclone/rclone.conf".to_string(),
            RCLONE_ENV.to_string(),
            "/var/lib/rclone".to_string(),
            RCLONE_BIN.to_string(),
        ]);
    } else if let Some(recipe) = get_declarative_recipe(&lower) {
        for step in &recipe.remove_steps {
            match step {
                DeclarativeStep::RemovePaths {
                    paths,
                    only_if_delete_data: true,
                    ..
                } => {
                    for p in paths {
                        if !is_shared_or_excluded_root(p) && !candidate_logical_paths.contains(p) {
                            candidate_logical_paths.push(p.clone());
                        }
                    }
                }
                DeclarativeStep::PurgeSystemUser {
                    home_dir: Some(home),
                    ..
                } => {
                    if !is_shared_or_excluded_root(home) && !candidate_logical_paths.contains(home)
                    {
                        candidate_logical_paths.push(home.clone());
                    }
                }
                _ => {}
            }
        }
    } else {
        for candidate in [
            format!("/var/lib/{lower}"),
            format!("/etc/{lower}"),
            format!("/opt/AetherFlow/apps/{lower}"),
        ] {
            if !is_shared_or_excluded_root(&candidate)
                && !candidate_logical_paths.contains(&candidate)
            {
                candidate_logical_paths.push(candidate);
            }
        }
    }

    let mut found = Vec::new();
    for logical in candidate_logical_paths {
        let resolved = resolve_path_for_fs_root(&logical, fs_root);
        if matches!(confined_entry_exists(&resolved, fs_root), Ok(true)) {
            found.push(logical);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_root(label: &str) -> PathBuf {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("af-purge-{label}-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rclone_unmanaged_distro_and_unrelated_files_are_not_present() {
        let root = temp_root("unmanaged-rclone");
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        fs::create_dir_all(root.join("etc/rclone")).unwrap();
        fs::create_dir_all(root.join("etc/aetherflow")).unwrap();
        fs::create_dir_all(root.join("mnt/remote")).unwrap();
        fs::create_dir_all(root.join("install")).unwrap();
        fs::create_dir_all(root.join("usr/bin/rclone.af-backup.foreign")).unwrap();
        // A filename alone is insufficient to authorize purge of unrelated state.
        fs::create_dir_all(root.join("var/backups/aetherflow-rclone.operator")).unwrap();
        fs::write(
            root.join("var/backups/aetherflow-rclone.operator/sentinel"),
            b"keep",
        )
        .unwrap();

        fs::write(root.join("usr/bin/rclone"), b"distro-rclone").unwrap();
        fs::write(root.join("usr/local/bin/rclone"), b"manual-rclone").unwrap();
        fs::write(root.join("etc/rclone/custom.conf"), b"[custom]\n").unwrap();
        fs::write(root.join("etc/aetherflow/aetherflow.env"), b"KEY=val\n").unwrap();
        fs::write(root.join("mnt/remote/sentinel.txt"), b"keep\n").unwrap();
        fs::write(
            root.join("install/.sonarr.retained"),
            af_models::format_retained_package_receipt("sonarr", "2026-11-22T00:00:00Z"),
        )
        .unwrap();
        // Foreign backup owned by another entity / without .af-archive-owner
        fs::write(
            root.join("usr/bin/rclone.af-backup.foreign/sentinel"),
            b"foreign",
        )
        .unwrap();

        let inspection =
            inspect_package_purge_state("rclone", Some("/install/.rclone.lock"), Some(&root))
                .unwrap();
        assert_eq!(inspection.eligibility, PackagePurgeEligibility::NotPresent);
        assert!(!inspection.allows_purge());
        assert!(inspection.ownership_evidence.is_empty());
        assert!(inspection.ambiguous_paths.is_empty());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rclone_markerless_state_is_refused_as_ambiguous() {
        let root = temp_root("ambiguous-rclone");
        fs::create_dir_all(root.join("etc/rclone")).unwrap();
        fs::write(
            root.join("etc/rclone/rclone.conf"),
            b"[gdrive]\ntype = drive\n",
        )
        .unwrap();
        fs::write(root.join("etc/rclone/rclone.env"), b"RCLONE_USER=u\n").unwrap();

        let inspection =
            inspect_package_purge_state("rclone", Some("/install/.rclone.lock"), Some(&root))
                .unwrap();
        assert_eq!(
            inspection.eligibility,
            PackagePurgeEligibility::AmbiguousMarkerless
        );
        assert!(!inspection.allows_purge());
        assert!(inspection
            .ambiguous_paths
            .contains(&"/etc/rclone/rclone.conf".to_string()));
        assert!(inspection
            .ambiguous_paths
            .contains(&"/etc/rclone/rclone.env".to_string()));
        let msg = format_ambiguous_purge_error(&inspection);
        assert!(msg.contains("Refusing to purge 'rclone'"), "{msg}");
        assert!(msg.contains("/etc/rclone/rclone.conf"), "{msg}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rclone_retained_receipt_and_pre_fix_ownership_proofs_allow_purge() {
        let root = temp_root("proven-rclone");
        fs::create_dir_all(root.join("install")).unwrap();
        fs::write(
            root.join("install/.rclone.retained"),
            af_models::format_retained_package_receipt("rclone", "2026-11-22T00:00:00Z"),
        )
        .unwrap();
        let via_receipt =
            inspect_package_purge_state("rclone", Some("/install/.rclone.lock"), Some(&root))
                .unwrap();
        assert_eq!(
            via_receipt.eligibility,
            PackagePurgeEligibility::RetainedProven
        );
        assert!(via_receipt.allows_purge());

        // Pre-fix retained via SQLite retained_app_ingress_configs (no .retained file)
        fs::remove_file(root.join("install/.rclone.retained")).unwrap();
        let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
             INSERT INTO retained_app_ingress_configs VALUES ('rclone', '{\"appName\":\"rclone\",\"listenPort\":5572}');",
        )
        .unwrap();
        drop(conn);

        let via_ingress =
            inspect_package_purge_state("rclone", Some("/install/.rclone.lock"), Some(&root))
                .unwrap();
        assert_eq!(
            via_ingress.eligibility,
            PackagePurgeEligibility::RetainedProven
        );
        assert!(via_ingress
            .ownership_evidence
            .iter()
            .any(|e| e.starts_with("retained_ingress_config:rclone")));

        // Pre-fix retained via AetherFlow managed rclone.conf header (no DB, no .retained)
        fs::remove_file(&db_path).unwrap();
        fs::create_dir_all(root.join("etc/rclone")).unwrap();
        fs::write(
            root.join("etc/rclone/rclone.conf"),
            b"# AetherFlow managed rclone configuration\n[remote]\ntype = s3\n",
        )
        .unwrap();
        let via_conf =
            inspect_package_purge_state("rclone", Some("/install/.rclone.lock"), Some(&root))
                .unwrap();
        assert_eq!(
            via_conf.eligibility,
            PackagePurgeEligibility::RetainedProven
        );
        assert!(via_conf
            .ownership_evidence
            .iter()
            .any(|e| e.starts_with("aetherflow_rclone_conf:")));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn lifecycle_retention_state_proves_retained_and_clears_after_purge() {
        let root = temp_root("lifecycle-db");
        let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let mut conn = Connection::open(&db_path).unwrap();
        af_release::lifecycle::initialize_schema(&conn).unwrap();

        let lease = af_release::lifecycle::admit_job(
            &mut conn,
            "cloudplow",
            "rm-1",
            "remove",
            "2026-11-22T00:00:00Z",
            &[],
        )
        .unwrap();
        af_release::lifecycle::finish_job_with_diagnostics(
            &conn,
            "cloudplow",
            "rm-1",
            "remove",
            true,
            af_release::lifecycle::LifecycleJobDiagnostics {
                retention_state: Some(af_release::lifecycle::RETENTION_STATE_RETAINED),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease);

        let retained = inspect_package_purge_state_with_conn(
            "cloudplow",
            Some("/install/.cloudplow.lock"),
            Some(&root),
            Some(&conn),
        )
        .unwrap();
        assert_eq!(
            retained.eligibility,
            PackagePurgeEligibility::RetainedProven
        );

        let lease2 = af_release::lifecycle::admit_job(
            &mut conn,
            "cloudplow",
            "purge-1",
            "remove",
            "2026-11-22T00:01:00Z",
            &[],
        )
        .unwrap();
        af_release::lifecycle::finish_job_with_diagnostics(
            &conn,
            "cloudplow",
            "purge-1",
            "remove",
            true,
            af_release::lifecycle::LifecycleJobDiagnostics {
                retention_state: Some(af_release::lifecycle::RETENTION_STATE_PURGED),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease2);

        let purged = inspect_package_purge_state_with_conn(
            "cloudplow",
            Some("/install/.cloudplow.lock"),
            Some(&root),
            Some(&conn),
        )
        .unwrap();
        assert_eq!(purged.eligibility, PackagePurgeEligibility::NotPresent);

        drop(conn);
        let _ = fs::remove_dir_all(&root);
    }
}
