use super::fs_helpers::{
    ensure_no_symlink_ancestors, lookup_group_gid, write_file_atomic_exclusive,
};
use super::preflight::is_effective_root_user;
use super::state::ProvisionStateStore;
use crate::error::{CliError, CliResult};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

static SAFE_APACHE_USER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z_][a-z0-9_-]{0,31}$").unwrap());

fn has_valid_bcrypt_entries(content: &str) -> bool {
    content.lines().any(|raw_line| {
        let line = raw_line.trim();
        let Some((user, hash)) = line.split_once(':') else {
            return false;
        };
        SAFE_APACHE_USER_RE.is_match(user)
            && hash.len() == 60
            && (hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$"))
    })
}

/// Provisions `/etc/apache2/AetherFlow/htpasswd` (`0640`, `root:www-data`) with a bcrypt `$2y$`
/// credential entry when `/etc/apache2/AetherFlow` is present/configured and an explicit
/// plaintext password is supplied.
///
/// When no plaintext password is supplied (for example when `.master.creds` is encrypted with
/// `enc:v1:`), preserves any existing file with valid bcrypt entries (`$2a$`/`$2b$`/`$2y$`) and
/// returns `Ok(Some(path))`, or returns `Ok(None)` without writing a random password.
pub fn provision_apache_htpasswd_if_configured(
    store: &ProvisionStateStore,
) -> CliResult<Option<PathBuf>> {
    let paths = store.paths();
    let apache_af_dir = paths.fs_root.join("etc/apache2/AetherFlow");
    ensure_no_symlink_ancestors(&apache_af_dir, "etc/apache2/AetherFlow")?;
    match fs::symlink_metadata(&apache_af_dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(CliError::Validation(format!(
                    "{} exists and is not a directory",
                    apache_af_dir.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CliError::io(
                format!("inspecting {}", apache_af_dir.display()),
                e,
            ))
        }
    }

    let htpasswd_path = apache_af_dir.join("htpasswd");
    ensure_no_symlink_ancestors(&htpasswd_path, "etc/apache2/AetherFlow/htpasswd")?;

    let config_map = store.read_config_map()?;
    let master_creds_json = read_unencrypted_master_creds_json(&paths.var_lib_aetherflow);

    let candidate_user = config_map
        .get("username")
        .cloned()
        .or_else(|| {
            std::env::var("AETHERFLOW_USERNAME")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("AF_SETUP_USER")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| read_trimmed_regular_file(&paths.fs_root.join("etc/apache2/master.txt")))
        .or_else(|| {
            master_creds_json
                .as_ref()
                .and_then(|v| v.get("username").and_then(|u| u.as_str()))
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "admin".to_string());
    let username = candidate_user.trim().to_string();
    if !SAFE_APACHE_USER_RE.is_match(&username) {
        return Err(CliError::Validation(format!(
            "invalid Apache admin username {:?}",
            username
        )));
    }

    let explicit_password = std::env::var("AETHERFLOW_PASSWORD")
        .ok()
        .or_else(|| std::env::var("AETHERFLOW_MASTER_CREDS_SECRET").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with("enc:v1:"))
        .or_else(|| {
            master_creds_json
                .as_ref()
                .and_then(|v| v.get("password").and_then(|p| p.as_str()))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && !s.starts_with("enc:v1:"))
        });

    let existing_raw = if htpasswd_path.is_file() {
        Some(
            fs::read_to_string(&htpasswd_path)
                .map_err(|e| CliError::io(format!("reading {}", htpasswd_path.display()), e))?,
        )
    } else {
        None
    };

    let Some(password) = explicit_password else {
        if let Some(ref content) = existing_raw {
            if has_valid_bcrypt_entries(content) {
                enforce_apache_htpasswd_perms(&htpasswd_path);
                return Ok(Some(htpasswd_path));
            }
        }
        return Ok(None);
    };
    let bcrypt_hash = generate_bcrypt_2y_hash(&password)?;

    let user_prefix = format!("{}:", username);
    let mut lines: Vec<String> = existing_raw
        .as_deref()
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(&user_prefix))
        .map(ToString::to_string)
        .collect();
    lines.push(format!("{}:{}", username, bcrypt_hash));
    let mut body = lines.join("\n");
    body.push('\n');

    write_file_atomic_exclusive(
        &htpasswd_path,
        body.as_bytes(),
        0o640,
        "etc/apache2/AetherFlow/htpasswd",
    )?;
    enforce_apache_htpasswd_perms(&htpasswd_path);

    Ok(Some(htpasswd_path))
}

fn read_trimmed_regular_file(path: &Path) -> Option<String> {
    if ensure_no_symlink_ancestors(path, "regular config file").is_err() {
        return None;
    }
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 256 {
        return None;
    }
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_unencrypted_master_creds_json(var_lib_aetherflow: &Path) -> Option<serde_json::Value> {
    let creds_path = var_lib_aetherflow.join(".master.creds");
    if ensure_no_symlink_ancestors(&creds_path, ".master.creds").is_err() {
        return None;
    }
    let meta = fs::symlink_metadata(&creds_path).ok()?;
    if !meta.is_file() || meta.len() > 16384 {
        return None;
    }
    let raw = fs::read_to_string(&creds_path).ok()?;
    serde_json::from_str::<serde_json::Value>(&raw).ok()
}

fn enforce_apache_htpasswd_perms(htpasswd_path: &Path) {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        if is_effective_root_user() {
            let gid = lookup_group_gid("www-data").unwrap_or(0);
            if let Ok(path_c) = CString::new(htpasswd_path.as_os_str().as_bytes()) {
                let _ = unsafe { libc::lchown(path_c.as_ptr(), 0, gid) };
            }
        }
        let _ = fs::set_permissions(htpasswd_path, fs::Permissions::from_mode(0o640));
    }
    #[cfg(not(unix))]
    {
        let _ = htpasswd_path;
    }
}

fn generate_bcrypt_2y_hash(password: &str) -> CliResult<String> {
    if password.contains('\0') || password.contains('\n') || password.contains('\r') {
        return Err(CliError::Validation(
            "password must not contain NUL or newline characters".to_string(),
        ));
    }
    let parts = bcrypt::hash_with_result(password, 10)
        .map_err(|e| CliError::Execution(format!("failed to hash htpasswd credential: {}", e)))?;
    Ok(parts.format_for_version(bcrypt::Version::TwoY))
}
