use crate::auth::{api_error, AuthUser};
use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
pub(super) struct FsQuery {
    #[serde(default)]
    path: String,
}

pub(crate) fn get_allowed_fs_roots() -> Vec<PathBuf> {
    let env_override = env::var("AF_ALLOWED_FS_ROOTS").ok();
    get_allowed_fs_roots_with(env_override.as_deref())
}

fn get_allowed_fs_roots_with(env_override: Option<&str>) -> Vec<PathBuf> {
    let mut raw_roots: Vec<PathBuf> = Vec::new();
    let has_env_override = if let Some(env_roots) = env_override {
        for part in env_roots.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                raw_roots.push(PathBuf::from(trimmed));
            }
        }
        !raw_roots.is_empty()
    } else {
        false
    };

    if !has_env_override {
        for def in ["/mnt", "/media", "/srv", "/data", "/home"] {
            raw_roots.push(PathBuf::from(def));
        }

        if let Ok(cwd) = env::current_dir() {
            let cwd_canon = fs::canonicalize(&cwd).unwrap_or_else(|_| cwd.clone());
            let is_restricted_service_dir =
                ["/opt/AetherFlow", "/var/lib/aetherflow"]
                    .iter()
                    .any(|restricted| {
                        let r_path = std::path::Path::new(restricted);
                        let r_canon =
                            fs::canonicalize(r_path).unwrap_or_else(|_| r_path.to_path_buf());
                        cwd_canon == r_canon || cwd_canon.starts_with(&r_canon)
                    });
            if !is_restricted_service_dir {
                raw_roots.push(cwd);
            }
        }
    }

    let mut resolved = Vec::with_capacity(raw_roots.len());
    for root in raw_roots {
        if let Ok(canon) = fs::canonicalize(&root) {
            resolved.push(canon);
        } else {
            resolved.push(root);
        }
    }
    resolved
}

pub(crate) fn is_fs_path_allowed(target: &std::path::Path, allowed_roots: &[PathBuf]) -> bool {
    for root in allowed_roots {
        if target == root || target.starts_with(root) {
            return true;
        }
    }
    false
}

pub(super) async fn browse_directories(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<FsQuery>,
) -> Response {
    if auth_user.role != "admin" || crate::mcbrowser::validate_mcbrowser_user(&auth_user).is_err() {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Host filesystem browsing requires admin access",
        );
    }
    tokio::task::spawn_blocking(move || {
        let Ok(connection) = af_db::get_read_conn() else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        };
        let live_admin = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM users AS account
                LEFT JOIN user_quotas AS quota ON quota.user_id = account.id
                WHERE account.id = ?1 AND account.role = 'admin'
                AND account.username NOT LIKE 'plugin:%'
                AND LOWER(TRIM(COALESCE(quota.status, ''))) IN ('', 'active')
            )",
            [auth_user.user_id],
            |row| row.get::<_, bool>(0),
        );
        drop(connection);
        match live_admin {
            Ok(true) => browse_host_directories(query),
            Ok(false) => api_error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Host filesystem browsing requires active admin access",
            ),
            Err(_) => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Account authorization unavailable",
            ),
        }
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Filesystem worker failed",
        )
    })
}

pub(super) fn browse_host_directories(q: FsQuery) -> Response {
    let raw_path = q.path.trim();
    if raw_path.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Path query parameter is required",
        );
    }
    if raw_path.contains('\0') {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PATH",
            "Path query parameter must not contain null bytes",
        );
    }
    let p = PathBuf::from(raw_path);
    if !p.exists() && fs::symlink_metadata(&p).is_err() {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Directory not found");
    }

    let resolved_path = match fs::canonicalize(&p) {
        Ok(rp) => rp,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Directory not found");
        }
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_PATH",
                "Could not resolve directory path",
            );
        }
    };

    let allowed_roots = get_allowed_fs_roots();
    if !is_fs_path_allowed(&resolved_path, &allowed_roots) {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Access denied: path is outside allowed sandbox",
        );
    }

    let Ok(dir_meta) = fs::metadata(&resolved_path) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Directory not found");
    };
    if !dir_meta.is_dir() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "NOT_A_DIRECTORY",
            "Path is not a directory",
        );
    }

    let Ok(read_dir) = fs::read_dir(&resolved_path) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to read directory",
        );
    };

    let mut directories = Vec::new();
    let mut entries = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let entry_path = entry.path();
        let full = entry_path.to_string_lossy().into_owned();

        let sym_meta = fs::symlink_metadata(&entry_path).ok();
        let size = sym_meta.as_ref().map(|m| m.len() as i64).unwrap_or(0);
        let mod_time = sym_meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        let mut is_dir = sym_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        if !is_dir
            && sym_meta
                .as_ref()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            if let Ok(target_meta) = fs::metadata(&entry_path) {
                if target_meta.is_dir() {
                    if let Ok(canon_target) = fs::canonicalize(&entry_path) {
                        if is_fs_path_allowed(&canon_target, &allowed_roots) {
                            is_dir = true;
                        }
                    }
                }
            }
        }

        if is_dir {
            directories.push(name.clone());
        }
        entries.push(serde_json::json!({
            "name": name,
            "path": full,
            "is_dir": is_dir,
            "size": size,
            "mod_time": mod_time,
        }));
    }

    directories.sort();
    entries.sort_by(|a, b| {
        let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        na.cmp(nb)
    });

    let parent = resolved_path
        .parent()
        .filter(|par| *par != resolved_path && is_fs_path_allowed(par, &allowed_roots))
        .map(|par| par.to_string_lossy().into_owned())
        .unwrap_or_default();

    Json(serde_json::json!({
        "current_path": resolved_path.to_string_lossy().into_owned(),
        "parent_path": parent,
        "directories": directories,
        "entries": entries,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_allowed_fs_roots_includes_data_root() {
        let roots = get_allowed_fs_roots_with(None);
        let expected_data = fs::canonicalize("/data").unwrap_or_else(|_| PathBuf::from("/data"));
        assert!(
            roots.contains(&expected_data),
            "expected /data in default allowed fs roots, got: {roots:?}"
        );
        for required in ["/mnt", "/media", "/srv", "/data", "/home"] {
            let expected = fs::canonicalize(required).unwrap_or_else(|_| PathBuf::from(required));
            assert!(
                roots.contains(&expected),
                "expected {required} in default allowed fs roots, got: {roots:?}"
            );
        }

        let overridden = get_allowed_fs_roots_with(Some("/srv,/mnt"));
        assert!(!overridden.contains(&expected_data));

        let temp_canon = fs::canonicalize(env::temp_dir()).unwrap_or_else(|_| env::temp_dir());
        assert!(
            !roots.contains(&temp_canon),
            "default allowed fs roots must not include temp_dir ({temp_canon:?}), got: {roots:?}"
        );
    }

    #[test]
    fn get_allowed_fs_roots_includes_data_when_env_unset() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        env::remove_var("AF_ALLOWED_FS_ROOTS");
        let roots = get_allowed_fs_roots();
        let expected_data = fs::canonicalize("/data").unwrap_or_else(|_| PathBuf::from("/data"));
        assert!(
            roots.contains(&expected_data),
            "expected /data in get_allowed_fs_roots() when AF_ALLOWED_FS_ROOTS is unset, got: {roots:?}"
        );
        let temp_canon = fs::canonicalize(env::temp_dir()).unwrap_or_else(|_| env::temp_dir());
        assert!(
            !roots.contains(&temp_canon),
            "default allowed fs roots must not include temp_dir ({temp_canon:?}), got: {roots:?}"
        );
        let tmp_root = fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
        assert!(
            !is_fs_path_allowed(&tmp_root, &roots),
            "/tmp ({tmp_root:?}) must be denied when AF_ALLOWED_FS_ROOTS is unset, got: {roots:?}"
        );
    }
}
