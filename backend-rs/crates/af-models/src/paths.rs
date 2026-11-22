use std::collections::HashMap;

fn normalize_path_for_comparison(path: &std::path::Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    if raw.len() > 1 {
        raw.trim_end_matches('/').to_string()
    } else {
        raw
    }
}

pub fn normalize_lexical_path(
    path: &std::path::Path,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    let raw_str = path.to_string_lossy();
    if raw_str.trim().is_empty() {
        return Err(format!("{} must not be empty", label));
    }
    if raw_str.contains('\0') {
        return Err(format!("{} contains NUL byte", label));
    }
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(format!(
                    "{} '{}' must not contain parent traversal ('..')",
                    label,
                    path.display()
                ));
            }
            std::path::Component::Normal(segment) => {
                if segment.to_string_lossy() == ".." {
                    return Err(format!(
                        "{} '{}' must not contain parent traversal ('..')",
                        label,
                        path.display()
                    ));
                }
                normalized.push(segment);
            }
        }
    }
    Ok(normalized)
}

pub fn validate_path_within_isolated_root(
    candidate: &std::path::Path,
    isolated_root: &std::path::Path,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    let norm_root = normalize_lexical_path(isolated_root, "isolated_root")?;
    if !norm_root.is_absolute() {
        return Err(format!(
            "isolated_root '{}' must be an absolute path",
            isolated_root.display()
        ));
    }
    let norm_candidate = normalize_lexical_path(candidate, label)?;
    if !norm_candidate.is_absolute() {
        return Err(format!(
            "{} '{}' must be an absolute path when isolated root '{}' is active",
            label,
            candidate.display(),
            norm_root.display()
        ));
    }
    if !norm_candidate.starts_with(&norm_root) || norm_candidate == norm_root {
        return Err(format!(
            "{} '{}' is outside active isolated root '{}'",
            label,
            candidate.display(),
            norm_root.display()
        ));
    }
    Ok(norm_candidate)
}

fn unescape_env_file_value(raw_val: &str) -> String {
    let trimmed = raw_val.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        let quote_char = trimmed.chars().next().unwrap_or('"');
        let inner = &trimmed[1..trimmed.len() - 1];
        if quote_char == '\'' {
            return inner.to_string();
        }
        let mut decoded = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => decoded.push('\n'),
                    Some('r') => decoded.push('\r'),
                    Some('t') => decoded.push('\t'),
                    Some('\\') => decoded.push('\\'),
                    Some('"') => decoded.push('"'),
                    Some('$') => decoded.push('$'),
                    Some('`') => decoded.push('`'),
                    Some(other_ch) => {
                        decoded.push('\\');
                        decoded.push(other_ch);
                    }
                    None => decoded.push('\\'),
                }
            } else {
                decoded.push(ch);
            }
        }
        return decoded;
    }
    trimmed.to_string()
}

pub fn parse_key_value_env_str(contents: &str) -> HashMap<String, String> {
    let mut parsed_map = HashMap::new();
    for raw_line in contents.lines() {
        let trimmed_line = raw_line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }
        let without_export = trimmed_line
            .strip_prefix("export ")
            .map(str::trim)
            .unwrap_or(trimmed_line);
        let Some((raw_key, raw_val)) = without_export.split_once('=') else {
            continue;
        };
        let key_name = raw_key.trim();
        if key_name.is_empty() {
            continue;
        }
        let value_str = unescape_env_file_value(raw_val);
        if !value_str.is_empty() {
            parsed_map.insert(key_name.to_string(), value_str);
        }
    }
    parsed_map
}

fn load_authoritative_env_fallback_map<F>(
    isolated_root: Option<&std::path::Path>,
    allow_host_etc_fallback: bool,
    get_env: &mut F,
) -> Result<HashMap<String, String>, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut combined = HashMap::new();
    let mut candidate_files: Vec<std::path::PathBuf> = Vec::new();

    if let Some(root_path) = isolated_root {
        candidate_files.push(root_path.join("etc/aetherflow/release-manager.conf"));
        candidate_files.push(root_path.join("etc/aetherflow/aetherflow.env"));
        candidate_files.push(root_path.join("etc/AetherFlow/.env"));
    } else if allow_host_etc_fallback {
        candidate_files.push(std::path::PathBuf::from(
            "/etc/aetherflow/release-manager.conf",
        ));
        candidate_files.push(std::path::PathBuf::from("/etc/aetherflow/aetherflow.env"));
    }

    if let Some(explicit_env_file) = get_env("AETHERFLOW_ENV_FILE") {
        let trimmed_file = explicit_env_file.trim();
        if !trimmed_file.is_empty() {
            let env_file_path = std::path::PathBuf::from(trimmed_file);
            if let Some(root_path) = isolated_root {
                validate_path_within_isolated_root(
                    &env_file_path,
                    root_path,
                    "AETHERFLOW_ENV_FILE",
                )?;
            }
            candidate_files.push(env_file_path);
        }
    }

    for file_path in candidate_files {
        if let Ok(meta) = std::fs::symlink_metadata(&file_path) {
            if meta.file_type().is_file() {
                if let Ok(contents) = std::fs::read_to_string(&file_path) {
                    for (entry_key, entry_val) in parse_key_value_env_str(&contents) {
                        combined.insert(entry_key, entry_val);
                    }
                }
            }
        }
    }

    Ok(combined)
}

pub fn try_resolve_isolated_root_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    mut get_env: F,
) -> Result<Option<std::path::PathBuf>, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut roots: Vec<(&str, std::path::PathBuf)> = Vec::new();
    if let Some(root) = explicit_root {
        if !root.as_os_str().is_empty() {
            let norm = normalize_lexical_path(root, "--root")?;
            roots.push(("--root", norm));
        }
    }
    for key in ["AETHERFLOW_BACKUP_ISOLATED_ROOT", "AETHERFLOW_RELEASE_ROOT"] {
        if let Some(val) = get_env(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                let norm = normalize_lexical_path(std::path::Path::new(trimmed), key)?;
                roots.push((key, norm));
            }
        }
    }
    if let Some((first_label, first_path)) = roots.first() {
        let first_norm = normalize_path_for_comparison(first_path);
        for (other_label, other_path) in roots.iter().skip(1) {
            let other_norm = normalize_path_for_comparison(other_path);
            if first_norm != other_norm {
                return Err(format!(
                    "conflicting isolated root overrides: {}='{}' vs {}='{}'",
                    first_label,
                    first_path.display(),
                    other_label,
                    other_path.display()
                ));
            }
        }
        return Ok(Some(first_path.clone()));
    }
    Ok(None)
}

fn try_resolve_active_db_path_internal<F>(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
    allow_host_etc_fallback: bool,
    mut get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc_fallback,
        &mut get_env,
    )?;

    let mut db_overrides: Vec<(&str, std::path::PathBuf)> = Vec::new();
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        if let Some(val) = get_env(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                db_overrides.push((key, std::path::PathBuf::from(trimmed)));
            }
        }
    }
    if db_overrides.is_empty() {
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = file_env_map.get(key) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    db_overrides.push((key, std::path::PathBuf::from(trimmed)));
                }
            }
        }
    }

    let configured_data_dir = get_env("DATA_DIR")
        .or_else(|| file_env_map.get("DATA_DIR").cloned())
        .map(|raw_dir| raw_dir.trim().to_string())
        .filter(|trimmed_dir| !trimmed_dir.is_empty());

    let custom_non_default_data_dir = configured_data_dir.as_deref().filter(|dir_str| {
        normalize_path_for_comparison(std::path::Path::new(dir_str)) != "/var/lib/aetherflow"
    });

    let file_has_explicit_default_db =
        ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"]
            .iter()
            .any(|key| {
                file_env_map
                    .get(*key)
                    .map(|val| {
                        normalize_path_for_comparison(std::path::Path::new(val.trim()))
                            == "/var/lib/aetherflow/aetherflow.sqlite"
                    })
                    .unwrap_or(false)
            });

    if let Some((first_key, first_path)) = db_overrides.first() {
        let first_norm = normalize_path_for_comparison(first_path);
        for (other_key, other_path) in db_overrides.iter().skip(1) {
            let other_norm = normalize_path_for_comparison(other_path);
            if first_norm != other_norm {
                return Err(format!(
                    "conflicting database path overrides: {}='{}' vs {}='{}'",
                    first_key,
                    first_path.display(),
                    other_key,
                    other_path.display()
                ));
            }
        }
        let is_legacy_unit_default_db = first_norm == "/var/lib/aetherflow/aetherflow.sqlite"
            && *first_key != "AF_DB_PATH"
            && !file_has_explicit_default_db;
        if !(is_legacy_unit_default_db
            && custom_non_default_data_dir.is_some()
            && isolated_root.is_none())
        {
            if let Some(ref root_path) = isolated_root {
                return validate_path_within_isolated_root(first_path, root_path, first_key);
            }
            return normalize_lexical_path(first_path, first_key);
        }
    }

    if let Some(ref root_path) = isolated_root {
        if let Some(custom_dir) = custom_non_default_data_dir {
            let candidate_db = std::path::Path::new(custom_dir).join("aetherflow.sqlite");
            return validate_path_within_isolated_root(&candidate_db, root_path, "DATA_DIR");
        }
        return Ok(root_path.join("var/lib/aetherflow/aetherflow.sqlite"));
    }

    if let Some(custom_dir) = custom_non_default_data_dir {
        let candidate_db = std::path::Path::new(custom_dir).join("aetherflow.sqlite");
        return normalize_lexical_path(&candidate_db, "DATA_DIR");
    }

    if let Some(state_dir) = get_env("STATE_DIRECTORY") {
        if let Some(first_dir) = state_dir
            .split(':')
            .map(str::trim)
            .find(|entry| !entry.is_empty())
        {
            return Ok(std::path::Path::new(first_dir).join("aetherflow.sqlite"));
        }
    }

    if let Some(ref data_dir) = configured_data_dir {
        return Ok(std::path::Path::new(data_dir).join("aetherflow.sqlite"));
    }

    Ok(std::path::PathBuf::from(default_fallback))
}

pub fn try_resolve_active_db_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
    get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    try_resolve_active_db_path_internal(explicit_root, default_fallback, false, get_env)
}

pub fn try_resolve_active_db_path_from_env(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
) -> Result<std::path::PathBuf, String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    try_resolve_active_db_path_internal(explicit_root, default_fallback, allow_host_etc, |key| {
        std::env::var(key).ok()
    })
}

pub fn resolve_active_db_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
    mut get_env: F,
) -> std::path::PathBuf
where
    F: FnMut(&str) -> Option<String>,
{
    match try_resolve_active_db_path_with_env(explicit_root, default_fallback, &mut get_env) {
        Ok(resolved_path) => resolved_path,
        Err(_) => {
            if let Ok(Some(root_path)) =
                try_resolve_isolated_root_with_env(explicit_root, &mut get_env)
            {
                return root_path.join("var/lib/aetherflow/aetherflow.sqlite");
            }
            if let Some(root_path) =
                explicit_root.filter(|path_val| !path_val.as_os_str().is_empty())
            {
                return root_path.join("var/lib/aetherflow/aetherflow.sqlite");
            }
            std::path::PathBuf::from(default_fallback)
        }
    }
}

pub fn resolve_active_db_path_from_env(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
) -> std::path::PathBuf {
    match try_resolve_active_db_path_from_env(explicit_root, default_fallback) {
        Ok(resolved_path) => resolved_path,
        Err(_) => resolve_active_db_path_with_env(explicit_root, default_fallback, |key| {
            std::env::var(key).ok()
        }),
    }
}

fn try_resolve_active_backup_dir_internal<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
    allow_host_etc_fallback: bool,
    mut get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc_fallback,
        &mut get_env,
    )?;

    if let Some(val) = get_env("AETHERFLOW_BACKUP_DIR")
        .or_else(|| file_env_map.get("AETHERFLOW_BACKUP_DIR").cloned())
    {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            let candidate_dir = std::path::PathBuf::from(trimmed);
            if let Some(ref root_path) = isolated_root {
                return validate_path_within_isolated_root(
                    &candidate_dir,
                    root_path,
                    "AETHERFLOW_BACKUP_DIR",
                );
            }
            return normalize_lexical_path(&candidate_dir, "AETHERFLOW_BACKUP_DIR");
        }
    }

    if let Some(db_path) = active_db_path {
        if !db_path.as_os_str().is_empty() {
            if let Some(ref root_path) = isolated_root {
                validate_path_within_isolated_root(db_path, root_path, "active_db_path")?;
            }
            if let Some(parent) = db_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let candidate_dir = parent.join("backups");
                    if let Some(ref root_path) = isolated_root {
                        return validate_path_within_isolated_root(
                            &candidate_dir,
                            root_path,
                            "backup_dir",
                        );
                    }
                    return Ok(candidate_dir);
                }
            }
        }
    }

    let resolved_db = try_resolve_active_db_path_internal(
        explicit_root,
        "",
        allow_host_etc_fallback,
        &mut get_env,
    )?;
    if !resolved_db.as_os_str().is_empty() {
        if let Some(parent) = resolved_db.parent() {
            if !parent.as_os_str().is_empty() {
                let candidate_dir = parent.join("backups");
                if let Some(ref root_path) = isolated_root {
                    return validate_path_within_isolated_root(
                        &candidate_dir,
                        root_path,
                        "backup_dir",
                    );
                }
                return Ok(candidate_dir);
            }
        }
    }

    if let Some(root_path) = isolated_root {
        return Ok(root_path.join("var/lib/aetherflow/backups"));
    }

    Ok(std::path::PathBuf::from(default_fallback))
}

pub fn try_resolve_active_backup_dir_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
    get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    try_resolve_active_backup_dir_internal(
        explicit_root,
        active_db_path,
        default_fallback,
        false,
        get_env,
    )
}

pub fn try_resolve_active_backup_dir_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
) -> Result<std::path::PathBuf, String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    try_resolve_active_backup_dir_internal(
        explicit_root,
        active_db_path,
        default_fallback,
        allow_host_etc,
        |key| std::env::var(key).ok(),
    )
}

pub fn resolve_active_backup_dir_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
    mut get_env: F,
) -> std::path::PathBuf
where
    F: FnMut(&str) -> Option<String>,
{
    match try_resolve_active_backup_dir_with_env(
        explicit_root,
        active_db_path,
        default_fallback,
        &mut get_env,
    ) {
        Ok(resolved_dir) => resolved_dir,
        Err(_) => {
            if let Ok(Some(root_path)) =
                try_resolve_isolated_root_with_env(explicit_root, &mut get_env)
            {
                return root_path.join("var/lib/aetherflow/backups");
            }
            if let Some(root_path) =
                explicit_root.filter(|path_val| !path_val.as_os_str().is_empty())
            {
                return root_path.join("var/lib/aetherflow/backups");
            }
            std::path::PathBuf::from(default_fallback)
        }
    }
}

pub fn resolve_active_backup_dir_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
) -> std::path::PathBuf {
    match try_resolve_active_backup_dir_from_env(explicit_root, active_db_path, default_fallback) {
        Ok(resolved_dir) => resolved_dir,
        Err(_) => resolve_active_backup_dir_with_env(
            explicit_root,
            active_db_path,
            default_fallback,
            |key| std::env::var(key).ok(),
        ),
    }
}

fn map_default_lock_parent_to_shared_runtime_anchor(
    candidate_parent: &std::path::Path,
    isolated_root: Option<&std::path::Path>,
) -> std::path::PathBuf {
    let normalized_parent = normalize_path_for_comparison(candidate_parent);
    if isolated_root.is_none() && normalized_parent == "/var/lib/aetherflow" {
        return std::path::PathBuf::from("/run/aetherflow/.snapshot.lock");
    }
    if let Some(root_path) = isolated_root {
        let isolated_var_lib = root_path.join("var/lib/aetherflow");
        if normalize_path_for_comparison(&isolated_var_lib) == normalized_parent {
            let isolated_run_dir = root_path.join("run/aetherflow");
            let mut use_run_anchor = isolated_run_dir.exists();
            #[cfg(unix)]
            if !use_run_anchor {
                use std::os::unix::fs::MetadataExt;
                if let (Ok(root_meta), Ok(var_meta)) = (
                    std::fs::symlink_metadata(root_path),
                    std::fs::symlink_metadata(&isolated_var_lib),
                ) {
                    if root_meta.uid() == 0 && var_meta.uid() != 0 {
                        use_run_anchor = true;
                    }
                }
            }
            if use_run_anchor {
                return isolated_run_dir.join(".snapshot.lock");
            }
        }
    }
    candidate_parent.join(".snapshot.lock")
}

fn try_resolve_canonical_maintenance_lock_path_internal<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
    allow_host_etc_fallback: bool,
    mut get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc_fallback,
        &mut get_env,
    )?;

    if let Some(val) = get_env("AETHERFLOW_MAINTENANCE_LOCK_PATH").or_else(|| {
        file_env_map
            .get("AETHERFLOW_MAINTENANCE_LOCK_PATH")
            .cloned()
    }) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            let candidate_lock = std::path::PathBuf::from(trimmed);
            if let Some(ref root_path) = isolated_root {
                return validate_path_within_isolated_root(
                    &candidate_lock,
                    root_path,
                    "AETHERFLOW_MAINTENANCE_LOCK_PATH",
                );
            }
            return normalize_lexical_path(&candidate_lock, "AETHERFLOW_MAINTENANCE_LOCK_PATH");
        }
    }

    if let Some(db_path) = active_db_path {
        if !db_path.as_os_str().is_empty() {
            if let Some(ref root_path) = isolated_root {
                validate_path_within_isolated_root(db_path, root_path, "active_db_path")?;
            }
            if let Some(parent) = db_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let candidate_lock = map_default_lock_parent_to_shared_runtime_anchor(
                        parent,
                        isolated_root.as_deref(),
                    );
                    if let Some(ref root_path) = isolated_root {
                        return validate_path_within_isolated_root(
                            &candidate_lock,
                            root_path,
                            "maintenance_lock_path",
                        );
                    }
                    return Ok(candidate_lock);
                }
            }
        }
    }

    let resolved_db = try_resolve_active_db_path_internal(
        explicit_root,
        "",
        allow_host_etc_fallback,
        &mut get_env,
    )?;
    if !resolved_db.as_os_str().is_empty() {
        if let Some(parent) = resolved_db.parent() {
            if !parent.as_os_str().is_empty() {
                let candidate_lock = map_default_lock_parent_to_shared_runtime_anchor(
                    parent,
                    isolated_root.as_deref(),
                );
                if let Some(ref root_path) = isolated_root {
                    return validate_path_within_isolated_root(
                        &candidate_lock,
                        root_path,
                        "maintenance_lock_path",
                    );
                }
                return Ok(candidate_lock);
            }
        }
    }

    if let Some(ref root_path) = isolated_root {
        let isolated_var_lib = root_path.join("var/lib/aetherflow");
        return Ok(map_default_lock_parent_to_shared_runtime_anchor(
            &isolated_var_lib,
            Some(root_path),
        ));
    }

    if let Some(data_dir) = get_env("DATA_DIR").or_else(|| file_env_map.get("DATA_DIR").cloned()) {
        let trimmed = data_dir.trim();
        if !trimmed.is_empty() {
            return Ok(map_default_lock_parent_to_shared_runtime_anchor(
                std::path::Path::new(trimmed),
                None,
            ));
        }
    }

    if let Some(dir) = fallback_dir {
        if let Some(parent) = dir.parent() {
            if dir.file_name().and_then(|os_str| os_str.to_str()) == Some("backups")
                && !parent.as_os_str().is_empty()
            {
                return Ok(map_default_lock_parent_to_shared_runtime_anchor(
                    parent, None,
                ));
            }
        }
        return Ok(map_default_lock_parent_to_shared_runtime_anchor(dir, None));
    }

    Ok(std::path::PathBuf::from("/run/aetherflow/.snapshot.lock"))
}

pub fn try_resolve_trusted_sqlite_ids_from_env(
    explicit_root: Option<&std::path::Path>,
) -> Result<(Option<u32>, Option<u32>), String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    let mut get_env = |key: &str| std::env::var(key).ok();
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc,
        &mut get_env,
    )?;

    let parse_optional_u32 = |keys: &[&str], label: &str| -> Result<Option<u32>, String> {
        for key in keys {
            let raw_opt = get_env(key).or_else(|| file_env_map.get(*key).cloned());
            if let Some(raw_val) = raw_opt {
                let trimmed = raw_val.trim();
                if !trimmed.is_empty() {
                    let parsed = trimmed
                        .parse::<u32>()
                        .map_err(|_| format!("invalid numeric {} '{}'", label, trimmed))?;
                    return Ok(Some(parsed));
                }
            }
        }
        Ok(None)
    };

    let uid_opt = parse_optional_u32(
        &["AETHERFLOW_TRUSTED_SQLITE_UID", "AETHERFLOW_SQLITE_UID"],
        "trusted_sqlite_uid",
    )?;
    let gid_opt = parse_optional_u32(
        &["AETHERFLOW_TRUSTED_SQLITE_GID", "AETHERFLOW_SQLITE_GID"],
        "trusted_sqlite_gid",
    )?;
    Ok((uid_opt, gid_opt))
}

pub fn resolve_trusted_sqlite_ids_from_env(
    explicit_root: Option<&std::path::Path>,
) -> (Option<u32>, Option<u32>) {
    try_resolve_trusted_sqlite_ids_from_env(explicit_root).unwrap_or((None, None))
}

pub fn try_resolve_canonical_maintenance_lock_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
    get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    try_resolve_canonical_maintenance_lock_path_internal(
        explicit_root,
        active_db_path,
        fallback_dir,
        false,
        get_env,
    )
}

pub fn try_resolve_canonical_maintenance_lock_path_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    try_resolve_canonical_maintenance_lock_path_internal(
        explicit_root,
        active_db_path,
        fallback_dir,
        allow_host_etc,
        |key| std::env::var(key).ok(),
    )
}

pub fn resolve_canonical_maintenance_lock_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
    mut get_env: F,
) -> std::path::PathBuf
where
    F: FnMut(&str) -> Option<String>,
{
    match try_resolve_canonical_maintenance_lock_path_with_env(
        explicit_root,
        active_db_path,
        fallback_dir,
        &mut get_env,
    ) {
        Ok(resolved_lock) => resolved_lock,
        Err(_) => {
            if let Ok(Some(root_path)) =
                try_resolve_isolated_root_with_env(explicit_root, &mut get_env)
            {
                let isolated_var_lib = root_path.join("var/lib/aetherflow");
                return map_default_lock_parent_to_shared_runtime_anchor(
                    &isolated_var_lib,
                    Some(&root_path),
                );
            }
            if let Some(root_path) =
                explicit_root.filter(|path_val| !path_val.as_os_str().is_empty())
            {
                let isolated_var_lib = root_path.join("var/lib/aetherflow");
                return map_default_lock_parent_to_shared_runtime_anchor(
                    &isolated_var_lib,
                    Some(root_path),
                );
            }
            std::path::PathBuf::from("/run/aetherflow/.snapshot.lock")
        }
    }
}

pub fn resolve_canonical_maintenance_lock_path_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
) -> std::path::PathBuf {
    match try_resolve_canonical_maintenance_lock_path_from_env(
        explicit_root,
        active_db_path,
        fallback_dir,
    ) {
        Ok(resolved_lock) => resolved_lock,
        Err(_) => resolve_canonical_maintenance_lock_path_with_env(
            explicit_root,
            active_db_path,
            fallback_dir,
            |key| std::env::var(key).ok(),
        ),
    }
}

pub fn derive_sqlite_target_rel_path(
    target_root: &std::path::Path,
    configured_db_path: &std::path::Path,
) -> Option<String> {
    if configured_db_path.as_os_str().is_empty() {
        return None;
    }
    let norm_root = normalize_lexical_path(target_root, "target_root").ok()?;
    let norm_db = normalize_lexical_path(configured_db_path, "configured_db_path").ok()?;
    if let Ok(stripped) = norm_db.strip_prefix(&norm_root) {
        let rel = stripped
            .to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();
        if !rel.is_empty() {
            return Some(rel);
        }
    }
    let root_norm = normalize_path_for_comparison(&norm_root);
    if root_norm == "/" {
        let rel = norm_db
            .to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();
        if !rel.is_empty() {
            return Some(rel);
        }
    }
    if let Some(parent) = norm_db.parent() {
        if normalize_path_for_comparison(parent) == root_norm {
            if let Some(name) = norm_db.file_name().and_then(|os_name| os_name.to_str()) {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

pub fn resolve_contained_sqlite_restore_override(
    target_root: &std::path::Path,
    configured_db_path: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    let db_path = configured_db_path?;
    if db_path.as_os_str().is_empty() {
        return None;
    }
    let norm_root = normalize_lexical_path(target_root, "target_root").ok()?;
    let norm_db = normalize_lexical_path(db_path, "configured_db_path").ok()?;
    if !norm_root.is_absolute() || !norm_db.is_absolute() {
        return None;
    }
    if normalize_path_for_comparison(&norm_root) == "/" {
        return Some(norm_db);
    }
    if norm_db.starts_with(&norm_root) && norm_db != norm_root {
        return Some(norm_db);
    }
    None
}
