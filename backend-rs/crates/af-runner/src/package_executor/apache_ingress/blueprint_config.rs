use super::*;

pub(in crate::package_executor) fn write_config_atomic_preserving_meta(
    file_path: &Path,
    content: &[u8],
    fs_root: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(file_path, fs_root)?;
    let existing_meta = match fs::symlink_metadata(file_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "refusing to overwrite non-regular config file {}",
                    file_path.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing to overwrite hardlinked config file {} (nlink={})",
                        file_path.display(),
                        meta.nlink()
                    )));
                }
            }
            Some(meta)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        existing_meta
            .as_ref()
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o600)
    };
    #[cfg(not(unix))]
    let mode = 0o600;

    write_file_atomic_with_mode_bounded(file_path, content, mode, fs_root)?;

    #[cfg(unix)]
    if let Some(meta) = existing_meta {
        use std::os::unix::fs::{chown, MetadataExt};
        let _ = chown(file_path, Some(meta.uid()), Some(meta.gid()));
        let _ = fs::set_permissions(file_path, meta.permissions());
    }
    Ok(())
}

pub(in crate::package_executor) fn runner_candidate_exists_or_symlink(p: &Path) -> Result<bool, PackageExecutorError> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect required blueprint config {}: {}",
            p.display(),
            err
        ))),
    }
}

pub(in crate::package_executor) fn validate_regular_config_candidate(
    file_path: &Path,
    fs_root: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(file_path, fs_root)?;
    let meta = fs::symlink_metadata(file_path)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to use non-regular config file {}",
            file_path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to use hardlinked config file {} (nlink={})",
                file_path.display(),
                meta.nlink()
            )));
        }
    }
    Ok(())
}

pub(in crate::package_executor) fn runner_mutate_xml_tag(
    file_path: &Path,
    tag_name: &str,
    new_value: &str,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    if !runner_candidate_exists_or_symlink(file_path)? {
        return Ok(false);
    }
    validate_regular_config_candidate(file_path, fs_root)?;
    let existing = fs::read_to_string(file_path)?;
    let root_tag = if existing.contains("<NetworkConfiguration") {
        "NetworkConfiguration"
    } else if existing.contains("<ServerConfiguration") {
        "ServerConfiguration"
    } else {
        "Config"
    };
    let escaped_tag = regex::escape(tag_name);
    if tag_name == "KnownProxies" && root_tag == "NetworkConfiguration" {
        let escaped_val = regex::escape(new_value.trim());
        let check_re = Regex::new(&format!(
            r"(?is)<KnownProxies>\s*<string>\s*{}\s*</string>\s*</KnownProxies>",
            escaped_val
        ))
        .unwrap();
        if check_re.is_match(&existing) {
            return Ok(false);
        }
    } else {
        let extract_re =
            Regex::new(&format!(r"(?is)<{0}>\s*([^<]*?)\s*</{0}>", escaped_tag)).unwrap();
        if let Some(caps) = extract_re.captures(&existing) {
            if caps.get(1).map(|m| m.as_str().trim()) == Some(new_value.trim()) {
                return Ok(false);
            }
        }
    }

    let mut content = existing.clone();
    let closing_tag = format!("</{}>", root_tag);
    if tag_name == "KnownProxies" && root_tag == "NetworkConfiguration" {
        let re_known =
            Regex::new(r"(?s)<KnownProxies\s*/>|<KnownProxies>.*?</KnownProxies>").unwrap();
        let replacement = format!(
            "<KnownProxies>\n    <string>{}</string>\n  </KnownProxies>",
            new_value
        );
        if re_known.is_match(&content) {
            content = re_known
                .replace_all(&content, replacement.as_str())
                .into_owned();
        } else if let Some(idx) = content.rfind(&closing_tag) {
            content.insert_str(idx, &format!("  {}\n", replacement));
        }
    } else {
        let re_tag = Regex::new(&format!(r"(?s)<{0}>.*?</{0}>|<{0}\s*/>", escaped_tag)).unwrap();
        let new_elem = format!("<{0}>{1}</{0}>", tag_name, new_value);
        if re_tag.is_match(&content) {
            content = re_tag.replace_all(&content, new_elem.as_str()).into_owned();
        } else if let Some(idx) = content.rfind(&closing_tag) {
            content.insert_str(idx, &format!("  {}\n", new_elem));
        }
    }
    if content == existing {
        return Ok(false);
    }
    write_config_atomic_preserving_meta(file_path, content.as_bytes(), fs_root)?;
    Ok(true)
}

pub(in crate::package_executor) fn runner_mutate_ini_key(
    file_path: &Path,
    section: &str,
    key: &str,
    new_value: &str,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    if !runner_candidate_exists_or_symlink(file_path)? {
        return Ok(false);
    }
    validate_regular_config_candidate(file_path, fs_root)?;
    let existing = fs::read_to_string(file_path)?;
    let key_trimmed = key.trim();
    let section_trimmed = section.trim();
    let want_sec_lower = section_trimmed.to_lowercase();
    let mut current_section = String::new();
    let mut found_section = want_sec_lower.is_empty();
    let mut key_updated = false;
    let mut output_lines: Vec<String> = Vec::new();
    let mut insert_after_section_idx: Option<usize> = None;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            output_lines.push(line.to_string());
            if !want_sec_lower.is_empty() && current_section == want_sec_lower {
                found_section = true;
                insert_after_section_idx = Some(output_lines.len());
            }
            continue;
        }
        let in_matching_section = want_sec_lower.is_empty()
            || current_section == want_sec_lower
            || current_section.is_empty();
        if !key_updated
            && in_matching_section
            && !trimmed.starts_with('#')
            && !trimmed.starts_with(';')
        {
            if let Some((lhs, rhs)) = line.split_once('=') {
                if lhs.trim().eq_ignore_ascii_case(key_trimmed) {
                    if rhs.trim() == new_value.trim() {
                        return Ok(false);
                    }
                    output_lines.push(format!("{}={}", lhs, new_value));
                    key_updated = true;
                    continue;
                }
            }
        }
        output_lines.push(line.to_string());
        if !want_sec_lower.is_empty() && current_section == want_sec_lower {
            insert_after_section_idx = Some(output_lines.len());
        }
    }

    if !key_updated {
        let new_line = format!("{}={}", key_trimmed, new_value);
        if let Some(idx) = insert_after_section_idx {
            output_lines.insert(idx, new_line);
        } else if !found_section && !want_sec_lower.is_empty() {
            if !output_lines.is_empty() && !output_lines.last().unwrap().trim().is_empty() {
                output_lines.push(String::new());
            }
            output_lines.push(format!("[{}]", section_trimmed));
            output_lines.push(new_line);
        } else {
            output_lines.push(new_line);
        }
    }

    let final_content = format!("{}\n", output_lines.join("\n"));
    if final_content == existing {
        return Ok(false);
    }
    write_config_atomic_preserving_meta(file_path, final_content.as_bytes(), fs_root)?;
    Ok(true)
}

pub(in crate::package_executor) fn runner_mutate_json_key(
    file_path: &Path,
    key: &str,
    new_value: serde_json::Value,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    if !runner_candidate_exists_or_symlink(file_path)? {
        return Ok(false);
    }
    validate_regular_config_candidate(file_path, fs_root)?;
    let existing = fs::read_to_string(file_path)?;
    let mut root = serde_json::from_str::<serde_json::Value>(&existing).map_err(|err| {
        PackageExecutorError::VerificationFailed(format!(
            "invalid JSON config {}: {}",
            file_path.display(),
            err
        ))
    })?;
    let Some(obj) = root.as_object_mut() else {
        return Err(PackageExecutorError::VerificationFailed(format!(
            "JSON config {} root is not an object",
            file_path.display()
        )));
    };
    let mut changed = false;
    if let Some((parent_key, child_key)) = key.split_once('.') {
        if obj.contains_key(key) {
            if obj.get(key) != Some(&new_value) {
                obj.insert(key.to_string(), new_value);
                changed = true;
            }
        } else {
            let entry = obj
                .entry(parent_key.to_string())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            let Some(sub) = entry.as_object_mut() else {
                return Err(PackageExecutorError::VerificationFailed(format!(
                    "JSON config {} key '{}' is not an object",
                    file_path.display(),
                    parent_key
                )));
            };
            if sub.get(child_key) != Some(&new_value) {
                sub.insert(child_key.to_string(), new_value);
                changed = true;
            }
        }
    } else if obj.get(key) != Some(&new_value) {
        obj.insert(key.to_string(), new_value);
        changed = true;
    }
    if !changed {
        return Ok(false);
    }
    let serialized = serde_json::to_string_pretty(&root).map_err(|err| {
        PackageExecutorError::VerificationFailed(format!(
            "failed to serialize JSON config {}: {}",
            file_path.display(),
            err
        ))
    })?;
    let final_content = format!("{}\n", serialized);
    write_config_atomic_preserving_meta(file_path, final_content.as_bytes(), fs_root)?;
    Ok(true)
}

/// Applies post-install blueprint config mutations inside the privileged runner process so that
/// root-owned or service-user-owned config files under `/etc` and `/var/lib` are updated with
/// preserved ownership and permissions before control returns to the unprivileged API process.
pub fn apply_runner_blueprint_app_config(fs_root: Option<&Path>, pkg_id: &str, listen_port: i32) {
    let _ = try_apply_runner_blueprint_app_config(fs_root, pkg_id, listen_port);
}

/// Fallible variant of [`apply_runner_blueprint_app_config`] that validates candidate config files
/// against symlinks/hardlinks and propagates any config mutation or verification errors.
pub fn try_apply_runner_blueprint_app_config(
    fs_root: Option<&Path>,
    pkg_id: &str,
    listen_port: i32,
) -> Result<(), PackageExecutorError> {
    try_apply_runner_blueprint_app_config_with_ingress(fs_root, pkg_id, listen_port, |canonical| {
        let load_error = |err| {
            PackageExecutorError::VerificationFailed(format!(
                "failed to load blueprint ingress for {canonical}: {err}",
            ))
        };
        match af_db::get_conn() {
            Ok(conn) => load_runner_blueprint_ingress(&conn, canonical),
            Err(_) => {
                let conn = crate::open_runner_state_database(fs_root).map_err(load_error)?;
                load_runner_blueprint_ingress(&conn, canonical)
            }
        }
    })
}

pub(crate) async fn apply_runner_blueprint_in_background(
    fs_root: Option<PathBuf>,
    package: String,
    port: i32,
) -> Result<(), PackageExecutorError> {
    let lease = crate::PACKAGE_MAINTENANCE_LEASE.try_with(Arc::clone).ok();
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        try_apply_runner_blueprint_app_config(fs_root.as_deref(), &package, port)
    })
    .await
    .map_err(|error| PackageExecutorError::VerificationFailed(error.to_string()))?
}

pub(in crate::package_executor) fn load_runner_blueprint_ingress(
    conn: &rusqlite::Connection,
    canonical: &str,
) -> Result<Option<af_models::AppIngressConfig>, PackageExecutorError> {
    af_db::load_lifecycle_ingress(conn, canonical).map_err(|err| {
        PackageExecutorError::VerificationFailed(format!(
            "failed to load blueprint ingress for {}: {}",
            canonical, err
        ))
    })
}

pub(in crate::package_executor) struct RunnerBlueprintConfigBackup {
    path: PathBuf,
    previous: Option<(Vec<u8>, fs::Metadata)>,
}

impl RunnerBlueprintConfigBackup {
    fn read(path: &Path, fs_root: Option<&Path>) -> Result<Self, PackageExecutorError> {
        validate_filesystem_path(path, fs_root)?;
        let previous = match crate::blueprint::open_mutation_file(path) {
            Ok(file) => {
                const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
                let metadata = file.metadata()?;
                let mut content = Vec::new();
                file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut content)?;
                if content.len() as u64 > MAX_CONFIG_BYTES {
                    return Err(PackageExecutorError::VerificationFailed(format!(
                        "blueprint config {} exceeds 2 MiB",
                        path.display()
                    )));
                }
                Some((content, metadata))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PackageExecutorError::VerificationFailed(format!(
                    "failed to inspect blueprint config {}: {}",
                    path.display(),
                    err
                )));
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            previous,
        })
    }

    fn restore(&self, fs_root: Option<&Path>) -> Result<(), PackageExecutorError> {
        let current = Self::read(&self.path, fs_root)?;
        match &self.previous {
            Some((content, metadata)) => {
                if current.previous.as_ref().map(|(raw, _)| raw) != Some(content) {
                    #[cfg(unix)]
                    let mode = {
                        use std::os::unix::fs::PermissionsExt;
                        metadata.permissions().mode() & 0o7777
                    };
                    #[cfg(not(unix))]
                    let mode = 0o644;
                    write_file_atomic_with_mode_bounded(&self.path, content, mode, fs_root)?;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{chown, MetadataExt};
                    let current_metadata = fs::symlink_metadata(&self.path)?;
                    if current_metadata.uid() != metadata.uid()
                        || current_metadata.gid() != metadata.gid()
                    {
                        chown(&self.path, Some(metadata.uid()), Some(metadata.gid()))?;
                    }
                }
                if fs::symlink_metadata(&self.path)?.permissions() != metadata.permissions() {
                    fs::set_permissions(&self.path, metadata.permissions())?;
                }
            }
            None if current.previous.is_some() => fs::remove_file(&self.path)?,
            None => {}
        }
        Ok(())
    }
}

pub(crate) struct RunnerBlueprintConfigChanges<'a> {
    pub(crate) fs_root: Option<&'a Path>,
    backups: Vec<RunnerBlueprintConfigBackup>,
    removed_aliases: Vec<(PathBuf, PathBuf)>,
    changed_units: Vec<String>,
}

impl<'a> RunnerBlueprintConfigChanges<'a> {
    pub(crate) fn new(fs_root: Option<&'a Path>) -> Self {
        Self {
            fs_root,
            backups: Vec::new(),
            removed_aliases: Vec::new(),
            changed_units: Vec::new(),
        }
    }

    pub(crate) fn capture(&mut self, path: &Path) -> Result<(), PackageExecutorError> {
        if !self.backups.iter().any(|backup| backup.path == path) {
            self.backups
                .push(RunnerBlueprintConfigBackup::read(path, self.fs_root)?);
        }
        Ok(())
    }

    pub(in crate::package_executor) fn write_vhost(
        &mut self,
        path: &Path,
        content: &str,
    ) -> Result<(), PackageExecutorError> {
        self.capture(path)?;
        write_file_atomic_with_mode_bounded(path, content.as_bytes(), 0o644, self.fs_root).map_err(
            |err| {
                PackageExecutorError::VerificationFailed(format!(
                    "failed to write required Apache vhost {}: {}",
                    path.display(),
                    err
                ))
            },
        )
    }

    pub(in crate::package_executor) fn remove_vhost(&mut self, path: &Path) -> Result<(), PackageExecutorError> {
        self.capture(path)?;
        validate_regular_config_candidate(path, self.fs_root)?;
        fs::remove_file(path).map_err(|err| {
            PackageExecutorError::VerificationFailed(format!(
                "failed to remove required Apache vhost {}: {}",
                path.display(),
                err
            ))
        })
    }

    fn remove_vhost_alias(&mut self, path: &Path) -> Result<(), PackageExecutorError> {
        if let Some(parent) = path.parent() {
            validate_filesystem_path(parent, self.fs_root)?;
        }
        let target = fs::read_link(path)?;
        fs::remove_file(path)?;
        self.removed_aliases.push((path.to_path_buf(), target));
        Ok(())
    }

    pub(crate) fn rollback(self, error: PackageExecutorError) -> PackageExecutorError {
        if self.backups.is_empty() && self.removed_aliases.is_empty() {
            return error;
        }
        let mut failures = Vec::new();
        for backup in self.backups.into_iter().rev() {
            if let Err(err) = backup.restore(self.fs_root) {
                failures.push(format!(
                    "failed to restore {}: {}",
                    backup.path.display(),
                    err
                ));
            }
        }
        for (path, target) in self.removed_aliases.into_iter().rev() {
            if let Err(err) = std::os::unix::fs::symlink(target, &path) {
                failures.push(format!("failed to restore {}: {err}", path.display()));
            }
        }
        if failures.is_empty() {
            PackageExecutorError::VerificationFailed(format!(
                "{}; restored previous blueprint configuration",
                error
            ))
        } else {
            PackageExecutorError::VerificationFailed(format!(
                "{}; incomplete rollback: {}",
                error,
                failures.join("; ")
            ))
        }
    }
}

/// Collects all candidate blueprint configuration file paths for a package (both application-specific
/// config files and Apache reverse proxy vhosts), rebased under `fs_root` if provided.
pub fn collect_blueprint_target_paths(pkg_id: &str, fs_root: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let canonical = resolve_package_lock_name(pkg_id);
    let rebase = |logical: &str| -> PathBuf {
        match fs_root {
            Some(root) => root.join(logical.trim_start_matches('/')),
            None => PathBuf::from(logical),
        }
    };

    if canonical == "listenarr" {
        paths.push(rebase("/etc/systemd/system/listenarr.service"));
    }
    match canonical {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "whisparr" | "listenarr" => {
            paths.push(rebase(&format!("/var/lib/{}/config.xml", canonical)));
            paths.push(rebase(&format!(
                "/var/lib/{}/.config/{}/config.xml",
                canonical, canonical
            )));
        }
        "jellyfin" => {
            paths.push(rebase("/etc/jellyfin/network.xml"));
            paths.push(rebase("/var/lib/jellyfin/config/network.xml"));
        }
        "emby" => {
            paths.push(rebase("/var/lib/emby/config/system.xml"));
            paths.push(rebase("/var/lib/emby/system.xml"));
        }
        "qbittorrent" => {
            paths.push(rebase(
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
            ));
            paths.push(rebase("/var/lib/qbittorrent/qBittorrent.conf"));
        }
        "sabnzbd" => {
            paths.push(rebase("/var/lib/sabnzbd/sabnzbd.ini"));
            paths.push(rebase("/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini"));
            paths.push(rebase("/etc/sabnzbd/sabnzbd.ini"));
        }
        "tautulli" => {
            paths.push(rebase("/var/lib/tautulli/config.ini"));
            paths.push(rebase("/opt/Tautulli/config.ini"));
        }
        "gitea" => {
            paths.push(rebase("/etc/gitea/app.ini"));
            paths.push(rebase("/var/lib/gitea/custom/conf/app.ini"));
        }
        "transmission" => {
            paths.extend(crate::blueprint::TRANSMISSION_CONFIG_PATHS.map(rebase));
        }
        "overseerr" | "jellyseerr" => {
            paths.push(rebase(&format!("/etc/systemd/system/{canonical}.service")));
            paths.push(rebase(&format!("/var/lib/{canonical}/settings.json")));
            paths.push(rebase(&format!(
                "/var/lib/{canonical}/config/settings.json"
            )));
            paths.push(rebase(&format!("/opt/{canonical}/config/settings.json")));
        }
        "jackett" => {
            paths.push(rebase("/var/lib/jackett/Jackett/ServerConfig.json"));
            paths.push(rebase("/var/lib/jackett/.config/Jackett/ServerConfig.json"));
        }
        _ => {}
    }

    let clean_app: String = canonical
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if !clean_app.is_empty() {
        let sites_avail = rebase("/etc/apache2/sites-available");
        let sites_en = rebase("/etc/apache2/sites-enabled");
        for dir in [&sites_avail, &sites_en] {
            paths.push(dir.join(format!("aetherflow-app-{}.conf", clean_app)));
            paths.push(dir.join(format!("aetherflow-ext-{}.conf", clean_app)));
            paths.push(dir.join(format!("aetherflow-ext-{}-le-ssl.conf", clean_app)));
            paths.push(dir.join(format!("{}.conf", clean_app)));
        }
    }

    paths
}

pub(in crate::package_executor) fn try_apply_runner_blueprint_app_config_with_ingress(
    fs_root: Option<&Path>,
    pkg_id: &str,
    listen_port: i32,
    load_ingress: impl FnOnce(&str) -> Result<Option<af_models::AppIngressConfig>, PackageExecutorError>,
) -> Result<(), PackageExecutorError> {
    let transmission = fs_root.is_none()
        && (1024..=65535).contains(&listen_port)
        && resolve_package_lock_name(pkg_id) == "transmission"
        && crate::blueprint::TRANSMISSION_CONFIG_PATHS
            .iter()
            .any(|path| Path::new(path).symlink_metadata().is_ok());
    crate::blueprint::with_transmission_stopped(
        transmission,
        crate::blueprint::run_systemctl,
        || {
            let mut changes = RunnerBlueprintConfigChanges::new(fs_root);
            if let Err(error) = apply_runner_blueprint_app_config_changes(
                &mut changes,
                pkg_id,
                listen_port,
                load_ingress,
            ) {
                return Err(changes.rollback(error).into());
            }
            if fs_root.is_none() {
                let run = crate::blueprint::run_systemctl;
                if let Err(error) =
                    crate::blueprint::reload_changed_units(&changes.changed_units, run)
                {
                    let units = std::mem::take(&mut changes.changed_units);
                    let rollback = changes
                        .rollback(PackageExecutorError::VerificationFailed(error.to_string()));
                    if let Err(error) = crate::blueprint::reload_changed_units(&units, run) {
                        anyhow::bail!(
                            "{rollback}; reloading restored systemd units failed: {error}"
                        );
                    }
                    return Err(rollback.into());
                }
            }
            Ok(())
        },
    )
    .map_err(|error| {
        error
            .downcast::<PackageExecutorError>()
            .unwrap_or_else(|err| PackageExecutorError::VerificationFailed(err.to_string()))
    })
}

pub(in crate::package_executor) fn apply_runner_blueprint_app_config_changes(
    changes: &mut RunnerBlueprintConfigChanges<'_>,
    pkg_id: &str,
    listen_port: i32,
    load_ingress: impl FnOnce(&str) -> Result<Option<af_models::AppIngressConfig>, PackageExecutorError>,
) -> Result<(), PackageExecutorError> {
    if !(1024..=65535).contains(&listen_port) {
        return Ok(());
    }
    let fs_root = changes.fs_root;
    let canonical = resolve_package_lock_name(pkg_id);
    let rebase = |logical: &str| -> PathBuf {
        match fs_root {
            Some(root) => root.join(logical.trim_start_matches('/')),
            None => PathBuf::from(logical),
        }
    };
    let port_str = listen_port.to_string();

    if canonical == "listenarr" {
        let path = rebase("/etc/systemd/system/listenarr.service");
        if runner_candidate_exists_or_symlink(&path)? {
            changes.capture(&path)?;
            if crate::blueprint::mutate_systemd_aspnetcore_urls(&path, listen_port)
                .map_err(PackageExecutorError::VerificationFailed)?
            {
                changes
                    .changed_units
                    .push(path.to_string_lossy().into_owned());
            }
        }
    }
    let mut ingress = None;
    let mut load_ingress = Some(load_ingress);

    match canonical {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "whisparr" | "listenarr" => {
            static BIND_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"(?is)<BindAddress>\s*([^<]*?)\s*</BindAddress>").unwrap()
            });
            for candidate in [
                format!("/var/lib/{}/config.xml", canonical),
                format!("/var/lib/{}/.config/{}/config.xml", canonical, canonical),
            ] {
                let p = rebase(&candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_bind = BIND_RE
                        .captures(&existing)
                        .and_then(|c| c.get(1))
                        .is_some_and(|m| !m.as_str().trim().is_empty());
                    runner_mutate_xml_tag(&p, "Port", &port_str, fs_root)?;
                    if !has_bind {
                        runner_mutate_xml_tag(&p, "BindAddress", "127.0.0.1", fs_root)?;
                    }
                    runner_mutate_xml_tag(&p, "AuthenticationMethod", "Forms", fs_root)?;
                    runner_mutate_xml_tag(&p, "AnalyticsEnabled", "False", fs_root)?;
                }
            }
        }
        "jellyfin" => {
            static REMOTE_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"(?is)<EnableRemoteAccess>\s*([^<]*?)\s*</EnableRemoteAccess>").unwrap()
            });
            static KNOWN_PROXIES_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"(?is)<KnownProxies>\s*(.*?)\s*</KnownProxies>").unwrap());
            for candidate in [
                "/etc/jellyfin/network.xml",
                "/var/lib/jellyfin/config/network.xml",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_remote_access = REMOTE_ACCESS_RE
                        .captures(&existing)
                        .and_then(|c| c.get(1))
                        .is_some_and(|m| !m.as_str().trim().is_empty());
                    let has_known_proxies = KNOWN_PROXIES_RE
                        .captures(&existing)
                        .and_then(|c| c.get(1))
                        .is_some_and(|m| !m.as_str().trim().is_empty());
                    runner_mutate_xml_tag(&p, "InternalHttpPort", &port_str, fs_root)?;
                    runner_mutate_xml_tag(&p, "PublicHttpPort", &port_str, fs_root)?;
                    runner_mutate_xml_tag(&p, "EnableIPV4", "true", fs_root)?;
                    if !has_remote_access {
                        runner_mutate_xml_tag(&p, "EnableRemoteAccess", "true", fs_root)?;
                    }
                    if !has_known_proxies {
                        runner_mutate_xml_tag(&p, "KnownProxies", "127.0.0.1", fs_root)?;
                    }
                }
            }
        }
        "emby" => {
            for candidate in [
                "/var/lib/emby/config/system.xml",
                "/var/lib/emby/system.xml",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_xml_tag(&p, "HttpServerPortNumber", &port_str, fs_root)?;
                    runner_mutate_xml_tag(&p, "PublicPort", &port_str, fs_root)?;
                }
            }
        }
        "qbittorrent" => {
            for candidate in [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/qBittorrent.conf",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_addr = existing.lines().any(|line| {
                        let t = line.trim();
                        !t.starts_with('#')
                            && !t.starts_with(';')
                            && t.split_once('=').is_some_and(|(k, v)| {
                                k.trim().eq_ignore_ascii_case(r"WebUI\Address")
                                    && !v.trim().is_empty()
                            })
                    });
                    runner_mutate_ini_key(&p, "Preferences", r"WebUI\Port", &port_str, fs_root)?;
                    if !has_addr {
                        runner_mutate_ini_key(
                            &p,
                            "Preferences",
                            r"WebUI\Address",
                            "127.0.0.1",
                            fs_root,
                        )?;
                    }
                }
            }
        }
        "sabnzbd" => {
            for candidate in [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/etc/sabnzbd/sabnzbd.ini",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_host = existing.lines().any(|line| {
                        let t = line.trim();
                        !t.starts_with('#')
                            && !t.starts_with(';')
                            && t.split_once('=').is_some_and(|(k, v)| {
                                k.trim().eq_ignore_ascii_case("host") && !v.trim().is_empty()
                            })
                    });
                    runner_mutate_ini_key(&p, "misc", "port", &port_str, fs_root)?;
                    if !has_host {
                        runner_mutate_ini_key(&p, "misc", "host", "127.0.0.1", fs_root)?;
                    }
                }
            }
        }
        "tautulli" => {
            for candidate in ["/var/lib/tautulli/config.ini", "/opt/Tautulli/config.ini"] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_ini_key(&p, "General", "http_port", &port_str, fs_root)?;
                }
            }
        }
        "gitea" => {
            for candidate in ["/etc/gitea/app.ini", "/var/lib/gitea/custom/conf/app.ini"] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_ini_key(&p, "server", "HTTP_PORT", &port_str, fs_root)?;
                }
            }
        }
        "transmission" => {
            for candidate in crate::blueprint::TRANSMISSION_CONFIG_PATHS {
                let p = rebase(candidate);
                if crate::blueprint::is_transmission_config_alias(&p, rebase) {
                    continue;
                }
                if runner_candidate_exists_or_symlink(&p)? {
                    if let Some(load) = load_ingress.take() {
                        ingress = load(canonical)?;
                    }
                    changes.capture(&p)?;
                    runner_mutate_json_key(
                        &p,
                        "rpc-port",
                        serde_json::json!(listen_port),
                        fs_root,
                    )?;
                    let base = crate::blueprint::blueprint_base_domain(None)
                        .map_err(|err| PackageExecutorError::VerificationFailed(err.to_string()))?;
                    crate::blueprint::mutate_transmission_whitelist(&p, &base, ingress.as_ref())
                        .map_err(PackageExecutorError::VerificationFailed)?;
                }
            }
        }
        "overseerr" | "jellyseerr" => {
            let path = rebase(&format!("/etc/systemd/system/{canonical}.service"));
            if runner_candidate_exists_or_symlink(&path)? {
                changes.capture(&path)?;
                if crate::blueprint::mutate_systemd_port(&path, listen_port)
                    .map_err(PackageExecutorError::VerificationFailed)?
                {
                    changes
                        .changed_units
                        .push(path.to_string_lossy().into_owned());
                }
            }
            for candidate in [
                format!("/var/lib/{canonical}/settings.json"),
                format!("/var/lib/{canonical}/config/settings.json"),
                format!("/opt/{canonical}/config/settings.json"),
            ] {
                let path = rebase(&candidate);
                let result = (|| -> Result<(), PackageExecutorError> {
                    if runner_candidate_exists_or_symlink(&path)? {
                        changes.capture(&path)?;
                        runner_mutate_json_key(
                            &path,
                            "main.port",
                            serde_json::json!(listen_port),
                            fs_root,
                        )?;
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    tracing::warn!(path = %path.display(), %error, "Could not update optional Seerr settings");
                }
            }
        }
        "jackett" => {
            for candidate in [
                "/var/lib/jackett/Jackett/ServerConfig.json",
                "/var/lib/jackett/.config/Jackett/ServerConfig.json",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_json_key(&p, "Port", serde_json::json!(listen_port), fs_root)?;
                }
            }
        }
        _ => {}
    }

    let clean_app: String = canonical
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let sites_avail = rebase("/etc/apache2/sites-available");
    let sites_en = rebase("/etc/apache2/sites-enabled");
    let sites_avail_exists =
        !clean_app.is_empty() && runner_apache_directory_exists(&sites_avail, fs_root)?;
    let sites_en_exists =
        !clean_app.is_empty() && runner_apache_directory_exists(&sites_en, fs_root)?;
    if sites_avail_exists || sites_en_exists {
        let mut candidate_vhosts = Vec::new();
        for (dir, exists) in [
            (&sites_avail, sites_avail_exists),
            (&sites_en, sites_en_exists),
        ] {
            if exists {
                candidate_vhosts.push(dir.join(format!("aetherflow-app-{}.conf", clean_app)));
                candidate_vhosts.push(dir.join(format!("aetherflow-ext-{}.conf", clean_app)));
                candidate_vhosts.push(dir.join(format!("{}.conf", clean_app)));
            }
        }
        let preserved_blocks =
            extract_runner_apache_custom_blocks(&candidate_vhosts, fs_root, &sites_en)?;
        let existing_ingress = match load_ingress {
            Some(load) => load(canonical)?,
            None => ingress,
        };
        let req = af_models::RunnerApacheVhostRequest {
            app_name: clean_app.clone(),
            listen_port,
            internal_domain: Some(format!("{clean_app}.aether.local")),
            public_domain: existing_ingress
                .as_ref()
                .map(|ing| ing.public_domain.clone())
                .filter(|domain| !domain.is_empty()),
            external_access_enabled: existing_ingress
                .as_ref()
                .is_some_and(|ing| ing.external_access_enabled),
            tls_enabled: existing_ingress.as_ref().is_some_and(|ing| ing.tls_enabled),
            ..Default::default()
        };
        crate::validate_ingress_vhost_request(&req)
            .map_err(PackageExecutorError::VerificationFailed)?;
        let render_error =
            |error: anyhow::Error| PackageExecutorError::VerificationFailed(error.to_string());
        let upstream = apache_upstream_tls(&clean_app, fs_root).map_err(render_error)?;
        let mut modified_any = false;

        let internal_name = format!("aetherflow-app-{clean_app}.conf");
        let external_name = format!("aetherflow-ext-{clean_app}.conf");
        let ssl_name = format!("aetherflow-ext-{clean_app}-le-ssl.conf");
        let legacy_name = format!("{clean_app}.conf");
        let mut external_sources = Vec::new();
        for dir in [&sites_avail, &sites_en] {
            for name in [&external_name, &ssl_name] {
                if let Some(raw) =
                    read_runner_apache_vhost(&dir.join(name), fs_root, dir == &sites_en)?
                {
                    external_sources.push(raw);
                }
            }
        }
        let external_sources: Vec<&str> = external_sources.iter().map(String::as_str).collect();
        let shared: Vec<&str> = preserved_blocks.iter().map(String::as_str).collect();
        let external_body = req
            .public_domain
            .as_deref()
            .filter(|_| req.external_access_enabled)
            .map(|domain| {
                render_managed_apache_vhost(
                    &req,
                    domain,
                    false,
                    &upstream,
                    fs_root,
                    &external_sources,
                    &shared,
                )
            })
            .transpose()
            .map_err(render_error)?;

        let extra_existing_paths = [
            sites_avail.join(&internal_name),
            sites_avail.join(&external_name),
            sites_avail.join(&ssl_name),
            sites_avail.join(&legacy_name),
            sites_en.join(&internal_name),
            sites_en.join(&external_name),
            sites_en.join(&ssl_name),
            sites_en.join(&legacy_name),
        ];
        for path in extra_existing_paths {
            let name = path.file_name().unwrap_or_default();
            let in_enabled = path.parent() == Some(sites_en.as_path());
            let is_alias = in_enabled
                && fs::symlink_metadata(&path)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink());
            if is_alias {
                if name == ssl_name.as_str()
                    || (name == external_name.as_str()
                        && existing_ingress.is_some()
                        && external_body.is_none())
                {
                    changes.remove_vhost_alias(&path)?;
                    modified_any = true;
                }
                continue;
            }
            let prior = read_runner_apache_vhost(&path, fs_root, in_enabled)?;
            if prior.is_none()
                && (in_enabled
                    || !sites_avail_exists
                    || (name != internal_name.as_str() && name != external_name.as_str()))
            {
                continue;
            }

            let next = if name == internal_name.as_str() {
                let existing: Vec<_> = prior.iter().map(String::as_str).collect();
                Some(
                    render_managed_apache_vhost(
                        &req,
                        req.internal_domain.as_deref().unwrap_or_default(),
                        true,
                        &upstream,
                        fs_root,
                        &existing,
                        &shared,
                    )
                    .map_err(render_error)?,
                )
            } else if name == external_name.as_str() && existing_ingress.is_some() {
                external_body.clone()
            } else if name == ssl_name.as_str() {
                None
            } else {
                prior
                    .as_deref()
                    .map(|raw| {
                        update_legacy_apache_vhost_with_blocks(
                            raw,
                            &req,
                            &upstream,
                            fs_root,
                            name == external_name.as_str(),
                            &preserved_blocks,
                        )
                    })
                    .transpose()
                    .map_err(render_error)?
            };

            match (prior.as_deref(), next.as_deref()) {
                (old, Some(new)) if old != Some(new) => {
                    changes.write_vhost(&path, new)?;
                    modified_any = true;
                }
                (Some(_), None) => {
                    changes.remove_vhost(&path)?;
                    modified_any = true;
                }
                _ => {}
            }
        }

        if modified_any && fs_root.is_none() {
            match fs::metadata("/etc/apache2/apache2.conf") {
                Ok(metadata) if metadata.is_file() => {
                    crate::enable_managed_apache_modules(req.tls_enabled || upstream.enabled)
                        .map_err(|err| PackageExecutorError::VerificationFailed(err.to_string()))?;
                    verify_runner_apache_configtest().map_err(|err| {
                        PackageExecutorError::VerificationFailed(format!(
                            "apache2ctl configtest failed for {}: {}",
                            clean_app, err
                        ))
                    })?;
                }
                Ok(_) => {
                    return Err(PackageExecutorError::VerificationFailed(
                        "Apache configuration /etc/apache2/apache2.conf is not a regular file"
                            .to_string(),
                    ));
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(PackageExecutorError::VerificationFailed(format!(
                        "failed to inspect Apache configuration /etc/apache2/apache2.conf: {}",
                        err
                    )));
                }
            }
        }
    }

    if fs_root.is_none() {
        let internal_domain = format!("{}.aether.local", canonical);
        let _ = crate::update_hosts_file_local(&[internal_domain], false);
    }
    Ok(())
}

