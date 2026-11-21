use super::*;

pub(super) fn write_config_atomic_preserving_meta(
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

pub(super) fn runner_candidate_exists_or_symlink(p: &Path) -> Result<bool, PackageExecutorError> {
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

pub(super) fn validate_regular_config_candidate(
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

pub(super) fn runner_mutate_xml_tag(
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

pub(super) fn runner_mutate_ini_key(
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

pub(super) fn runner_mutate_json_key(
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

pub(super) fn load_runner_blueprint_ingress(
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

pub(super) struct RunnerBlueprintConfigBackup {
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

    pub(super) fn write_vhost(
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

    pub(super) fn remove_vhost(&mut self, path: &Path) -> Result<(), PackageExecutorError> {
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

pub(super) fn try_apply_runner_blueprint_app_config_with_ingress(
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

pub(super) fn apply_runner_blueprint_app_config_changes(
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LibreSpeedUpstreamTlsConfig {
    pub enabled: bool,
    pub ca_cert_file: Option<String>,
}

pub fn librespeed_runner_settings_tls_enabled(settings_path: &Path) -> bool {
    librespeed_runner_settings_tls_config(settings_path, None).enabled
}

pub fn librespeed_runner_settings_tls_config(
    settings_path: &Path,
    fs_root: Option<&Path>,
) -> LibreSpeedUpstreamTlsConfig {
    try_librespeed_runner_settings_tls_config(settings_path, fs_root).unwrap_or_default()
}

/// Reads `/opt/librespeed/settings.toml` safely (`O_NOFOLLOW` + non-symlink ancestors).
/// Returns `None` when `PermissionDenied` prevents an unprivileged caller from inspecting
/// `settings.toml`, allowing callers with an existing vhost to preserve current TLS directives.
pub fn try_librespeed_runner_settings_tls_config(
    settings_path: &Path,
    fs_root: Option<&Path>,
) -> Option<LibreSpeedUpstreamTlsConfig> {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut cur = settings_path.parent();
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() || dir == Path::new("/") {
            break;
        }
        match fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => {
                return Some(LibreSpeedUpstreamTlsConfig::default());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(_) => return Some(LibreSpeedUpstreamTlsConfig::default()),
        }
        cur = dir.parent();
    }

    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    let file = match opts.open(settings_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(_) => return Some(LibreSpeedUpstreamTlsConfig::default()),
    };
    let Ok(meta) = file.metadata() else {
        return Some(LibreSpeedUpstreamTlsConfig::default());
    };
    if !meta.is_file() || meta.len() > 1_048_576 {
        return Some(LibreSpeedUpstreamTlsConfig::default());
    }
    let mut raw = String::new();
    if file.take(1_048_576).read_to_string(&mut raw).is_err() {
        return Some(LibreSpeedUpstreamTlsConfig::default());
    }
    let (enabled, raw_cert) = parse_librespeed_root_tls_config(&raw);
    let ca_cert_file = if enabled {
        raw_cert.and_then(|cert_str| validate_librespeed_apache_ca_cert(&cert_str, fs_root))
    } else {
        None
    };
    Some(LibreSpeedUpstreamTlsConfig {
        enabled,
        ca_cert_file,
    })
}

pub(super) fn validate_librespeed_apache_ca_cert(
    cert_str: &str,
    fs_root: Option<&Path>,
) -> Option<String> {
    let trimmed = cert_str.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with('/')
        || trimmed.len() > 512
        || trimmed.bytes().any(|b| {
            b.is_ascii_whitespace()
                || b.is_ascii_control()
                || matches!(b, b'"' | b'\'' | b'\\' | b'#')
        })
    {
        return None;
    }
    let cert_path = Path::new(trimmed);
    for comp in cert_path.components() {
        if matches!(
            comp,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            return None;
        }
    }
    let disk_path = match fs_root {
        Some(root) => root.join(trimmed.trim_start_matches('/')),
        None => cert_path.to_path_buf(),
    };
    for anc in disk_path.ancestors().skip(1) {
        if anc.as_os_str().is_empty() || anc == Path::new("/") {
            break;
        }
        if fs::symlink_metadata(anc)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return None;
        }
    }
    let meta = fs::symlink_metadata(&disk_path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() == 0 || meta.len() > 1_048_576
    {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
pub(super) fn parse_librespeed_root_tls_flag(raw: &str) -> bool {
    parse_librespeed_root_tls_config(raw).0
}

pub(super) fn scan_librespeed_toml_statements(input: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum QuoteState {
        None,
        Single,
        Double,
        TripleSingle,
        TripleDouble,
    }

    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = QuoteState::None;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let bytes = input.as_bytes();
    let mut i: usize = 0;

    while i < bytes.len() {
        let ch = input[i..].chars().next()?;
        let ch_len = ch.len_utf8();
        match quote {
            QuoteState::None => {
                if ch == '#' {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                if input[i..].starts_with("\"\"\"") {
                    quote = QuoteState::TripleDouble;
                    cur.push_str("\"\"\"");
                    i += 3;
                    continue;
                }
                if input[i..].starts_with("'''") {
                    quote = QuoteState::TripleSingle;
                    cur.push_str("'''");
                    i += 3;
                    continue;
                }
                match ch {
                    '"' => {
                        quote = QuoteState::Double;
                        cur.push(ch);
                    }
                    '\'' => {
                        quote = QuoteState::Single;
                        cur.push(ch);
                    }
                    '[' => {
                        bracket_depth += 1;
                        cur.push(ch);
                    }
                    ']' => {
                        bracket_depth = bracket_depth.checked_sub(1)?;
                        cur.push(ch);
                    }
                    '{' => {
                        brace_depth += 1;
                        cur.push(ch);
                    }
                    '}' => {
                        brace_depth = brace_depth.checked_sub(1)?;
                        cur.push(ch);
                    }
                    '\n' => {
                        if bracket_depth == 0 && brace_depth == 0 {
                            let trimmed = cur.trim();
                            if !trimmed.is_empty() {
                                out.push(trimmed.to_string());
                            }
                            cur.clear();
                        } else {
                            cur.push(' ');
                        }
                    }
                    '\r' => {}
                    _ => cur.push(ch),
                }
            }
            QuoteState::Double => {
                if ch == '\\' {
                    cur.push(ch);
                    i += ch_len;
                    if i < bytes.len() {
                        let next_ch = input[i..].chars().next()?;
                        cur.push(next_ch);
                        i += next_ch.len_utf8();
                    }
                    continue;
                }
                if ch == '\n' {
                    return None;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
                cur.push(ch);
            }
            QuoteState::Single => {
                if ch == '\n' {
                    return None;
                }
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                cur.push(ch);
            }
            QuoteState::TripleDouble => {
                if ch == '\\' {
                    cur.push(ch);
                    i += ch_len;
                    if i < bytes.len() {
                        let next_ch = input[i..].chars().next()?;
                        cur.push(next_ch);
                        i += next_ch.len_utf8();
                    }
                    continue;
                }
                if input[i..].starts_with("\"\"\"") {
                    quote = QuoteState::None;
                    cur.push_str("\"\"\"");
                    i += 3;
                    continue;
                }
                cur.push(ch);
            }
            QuoteState::TripleSingle => {
                if input[i..].starts_with("'''") {
                    quote = QuoteState::None;
                    cur.push_str("'''");
                    i += 3;
                    continue;
                }
                cur.push(ch);
            }
        }
        i += ch_len;
    }

    if quote != QuoteState::None || bracket_depth > 0 || brace_depth > 0 {
        return None;
    }
    let trimmed = cur.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    Some(out)
}

pub(super) fn split_librespeed_toml_kv(stmt: &str) -> Option<(&str, &str)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut in_triple_double = false;
    let mut in_triple_single = false;
    let mut escaped = false;
    let mut bracket_depth = 0usize;
    let bytes = stmt.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = stmt[i..].chars().next()?;
        let ch_len = ch.len_utf8();
        if in_triple_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if stmt[i..].starts_with("\"\"\"") {
                in_triple_double = false;
                i += 3;
                continue;
            }
            i += ch_len;
            continue;
        }
        if in_triple_single {
            if stmt[i..].starts_with("'''") {
                in_triple_single = false;
                i += 3;
                continue;
            }
            i += ch_len;
            continue;
        }
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            i += ch_len;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            i += ch_len;
            continue;
        }
        if stmt[i..].starts_with("\"\"\"") {
            in_triple_double = true;
            i += 3;
            continue;
        }
        if stmt[i..].starts_with("'''") {
            in_triple_single = true;
            i += 3;
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '=' if bracket_depth == 0 => return Some((&stmt[..i], &stmt[i + 1..])),
            _ => {}
        }
        i += ch_len;
    }
    None
}

pub(super) fn unquote_librespeed_toml_scalar(raw_val: &str) -> String {
    let trimmed = raw_val.trim();
    if trimmed.starts_with("\"\"\"") && trimmed.ends_with("\"\"\"") && trimmed.len() >= 6 {
        let inner = &trimmed[3..trimmed.len() - 3];
        let inner = inner
            .strip_prefix("\r\n")
            .or_else(|| inner.strip_prefix('\n'))
            .unwrap_or(inner);
        return inner.to_string();
    }
    if trimmed.starts_with("'''") && trimmed.ends_with("'''") && trimmed.len() >= 6 {
        let inner = &trimmed[3..trimmed.len() - 3];
        let inner = inner
            .strip_prefix("\r\n")
            .or_else(|| inner.strip_prefix('\n'))
            .unwrap_or(inner);
        return inner.to_string();
    }
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        if let Ok(parsed) = serde_json::from_str::<String>(trimmed) {
            return parsed;
        }
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    trimmed.to_string()
}

pub(super) fn parse_librespeed_root_tls_config(raw: &str) -> (bool, Option<String>) {
    let mut enabled = false;
    let mut cert_file: Option<String> = None;
    let Some(stmts) = scan_librespeed_toml_statements(raw) else {
        return (false, None);
    };
    for stmt in stmts {
        if stmt.starts_with('[') && split_librespeed_toml_kv(&stmt).is_none() {
            break;
        }
        if let Some((k, v)) = split_librespeed_toml_kv(&stmt) {
            let key = unquote_librespeed_toml_scalar(k);
            let val = unquote_librespeed_toml_scalar(v);
            if key == "enable_tls" {
                enabled = val.trim().eq_ignore_ascii_case("true");
            } else if key == "tls_cert_file" {
                let trimmed = val.trim();
                cert_file = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
        }
    }
    (enabled, cert_file)
}

pub(super) fn rewrite_runner_apache_proxy_url_port(
    token: &str,
    listen_port: i32,
    upstream_tls: Option<bool>,
) -> Option<String> {
    for scheme in ["http://", "https://", "ws://", "wss://"] {
        if let Some(rest) = token.strip_prefix(scheme) {
            let out_scheme = match (scheme, upstream_tls) {
                ("http://" | "https://", Some(true)) => "https://",
                ("http://" | "https://", Some(false)) => "http://",
                ("ws://" | "wss://", Some(true)) => "wss://",
                ("ws://" | "wss://", Some(false)) => "ws://",
                _ => scheme,
            };
            for host in ["127.0.0.1:", "localhost:", "0.0.0.0:", "[::1]:"] {
                if let Some(after_host) = rest.strip_prefix(host) {
                    let digit_len = after_host
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .count();
                    if digit_len > 0 {
                        let suffix = &after_host[digit_len..];
                        return Some(format!("{out_scheme}{host}{listen_port}{suffix}"));
                    }
                }
            }
        }
    }
    None
}

pub(super) fn runner_apache_directory_exists(
    path: &Path,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    validate_filesystem_path(path, fs_root)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(PackageExecutorError::VerificationFailed(format!(
            "required Apache configuration directory is not a directory: {}",
            path.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect Apache configuration directory {}: {}",
            path.display(),
            err
        ))),
    }
}

pub(super) fn read_runner_apache_vhost(
    path: &Path,
    fs_root: Option<&Path>,
    allow_enabled_alias: bool,
) -> Result<Option<String>, PackageExecutorError> {
    if let Some(parent) = path.parent() {
        validate_filesystem_path(parent, fs_root)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if allow_enabled_alias && metadata.file_type().is_symlink() => Ok(None),
        Ok(_) => {
            validate_regular_config_candidate(path, fs_root)?;
            fs::read_to_string(path).map(Some).map_err(|err| {
                PackageExecutorError::VerificationFailed(format!(
                    "failed to read required Apache vhost {}: {}",
                    path.display(),
                    err
                ))
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect required Apache vhost {}: {}",
            path.display(),
            err
        ))),
    }
}

pub(super) fn extract_runner_apache_custom_blocks(
    paths: &[PathBuf],
    fs_root: Option<&Path>,
    sites_en: &Path,
) -> Result<Vec<String>, PackageExecutorError> {
    let mut blocks = Vec::new();
    for path in paths {
        let source = match fs::symlink_metadata(path) {
            Ok(metadata)
                if path.parent() == Some(sites_en) && metadata.file_type().is_symlink() =>
            {
                validate_filesystem_path(sites_en, fs_root)?;
                match fs::canonicalize(path) {
                    Ok(target) => target,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => {
                        return Err(PackageExecutorError::VerificationFailed(format!(
                            "failed to resolve Apache vhost alias {}: {}",
                            path.display(),
                            err
                        )));
                    }
                }
            }
            _ => path.clone(),
        };
        let Some(raw) = read_runner_apache_vhost(&source, fs_root, false)? else {
            continue;
        };
        collect_apache_custom_blocks(&raw, &mut blocks);
    }
    Ok(blocks)
}

pub(super) fn collect_apache_custom_blocks(raw: &str, blocks: &mut Vec<String>) {
    collect_apache_live_custom_blocks(raw, blocks);
    let pending = raw
        .lines()
        .filter_map(|line| line.strip_prefix(TLS_PENDING_COMMENT))
        .collect::<Vec<_>>()
        .join("\n");
    collect_apache_live_custom_blocks(&pending, blocks);
}

pub(super) fn collect_apache_live_custom_blocks(raw: &str, blocks: &mut Vec<String>) {
    let mut depth = 0usize;
    let mut section = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        let directive = trimmed
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if depth > 0 {
            if !section.is_empty() {
                section.push(line);
            }
            if directive.starts_with("</") {
                depth -= 1;
            } else if directive.starts_with('<') && trimmed.ends_with('>') {
                depth += 1;
            }
            if depth == 0 && !section.is_empty() {
                let block = section.join("\n");
                if !ACME_HTTP_EXEMPTION.contains(block.trim())
                    && !blocks
                        .iter()
                        .any(|existing| existing.trim() == block.trim())
                {
                    blocks.push(block);
                }
                section.clear();
            }
        } else if directive.starts_with('<')
            && !directive.starts_with("</")
            && directive != "<virtualhost"
            && trimmed.ends_with('>')
        {
            depth = 1;
            if matches!(
                directive.as_str(),
                "<location"
                    | "<locationmatch"
                    | "<directory"
                    | "<directorymatch"
                    | "<files"
                    | "<filesmatch"
                    | "<requireall>"
                    | "<requireany>"
                    | "<requirenone>"
            ) {
                section.push(line);
            }
        } else if matches!(
            directive.as_str(),
            "authtype"
                | "authname"
                | "authuserfile"
                | "authgroupfile"
                | "authbasicprovider"
                | "require"
                | "include"
                | "includeoptional"
        ) && !blocks.iter().any(|block| block.trim() == trimmed)
        {
            blocks.push(line.to_string());
        }
    }
}

pub(crate) fn apache_upstream_tls(
    app: &str,
    fs_root: Option<&Path>,
) -> anyhow::Result<LibreSpeedUpstreamTlsConfig> {
    let rebase = |path: &str| {
        fs_root.map_or_else(
            || PathBuf::from(path),
            |root| root.join(path.trim_start_matches('/')),
        )
    };
    let config = match app {
        "librespeed" => {
            let settings = env::var_os("AETHERFLOW_LIBRESPEED_SETTINGS_PATH")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| rebase("/opt/librespeed/settings.toml"));
            try_librespeed_runner_settings_tls_config(&settings, fs_root)
                .ok_or_else(|| anyhow::anyhow!("cannot verify LibreSpeed upstream TLS settings"))?
        }
        "kasmvnc" => LibreSpeedUpstreamTlsConfig {
            enabled: true,
            ca_cert_file: [
                "/etc/kasmvnc/kasmvnc.crt",
                "/var/lib/kasmvnc/.vnc/aetherflow-cert.pem",
            ]
            .into_iter()
            .find_map(|path| validate_librespeed_apache_ca_cert(path, fs_root)),
        },
        _ => Default::default(),
    };
    anyhow::ensure!(
        !config.enabled || config.ca_cert_file.is_some(),
        "{app} upstream TLS requires a regular, non-symlinked certificate for Apache SSLProxyCACertificateFile pinning"
    );
    Ok(config)
}

pub(super) const INTERNAL_NETWORKS: &str =
    "127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7 fe80::/10";
pub(super) const APACHE_HTPASSWD: &str = "/etc/apache2/AetherFlow/htpasswd";
pub const GATEWAY_APP_HEADER: &str = "x-aetherflow-external-app";

/// Applications whose public routes require AetherFlow authentication.
pub fn requires_external_app_auth(app: &str) -> bool {
    matches!(
        app,
        "mcvnc"
            | "scrutiny"
            | "prometheus"
            | "flaresolverr"
            | "jackett"
            | "threadfin"
            | "rutorrent"
            | "unmanic"
            | "netdata"
            | "autoscan"
    )
}

pub(super) fn apache_bcrypt_entry(username: &str, hash: &str) -> Option<String> {
    if !SAFE_USERNAME.is_match(username) || hash.len() != 60 {
        return None;
    }
    let (version, remainder) = hash.split_at_checked(4)?;
    if !matches!(version, "$2a$" | "$2b$" | "$2y$")
        || !remainder
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'.' | b'/'))
        || !remainder.as_bytes()[..2].iter().all(u8::is_ascii_digit)
        || remainder.as_bytes()[2] != b'$'
        || remainder.as_bytes()[3..].contains(&b'$')
    {
        return None;
    }
    Some(format!("{username}:$2y${remainder}\n"))
}

pub(super) fn htpasswd_from_master_file(path: &Path) -> Option<String> {
    let contents = crate::read_confined_text(path, &[]).ok()?;
    let (user, password) = contents.trim_end_matches(['\r', '\n']).split_once(':')?;
    if !SAFE_USERNAME.is_match(user) || password.is_empty() || password.contains(['\r', '\n', '\0'])
    {
        return None;
    }
    // apache2-utils is installed with Apache. Pass the password only on stdin.
    let mut child = std::process::Command::new("/usr/bin/htpasswd")
        .args(["-niBC", "10", user])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let written = child
        .stdin
        .take()
        .is_some_and(|mut input| writeln!(input, "{password}").is_ok());
    let output = child.wait_with_output().ok()?;
    if !written || !output.status.success() {
        return None;
    }
    let output = std::str::from_utf8(&output.stdout).ok()?.trim();
    let (result_user, hash) = output.split_once(':')?;
    (result_user == user)
        .then(|| apache_bcrypt_entry(user, hash))
        .flatten()
}

pub(super) fn htpasswd_from_admin_database() -> Option<String> {
    let conn = crate::open_runner_state_database(None).ok()?;
    let mut query = conn
        .prepare(
            "SELECT username, password_hash FROM users
         WHERE role = 'admin' AND password_hash != '' AND COALESCE(totp_enabled, 0) = 0
         ORDER BY id",
        )
        .ok()?;
    let rows = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .ok()?;
    for (username, hash) in rows.filter_map(Result::ok) {
        if let Some(entry) = apache_bcrypt_entry(&username, &hash) {
            return Some(entry);
        }
    }
    None
}

pub(super) fn ensure_apache_htpasswd_file(path: &Path) -> anyhow::Result<()> {
    ensure_apache_htpasswd_with(path, || {
        ["/etc/aetherflow/.master.creds", "/root/.master.creds"]
            .into_iter()
            .find_map(|file| htpasswd_from_master_file(Path::new(file)))
            .or_else(htpasswd_from_admin_database)
    })
}

pub(super) fn ensure_apache_htpasswd_with(
    path: &Path,
    entry: impl FnOnce() -> Option<String>,
) -> anyhow::Result<()> {
    static PROVISION: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = PROVISION.lock().unwrap_or_else(|err| err.into_inner());
    match crate::open_confined_file(path, &[]) {
        Ok(file) if file.metadata()?.len() > 0 => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let Some(entry) = entry() else {
        anyhow::bail!(
            "{} requires a master credential or an administrator bcrypt hash",
            path.display()
        );
    };
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("htpasswd path has no parent"))?;
    validate_filesystem_path(parent, None)?;
    create_dir_all_0755(parent)?;
    let owner = (unsafe { libc::geteuid() } == 0)
        .then(|| (0, crate::lookup_group_gid("www-data").unwrap_or(0)));
    crate::replace_confined_file(
        path,
        entry.as_bytes(),
        Some(&[]),
        Some(0o640),
        false,
        false,
        owner,
    )?;
    Ok(())
}

pub(super) fn external_auth_policy(app: &str, fs_root: Option<&Path>) -> anyhow::Result<String> {
    external_auth_policy_for_vhost(app, fs_root, false)
}

pub(super) fn external_auth_policy_for_vhost(
    app: &str,
    fs_root: Option<&Path>,
    acme: bool,
) -> anyhow::Result<String> {
    if !requires_external_app_auth(app) {
        return Ok(String::new());
    }
    let path = fs_root.map_or_else(
        || PathBuf::from(APACHE_HTPASSWD),
        |root| root.join(APACHE_HTPASSWD.trim_start_matches('/')),
    );
    if fs_root.is_none() && unsafe { libc::geteuid() } == 0 {
        ensure_apache_htpasswd_file(&path)?;
    }
    anyhow::ensure!(
        crate::open_confined_file(&path, &[])
            .and_then(|file| file.metadata())
            .is_ok_and(|meta| meta.len() > 0),
        "external access for {app} requires {APACHE_HTPASSWD}"
    );
    // Apache merges <If> after <Location>. And preserves restrictions already applied
    // to an operator location and also requires the managed credentials there.
    let condition = if acme {
        "%{REQUEST_URI} !~ m#^/\\.well-known/acme-challenge/#"
    } else {
        "true"
    };
    Ok(format!(
        "    <If \"{condition}\">
        AuthType Basic
        AuthName \"AetherFlow\"
        AuthBasicProvider file
        AuthUserFile {APACHE_HTPASSWD}
        AuthMerging And
        Require valid-user
    </If>
"
    ))
}

pub(super) fn internal_network_policy() -> String {
    format!(
        "    <Proxy \"*\">
        Require ip {INTERNAL_NETWORKS}
    </Proxy>
"
    )
}

pub(super) fn internal_rewrite_guard() -> String {
    // The vhost rewrite guard also covers any <Location> with its own authz rules
    // and runs before the WebSocket proxy rewrite.
    let networks = INTERNAL_NETWORKS
        .split_whitespace()
        .map(|network| format!("-R '{network}'"))
        .collect::<Vec<_>>()
        .join(" || ");
    format!(
        "    RewriteCond expr \"!({networks})\"
    RewriteRule ^ - [F,L]
"
    )
}

pub(super) fn apache_tls_pair(domain: &str, fs_root: Option<&Path>) -> Option<(String, String)> {
    if !af_models::valid_ingress_hostname(domain) || domain.ends_with(".aether.local") {
        return None;
    }
    let resolve = |path: &str| {
        let resolved = fs_root.map_or_else(
            || PathBuf::from(path),
            |root| root.join(path.trim_start_matches('/')),
        );
        if let Some(root) = fs_root {
            if !resolved
                .canonicalize()
                .is_ok_and(|path| path.starts_with(root))
            {
                return None;
            }
        }
        fs::metadata(&resolved)
            .is_ok_and(|meta| meta.is_file() && meta.len() > 0)
            .then_some(resolved)
    };
    let live_pair = |name: &str| {
        (
            format!("/etc/letsencrypt/live/{name}/fullchain.pem"),
            format!("/etc/letsencrypt/live/{name}/privkey.pem"),
        )
    };
    let pair_is_valid = |pair: &(String, String)| {
        let (Some(cert), Some(key)) = (resolve(&pair.0), resolve(&pair.1)) else {
            return false;
        };
        tls_certificate_matches_key(&cert, &key)
    };
    let pair = live_pair(domain);
    if pair_is_valid(&pair) {
        return Some(pair);
    }
    if resolve(&pair.0).is_none() {
        let mut ancestor = domain;
        while let Some((_, parent)) = ancestor.split_once('.') {
            if !parent.contains('.') {
                break;
            }
            ancestor = parent;
            let pair = live_pair(parent);
            if let Some(cert) = resolve(&pair.0) {
                if cert_san_covers_domain(&cert, domain) && pair_is_valid(&pair) {
                    return Some(pair);
                }
            }
        }
    }
    [
        (
            format!("/etc/ssl/AetherFlow/{domain}/fullchain.pem"),
            format!("/etc/ssl/AetherFlow/{domain}/privkey.pem"),
        ),
        (
            format!("/etc/ssl/AetherFlow/{domain}.crt"),
            format!("/etc/ssl/AetherFlow/{domain}.key"),
        ),
    ]
    .into_iter()
    .find(pair_is_valid)
}

pub(super) fn tls_certificate_matches_key(cert: &Path, key: &Path) -> bool {
    let cert = std::process::Command::new("openssl")
        .args(["x509", "-noout", "-checkend", "0", "-pubkey", "-in"])
        .arg(cert)
        .output();
    let Ok(cert) = cert else {
        return false;
    };
    if !cert.status.success() {
        return false;
    }
    let key = std::process::Command::new("openssl")
        .args(["pkey", "-pubout", "-passin", "pass:", "-in"])
        .arg(key)
        .output();
    let Ok(key) = key else {
        return false;
    };
    key.status.success()
        && !key.stdout.is_empty()
        && String::from_utf8_lossy(&cert.stdout)
            .contains(String::from_utf8_lossy(&key.stdout).trim())
}

pub(super) fn cert_san_covers_domain(cert: &Path, domain: &str) -> bool {
    let Ok(output) = std::process::Command::new("openssl")
        .args(["x509", "-noout", "-ext", "subjectAltName", "-in"])
        .arg(cert)
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let wildcard = domain
        .split_once('.')
        .map(|(_, parent)| format!("*.{parent}"));
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .flat_map(|line| line.split(','))
        .filter_map(|san| san.trim().strip_prefix("DNS:"))
        .any(|san| {
            san.eq_ignore_ascii_case(domain)
                || wildcard
                    .as_ref()
                    .is_some_and(|name| san.eq_ignore_ascii_case(name))
        })
}

/// Checks whether a public domain can use an installed TLS certificate and key.
pub fn check_domain_tls_ready(domain: &str, fs_root: Option<&Path>) -> bool {
    apache_tls_pair(domain, fs_root).is_some()
}

pub(super) const TLS_PENDING_COMMENT: &str = "# af-tls-pending: ";
pub(super) const ACME_HTTP_EXEMPTION: &str = r#"    Alias /.well-known/acme-challenge /var/www/aetherflow-default/.well-known/acme-challenge
    <Directory /var/www/aetherflow-default/.well-known/acme-challenge>
        Options None
        AllowOverride None
        Require all granted
    </Directory>
    ProxyPass /.well-known/acme-challenge/ !
"#;
pub(super) const ACME_REWRITE_GUARD: &str = r"    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
";

fn apache_gateway_address(bind_host: &str, port: &str) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};

    let bind_host = bind_host.trim();
    let mut address = if let Ok(address) = bind_host.parse::<SocketAddr>() {
        address
    } else {
        let host = bind_host.trim_start_matches('[').trim_end_matches(']');
        let ip = if host.is_empty() {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            host.parse().ok()?
        };
        let port = match port.trim() {
            "" => 8080,
            port => port.parse().ok()?,
        };
        SocketAddr::new(ip, port)
    };
    // Apache and the API run on the same host. Keep credentials on loopback
    // even when the API listens on every interface.
    if address.ip().is_unspecified() {
        address.set_ip(match address {
            SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
        });
    }
    (address.ip().is_loopback() && address.port() != 0).then_some(address)
}

pub(crate) fn render_managed_apache_vhost(
    req: &af_models::RunnerApacheVhostRequest,
    domain: &str,
    internal: bool,
    upstream: &LibreSpeedUpstreamTlsConfig,
    fs_root: Option<&Path>,
    existing: &[&str],
    legacy: &[&str],
) -> anyhow::Result<String> {
    let mut blocks = Vec::new();
    for raw in existing.iter().chain(legacy) {
        collect_apache_custom_blocks(raw, &mut blocks);
    }
    let external = !internal && !domain.ends_with(".aether.local");
    let mut out = String::new();
    let (port, downstream_tls) = if external && req.tls_enabled {
        out.push_str(&format!(
            "<VirtualHost *:80>\n    ServerName {domain}\n{ACME_HTTP_EXEMPTION}    RewriteEngine On\n{ACME_REWRITE_GUARD}"
        ));
        let Some((cert, key)) = apache_tls_pair(domain, fs_root) else {
            out.push_str("    RewriteRule ^ - [R=503,L]\n    ErrorDocument 503 \"TLS certificate provisioning pending\"\n");
            for line in blocks.iter().flat_map(|block| block.lines()) {
                out.push_str(TLS_PENDING_COMMENT);
                out.push_str(line);
                out.push('\n');
            }
            out.push_str("</VirtualHost>\n");
            return Ok(out);
        };
        out.push_str(&format!(
            "    RewriteRule ^ https://{domain}%{{REQUEST_URI}} [R=308,L]\n</VirtualHost>\n"
        ));
        (443, format!("    SSLEngine On\n    SSLCertificateFile {cert}\n    SSLCertificateKeyFile {key}\n"))
    } else {
        (80, String::new())
    };
    let acme = external && port == 80;
    let acme_http = if acme { ACME_HTTP_EXEMPTION } else { "" };
    let acme_rewrite = if acme { ACME_REWRITE_GUARD } else { "" };
    // ruTorrent's local Apache/PHP vhost requires its own Basic credentials.
    // Inherited Apache blocks may also implement local routing or authentication.
    let gateway = if external
        && requires_external_app_auth(&req.app_name)
        && req.app_name != "rutorrent"
        && blocks.is_empty()
    {
        let bind = env::var("BIND_ADDR")
            .or_else(|_| env::var("AETHERFLOW_BIND_ADDR"))
            .unwrap_or_default();
        apache_gateway_address(&bind, &env::var("PORT").unwrap_or_default())
            .filter(|address| i32::from(address.port()) != req.listen_port)
    } else {
        None
    };
    let auth = if internal || gateway.is_some() {
        String::new()
    } else {
        external_auth_policy_for_vhost(&req.app_name, fs_root, acme)?
    };
    let ssl_proxy = upstream
        .ca_cert_file
        .as_ref()
        .filter(|_| gateway.is_none())
        .map_or_else(String::new, |ca_cert| {
            format!(
                "    SSLProxyEngine On
    SSLProxyVerify require
    SSLProxyCACertificateFile {ca_cert}
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerExpire off
"
            )
        });
    let (native_http, native_ws) = if upstream.enabled {
        ("https", "wss")
    } else {
        ("http", "ws")
    };
    let native_addr = format!("127.0.0.1:{}", req.listen_port);
    let (http, ws, proxy_addr, gateway_headers, native_reverse) = match gateway {
        Some(address) => (
            "http",
            "ws",
            address.to_string(),
            format!(
                "    ProxyAddHeaders On
    RequestHeader unset Forwarded
    RequestHeader unset X-Forwarded-For
    RequestHeader unset X-Forwarded-Port
    RequestHeader set {GATEWAY_APP_HEADER} {}
",
                req.app_name
            ),
            format!("    ProxyPassReverse / {native_http}://{native_addr}/\n"),
        ),
        None => (
            native_http,
            native_ws,
            native_addr,
            String::new(),
            String::new(),
        ),
    };
    let proto = if internal {
        "http"
    } else {
        "expr=%{REQUEST_SCHEME}"
    };
    let guard = if internal {
        internal_rewrite_guard()
    } else {
        String::new()
    };
    let ip_policy = if internal {
        internal_network_policy()
    } else {
        String::new()
    };
    out.push_str(&format!(
        "<VirtualHost *:{port}>
    ServerName {domain}
{acme_http}{downstream_tls}{ssl_proxy}    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
{guard}{acme_rewrite}    RewriteCond %{{HTTP:Upgrade}} =websocket [NC]
    RewriteRule /(.*) {ws}://{proxy_addr}/$1 [P,L]
    ProxyPass / {http}://{proxy_addr}/
    ProxyPassReverse / {http}://{proxy_addr}/
{native_reverse}{gateway_headers}    RequestHeader unset X-Real-IP
    RequestHeader unset X-Forwarded-Host
    RequestHeader unset X-Aetherflow-User
    RequestHeader unset Remote-User
    RequestHeader unset X-Forwarded-User
    RequestHeader set X-Real-IP \"%{{REMOTE_ADDR}}s\"
    RequestHeader set X-Forwarded-Proto \"{proto}\"
{ip_policy}"
    ));
    if req.app_name == "librespeed"
        && !blocks
            .iter()
            .any(|block| block.contains("/etc/aetherflow/librespeed-proxy-token.conf"))
    {
        blocks.push("    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf".to_string());
    }
    for block in blocks {
        out.push_str(&block);
        out.push('\n');
    }
    out.push_str(&auth);
    out.push_str(
        "</VirtualHost>
",
    );
    Ok(out)
}

#[cfg(test)]
#[test]
fn apache_gateway_address_uses_the_api_port_and_loopback_interface() {
    for (bind, port, expected) in [
        ("", "", Some("127.0.0.1:8080")),
        ("0.0.0.0", "18080", Some("127.0.0.1:18080")),
        ("[::]:18443", "8080", Some("[::1]:18443")),
        ("192.0.2.1", "8080", None),
        ("127.0.0.1", "0", None),
    ] {
        assert_eq!(
            apache_gateway_address(bind, port),
            expected.map(|address| address.parse().unwrap())
        );
    }
}

pub(crate) fn update_legacy_apache_vhost(
    raw: &str,
    req: &af_models::RunnerApacheVhostRequest,
    upstream: &LibreSpeedUpstreamTlsConfig,
    fs_root: Option<&Path>,
    external: bool,
) -> anyhow::Result<String> {
    update_legacy_apache_vhost_with_blocks(raw, req, upstream, fs_root, external, &[])
}

pub(super) fn strip_legacy_duplicate_public_vhosts(raw: &str, domain: &str) -> String {
    static VHOST: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?is)<VirtualHost\s+[^>]+>.*?</VirtualHost\s*>").unwrap());
    VHOST
        .replace_all(raw, |captures: &regex::Captures<'_>| {
            let block = &captures[0];
            let is_domain = |value: &str| value.trim_matches('"').eq_ignore_ascii_case(domain);
            if block.lines().any(|line| {
                let mut words = line.split_whitespace();
                words
                    .next()
                    .is_some_and(|word| word.eq_ignore_ascii_case("ServerName"))
                    && words.next().is_some_and(is_domain)
            }) {
                return String::new();
            }
            block
                .lines()
                .filter_map(|line| {
                    let mut words = line.split_whitespace();
                    if words
                        .next()
                        .is_some_and(|word| word.eq_ignore_ascii_case("ServerAlias"))
                    {
                        let aliases: Vec<_> = words.filter(|name| !is_domain(name)).collect();
                        if aliases.is_empty() {
                            return None;
                        }
                        return Some(format!("    ServerAlias {}", aliases.join(" ")));
                    }
                    Some(line.to_owned())
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .into_owned()
}

pub(super) fn update_legacy_apache_vhost_with_blocks(
    raw: &str,
    req: &af_models::RunnerApacheVhostRequest,
    upstream: &LibreSpeedUpstreamTlsConfig,
    fs_root: Option<&Path>,
    external: bool,
    blocks: &[String],
) -> anyhow::Result<String> {
    // Package reconciliation can run without the ingress row. An existing
    // managed gateway vhost must continue to let the API resolve that state.
    if external {
        let marker = format!("RequestHeader set {GATEWAY_APP_HEADER} {}", req.app_name);
        if raw.lines().any(|line| line.trim() == marker) {
            return Ok(raw.to_owned());
        }
    }
    let tls = matches!(req.app_name.as_str(), "librespeed" | "kasmvnc").then_some(upstream.enabled);
    let updated = render_or_update_runner_apache_vhost_with_ca(
        Some(raw),
        raw,
        None,
        req.listen_port,
        tls,
        upstream.ca_cert_file.as_deref(),
        blocks,
    );
    let updated = if req.tls_enabled && req.external_access_enabled {
        if let Some(domain) = req.public_domain.as_deref() {
            strip_legacy_duplicate_public_vhosts(&updated, domain)
        } else {
            updated
        }
    } else {
        updated
    };
    static VHOST_END: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)</VirtualHost\s*>").unwrap());
    let mut out = String::new();
    let mut start = 0;
    for close_tag in VHOST_END.find_iter(&updated) {
        let host = &updated[start..close_tag.end()];
        let body = &updated[start..close_tag.start()];
        start = close_tag.end();
        let internal = host.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next().is_some_and(|word| {
                word.eq_ignore_ascii_case("ServerName") || word.eq_ignore_ascii_case("ServerAlias")
            }) && words.any(|name| {
                name.trim_matches('"')
                    .to_ascii_lowercase()
                    .ends_with(".aether.local")
            })
        });
        if internal && !body.contains(&internal_network_policy()) {
            // Put the vhost rewrite guard ahead of existing proxy rules.
            let open = body
                .to_ascii_lowercase()
                .find("<virtualhost")
                .and_then(|offset| body[offset..].find('>').map(|end| offset + end + 1))
                .unwrap_or_default();
            out.push_str(&body[..open]);
            out.push_str(
                "
    RewriteEngine On
",
            );
            out.push_str(&internal_rewrite_guard());
            out.push_str(&body[open..]);
            out.push_str(&internal_network_policy());
        } else {
            out.push_str(body);
        }
        if external || (!internal && req.external_access_enabled) {
            let auth = external_auth_policy(&req.app_name, fs_root)?;
            if !body.contains(&auth) {
                out.push_str(&auth);
            }
        }
        out.push_str(close_tag.as_str());
    }
    out.push_str(&updated[start..]);
    Ok(out)
}

#[cfg(test)]
pub(super) fn render_or_update_runner_apache_vhost(
    existing_raw: Option<&str>,
    default_template: &str,
    desired_server_name: Option<&str>,
    listen_port: i32,
    upstream_tls: Option<bool>,
    preserved_blocks: &[String],
) -> String {
    render_or_update_runner_apache_vhost_with_ca(
        existing_raw,
        default_template,
        desired_server_name,
        listen_port,
        upstream_tls,
        None,
        preserved_blocks,
    )
}

pub(super) fn render_or_update_runner_apache_vhost_with_ca(
    existing_raw: Option<&str>,
    default_template: &str,
    desired_server_name: Option<&str>,
    listen_port: i32,
    upstream_tls: Option<bool>,
    upstream_ca_cert: Option<&str>,
    preserved_blocks: &[String],
) -> String {
    let base = match existing_raw {
        Some(raw) if raw.to_ascii_lowercase().contains("<virtualhost") => {
            let mut out_lines = Vec::new();
            for line in raw.lines() {
                let trimmed = line.trim_start();
                let indent = &line[..line.len() - trimmed.len()];
                let lower = trimmed.to_ascii_lowercase();
                if upstream_tls.is_some()
                    && (lower.starts_with("sslproxyengine ")
                        || lower.starts_with("sslproxyengine\t")
                        || lower.starts_with("sslproxyverify ")
                        || lower.starts_with("sslproxyverify\t")
                        || lower.starts_with("sslproxycacertificatefile ")
                        || lower.starts_with("sslproxycacertificatefile\t")
                        || lower.starts_with("sslproxycheckpeercn ")
                        || lower.starts_with("sslproxycheckpeercn\t")
                        || lower.starts_with("sslproxycheckpeername ")
                        || lower.starts_with("sslproxycheckpeername\t")
                        || lower.starts_with("sslproxycheckpeerexpire ")
                        || lower.starts_with("sslproxycheckpeerexpire\t"))
                {
                    continue;
                }
                if let Some(dom) = desired_server_name {
                    if lower.starts_with("servername ") || lower.starts_with("servername\t") {
                        out_lines.push(format!("{indent}ServerName {dom}"));
                        continue;
                    }
                }
                if lower.starts_with("proxypass ")
                    || lower.starts_with("proxypass\t")
                    || lower.starts_with("proxypassreverse ")
                    || lower.starts_with("proxypassreverse\t")
                    || lower.starts_with("rewriterule ")
                    || lower.starts_with("rewriterule\t")
                {
                    let tokens: Vec<String> = trimmed
                        .split_whitespace()
                        .map(|tok| {
                            rewrite_runner_apache_proxy_url_port(tok, listen_port, upstream_tls)
                                .unwrap_or_else(|| tok.to_string())
                        })
                        .collect();
                    out_lines.push(format!("{indent}{}", tokens.join(" ")));
                } else {
                    out_lines.push(line.to_string());
                }
            }
            if let (Some(true), Some(ca_cert)) = (upstream_tls, upstream_ca_cert) {
                let insert_pos = out_lines
                    .iter()
                    .position(|l| {
                        l.trim()
                            .to_ascii_lowercase()
                            .starts_with("proxypreservehost ")
                    })
                    .or_else(|| {
                        out_lines
                            .iter()
                            .position(|l| l.trim().eq_ignore_ascii_case("</virtualhost>"))
                    })
                    .unwrap_or(out_lines.len());
                let ssl_lines = vec![
                    "    SSLProxyEngine On".to_string(),
                    "    SSLProxyVerify require".to_string(),
                    format!("    SSLProxyCACertificateFile {ca_cert}"),
                    "    SSLProxyCheckPeerCN off".to_string(),
                    "    SSLProxyCheckPeerName off".to_string(),
                    "    SSLProxyCheckPeerExpire off".to_string(),
                ];
                out_lines.splice(insert_pos..insert_pos, ssl_lines);
            }
            let mut joined = out_lines.join("\n");
            joined.push('\n');
            joined
        }
        _ => default_template.to_string(),
    };

    if preserved_blocks.is_empty() {
        return base;
    }

    let mut missing = Vec::new();
    for block in preserved_blocks {
        let trimmed_block = block.trim();
        if !trimmed_block.is_empty() && !base.contains(trimmed_block) {
            missing.push(block.clone());
        }
    }
    if missing.is_empty() {
        return base;
    }

    let mut final_lines = Vec::new();
    let mut inserted = false;
    for line in base.lines() {
        if !inserted && line.trim().eq_ignore_ascii_case("</virtualhost>") {
            for block in &missing {
                final_lines.push(block.clone());
            }
            inserted = true;
        }
        final_lines.push(line.to_string());
    }
    if !inserted {
        for block in &missing {
            final_lines.push(block.clone());
        }
    }
    let mut out = final_lines.join("\n");
    out.push('\n');
    out
}

pub(super) fn verify_runner_apache_configtest() -> Result<(), String> {
    for bin in [
        "/usr/sbin/apache2ctl",
        "/usr/sbin/apachectl",
        "apache2ctl",
        "apachectl",
    ] {
        match std::process::Command::new(bin).arg("-t").output() {
            Ok(out) => {
                if out.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                return Err(format!("{} {}", stderr.trim(), stdout.trim())
                    .trim()
                    .to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("failed to execute {}: {}", bin, err)),
        }
    }
    Err("no Apache configtest command is available".to_string())
}
