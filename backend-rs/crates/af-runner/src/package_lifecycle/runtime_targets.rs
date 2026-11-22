use std::path::{Path, PathBuf};

const MERGED_USR_ALIASES: &[&str] = &["bin", "sbin", "lib", "lib32", "lib64", "libx32"];

/// Debian/Ubuntu merged-`/usr` aliases (`<root>/lib` -> `usr/lib`) are real
/// directory ancestors. Any other symlink target stays prohibited.
pub(super) fn is_trusted_merged_usr_symlink(dir_path: &Path, fs_root: Option<&Path>) -> bool {
    let base_root = fs_root.unwrap_or_else(|| Path::new("/"));
    let alias = MERGED_USR_ALIASES
        .iter()
        .copied()
        .find(|alias| dir_path.components().eq(base_root.join(alias).components()));
    let Some(alias) = alias else {
        return false;
    };
    let Ok(meta) = std::fs::symlink_metadata(dir_path) else {
        return false;
    };
    if !meta.file_type().is_symlink() {
        return false;
    }
    let Ok(target) = std::fs::read_link(dir_path) else {
        return false;
    };
    let target_str = target.to_string_lossy();
    let expected_rel = format!("usr/{alias}");
    let expected_abs = format!("/usr/{alias}");
    if target_str != expected_rel && target_str != expected_abs {
        return false;
    }
    let usr_alias = base_root.join("usr").join(alias);
    match std::fs::symlink_metadata(&usr_alias) {
        Ok(usr_meta) => usr_meta.is_dir() && !usr_meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

pub(super) fn verify_no_symlink_ancestors_with_root(
    path: &Path,
    fs_root: Option<&Path>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component);
            if current.as_os_str() == "/" {
                continue;
            }
            match std::fs::symlink_metadata(&current) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        if is_trusted_merged_usr_symlink(&current, fs_root) {
                            continue;
                        }
                        return Err(format!(
                            "Ancestor directory {} is a symlink (symlink traversal prohibited)",
                            current.display()
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    break;
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to check ancestor directory {}: {}",
                        current.display(),
                        e
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn verify_no_symlink_ancestors(path: &Path) -> Result<(), String> {
    verify_no_symlink_ancestors_with_root(path, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTargetKind {
    Directory,
    FileOrSymlink,
}

pub fn is_receipt_file_name(name: &str) -> bool {
    matches!(name, ".af-version" | ".af-components.json")
}

pub(super) fn is_protected_root(path: &Path) -> bool {
    let p = path.to_string_lossy();
    let norm = p.trim_end_matches('/');
    if matches!(
        norm,
        "" | "/"
            | "/opt"
            | "/var"
            | "/var/lib"
            | "/var/www"
            | "/var/www/html"
            | "/etc"
            | "/usr"
            | "/usr/bin"
            | "/usr/lib"
            | "/lib"
            | "/lib/systemd"
            | "/lib/systemd/system"
            | "/usr/lib/systemd"
            | "/usr/lib/systemd/system"
            | "/usr/share"
            | "/usr/sbin"
            | "/usr/libexec"
            | "/usr/local"
            | "/usr/local/bin"
            | "/usr/local/sbin"
            | "/usr/local/share"
            | "/usr/local/lib"
            | "/sbin"
            | "/etc/systemd"
            | "/etc/systemd/system"
            | "/etc/default"
            | "/install"
    ) {
        return true;
    }
    let comp_count = path.components().count();
    comp_count <= 1
}

pub(super) fn candidate_runtime_targets(
    package_id: &str,
    units: &[String],
    env_cfg: &crate::PackageExecutionEnv,
) -> Vec<(PathBuf, RuntimeTargetKind)> {
    let resolve = |p: &str| -> PathBuf {
        let mut logical = p.to_string();
        for alias in MERGED_USR_ALIASES {
            let prefix = format!("/{alias}/");
            if logical.starts_with(&prefix) {
                let alias_path = match env_cfg.fs_root.as_ref() {
                    Some(root) => root.join(alias),
                    None => PathBuf::from(format!("/{alias}")),
                };
                if is_trusted_merged_usr_symlink(&alias_path, env_cfg.fs_root.as_deref()) {
                    logical = format!("/usr{logical}");
                }
                break;
            }
        }
        if let Some(ref root) = env_cfg.fs_root {
            let rel = logical.trim_start_matches(['/', '\\']);
            root.join(rel)
        } else {
            PathBuf::from(logical)
        }
    };

    let pkg = package_id.trim();
    let pkg_lower = pkg.to_ascii_lowercase();

    let mut dir_candidates: Vec<String> = vec![
        format!("/opt/{pkg}"),
        format!("/opt/{pkg_lower}"),
        format!("/etc/{pkg}"),
        format!("/etc/{pkg_lower}"),
        format!("/var/lib/{pkg}"),
        format!("/var/lib/{pkg_lower}"),
        format!("/usr/share/{pkg}"),
        format!("/usr/share/{pkg_lower}"),
        format!("/usr/lib/{pkg}"),
        format!("/usr/lib/{pkg_lower}"),
        format!("/usr/libexec/{pkg}"),
        format!("/usr/libexec/{pkg_lower}"),
        format!("/usr/local/share/{pkg}"),
        format!("/usr/local/share/{pkg_lower}"),
    ];

    match pkg_lower.as_str() {
        "adguardhome" => dir_candidates.push("/opt/AdGuardHome".into()),
        "bazarr" => dir_candidates.push("/opt/Bazarr".into()),
        "calibreweb" => {
            dir_candidates.extend([
                "/opt/calibre-web".into(),
                "/var/lib/calibre-web".into(),
                "/var/lib/calibre-library".into(),
            ]);
        }
        "duplicati" => dir_candidates.push("/usr/lib/duplicati".into()),
        "emby" => {
            dir_candidates.extend([
                "/opt/emby-server".into(),
                "/etc/emby-server".into(),
                "/usr/lib/emby-server".into(),
                "/usr/share/emby-server".into(),
                "/var/lib/emby-server".into(),
            ]);
        }
        "filebot" => {
            dir_candidates.extend(["/opt/filebot".into(), "/opt/filebot-node".into()]);
        }
        "jackett" => dir_candidates.push("/opt/Jackett".into()),
        "jellyfin" => dir_candidates.push("/usr/lib/jellyfin".into()),
        "grafana" => dir_candidates.push("/usr/share/grafana-server".into()),
        "kasmvnc" => {
            dir_candidates.extend([
                "/usr/lib/kasmvnc".into(),
                "/usr/lib/kasmvncserver".into(),
                "/usr/share/kasmvnc".into(),
                "/usr/share/kasmvncserver".into(),
            ]);
        }
        "kavita" => dir_candidates.push("/opt/Kavita".into()),
        "librespeed" => dir_candidates.extend([
            "/var/www/librespeed".into(),
            "/etc/aetherflow/librespeed".into(),
        ]),
        "lidarr" => dir_candidates.push("/opt/Lidarr".into()),
        "listenarr" => dir_candidates.push("/opt/Listenarr".into()),
        "maintainerr" => dir_candidates.push("/etc/systemd/system/af-maintainerr.service.d".into()),
        "netdata" => dir_candidates.push("/usr/lib/netdata".into()),
        "nextcloud" => {
            dir_candidates.extend([
                "/var/www/nextcloud".into(),
                "/var/www/html/nextcloud".into(),
            ]);
        }
        "ombi" => {
            dir_candidates.extend(["/opt/Ombi".into(), "/etc/Ombi".into()]);
        }
        "organizr" => dir_candidates.push("/var/www/organizr".into()),
        "paperless-ngx" => {
            dir_candidates.extend(["/opt/paperless".into(), "/var/lib/paperless".into()]);
        }
        "pihole" => {
            dir_candidates.extend([
                "/etc/.pihole".into(),
                "/var/www/html/admin".into(),
                "/var/www/html/pihole".into(),
            ]);
        }
        "piped" => {
            dir_candidates.extend([
                "/opt/piped".into(),
                "/opt/piped-backend".into(),
                "/opt/piped-proxy".into(),
            ]);
        }
        "plex" => {
            dir_candidates.extend([
                "/usr/lib/plexmediaserver".into(),
                "/usr/share/plexmediaserver".into(),
                "/var/lib/plexmediaserver".into(),
                "/etc/plexmediaserver".into(),
            ]);
        }
        "prowlarr" => dir_candidates.push("/opt/Prowlarr".into()),
        "qbittorrent" => dir_candidates.push("/usr/lib/qbittorrent".into()),
        "quassel" => dir_candidates.push("/usr/lib/quassel".into()),
        "radarr" => dir_candidates.push("/opt/Radarr".into()),
        "readarr" => dir_candidates.push("/opt/Readarr".into()),
        "rutorrent" => dir_candidates.push("/var/www/rutorrent".into()),
        "sabnzbd" => dir_candidates.push("/opt/SABnzbd".into()),
        "sonarr" => {
            dir_candidates.extend(["/opt/Sonarr".into(), "/opt/NzbDrone".into()]);
        }
        "tautulli" => {
            dir_candidates.extend(["/opt/Tautulli".into(), "/opt/plexpy".into()]);
        }
        "transmission" => {
            dir_candidates.extend([
                "/etc/transmission-daemon".into(),
                "/usr/lib/transmission".into(),
                "/var/lib/transmission-daemon".into(),
            ]);
        }
        "prometheus" => dir_candidates.push("/usr/share/prometheus-node-exporter".into()),
        "uptimekuma" => dir_candidates.push("/opt/uptime-kuma".into()),
        "wireguard" => dir_candidates.push("/usr/share/wireguard-tools".into()),
        "x2go" => dir_candidates.push("/usr/lib/x2go".into()),
        "xrdp" => dir_candidates.push("/usr/lib/xrdp".into()),
        "znc" => dir_candidates.push("/usr/lib/znc".into()),
        _ => {}
    }

    let mut all_units: Vec<String> = units.to_vec();
    match pkg_lower.as_str() {
        "deluge" => all_units.extend(["deluged.service".into(), "deluge-web.service".into()]),
        "dispatcharr" => all_units.extend([
            "dispatcharr-celery.service".into(),
            "dispatcharr-celerybeat.service".into(),
        ]),
        "emby" => all_units.push("emby-server.service".into()),
        "grafana" => all_units.push("grafana-server.service".into()),
        "homeassistant" => all_units.push("home-assistant@homeassistant.service".into()),
        "invidious" => all_units.extend([
            "af-invidious.service".into(),
            "af-invidious-companion.service".into(),
        ]),
        "kasmvnc" => all_units.push("af-kasmvnc.service".into()),
        "librespeed" => all_units.push("librespeed.socket".into()),
        "maintainerr" => all_units.push("af-maintainerr.service".into()),
        "mcvnc" => all_units.push("af-mcvnc.service".into()),
        "novnc" => all_units.extend(["novnc-xvnc.service".into(), "novnc-session.service".into()]),
        "palate" => all_units.push("af-palate.service".into()),
        "paperless-ngx" => all_units.extend([
            "paperless-webserver.service".into(),
            "paperless-worker.service".into(),
            "paperless-scheduler.service".into(),
        ]),
        "pihole" => all_units.push("pihole-FTL.service".into()),
        "piped" => all_units.extend([
            "af-piped.service".into(),
            "af-piped-api.service".into(),
            "af-piped-proxy.service".into(),
            "piped-backend.service".into(),
            "piped-proxy.service".into(),
        ]),
        "plex" => all_units.push("plexmediaserver.service".into()),
        "prometheus" => all_units.extend([
            "node_exporter.service".into(),
            "prometheus-node-exporter.service".into(),
        ]),
        "quassel" => all_units.push("quasselcore.service".into()),
        "rclone" => all_units.push("rclone-vfs.service".into()),
        "recyclarr" => all_units.extend(["recyclarr.service".into(), "recyclarr.timer".into()]),
        "scrutiny" => all_units.extend([
            "scrutiny-collector.service".into(),
            "scrutiny-collector.timer".into(),
        ]),
        "tailscale" => all_units.push("tailscaled.service".into()),
        "transmission" => all_units.push("transmission-daemon.service".into()),
        "uptimekuma" => all_units.push("uptime-kuma.service".into()),
        "wireguard" => all_units.push("wg-quick@wg0.service".into()),
        "x2go" => all_units.push("x2goserver.service".into()),
        "xrdp" => all_units.push("xrdp-sesman.service".into()),
        _ => {}
    }

    let mut file_candidates: Vec<String> = vec![
        format!("/usr/local/bin/{pkg}"),
        format!("/usr/local/bin/{pkg_lower}"),
        format!("/usr/bin/{pkg}"),
        format!("/usr/bin/{pkg_lower}"),
        format!("/usr/sbin/{pkg}"),
        format!("/usr/sbin/{pkg_lower}"),
        format!("/usr/local/sbin/{pkg}"),
        format!("/usr/local/sbin/{pkg_lower}"),
        format!("/etc/systemd/system/{pkg}.service"),
        format!("/etc/systemd/system/{pkg_lower}.service"),
        format!("/lib/systemd/system/{pkg_lower}.service"),
        format!("/usr/lib/systemd/system/{pkg_lower}.service"),
        format!("/etc/systemd/system/{pkg}.timer"),
        format!("/etc/systemd/system/{pkg_lower}.timer"),
        format!("/etc/systemd/system/{pkg}.socket"),
        format!("/etc/systemd/system/{pkg_lower}.socket"),
        format!("/etc/default/{pkg}"),
        format!("/etc/default/{pkg_lower}"),
        format!("/install/.{pkg_lower}.lock"),
        format!("/install/.{pkg_lower}.retained"),
    ];
    let lock_alias = af_models::resolve_package_lock_name(&pkg_lower);
    if lock_alias != pkg_lower {
        file_candidates.push(format!("/install/.{lock_alias}.lock"));
        file_candidates.push(format!("/install/.{lock_alias}.retained"));
    }

    if pkg_lower == "rclone" {
        dir_candidates.retain(|path| matches!(path.as_str(), "/etc/rclone" | "/var/lib/rclone"));
        // Global executables and vendor units are outside this package's rollback boundary.
        file_candidates.extend([
            crate::package_executor::RCLONE_BIN.into(),
            crate::package_executor::RCLONE_BIN_OWNER.into(),
            crate::package_executor::RCLONE_ENV.into(),
            crate::package_executor::RCLONE_LEGACY_ENV.into(),
        ]);
    }

    for unit in all_units {
        let u = unit.trim();
        if u.is_empty() || u.starts_with("port:") {
            continue;
        }
        let unit_file = if u.contains('.') {
            u.to_string()
        } else {
            format!("{u}.service")
        };
        file_candidates.push(format!("/etc/systemd/system/{unit_file}"));
        file_candidates.push(format!("/lib/systemd/system/{unit_file}"));
        file_candidates.push(format!("/usr/lib/systemd/system/{unit_file}"));
        if unit_file.ends_with(".socket") {
            file_candidates.push(format!(
                "/etc/systemd/system/sockets.target.wants/{unit_file}"
            ));
        } else if unit_file.ends_with(".timer") {
            file_candidates.push(format!(
                "/etc/systemd/system/timers.target.wants/{unit_file}"
            ));
        } else {
            file_candidates.push(format!(
                "/etc/systemd/system/multi-user.target.wants/{unit_file}"
            ));
        }
    }

    match pkg_lower.as_str() {
        "autobrr" => file_candidates.push("/usr/local/bin/autobrrctl".into()),
        "deluge" => file_candidates.extend([
            "/etc/default/deluged".into(),
            "/usr/bin/deluged".into(),
            "/usr/bin/deluge-web".into(),
            "/usr/bin/deluge-console".into(),
        ]),
        "duplicati" => file_candidates.push("/usr/bin/duplicati-server".into()),
        "emby" => file_candidates.extend([
            "/etc/emby-server.conf".into(),
            "/usr/bin/emby-server".into(),
        ]),
        "fail2ban" => file_candidates.extend([
            "/usr/bin/fail2ban-server".into(),
            "/usr/bin/fail2ban-client".into(),
        ]),
        "grafana" => file_candidates.extend([
            "/usr/bin/grafana-server".into(),
            "/usr/bin/grafana-cli".into(),
            "/usr/sbin/grafana-server".into(),
        ]),
        "kasmvnc" => file_candidates.extend([
            "/usr/local/bin/af-kasmvnc-start".into(),
            "/usr/bin/kasmvncserver".into(),
            "/usr/bin/kasmvncpasswd".into(),
            "/usr/bin/Xkasmvnc".into(),
            "/usr/bin/Xvnc".into(),
            "/usr/bin/vncserver".into(),
        ]),
        "librespeed" => file_candidates.push("/etc/aetherflow/librespeed-proxy-token.conf".into()),
        "maintainerr" => file_candidates.push("/usr/local/bin/af-systemd-sandbox".into()),
        "netdata" => {
            file_candidates.extend(["/usr/sbin/netdata".into(), "/usr/local/sbin/netdata".into()])
        }
        "novnc" => file_candidates.extend([
            "/usr/local/bin/af-novnc-start".into(),
            "/usr/local/bin/af-novnc-xvnc-start".into(),
            "/usr/bin/Xtigervnc".into(),
            "/usr/bin/tigervncserver".into(),
            "/usr/bin/websockify".into(),
            "/usr/bin/x11vnc".into(),
        ]),
        "nzbget" => file_candidates.push("/etc/nzbget.conf".into()),
        "paperless-ngx" => file_candidates.push("/etc/paperless.conf".into()),
        "pihole" => file_candidates.push("/usr/bin/pihole-FTL".into()),
        "plex" => file_candidates.extend([
            "/etc/default/plexmediaserver".into(),
            "/usr/bin/plexmediaserver".into(),
        ]),
        "prometheus" => file_candidates.extend([
            "/usr/local/bin/promtool".into(),
            "/usr/local/bin/node_exporter".into(),
            "/usr/bin/promtool".into(),
            "/usr/bin/prometheus-node-exporter".into(),
        ]),
        "qbittorrent" => file_candidates.push("/usr/bin/qbittorrent-nox".into()),
        "quassel" => file_candidates.extend([
            "/etc/default/quasselcore".into(),
            "/usr/bin/quasselcore".into(),
        ]),
        "sabnzbd" => file_candidates.push("/etc/default/sabnzbdplus".into()),
        "tailscale" => file_candidates.extend([
            "/etc/default/tailscaled".into(),
            "/usr/sbin/tailscaled".into(),
        ]),
        "transmission" => file_candidates.extend([
            "/usr/bin/transmission-daemon".into(),
            "/usr/bin/transmission-remote".into(),
        ]),
        "wireguard" => file_candidates.extend(["/usr/bin/wg".into(), "/usr/bin/wg-quick".into()]),
        "x2go" => file_candidates.extend([
            "/usr/bin/x2goruncommand".into(),
            "/usr/bin/x2gostartagent".into(),
            "/usr/sbin/x2gocleansessions".into(),
        ]),
        "xrdp" => file_candidates.extend(["/usr/sbin/xrdp".into(), "/usr/sbin/xrdp-sesman".into()]),
        _ => {}
    }

    if let Some(recipe) = crate::package_executor::get_declarative_recipe(pkg) {
        for step in recipe
            .install_steps
            .iter()
            .chain(recipe.update_steps.iter())
        {
            match step {
                crate::package_executor::DeclarativeStep::WriteTemplateFile { path, .. } => {
                    file_candidates.push(path.clone());
                }
                crate::package_executor::DeclarativeStep::WriteSystemdUnit {
                    unit_name, ..
                } => {
                    let u = unit_name.trim();
                    let unit_file = if u.contains('.') {
                        u.to_string()
                    } else {
                        format!("{u}.service")
                    };
                    file_candidates.push(format!("/etc/systemd/system/{unit_file}"));
                    file_candidates.push(format!("/lib/systemd/system/{unit_file}"));
                    file_candidates.push(format!("/usr/lib/systemd/system/{unit_file}"));
                }
                crate::package_executor::DeclarativeStep::DownloadBinary { dest_path, .. } => {
                    file_candidates.push(dest_path.clone());
                }
                crate::package_executor::DeclarativeStep::DownloadAndExtractTarGz {
                    dest_dir,
                    extract_binaries,
                    ..
                } => {
                    let clean = dest_dir.trim_end_matches('/');
                    for b in extract_binaries {
                        file_candidates.push(format!("{clean}/{b}"));
                    }
                }
                crate::package_executor::DeclarativeStep::GenerateSelfSignedTlsCert {
                    cert_path,
                    key_out_path,
                    ..
                } => {
                    file_candidates.push(cert_path.clone());
                    if let Some(ref k) = key_out_path {
                        file_candidates.push(k.clone());
                    }
                }
                crate::package_executor::DeclarativeStep::MergeIniSettings { path, .. } => {
                    file_candidates.push(path.clone());
                }
                _ => {}
            }
        }
    }

    if pkg_lower == "rclone" {
        file_candidates.retain(|path| {
            !path.starts_with("/usr/")
                && !path.starts_with("/lib/")
                && path != "/etc/default/rclone"
        });
    }

    let bp_paths =
        crate::package_executor::collect_blueprint_target_paths(pkg, env_cfg.fs_root.as_deref());

    let mut dir_targets: Vec<PathBuf> = Vec::new();
    for d in dir_candidates {
        let p = resolve(&d);
        if !dir_targets.contains(&p) {
            dir_targets.push(p);
        }
    }

    let mut file_targets: Vec<PathBuf> = Vec::new();
    for f in file_candidates {
        let p = resolve(&f);
        if dir_targets.iter().any(|d| p == *d || p.starts_with(d)) {
            continue;
        }
        if !file_targets.contains(&p) {
            file_targets.push(p);
        }
    }

    for p in bp_paths {
        if dir_targets.iter().any(|d| p == *d || p.starts_with(d)) {
            continue;
        }
        if !file_targets.contains(&p) {
            file_targets.push(p);
        }
    }

    let mut targets = Vec::new();
    for d in dir_targets {
        targets.push((d, RuntimeTargetKind::Directory));
    }
    for f in file_targets {
        targets.push((f, RuntimeTargetKind::FileOrSymlink));
    }
    targets
}
