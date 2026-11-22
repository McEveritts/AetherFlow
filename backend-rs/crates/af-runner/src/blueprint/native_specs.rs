use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{collections::HashMap, path::Path, time::Duration};

pub(crate) const TRANSMISSION_CONFIG_PATHS: [&str; 3] = [
    "/etc/transmission-daemon/settings.json",
    "/var/lib/transmission-daemon/info/settings.json",
    "/var/lib/transmission-daemon/.config/transmission-daemon/settings.json",
];

// ─────────────────────────────────────────────────────────────────────────────
// 4. SQLite Setting Mutator & `*arr` DownloadClients Route Injector
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrites `DownloadClients.Settings` JSON blobs in `*arr` SQLite databases (`sonarr.db`, `radarr.db`, etc.)
/// to route matching `Host` entries through the AetherFlow internal switchboard domain and port.
pub fn inject_arr_download_client_routes(
    db_path: &Path,
    routes: &HashMap<String, String>,
    target_port: i32,
) -> Result<usize, String> {
    if !db_path.is_file() || routes.is_empty() {
        return Ok(0);
    }

    let mut conn = Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| format!("failed to open *arr DB {}: {}", db_path.display(), e))?;
    conn.busy_timeout(Duration::from_millis(2500))
        .map_err(|err| err.to_string())?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|err| format!("failed to start transaction for *arr route update: {err}"))?;
    let has_clients: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'DownloadClients' AND type = 'table')",
        [],
        |row| row.get(0),
    ).map_err(|err| format!("cannot inspect *arr download clients: {err}"))?;
    if !has_clients {
        return Ok(0);
    }
    let has_implementation: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('DownloadClients') WHERE name = 'Implementation' COLLATE NOCASE)",
        [],
        |row| row.get(0),
    ).map_err(|err| format!("cannot inspect *arr download client settings: {err}"))?;

    let collected_rows: Vec<(i64, String, String)> = {
        let query = if has_implementation {
            "SELECT Id, COALESCE(Implementation, ''), Settings FROM DownloadClients"
        } else {
            "SELECT Id, '', Settings FROM DownloadClients"
        };
        let mut stmt = tx.prepare(query).map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<_, _>>()
            .map_err(|err| err.to_string())?
    };

    let mut updates: Vec<(i64, String)> = Vec::new();
    for (id, implementation, settings_str) in collected_rows {
        let Ok(mut settings_json) = serde_json::from_str::<Value>(&settings_str) else {
            continue;
        };
        let Some(obj) = settings_json.as_object_mut() else {
            continue;
        };
        let current_host = obj
            .get("Host")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("host").and_then(|v| v.as_str()))
            .map(|s| s.to_string());
        let existing_port = obj
            .get("Port")
            .and_then(|v| v.as_i64())
            .or_else(|| obj.get("port").and_then(|v| v.as_i64()))
            .unwrap_or(0) as i32;

        if let Some(host_val) = current_host {
            if let Some(default_host) = routes.get(&host_val) {
                let impl_lower = implementation.trim().to_ascii_lowercase();
                let (new_host, desired_port) = match impl_lower.as_str() {
                    "transmission" => ("transmission.aether.local".to_string(), {
                        let p =
                            crate::extract_app_runtime_meta_local("transmission").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "deluge" => ("deluge.aether.local".to_string(), {
                        let p = crate::extract_app_runtime_meta_local("deluge").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "sabnzbd" => ("sabnzbd.aether.local".to_string(), {
                        let p = crate::extract_app_runtime_meta_local("sabnzbd").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "nzbget" => ("nzbget.aether.local".to_string(), {
                        let p = crate::extract_app_runtime_meta_local("nzbget").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "" if existing_port == 9091 => {
                        ("transmission.aether.local".to_string(), existing_port)
                    }
                    "" if existing_port == 8112 || existing_port == 58846 => {
                        ("deluge.aether.local".to_string(), existing_port)
                    }
                    "" if existing_port == 8085 => {
                        ("sabnzbd.aether.local".to_string(), existing_port)
                    }
                    "" if existing_port == 6789 => {
                        ("nzbget.aether.local".to_string(), existing_port)
                    }
                    "qbittorrent" | "" => (default_host.clone(), target_port),
                    _ => continue,
                };
                if obj.contains_key("Host") {
                    obj.insert("Host".to_string(), Value::String(new_host));
                } else {
                    obj.insert("host".to_string(), Value::String(new_host));
                }
                if desired_port > 0 {
                    if obj.contains_key("Port") {
                        obj.insert("Port".to_string(), json!(desired_port));
                    } else {
                        obj.insert("port".to_string(), json!(desired_port));
                    }
                }
                if let Ok(serialized) = serde_json::to_string(&settings_json) {
                    updates.push((id, serialized));
                }
            }
        }
    }

    let count = updates.len();
    for (id, new_settings) in updates {
        tx.execute(
            "UPDATE DownloadClients SET Settings = ?1 WHERE Id = ?2",
            params![new_settings, id],
        )
        .map_err(|err| format!("failed to update DownloadClients Id={id}: {err}"))?;
    }
    tx.commit()
        .map_err(|err| format!("failed to commit *arr DB updates: {err}"))?;

    Ok(count)
}

pub struct NativeAppSpec {
    pub config_paths: Vec<String>,
    pub sqlite_db_path: Option<String>,
}

pub fn native_app_spec(canonical_app: &str, bp_config_path: &str) -> NativeAppSpec {
    let mut paths = Vec::new();
    if !bp_config_path.trim().is_empty() {
        paths.push(bp_config_path.trim().to_string());
    }

    match canonical_app {
        "dispatcharr" => NativeAppSpec {
            config_paths: vec!["/etc/dispatcharr/dispatcharr.env".to_string()],
            sqlite_db_path: None,
        },
        "gitea" => NativeAppSpec {
            config_paths: vec!["/etc/gitea/app.ini".to_string()],
            sqlite_db_path: None,
        },
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" => {
            for candidate in [
                format!("/var/lib/{}/config.xml", canonical_app),
                format!("/var/lib/{}/config/config.xml", canonical_app),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: Some(format!("/var/lib/{}/{}.db", canonical_app, canonical_app)),
            }
        }
        "listenarr" => {
            for candidate in [
                "/var/lib/listenarr/config.xml".to_string(),
                "/var/lib/listenarr/config/config.xml".to_string(),
                "/etc/systemd/system/listenarr.service".to_string(),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "bazarr" => {
            for candidate in [
                "/var/lib/bazarr/config/config.yaml".to_string(),
                "/var/lib/bazarr/data/config/config.yaml".to_string(),
                "/opt/bazarr/data/config/config.yaml".to_string(),
                "/etc/bazarr/config.yaml".to_string(),
                "/var/lib/bazarr/config/config.ini".to_string(),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "jellyfin" => {
            for p in [
                "/etc/jellyfin/network.xml",
                "/var/lib/jellyfin/config/network.xml",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "emby" => {
            for p in ["/var/lib/emby/config/system.xml", "/etc/emby/system.xml"] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "qbittorrent" => {
            for p in [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "sabnzbd" => {
            for p in [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/etc/sabnzbd/sabnzbd.ini",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "tautulli" => {
            for p in [
                "/var/lib/tautulli/config.ini",
                "/opt/Tautulli/config.ini",
                "/etc/tautulli/config.ini",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "transmission" | "transmission-daemon" => {
            for p in TRANSMISSION_CONFIG_PATHS {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "overseerr" | "jellyseerr" => {
            for candidate in [
                format!("/etc/systemd/system/{canonical_app}.service"),
                format!("/var/lib/{canonical_app}/settings.json"),
                format!("/var/lib/{canonical_app}/config/settings.json"),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "jackett" => {
            for p in [
                "/var/lib/jackett/Jackett/ServerConfig.json",
                "/var/lib/jackett/.config/Jackett/ServerConfig.json",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "pihole" => {
            let s = "/etc/pihole/pihole.toml".to_string();
            if !paths.contains(&s) {
                paths.push(s);
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        _ => NativeAppSpec {
            config_paths: paths,
            sqlite_db_path: None,
        },
    }
}
