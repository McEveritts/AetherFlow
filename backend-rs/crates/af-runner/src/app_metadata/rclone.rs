use super::parsers::{extract_runner_ini_value, read_app_metadata_config};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RcloneUnitPorts {
    pub gui_port: Option<u16>,
    pub api_port: Option<u16>,
}

pub fn parse_rclone_port_value(raw: &str) -> Option<u16> {
    let clean = raw.trim().trim_matches(['"', '\'']).trim();
    if clean.is_empty() || clean.len() > 5 || !clean.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    clean.parse::<u16>().ok().filter(|&p| p > 0)
}

fn parse_rclone_addr_port(raw: &str) -> Option<u16> {
    let clean = raw.trim().trim_matches(['"', '\'']).trim();
    if clean.is_empty()
        || clean
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    parse_rclone_port_value(clean.rsplit_once(':')?.1)
}

pub fn parse_rclone_unit_ports(unit_text: &str) -> RcloneUnitPorts {
    let mut joined: Vec<String> = Vec::new();
    for raw_line in unit_text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(last) = joined.last_mut().filter(|l| l.ends_with('\\')) {
            last.pop();
            last.push(' ');
            last.push_str(line.trim());
        } else {
            joined.push(line.to_string());
        }
    }

    let mut exec_lines: Vec<&str> = Vec::new();
    for line in &joined {
        if let Some((key, rest)) = line.trim().split_once('=') {
            if key.trim() == "ExecStart" {
                let value = rest.trim();
                if value.is_empty() {
                    exec_lines.clear();
                } else {
                    exec_lines.push(value);
                }
            }
        }
    }

    let mut result = RcloneUnitPorts::default();
    for line in exec_lines {
        let (mut saw_addr, mut args) = (false, line.split_whitespace().skip(1));
        while let Some(arg) = args.next() {
            let a = arg.trim_matches(['"', '\'']);
            let flag_val = |flag: &str, it: &mut std::iter::Skip<std::str::SplitWhitespace<'_>>| {
                a.strip_prefix(&format!("{flag}="))
                    .or_else(|| (a == flag).then(|| it.next()).flatten())
                    .and_then(parse_rclone_addr_port)
            };
            if let Some(p) = flag_val("--addr", &mut args) {
                result.gui_port = Some(p);
                saw_addr = true;
            } else if let Some(p) = flag_val("--rc-addr", &mut args) {
                if !saw_addr {
                    result.gui_port = Some(p);
                }
            } else if let Some(p) = flag_val("--api-addr", &mut args) {
                result.api_port = Some(p);
            }
        }
    }
    if result.api_port.is_some() && result.api_port == result.gui_port {
        result.api_port = None;
    }
    result
}

pub fn parse_rclone_env_api_port(content: &str) -> Result<Option<u16>, String> {
    let raw = extract_runner_ini_value(content, &["RCLONE_API_PORT"]);
    if raw.is_empty() {
        return Ok(None);
    }
    parse_rclone_port_value(&raw)
        .map(Some)
        .ok_or_else(|| format!("Invalid RCLONE_API_PORT {:?} in rclone.env", raw))
}

pub(super) fn effective_rclone_metadata_root() -> PathBuf {
    ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"]
        .into_iter()
        .find_map(|k| {
            env::var(k)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn read_rclone_unit_text_for_root(
    effective_root: &Path,
    unit_override: Option<&str>,
) -> Option<String> {
    let systemd_dir = effective_root.join("etc/systemd/system");
    let unit_name = match unit_override.map(str::trim) {
        Some("rclone-web" | "rclone-web.service") => "rclone-web.service",
        Some("rclone" | "rclone.service") => "rclone.service",
        _ if systemd_dir.join("rclone.service").exists()
            || !systemd_dir.join("rclone-web.service").exists() =>
        {
            "rclone.service"
        }
        _ => "rclone-web.service",
    };
    let mut combined = read_app_metadata_config(
        &systemd_dir.join(unit_name),
        Path::new(&format!("/etc/systemd/system/{unit_name}")),
    )
    .ok()?;

    let dropin_dir = systemd_dir.join(format!("{unit_name}.d"));
    if let Ok(entries) = fs::read_dir(&dropin_dir) {
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".conf"))
            .collect();
        names.sort();
        for name in names {
            let logical = format!("/etc/systemd/system/{unit_name}.d/{name}");
            if let Ok(text) = read_app_metadata_config(&dropin_dir.join(&name), Path::new(&logical))
            {
                combined.push('\n');
                combined.push_str(&text);
            }
        }
    }
    Some(combined)
}

pub fn extract_rclone_runtime_api_port_for_root(fs_root: Option<&Path>) -> Option<u16> {
    let text = read_rclone_unit_text_for_root(fs_root.unwrap_or(Path::new("/")), None)?;
    parse_rclone_unit_ports(&text).api_port
}

pub fn rclone_extra_reserved_ports(
    app_name: &str,
    fs_root: Option<&Path>,
) -> std::collections::BTreeSet<i32> {
    let mut extra = std::collections::BTreeSet::new();
    if !app_name.eq_ignore_ascii_case("rclone") {
        if let Some(api_port) = extract_rclone_runtime_api_port_for_root(fs_root) {
            extra.insert(api_port as i32);
        }
    }
    extra
}

pub fn rclone_secondary_port_update_for_root(
    fs_root: Option<&Path>,
    primary_port: i32,
    fallback_secondary: Option<i32>,
) -> Option<(&'static str, Option<i32>)> {
    let root = fs_root.unwrap_or(Path::new("/"));
    if let Some(text) = read_rclone_unit_text_for_root(root, None) {
        let api = parse_rclone_unit_ports(&text)
            .api_port
            .map(i32::from)
            .filter(|&p| primary_port <= 0 || p != primary_port);
        Some((af_models::RCLONE_RC_API_PORT_ROLE, api))
    } else {
        fallback_secondary
            .filter(|&p| (1..=65535).contains(&p) && p != primary_port)
            .map(|p| (af_models::RCLONE_RC_API_PORT_ROLE, Some(p)))
    }
}
