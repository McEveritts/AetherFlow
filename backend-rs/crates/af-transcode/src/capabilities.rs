//! Local transcode capability probing and vendor-aware render-node selection via `af-hardware`.

use crate::argv::{Capability, HwAccel};
use crate::config::{
    configured_real_ffmpeg_path, validate_real_ffmpeg_path, DEFAULT_PROBE_TIMEOUT,
};
use af_hardware::RenderNode;
use anyhow::Context;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Normalized PCI vendor IDs matching `af-hardware`.
pub const PCI_VENDOR_INTEL: &str = "0x8086";
pub const PCI_VENDOR_AMD: &str = "0x1002";
pub const PCI_VENDOR_NVIDIA: &str = "0x10de";

/// Serializable render-node entry for `af-transcode capabilities` and P9 `/health` JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderNodeInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
}

impl From<&RenderNode> for RenderNodeInfo {
    fn from(node: &RenderNode) -> Self {
        let vendor = node
            .vendor_id
            .as_deref()
            .and_then(vendor_name_for_id)
            .map(ToString::to_string);
        Self {
            path: node.path.to_string_lossy().into_owned(),
            vendor_id: node.vendor_id.clone(),
            vendor,
        }
    }
}

/// Complete capability report emitted by `af-transcode capabilities` and consumed by P9 `/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeCapabilities {
    pub ffmpeg_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ffmpeg_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ffmpeg_version_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    pub encoders: Vec<String>,
    pub render_nodes: Vec<RenderNodeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_render_node: Option<String>,
}

/// Configuration for probing transcode capabilities (supports isolated fixtures in tests).
#[derive(Debug, Clone)]
pub struct CapabilitiesConfig {
    pub real_ffmpeg: PathBuf,
    pub dpkg_query_path: Option<PathBuf>,
    pub render_nodes_override: Option<Vec<RenderNode>>,
    pub probe_timeout: Duration,
}

impl CapabilitiesConfig {
    pub fn from_env() -> Self {
        Self {
            real_ffmpeg: configured_real_ffmpeg_path(),
            dpkg_query_path: Some(PathBuf::from("/usr/bin/dpkg-query")),
            render_nodes_override: None,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
        }
    }
}

/// Maps a PCI vendor ID string (e.g. `0x8086`) to a human-readable vendor tag.
pub fn vendor_name_for_id(vendor_id: &str) -> Option<&'static str> {
    match vendor_id.trim().to_ascii_lowercase().as_str() {
        PCI_VENDOR_INTEL => Some("intel"),
        PCI_VENDOR_AMD => Some("amd"),
        PCI_VENDOR_NVIDIA => Some("nvidia"),
        _ => None,
    }
}

fn normalized_vendor_id(node: &RenderNode) -> Option<String> {
    node.vendor_id
        .as_deref()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

/// Selects the most suitable worker DRM render node from `af_hardware::RenderNode` candidates
/// for the job's inferred [`Capability`].
///
/// Rules:
/// - **QSV** (`HwAccel::Qsv` or `*_qsv` encoder): requires Intel (`0x8086`), falling back only to
///   a node whose vendor ID is absent (e.g. virtualized passthrough without sysfs vendor).
/// - **VA-API** (`HwAccel::Vaapi` or `*_vaapi` encoder): prefers Intel (`0x8086`) or AMD (`0x1002`)
///   in `af_hardware::detect_render_nodes()` order, falling back to an unknown-vendor node, never
///   selecting an NVIDIA-only (`0x10de`) node.
/// - **CUDA/NVENC**: prefers NVIDIA (`0x10de`), falling back to an unknown-vendor node.
/// - **Vulkan/OpenCL/DRM/generic**: selects the first detected render node in `af_hardware` order.
pub fn select_render_node(cap: &Capability, nodes: &[RenderNode]) -> Option<PathBuf> {
    if nodes.is_empty() {
        return None;
    }

    let needs_qsv = cap.hwaccel == Some(HwAccel::Qsv)
        || cap.required_hwaccels.contains(&HwAccel::Qsv)
        || cap
            .encoder
            .as_deref()
            .is_some_and(|e| e.to_ascii_lowercase().ends_with("_qsv"));

    if needs_qsv {
        return nodes
            .iter()
            .find(|n| normalized_vendor_id(n).as_deref() == Some(PCI_VENDOR_INTEL))
            .or_else(|| nodes.iter().find(|n| normalized_vendor_id(n).is_none()))
            .map(|n| n.path.clone());
    }

    let needs_vaapi = cap.hwaccel == Some(HwAccel::Vaapi)
        || cap.required_hwaccels.contains(&HwAccel::Vaapi)
        || cap
            .encoder
            .as_deref()
            .is_some_and(|e| e.to_ascii_lowercase().ends_with("_vaapi"));

    if needs_vaapi {
        return nodes
            .iter()
            .find(|n| {
                matches!(
                    normalized_vendor_id(n).as_deref(),
                    Some(PCI_VENDOR_AMD | PCI_VENDOR_INTEL)
                )
            })
            .or_else(|| nodes.iter().find(|n| normalized_vendor_id(n).is_none()))
            .map(|n| n.path.clone());
    }

    let needs_cuda = cap.hwaccel == Some(HwAccel::Cuda)
        || cap.required_hwaccels.contains(&HwAccel::Cuda)
        || cap
            .encoder
            .as_deref()
            .is_some_and(|e| e.to_ascii_lowercase().ends_with("_nvenc"));

    if needs_cuda {
        return nodes
            .iter()
            .find(|n| normalized_vendor_id(n).as_deref() == Some(PCI_VENDOR_NVIDIA))
            .or_else(|| nodes.iter().find(|n| normalized_vendor_id(n).is_none()))
            .map(|n| n.path.clone());
    }

    nodes.first().map(|n| n.path.clone())
}

/// Parses the version token and header line from `ffmpeg -version` output.
pub fn parse_ffmpeg_version(stdout: &str) -> (Option<String>, Option<String>) {
    let Some(first_line) = stdout.lines().map(str::trim).find(|l| !l.is_empty()) else {
        return (None, None);
    };
    let version = first_line
        .strip_prefix("ffmpeg version ")
        .and_then(|rest| rest.split_whitespace().next())
        .filter(|tok| !tok.is_empty())
        .map(ToString::to_string);
    (version, Some(first_line.to_string()))
}

/// Parses sorted, deduplicated video encoder names from `ffmpeg -hide_banner -encoders` output.
pub fn parse_ffmpeg_video_encoders(stdout: &str) -> Vec<String> {
    let mut encoders = BTreeSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim_start();
        let mut parts = trimmed.split_whitespace();
        let Some(flags) = parts.next() else {
            continue;
        };
        if flags.len() != 6 || !flags.starts_with('V') {
            continue;
        }
        if !flags.bytes().all(|b| b.is_ascii_uppercase() || b == b'.') {
            continue;
        }
        let Some(name) = parts.next() else {
            continue;
        };
        if name == "=" || name.starts_with('-') {
            continue;
        }
        if name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+'))
        {
            encoders.insert(name.to_string());
        }
    }
    encoders.into_iter().collect()
}

/// Parses installed `jellyfin-ffmpeg*` package name and version from
/// `dpkg-query -W -f='${Status}\t${Package}\t${Version}\n' 'jellyfin-ffmpeg*'`.
pub fn parse_dpkg_jellyfin_ffmpeg_version(stdout: &str) -> (Option<String>, Option<String>) {
    let mut installed: Vec<(String, String)> = Vec::new();
    for line in stdout.lines() {
        let mut cols = line.split('\t');
        let Some(status) = cols.next().map(str::trim) else {
            continue;
        };
        let Some(pkg) = cols.next().map(str::trim) else {
            continue;
        };
        let Some(ver) = cols.next().map(str::trim) else {
            continue;
        };
        if status == "install ok installed" && !pkg.is_empty() && !ver.is_empty() {
            installed.push((pkg.to_string(), ver.to_string()));
        }
    }
    installed.sort();
    installed
        .pop()
        .map(|(pkg, ver)| (Some(pkg), Some(ver)))
        .unwrap_or((None, None))
}

/// Runs a probe command in its own process group with a strict wall-clock deadline.
async fn run_bounded_output(
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> anyhow::Result<std::process::Output> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn probe '{}'", program.display()))?;
    let pgid = child.id().map(|id| Pid::from_raw(id as i32));

    let mut wait_fut = std::pin::pin!(child.wait_with_output());
    match tokio::time::timeout(timeout, &mut wait_fut).await {
        Ok(res) => res.with_context(|| format!("probe '{}' failed", program.display())),
        Err(_) => {
            if let Some(pgid) = pgid {
                let _ = killpg(pgid, Signal::SIGKILL);
            }
            anyhow::bail!(
                "probe '{}' timed out after {} ms",
                program.display(),
                timeout.as_millis()
            );
        }
    }
}

/// Collects local `ffmpeg` version, installed Debian `jellyfin-ffmpeg*` version, video encoders,
/// and DRM render nodes (via `af_hardware::detect_render_nodes()`).
pub async fn probe_capabilities(
    config: &CapabilitiesConfig,
) -> anyhow::Result<TranscodeCapabilities> {
    let real_ffmpeg = validate_real_ffmpeg_path(&config.real_ffmpeg)
        .with_context(|| format!("invalid real ffmpeg '{}'", config.real_ffmpeg.display()))?;

    let ver_output = run_bounded_output(&real_ffmpeg, &["-version"], config.probe_timeout).await?;
    let (ffmpeg_version, ffmpeg_version_line) = if ver_output.status.success() {
        parse_ffmpeg_version(&String::from_utf8_lossy(&ver_output.stdout))
    } else {
        (None, None)
    };

    let enc_output = run_bounded_output(
        &real_ffmpeg,
        &["-hide_banner", "-encoders"],
        config.probe_timeout,
    )
    .await?;
    let encoders = if enc_output.status.success() {
        parse_ffmpeg_video_encoders(&String::from_utf8_lossy(&enc_output.stdout))
    } else {
        Vec::new()
    };

    let (package_name, package_version) = match &config.dpkg_query_path {
        Some(dpkg_path) if dpkg_path.exists() => {
            match run_bounded_output(
                dpkg_path,
                &[
                    "-W",
                    "-f=${Status}\t${Package}\t${Version}\n",
                    "jellyfin-ffmpeg*",
                ],
                config.probe_timeout,
            )
            .await
            {
                Ok(out) => {
                    parse_dpkg_jellyfin_ffmpeg_version(&String::from_utf8_lossy(&out.stdout))
                }
                Err(_) => (None, None),
            }
        }
        _ => (None, None),
    };

    let detected_nodes = match &config.render_nodes_override {
        Some(nodes) => nodes.clone(),
        None => af_hardware::detect_render_nodes(),
    };
    let render_nodes: Vec<RenderNodeInfo> =
        detected_nodes.iter().map(RenderNodeInfo::from).collect();
    let primary_render_node = render_nodes.first().map(|n| n.path.clone());

    Ok(TranscodeCapabilities {
        ffmpeg_path: config.real_ffmpeg.to_string_lossy().into_owned(),
        ffmpeg_version,
        ffmpeg_version_line,
        package_name,
        package_version,
        encoders,
        render_nodes,
        primary_render_node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_debian_13_jellyfin_ffmpeg_outputs() {
        let ver_sample = "\
ffmpeg version 8.1.3-Jellyfin Copyright (c) 2000-2026 the FFmpeg developers
built with gcc 14 (Debian 14.2.0-19)
";
        let (ver, line) = parse_ffmpeg_version(ver_sample);
        assert_eq!(ver.as_deref(), Some("8.1.3-Jellyfin"));
        assert!(line.unwrap().starts_with("ffmpeg version 8.1.3-Jellyfin"));

        let enc_sample = "\
Encoders:
 V..... = Video
 A..... = Audio
 ------
 V....D av1_nvenc            NVIDIA NVENC av1 encoder (codec av1)
 V..... av1_qsv              AV1 (Intel Quick Sync Video acceleration) (codec av1)
 V....D av1_vaapi            AV1 (VAAPI) (codec av1)
 V....D h264_vaapi           H.264/AVC (VAAPI) (codec h264)
 V....D libx264              libx264 H.264
 A....D aac                  AAC (Advanced Audio Coding)
 S..... srt                  SubRip subtitle
";
        let encoders = parse_ffmpeg_video_encoders(enc_sample);
        assert_eq!(
            encoders,
            vec!["av1_nvenc", "av1_qsv", "av1_vaapi", "h264_vaapi", "libx264"]
        );

        let dpkg_sample = "\
unknown ok not-installed\tjellyfin-ffmpeg\t
unknown ok not-installed\tjellyfin-ffmpeg7\t
install ok installed\tjellyfin-ffmpeg8\t8.1.3-1-trixie
";
        assert_eq!(
            parse_dpkg_jellyfin_ffmpeg_version(dpkg_sample),
            (
                Some("jellyfin-ffmpeg8".to_string()),
                Some("8.1.3-1-trixie".to_string())
            )
        );
    }

    #[test]
    fn select_render_node_respects_vendor_and_order() {
        let amd = RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        };
        let intel = RenderNode {
            path: PathBuf::from("/dev/dri/renderD129"),
            vendor_id: Some("0x8086".to_string()),
        };
        let nvidia = RenderNode {
            path: PathBuf::from("/dev/dri/renderD130"),
            vendor_id: Some("0x10de".to_string()),
        };

        // QSV must pick Intel renderD129 even when AMD is renderD128
        let qsv_cap = Capability {
            hwaccel: Some(HwAccel::Qsv),
            required_hwaccels: vec![HwAccel::Vaapi, HwAccel::Qsv],
            encoder: Some("hevc_qsv".to_string()),
            ..Default::default()
        };
        assert_eq!(
            select_render_node(&qsv_cap, &[amd.clone(), intel.clone(), nvidia.clone()]),
            Some(PathBuf::from("/dev/dri/renderD129"))
        );
        // QSV on AMD+NVIDIA only -> None (no Intel node)
        assert_eq!(
            select_render_node(&qsv_cap, &[amd.clone(), nvidia.clone()]),
            None
        );

        // VA-API prefers first Intel/AMD in order, skips NVIDIA-only
        let vaapi_cap = Capability {
            hwaccel: Some(HwAccel::Vaapi),
            required_hwaccels: vec![HwAccel::Vaapi],
            encoder: Some("h264_vaapi".to_string()),
            ..Default::default()
        };
        assert_eq!(
            select_render_node(&vaapi_cap, &[nvidia.clone(), amd.clone(), intel.clone()]),
            Some(PathBuf::from("/dev/dri/renderD128"))
        );
        assert_eq!(
            select_render_node(&vaapi_cap, std::slice::from_ref(&nvidia)),
            None
        );

        // CUDA prefers NVIDIA
        let cuda_cap = Capability {
            hwaccel: Some(HwAccel::Cuda),
            required_hwaccels: vec![HwAccel::Cuda],
            encoder: Some("h264_nvenc".to_string()),
            ..Default::default()
        };
        assert_eq!(
            select_render_node(&cuda_cap, &[amd, intel, nvidia]),
            Some(PathBuf::from("/dev/dri/renderD130"))
        );
    }
}
