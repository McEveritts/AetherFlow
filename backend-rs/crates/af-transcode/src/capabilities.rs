//! Local transcode capability probing and vendor-aware render-node selection via `af-hardware`.

use crate::argv::{Capability, HwAccel};
use crate::config::{
    configured_real_ffmpeg_path, configured_worker_adapt_backend, configured_worker_max_jobs,
    validate_real_ffmpeg_path, BackendAdaptMode, DEFAULT_PROBE_TIMEOUT,
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

/// Parsed VA-API profile & entrypoint summary from `vainfo --display drm --device <node>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaInfoProfileSummary {
    pub driver: Option<String>,
    pub decode_codecs: Vec<String>,
    pub encode_codecs: Vec<String>,
    pub supports_vpp: bool,
}

/// Serializable render-node entry for `af-transcode capabilities` and P9 `/health` JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderNodeInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vaapi_driver: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vaapi_decode_codecs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vaapi_encode_codecs: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub supports_vpp: bool,
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
            vaapi_driver: None,
            vaapi_decode_codecs: Vec::new(),
            vaapi_encode_codecs: Vec::new(),
            supports_vpp: false,
        }
    }
}

/// Complete capability report emitted by `af-transcode capabilities` and consumed by P9 `/health`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_max_jobs: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hw_decoders: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hw_encoders_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapt_backend_mode: Option<BackendAdaptMode>,
}

impl TranscodeCapabilities {
    /// Returns the effective worker backend adaptation mode (`Off` when omitted).
    pub fn effective_adapt_backend_mode(&self) -> BackendAdaptMode {
        self.adapt_backend_mode.unwrap_or(BackendAdaptMode::Off)
    }
}

/// Configuration for probing transcode capabilities (supports isolated fixtures in tests).
#[derive(Debug, Clone)]
pub struct CapabilitiesConfig {
    pub real_ffmpeg: PathBuf,
    pub dpkg_query_path: Option<PathBuf>,
    pub vainfo_path: Option<PathBuf>,
    pub render_nodes_override: Option<Vec<RenderNode>>,
    pub probe_timeout: Duration,
}

impl CapabilitiesConfig {
    pub fn from_env() -> Self {
        Self {
            real_ffmpeg: configured_real_ffmpeg_path(),
            dpkg_query_path: Some(PathBuf::from("/usr/bin/dpkg-query")),
            vainfo_path: Some(PathBuf::from("/usr/bin/vainfo")),
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
        if cap.requires_vaapi_tonemap {
            // `tonemap_vaapi` relies on Intel VA-API VPP HDR tonemapping and fails on AMD Mesa VA-API.
            return nodes
                .iter()
                .find(|n| normalized_vendor_id(n).as_deref() == Some(PCI_VENDOR_INTEL))
                .or_else(|| nodes.iter().find(|n| normalized_vendor_id(n).is_none()))
                .map(|n| n.path.clone());
        }
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

fn vainfo_profile_codec_tags(profile: &str) -> &'static [&'static str] {
    if profile.starts_with("VAProfileH264") {
        &["h264"]
    } else if profile == "VAProfileHEVCMain10" {
        &["hevc", "hevc_10bit"]
    } else if profile.starts_with("VAProfileHEVC") {
        &["hevc"]
    } else if matches!(profile, "VAProfileVP9Profile2" | "VAProfileVP9Profile3") {
        &["vp9", "vp9_10bit"]
    } else if matches!(profile, "VAProfileVP9Profile0" | "VAProfileVP9Profile1") {
        &["vp9"]
    } else if matches!(profile, "VAProfileAV1Profile0" | "VAProfileAV1Profile1") {
        &["av1", "av1_10bit"]
    } else if profile.starts_with("VAProfileMPEG2") {
        &["mpeg2video"]
    } else if profile.starts_with("VAProfileVC1") {
        &["vc1"]
    } else if profile.starts_with("VAProfileVP8") {
        &["vp8"]
    } else if profile == "VAProfileJPEGBaseline" {
        &["mjpeg"]
    } else {
        &[]
    }
}

/// Parses driver version, supported decode/encode codecs, and VPP support from
/// `vainfo --display drm --device <render_node>` output.
pub fn parse_vainfo_output(stdout: &str) -> VaInfoProfileSummary {
    let mut driver: Option<String> = None;
    let mut decode_set = BTreeSet::new();
    let mut encode_set = BTreeSet::new();
    let mut supports_vpp = false;

    for raw_line in stdout.lines() {
        let trimmed = raw_line.trim();
        if let Some(rest) = trimmed.strip_prefix("vainfo: Driver version:") {
            let val = rest.trim();
            if !val.is_empty() {
                driver = Some(val.to_string());
            }
            continue;
        }
        if !trimmed.starts_with("VAProfile") {
            continue;
        }
        let Some((raw_profile, raw_entrypoint)) = trimmed.split_once(':') else {
            continue;
        };
        let profile = raw_profile.trim();
        let entrypoint = raw_entrypoint.trim();
        match entrypoint {
            "VAEntrypointVideoProc" => {
                supports_vpp = true;
            }
            "VAEntrypointVLD" => {
                for &tag in vainfo_profile_codec_tags(profile) {
                    decode_set.insert(tag.to_string());
                }
            }
            "VAEntrypointEncSlice" | "VAEntrypointEncSliceLP" | "VAEntrypointEncPicture" => {
                for &tag in vainfo_profile_codec_tags(profile) {
                    encode_set.insert(tag.to_string());
                }
            }
            _ => {}
        }
    }

    VaInfoProfileSummary {
        driver,
        decode_codecs: decode_set.into_iter().collect(),
        encode_codecs: encode_set.into_iter().collect(),
        supports_vpp,
    }
}

fn node_has_vainfo_data(node: &RenderNodeInfo) -> bool {
    !node.vaapi_decode_codecs.is_empty()
        || !node.vaapi_encode_codecs.is_empty()
        || node.vaapi_driver.is_some()
}

fn is_nvidia_node_info(node: &RenderNodeInfo) -> bool {
    node.vendor_id
        .as_deref()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(PCI_VENDOR_NVIDIA))
        || node
            .vendor
            .as_deref()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("nvidia"))
}

fn is_intel_node_info(node: &RenderNodeInfo) -> bool {
    node.vendor_id
        .as_deref()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(PCI_VENDOR_INTEL))
        || node
            .vendor
            .as_deref()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("intel"))
}

fn vaapi_codec_for_hw_encoder_prefix(prefix: &str) -> Option<&'static str> {
    match prefix {
        "h264" => Some("h264"),
        "hevc" => Some("hevc"),
        "vp9" => Some("vp9"),
        "av1" => Some("av1"),
        "mpeg2" => Some("mpeg2video"),
        "vp8" => Some("vp8"),
        "mjpeg" => Some("mjpeg"),
        _ => None,
    }
}

/// Filters `ffmpeg -encoders` against silicon-accurate `vainfo` encode profiles when at least
/// one render node was probed by `vainfo`.
///
/// Returns `(filtered_encoders, verified)`. When no render node has `vainfo` probe data, returns
/// `(encoders, false)` unchanged for backward compatibility.
pub fn filter_encoders_with_vainfo(
    encoders: Vec<String>,
    render_nodes: &[RenderNodeInfo],
) -> (Vec<String>, bool) {
    if !render_nodes.iter().any(node_has_vainfo_data) {
        return (encoders, false);
    }

    let mut non_nvidia_encode = BTreeSet::new();
    let mut intel_encode = BTreeSet::new();
    let mut has_probed_intel = false;

    for node in render_nodes {
        if !node_has_vainfo_data(node) || is_nvidia_node_info(node) {
            continue;
        }
        let is_intel = is_intel_node_info(node);
        if is_intel {
            has_probed_intel = true;
        }
        for codec in &node.vaapi_encode_codecs {
            let c = codec.to_ascii_lowercase();
            non_nvidia_encode.insert(c.clone());
            if is_intel {
                intel_encode.insert(c);
            }
        }
    }

    let filtered = encoders
        .into_iter()
        .filter(|enc| {
            let lower = enc.to_ascii_lowercase();
            if let Some(prefix) = lower.strip_suffix("_vaapi") {
                match vaapi_codec_for_hw_encoder_prefix(prefix) {
                    Some(codec) => non_nvidia_encode.contains(codec),
                    None => true,
                }
            } else if let Some(prefix) = lower.strip_suffix("_qsv") {
                match vaapi_codec_for_hw_encoder_prefix(prefix) {
                    Some(codec) => intel_encode.contains(codec),
                    None => has_probed_intel,
                }
            } else {
                true
            }
        })
        .collect();

    (filtered, true)
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
    let mut render_nodes: Vec<RenderNodeInfo> =
        detected_nodes.iter().map(RenderNodeInfo::from).collect();

    if let Some(ref vainfo_path) = config.vainfo_path {
        if vainfo_path.exists() {
            for node in &mut render_nodes {
                if is_nvidia_node_info(node) {
                    continue;
                }
                if let Ok(out) = run_bounded_output(
                    vainfo_path,
                    &["--display", "drm", "--device", &node.path],
                    config.probe_timeout,
                )
                .await
                {
                    if out.status.success() {
                        let summary = parse_vainfo_output(&String::from_utf8_lossy(&out.stdout));
                        node.vaapi_driver = summary.driver;
                        node.vaapi_decode_codecs = summary.decode_codecs;
                        node.vaapi_encode_codecs = summary.encode_codecs;
                        node.supports_vpp = summary.supports_vpp;
                    }
                }
            }
        }
    }

    let hw_decoders: Vec<String> = render_nodes
        .iter()
        .flat_map(|n| n.vaapi_decode_codecs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let (encoders, hw_encoders_verified) = filter_encoders_with_vainfo(encoders, &render_nodes);
    let primary_render_node = render_nodes.first().map(|n| n.path.clone());
    let adapt_backend_mode =
        Some(configured_worker_adapt_backend()).filter(|m| *m != BackendAdaptMode::Off);

    Ok(TranscodeCapabilities {
        ffmpeg_path: config.real_ffmpeg.to_string_lossy().into_owned(),
        ffmpeg_version,
        ffmpeg_version_line,
        package_name,
        package_version,
        encoders,
        render_nodes,
        primary_render_node,
        worker_max_jobs: Some(configured_worker_max_jobs()),
        hw_decoders,
        hw_encoders_verified,
        adapt_backend_mode,
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

    #[test]
    fn transcode_capabilities_worker_max_jobs_serde_is_backwards_compatible() {
        // Legacy JSON fixture omitting `worker_max_jobs` deserializes with `None`.
        let legacy_json = r#"{
            "ffmpeg_path": "/usr/lib/jellyfin-ffmpeg/ffmpeg",
            "ffmpeg_version": "8.1.3-Jellyfin",
            "encoders": ["h264_vaapi", "libx264"],
            "render_nodes": [],
            "primary_render_node": null
        }"#;
        let legacy: TranscodeCapabilities =
            serde_json::from_str(legacy_json).expect("deserialize legacy capabilities");
        assert_eq!(legacy.worker_max_jobs, None);

        // `None` is omitted on serialization (`skip_serializing_if`).
        let legacy_serialized = serde_json::to_string(&legacy).expect("serialize legacy");
        assert!(!legacy_serialized.contains("worker_max_jobs"));

        // `Some(n)` is serialized and round-trips cleanly.
        let mut advertised = legacy;
        advertised.worker_max_jobs = Some(12);
        let advertised_json = serde_json::to_string(&advertised).expect("serialize advertised");
        assert!(advertised_json.contains("\"worker_max_jobs\":12"));
        let round_trip: TranscodeCapabilities =
            serde_json::from_str(&advertised_json).expect("deserialize round trip");
        assert_eq!(round_trip.worker_max_jobs, Some(12));
    }

    #[test]
    fn parse_vainfo_output_extracts_intel_and_amd_profiles_and_vpp() {
        let hd630_sample = "\
Trying display: drm
vainfo: VA-API version: 1.22 (libva 2.22.0)
vainfo: Driver version: Intel iHD driver for Intel(R) Gen Graphics - 25.2.3 ()
vainfo: Supported profile and entrypoints
      VAProfileNone                   :\tVAEntrypointVideoProc
      VAProfileNone                   :\tVAEntrypointStats
      VAProfileMPEG2Simple            :\tVAEntrypointVLD
      VAProfileMPEG2Main              :\tVAEntrypointEncSlice
      VAProfileH264Main               :\tVAEntrypointVLD
      VAProfileH264Main               :\tVAEntrypointEncSliceLP
      VAProfileH264High               :\tVAEntrypointFEI
      VAProfileVC1Advanced            :\tVAEntrypointVLD
      VAProfileJPEGBaseline           :\tVAEntrypointVLD
      VAProfileJPEGBaseline           :\tVAEntrypointEncPicture
      VAProfileVP8Version0_3          :\tVAEntrypointVLD
      VAProfileVP8Version0_3          :\tVAEntrypointEncSlice
      VAProfileHEVCMain               :\tVAEntrypointVLD
      VAProfileHEVCMain               :\tVAEntrypointEncSlice
      VAProfileHEVCMain10             :\tVAEntrypointVLD
      VAProfileHEVCMain10             :\tVAEntrypointEncSlice
      VAProfileVP9Profile0            :\tVAEntrypointVLD
      VAProfileVP9Profile2            :\tVAEntrypointVLD
";
        let summary = parse_vainfo_output(hd630_sample);
        assert_eq!(
            summary.driver.as_deref(),
            Some("Intel iHD driver for Intel(R) Gen Graphics - 25.2.3 ()")
        );
        assert!(summary.supports_vpp);
        assert_eq!(
            summary.decode_codecs,
            vec![
                "h264",
                "hevc",
                "hevc_10bit",
                "mjpeg",
                "mpeg2video",
                "vc1",
                "vp8",
                "vp9",
                "vp9_10bit",
            ]
        );
        assert_eq!(
            summary.encode_codecs,
            vec!["h264", "hevc", "hevc_10bit", "mjpeg", "mpeg2video", "vp8",]
        );

        let av1_sample = "\
vainfo: Driver version: Mesa Gallium driver 25.0 for AMD Radeon
      VAProfileAV1Profile0            : VAEntrypointVLD
      VAProfileAV1Profile1            : VAEntrypointEncSlice
      VAProfileVP9Profile3            : VAEntrypointVLD
";
        let av1 = parse_vainfo_output(av1_sample);
        assert!(!av1.supports_vpp);
        assert_eq!(
            av1.decode_codecs,
            vec!["av1", "av1_10bit", "vp9", "vp9_10bit"]
        );
        assert_eq!(av1.encode_codecs, vec!["av1", "av1_10bit"]);
    }

    #[test]
    fn filter_encoders_with_vainfo_respects_silicon_and_unprobed_fallback() {
        let raw_encoders = vec![
            "av1_nvenc",
            "av1_qsv",
            "av1_vaapi",
            "h264_nvenc",
            "h264_qsv",
            "h264_vaapi",
            "hevc_qsv",
            "hevc_vaapi",
            "libx264",
            "libx265",
            "vp9_qsv",
            "vp9_vaapi",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();

        // 1. No vainfo probe data -> unchanged, verified=false.
        let unprobed = vec![RenderNodeInfo {
            path: "/dev/dri/renderD128".to_string(),
            vendor_id: Some(PCI_VENDOR_INTEL.to_string()),
            vendor: Some("intel".to_string()),
            ..Default::default()
        }];
        let (unchanged, verified) = filter_encoders_with_vainfo(raw_encoders.clone(), &unprobed);
        assert!(!verified);
        assert_eq!(unchanged, raw_encoders);

        // 2. Intel HD 630 (H.264 + HEVC encode only) -> strips av1/vp9 vaapi+qsv, keeps nvenc/sw.
        let hd630 = vec![RenderNodeInfo {
            path: "/dev/dri/renderD128".to_string(),
            vendor_id: Some(PCI_VENDOR_INTEL.to_string()),
            vendor: Some("intel".to_string()),
            vaapi_driver: Some("Intel iHD".to_string()),
            vaapi_decode_codecs: vec!["h264".into(), "hevc".into(), "vp9".into()],
            vaapi_encode_codecs: vec!["h264".into(), "hevc".into(), "hevc_10bit".into()],
            supports_vpp: true,
        }];
        let (intel_filtered, intel_verified) =
            filter_encoders_with_vainfo(raw_encoders.clone(), &hd630);
        assert!(intel_verified);
        assert_eq!(
            intel_filtered,
            vec![
                "av1_nvenc",
                "h264_nvenc",
                "h264_qsv",
                "h264_vaapi",
                "hevc_qsv",
                "hevc_vaapi",
                "libx264",
                "libx265",
            ]
        );

        // 3. AMD-only probed host -> strips ALL *_qsv encoders and unsupported *_vaapi encoders.
        let amd_only = vec![RenderNodeInfo {
            path: "/dev/dri/renderD128".to_string(),
            vendor_id: Some(PCI_VENDOR_AMD.to_string()),
            vendor: Some("amd".to_string()),
            vaapi_driver: Some("Mesa Gallium".to_string()),
            vaapi_decode_codecs: vec!["h264".into(), "hevc".into()],
            vaapi_encode_codecs: vec!["h264".into(), "hevc".into()],
            supports_vpp: true,
        }];
        let (amd_filtered, amd_verified) = filter_encoders_with_vainfo(raw_encoders, &amd_only);
        assert!(amd_verified);
        assert_eq!(
            amd_filtered,
            vec![
                "av1_nvenc",
                "h264_nvenc",
                "h264_vaapi",
                "hevc_vaapi",
                "libx264",
                "libx265",
            ]
        );
    }

    #[test]
    fn select_render_node_excludes_amd_when_vaapi_tonemap_is_required() {
        let amd = RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some(PCI_VENDOR_AMD.to_string()),
        };
        let intel = RenderNode {
            path: PathBuf::from("/dev/dri/renderD129"),
            vendor_id: Some(PCI_VENDOR_INTEL.to_string()),
        };
        let tonemap_cap = Capability {
            hwaccel: Some(HwAccel::Vaapi),
            required_hwaccels: vec![HwAccel::Vaapi],
            encoder: Some("h264_vaapi".to_string()),
            requires_vaapi_tonemap: true,
            ..Default::default()
        };

        assert_eq!(
            select_render_node(&tonemap_cap, std::slice::from_ref(&amd)),
            None
        );
        assert_eq!(
            select_render_node(&tonemap_cap, &[amd, intel]),
            Some(PathBuf::from("/dev/dri/renderD129"))
        );
    }

    #[test]
    fn transcode_capabilities_new_fields_serde_is_backwards_compatible() {
        let legacy_json = r#"{
            "ffmpeg_path": "/usr/lib/jellyfin-ffmpeg/ffmpeg",
            "encoders": ["h264_vaapi", "libx264"],
            "render_nodes": [{"path": "/dev/dri/renderD128", "vendor_id": "0x8086", "vendor": "intel"}],
            "primary_render_node": "/dev/dri/renderD128"
        }"#;
        let parsed: TranscodeCapabilities =
            serde_json::from_str(legacy_json).expect("deserialize legacy");
        assert!(parsed.hw_decoders.is_empty());
        assert!(!parsed.hw_encoders_verified);
        assert_eq!(parsed.adapt_backend_mode, None);
        assert_eq!(parsed.effective_adapt_backend_mode(), BackendAdaptMode::Off);
        assert_eq!(parsed.render_nodes[0].vaapi_driver, None);
        assert!(parsed.render_nodes[0].vaapi_decode_codecs.is_empty());
        assert!(parsed.render_nodes[0].vaapi_encode_codecs.is_empty());
        assert!(!parsed.render_nodes[0].supports_vpp);

        // Default values are omitted on serialization.
        let ser = serde_json::to_string(&parsed).expect("serialize defaults");
        assert!(!ser.contains("hw_decoders"));
        assert!(!ser.contains("hw_encoders_verified"));
        assert!(!ser.contains("adapt_backend_mode"));
        assert!(!ser.contains("vaapi_driver"));
        assert!(!ser.contains("supports_vpp"));

        // Populated values round-trip cleanly.
        let mut rich = parsed;
        rich.hw_decoders = vec!["h264".into(), "hevc".into()];
        rich.hw_encoders_verified = true;
        rich.adapt_backend_mode = Some(BackendAdaptMode::PreferQsv);
        rich.render_nodes[0].vaapi_driver = Some("Intel iHD".into());
        rich.render_nodes[0].supports_vpp = true;
        let rich_json = serde_json::to_string(&rich).expect("serialize rich");
        let rt: TranscodeCapabilities = serde_json::from_str(&rich_json).expect("deserialize rich");
        assert_eq!(
            rt.effective_adapt_backend_mode(),
            BackendAdaptMode::PreferQsv
        );
        assert!(rt.hw_encoders_verified);
        assert_eq!(rt.hw_decoders, vec!["h264", "hevc"]);
        assert!(rt.render_nodes[0].supports_vpp);
    }
}
