//! Local transcode capability probing and vendor-aware render-node selection via `af-hardware`.

use crate::argv::{Capability, HwAccel};
use crate::config::{
    configured_real_ffmpeg_path, configured_worker_adapt_backend, configured_worker_max_jobs,
    configured_worker_vulkan_compute, configured_worker_vulkan_video, validate_real_ffmpeg_path,
    BackendAdaptMode, DEFAULT_PROBE_TIMEOUT,
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

/// Parsed Vulkan Compute vs Vulkan Video summary from
/// `ffmpeg -hide_banner -v verbose -init_hw_device vulkan=vk -version`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VulkanProbeSummary {
    pub probed: bool,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub compute_supported: bool,
    pub video_decode_codecs: Vec<String>,
    pub video_encode_codecs: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulkan_compute: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulkan_device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulkan_video: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulkan_video_decode_codecs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulkan_video_encode_codecs: Vec<String>,
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
    pub vulkan_compute_override: Option<bool>,
    pub vulkan_video_override: Option<bool>,
}

impl CapabilitiesConfig {
    pub fn from_env() -> Self {
        Self {
            real_ffmpeg: configured_real_ffmpeg_path(),
            dpkg_query_path: Some(PathBuf::from("/usr/bin/dpkg-query")),
            vainfo_path: Some(PathBuf::from("/usr/bin/vainfo")),
            render_nodes_override: None,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            vulkan_compute_override: None,
            vulkan_video_override: None,
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

fn strip_ffmpeg_log_prefix(line: &str) -> &str {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(close_idx) = rest.find(']') {
            return rest[close_idx + 1..].trim();
        }
    }
    trimmed
}

fn split_trailing_paren(s: &str) -> Option<(&str, &str)> {
    let trimmed = s.trim_end();
    let without_close = trimmed.strip_suffix(')')?;
    let open_idx = without_close.rfind('(')?;
    Some((
        without_close[..open_idx].trim_end(),
        without_close[open_idx + 1..].trim(),
    ))
}

fn is_hex_device_id(token: &str) -> bool {
    token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn parse_selected_vulkan_device(body: &str) -> Option<(String, String)> {
    let after_device = body.strip_prefix("Device ")?;
    let (idx_part, rest) = after_device.split_once(" selected:")?;
    let idx_trimmed = idx_part.trim();
    if idx_trimmed.is_empty() || !idx_trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let mut tail = rest.trim();
    if let Some((before_hex, hex_inner)) = split_trailing_paren(tail) {
        if is_hex_device_id(hex_inner) {
            tail = before_hex;
        }
    }

    let (name_raw, type_raw) = split_trailing_paren(tail)?;
    let name = name_raw.trim();
    let dev_type = type_raw.trim();
    if name.is_empty() || dev_type.is_empty() {
        return None;
    }
    Some((name.to_string(), dev_type.to_string()))
}

fn parse_queue_family_line(body: &str) -> Option<(&str, &str)> {
    let (idx_part, rest) = body.split_once(':')?;
    let idx_trimmed = idx_part.trim();
    if idx_trimmed.is_empty() || !idx_trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.split_once("(queues:")
}

fn is_software_vulkan_renderer_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("llvmpipe")
        || lower.contains("lavapipe")
        || lower.contains("swiftshader")
        || lower.contains("software")
}

/// Parses combined stderr + stdout of
/// `ffmpeg -hide_banner -v verbose -init_hw_device vulkan=vk -version` to separate hardware
/// Vulkan Compute support from Vulkan Video hardware decode/encode codec support.
pub fn parse_ffmpeg_vulkan_probe_output(output: &str) -> VulkanProbeSummary {
    let probed = output.contains("[Vulkan @")
        || output.contains("[AVHWDeviceContext @")
        || output.contains("Instance creation failure:")
        || output.contains("Device creation failed")
        || output.contains("Failed to set value 'vulkan=vk'");
    if !probed {
        return VulkanProbeSummary::default();
    }

    let mut device_name: Option<String> = None;
    let mut device_type: Option<String> = None;
    let mut in_queue_families = false;
    let mut has_compute_queue = false;
    let mut has_decode_queue = false;
    let mut has_encode_queue = false;
    let mut has_decode_queue_ext = false;
    let mut has_encode_queue_ext = false;
    let mut decode_codecs = BTreeSet::new();
    let mut encode_codecs = BTreeSet::new();

    for raw_line in output.lines() {
        let body = strip_ffmpeg_log_prefix(raw_line);
        if body.is_empty() {
            continue;
        }

        if in_queue_families {
            if let Some((flags_part, queues_rest)) = parse_queue_family_line(body) {
                let count_is_zero = queues_rest
                    .split(')')
                    .next()
                    .map(str::trim)
                    .and_then(|count| count.parse::<u32>().ok())
                    == Some(0);
                if !count_is_zero {
                    for tok in flags_part.split(|c: char| c.is_whitespace() || c == ',') {
                        if tok.eq_ignore_ascii_case("compute") {
                            has_compute_queue = true;
                        } else if tok.eq_ignore_ascii_case("decode") {
                            has_decode_queue = true;
                        } else if tok.eq_ignore_ascii_case("encode") {
                            has_encode_queue = true;
                        }
                    }
                }
                continue;
            }
            in_queue_families = false;
        }

        if body == "Queue families:" || body.starts_with("Queue families:") {
            in_queue_families = true;
            continue;
        }

        if let Some((name, dev_type)) = parse_selected_vulkan_device(body) {
            device_name = Some(name);
            device_type = Some(dev_type);
            continue;
        }

        if let Some(rest) = body
            .strip_prefix("Using device extension")
            .filter(|r| r.starts_with(char::is_whitespace))
        {
            let ext = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|c| matches!(c, ',' | ';' | '\'' | '"'));
            match ext {
                "VK_KHR_video_decode_queue" => has_decode_queue_ext = true,
                "VK_KHR_video_encode_queue" => has_encode_queue_ext = true,
                "VK_KHR_video_decode_h264" => {
                    decode_codecs.insert("h264".to_string());
                }
                "VK_KHR_video_decode_h265" => {
                    decode_codecs.insert("hevc".to_string());
                }
                "VK_KHR_video_decode_av1" => {
                    decode_codecs.insert("av1".to_string());
                }
                "VK_KHR_video_decode_vp9" => {
                    decode_codecs.insert("vp9".to_string());
                }
                "VK_KHR_video_encode_h264" => {
                    encode_codecs.insert("h264".to_string());
                }
                "VK_KHR_video_encode_h265" => {
                    encode_codecs.insert("hevc".to_string());
                }
                "VK_KHR_video_encode_av1" => {
                    encode_codecs.insert("av1".to_string());
                }
                _ => {}
            }
        }
    }

    let is_hardware_gpu = device_type.as_deref().is_some_and(|dt| {
        dt.eq_ignore_ascii_case("integrated") || dt.eq_ignore_ascii_case("discrete")
    }) && device_name
        .as_deref()
        .is_some_and(|name| !is_software_vulkan_renderer_name(name));

    let compute_supported = is_hardware_gpu && has_compute_queue;
    let video_decode_codecs = if is_hardware_gpu && (has_decode_queue || has_decode_queue_ext) {
        decode_codecs.into_iter().collect()
    } else {
        Vec::new()
    };
    let video_encode_codecs = if is_hardware_gpu && (has_encode_queue || has_encode_queue_ext) {
        encode_codecs.into_iter().collect()
    } else {
        Vec::new()
    };

    VulkanProbeSummary {
        probed: true,
        device_name,
        device_type,
        compute_supported,
        video_decode_codecs,
        video_encode_codecs,
    }
}

fn vulkan_video_codec_for_encoder_prefix(prefix: &str) -> Option<&'static str> {
    match prefix {
        "h264" => Some("h264"),
        "hevc" => Some("hevc"),
        "av1" => Some("av1"),
        _ => None,
    }
}

/// Filters `*_vulkan` video encoders according to Vulkan Video policy and probed hardware
/// Vulkan Video encode extensions.
pub fn filter_encoders_with_vulkan(
    encoders: Vec<String>,
    vulkan_video_enabled: bool,
    vulkan_video_encode_codecs: &[String],
    vulkan_probed: bool,
) -> Vec<String> {
    if !vulkan_video_enabled {
        return encoders
            .into_iter()
            .filter(|enc| !enc.to_ascii_lowercase().ends_with("_vulkan"))
            .collect();
    }

    if !vulkan_probed {
        return encoders;
    }

    encoders
        .into_iter()
        .filter(|enc| {
            let lower = enc.to_ascii_lowercase();
            if let Some(prefix) = lower.strip_suffix("_vulkan") {
                vulkan_video_codec_for_encoder_prefix(prefix).is_some_and(|codec| {
                    vulkan_video_encode_codecs
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(codec))
                })
            } else {
                true
            }
        })
        .collect()
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

    let allow_vulkan_compute = config
        .vulkan_compute_override
        .unwrap_or_else(configured_worker_vulkan_compute);
    let allow_vulkan_video = config
        .vulkan_video_override
        .unwrap_or_else(configured_worker_vulkan_video);

    let vk = if (!allow_vulkan_compute && !allow_vulkan_video)
        || config
            .render_nodes_override
            .as_ref()
            .is_some_and(|nodes| nodes.is_empty())
    {
        VulkanProbeSummary {
            probed: true,
            compute_supported: false,
            ..Default::default()
        }
    } else {
        match run_bounded_output(
            &real_ffmpeg,
            &[
                "-hide_banner",
                "-v",
                "verbose",
                "-init_hw_device",
                "vulkan=vk",
                "-version",
            ],
            config.probe_timeout,
        )
        .await
        {
            Ok(out) => {
                let mut combined = String::from_utf8_lossy(&out.stderr).into_owned();
                if !out.stdout.is_empty() {
                    if !combined.is_empty() && !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(&String::from_utf8_lossy(&out.stdout));
                }
                parse_ffmpeg_vulkan_probe_output(&combined)
            }
            Err(_) => VulkanProbeSummary::default(),
        }
    };

    let vulkan_compute = if !allow_vulkan_compute {
        Some(false)
    } else {
        vk.probed.then_some(vk.compute_supported)
    };
    let (vulkan_video, vulkan_video_decode_codecs, vulkan_video_encode_codecs) =
        if !allow_vulkan_video {
            (Some(false), Vec::new(), Vec::new())
        } else if vk.probed {
            let has_video =
                !vk.video_decode_codecs.is_empty() || !vk.video_encode_codecs.is_empty();
            (
                Some(has_video),
                vk.video_decode_codecs.clone(),
                vk.video_encode_codecs.clone(),
            )
        } else {
            (None, Vec::new(), Vec::new())
        };
    let vulkan_device = if vk.probed && (vulkan_compute == Some(true) || vulkan_video == Some(true))
    {
        vk.device_name.clone()
    } else {
        None
    };

    let hw_decoders: Vec<String> = render_nodes
        .iter()
        .flat_map(|n| n.vaapi_decode_codecs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let (encoders, hw_encoders_verified) = filter_encoders_with_vainfo(encoders, &render_nodes);
    let encoders = filter_encoders_with_vulkan(
        encoders,
        allow_vulkan_video,
        &vulkan_video_encode_codecs,
        vk.probed,
    );
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
        vulkan_compute,
        vulkan_device,
        vulkan_video,
        vulkan_video_decode_codecs,
        vulkan_video_encode_codecs,
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

    #[test]
    fn parse_ffmpeg_vulkan_probe_output_separates_compute_video_and_software_renderers() {
        // 1. Intel HD 630 compute-only with parenthesized GPU name.
        let intel_compute_only = "\
[Vulkan @ 0x55a100001000] Supported validation layers:
[Vulkan @ 0x55a100001000] Device 0: Intel(R) HD Graphics 630 (KBL GT2) (integrated) (0x5912)
[Vulkan @ 0x55a100001000] Device 0 selected: Intel(R) HD Graphics 630 (KBL GT2) (integrated) (0x5912)
[Vulkan @ 0x55a100001000] Queue families:
[Vulkan @ 0x55a100001000]     0: graphics compute transfer sparse (queues: 1)
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_external_memory_fd
";
        let intel = parse_ffmpeg_vulkan_probe_output(intel_compute_only);
        assert_eq!(
            intel,
            VulkanProbeSummary {
                probed: true,
                device_name: Some("Intel(R) HD Graphics 630 (KBL GT2)".to_string()),
                device_type: Some("integrated".to_string()),
                compute_supported: true,
                video_decode_codecs: Vec::new(),
                video_encode_codecs: Vec::new(),
            }
        );

        // 2. AMD Rembrandt with compute + Vulkan Video decode & encode queues/extensions.
        let amd_full = "\
[Vulkan @ 0x55a100002000] Device 0 selected: AMD Radeon Graphics (RADV REMBRANDT) (integrated) (0x1681)
[Vulkan @ 0x55a100002000] Queue families:
[Vulkan @ 0x55a100002000]     0: graphics compute transfer sparse (queues: 1)
[Vulkan @ 0x55a100002000]     1: compute transfer sparse (queues: 4)
[Vulkan @ 0x55a100002000]     2: transfer decode (queues: 1)
[Vulkan @ 0x55a100002000]     3: transfer encode (queues: 1)
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_decode_queue
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_encode_queue
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_decode_h265
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_decode_h264
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_decode_av1
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_decode_vp9
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_encode_h265
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_encode_h264
[Vulkan @ 0x55a100002000] Using device extension VK_KHR_video_encode_av1
";
        let amd = parse_ffmpeg_vulkan_probe_output(amd_full);
        assert!(amd.probed);
        assert_eq!(
            amd.device_name.as_deref(),
            Some("AMD Radeon Graphics (RADV REMBRANDT)")
        );
        assert_eq!(amd.device_type.as_deref(), Some("integrated"));
        assert!(amd.compute_supported);
        assert_eq!(amd.video_decode_codecs, vec!["av1", "h264", "hevc", "vp9"]);
        assert_eq!(amd.video_encode_codecs, vec!["av1", "h264", "hevc"]);

        // 3. Software renderers (`cpu` type or llvmpipe/lavapipe/swiftshader/software) are rejected.
        let llvmpipe = "\
[Vulkan @ 0x55a100003000] Device 0 selected: llvmpipe (LLVM 19.1.7, 256 bits) (cpu) (0x0)
[Vulkan @ 0x55a100003000] Queue families:
[Vulkan @ 0x55a100003000]     0: graphics compute transfer (queues: 1)
";
        let sw = parse_ffmpeg_vulkan_probe_output(llvmpipe);
        assert!(sw.probed);
        assert_eq!(
            sw.device_name.as_deref(),
            Some("llvmpipe (LLVM 19.1.7, 256 bits)")
        );
        assert_eq!(sw.device_type.as_deref(), Some("cpu"));
        assert!(!sw.compute_supported);
        assert!(sw.video_decode_codecs.is_empty());
        assert!(sw.video_encode_codecs.is_empty());

        for fake_sw_name in ["Lavapipe GPU", "SwiftShader Device", "Software Rasterizer"] {
            let sample = format!(
                "[Vulkan @ 0x1] Device 0 selected: {fake_sw_name} (discrete) (0x1234)\n\
                 [Vulkan @ 0x1] Queue families:\n\
                 [Vulkan @ 0x1]     0: graphics compute decode encode (queues: 1)\n\
                 [Vulkan @ 0x1] Using device extension VK_KHR_video_decode_h264\n\
                 [Vulkan @ 0x1] Using device extension VK_KHR_video_encode_h264\n"
            );
            let parsed = parse_ffmpeg_vulkan_probe_output(&sample);
            assert!(parsed.probed);
            assert!(
                !parsed.compute_supported,
                "software renderer '{fake_sw_name}' must not report compute"
            );
            assert!(parsed.video_decode_codecs.is_empty());
            assert!(parsed.video_encode_codecs.is_empty());
        }

        // 4. Tokens after `(queues:` are ignored and codec extensions without queue support are ignored.
        let tricky = "\
[Vulkan @ 0x55a100004000] Device 0 selected: Generic Discrete GPU (discrete) (0x2684)
[Vulkan @ 0x55a100004000] Queue families:
[Vulkan @ 0x55a100004000]     0: graphics transfer (queues: 1) compute decode encode
[Vulkan @ 0x55a100004000] Using device extension VK_KHR_video_decode_h264
[Vulkan @ 0x55a100004000] Using device extension VK_KHR_video_encode_h264
";
        let tricky_res = parse_ffmpeg_vulkan_probe_output(tricky);
        assert!(tricky_res.probed);
        assert!(!tricky_res.compute_supported);
        assert!(tricky_res.video_decode_codecs.is_empty());
        assert!(tricky_res.video_encode_codecs.is_empty());

        // 5. Explicit Vulkan initialization failures mark `probed = true` with unsupported compute/video.
        for failure in [
            "Instance creation failure: VK_ERROR_INCOMPATIBLE_DRIVER\n",
            "Device creation failed: -12.\n",
            "Failed to set value 'vulkan=vk' for option 'init_hw_device': Generic error\n",
        ] {
            let failed = parse_ffmpeg_vulkan_probe_output(failure);
            assert!(failed.probed, "failure output must set probed=true");
            assert!(!failed.compute_supported);
            assert!(failed.video_decode_codecs.is_empty());
            assert!(failed.video_encode_codecs.is_empty());
        }

        // 6. Mock ffmpeg output ignoring `-init_hw_device` leaves `probed = false`.
        let mock_out = "ffmpeg version 8.1.3-Jellyfin\nbuilt with gcc 14\n";
        assert_eq!(
            parse_ffmpeg_vulkan_probe_output(mock_out),
            VulkanProbeSummary::default()
        );

        // 7. Trailing text after `(queues: 0)` must NOT bypass zero-queue filtering.
        let zero_queues_trailing = "\
[Vulkan @ 0x55a100005000] Device 0 selected: Generic Discrete GPU (discrete) (0x2684)
[Vulkan @ 0x55a100005000] Queue families:
[Vulkan @ 0x55a100005000]     0: graphics compute decode encode (queues: 0) [disabled]
[Vulkan @ 0x55a100005000] Using device extension VK_KHR_video_decode_h264
[Vulkan @ 0x55a100005000] Using device extension VK_KHR_video_encode_h264
";
        let zero_res = parse_ffmpeg_vulkan_probe_output(zero_queues_trailing);
        assert!(zero_res.probed);
        assert!(!zero_res.compute_supported);
        assert!(zero_res.video_decode_codecs.is_empty());
        assert!(zero_res.video_encode_codecs.is_empty());
    }

    #[test]
    fn parse_ffmpeg_vulkan_probe_output_supports_ffmpeg_7_avhwdevicecontext_prefix() {
        // Real FFmpeg 7.x (`jellyfin-ffmpeg7` / Debian ffmpeg 7.1.5) logs under `[AVHWDeviceContext @ 0x...]`.
        let ffmpeg7_hw_gpu = "\
[AVHWDeviceContext @ 0x55d8f0001200] Supported validation layers:
[AVHWDeviceContext @ 0x55d8f0001200] Device 0: AMD Radeon Graphics (RADV REMBRANDT) (integrated) (0x1681)
[AVHWDeviceContext @ 0x55d8f0001200] Device 0 selected: AMD Radeon Graphics (RADV REMBRANDT) (integrated) (0x1681)
[AVHWDeviceContext @ 0x55d8f0001200] Queue families:
[AVHWDeviceContext @ 0x55d8f0001200]     0: graphics compute transfer sparse (queues: 1)
[AVHWDeviceContext @ 0x55d8f0001200]     1: compute transfer sparse (queues: 4)
[AVHWDeviceContext @ 0x55d8f0001200]     2: transfer decode (queues: 1)
[AVHWDeviceContext @ 0x55d8f0001200]     3: transfer encode (queues: 1)
[AVHWDeviceContext @ 0x55d8f0001200] Using device extension VK_KHR_video_decode_queue
[AVHWDeviceContext @ 0x55d8f0001200] Using device extension VK_KHR_video_encode_queue
[AVHWDeviceContext @ 0x55d8f0001200] Using device extension VK_KHR_video_decode_h264
[AVHWDeviceContext @ 0x55d8f0001200] Using device extension VK_KHR_video_decode_h265
[AVHWDeviceContext @ 0x55d8f0001200] Using device extension VK_KHR_video_decode_av1
[AVHWDeviceContext @ 0x55d8f0001200] Using device extension VK_KHR_video_encode_h264
[AVHWDeviceContext @ 0x55d8f0001200] Using device extension VK_KHR_video_encode_h265
";
        let hw = parse_ffmpeg_vulkan_probe_output(ffmpeg7_hw_gpu);
        assert_eq!(
            hw,
            VulkanProbeSummary {
                probed: true,
                device_name: Some("AMD Radeon Graphics (RADV REMBRANDT)".to_string()),
                device_type: Some("integrated".to_string()),
                compute_supported: true,
                video_decode_codecs: vec!["av1".into(), "h264".into(), "hevc".into()],
                video_encode_codecs: vec!["h264".into(), "hevc".into()],
            }
        );

        let ffmpeg7_llvmpipe = "\
[AVHWDeviceContext @ 0x55d8f0002400] Device 0: llvmpipe (LLVM 19.1.7, 256 bits) (cpu) (0x0)
[AVHWDeviceContext @ 0x55d8f0002400] Device 0 selected: llvmpipe (LLVM 19.1.7, 256 bits) (cpu) (0x0)
[AVHWDeviceContext @ 0x55d8f0002400] Queue families:
[AVHWDeviceContext @ 0x55d8f0002400]     0: graphics compute transfer (queues: 1)
[AVHWDeviceContext @ 0x55d8f0002400] Using device extension VK_KHR_external_memory_fd
";
        let sw = parse_ffmpeg_vulkan_probe_output(ffmpeg7_llvmpipe);
        assert!(sw.probed);
        assert_eq!(
            sw.device_name.as_deref(),
            Some("llvmpipe (LLVM 19.1.7, 256 bits)")
        );
        assert_eq!(sw.device_type.as_deref(), Some("cpu"));
        assert!(!sw.compute_supported);
        assert!(sw.video_decode_codecs.is_empty());
        assert!(sw.video_encode_codecs.is_empty());
    }

    #[test]
    fn filter_encoders_with_vulkan_enforces_policy_and_probed_codecs() {
        let raw = vec![
            "av1_vulkan",
            "ffv1_vulkan",
            "h264_vaapi",
            "h264_vulkan",
            "hevc_vulkan",
            "libx264",
            "prores_ks_vulkan",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();

        // Disabled -> strips ALL *_vulkan encoders regardless of probe state.
        assert_eq!(
            filter_encoders_with_vulkan(raw.clone(), false, &["h264".into()], true),
            vec!["h264_vaapi", "libx264"]
        );
        assert_eq!(
            filter_encoders_with_vulkan(raw.clone(), false, &[], false),
            vec!["h264_vaapi", "libx264"]
        );

        // Enabled + probed -> keeps only supported h264/hevc/av1 Vulkan Video codecs.
        assert_eq!(
            filter_encoders_with_vulkan(raw.clone(), true, &["h264".into(), "hevc".into()], true),
            vec!["h264_vaapi", "h264_vulkan", "hevc_vulkan", "libx264"]
        );
        assert_eq!(
            filter_encoders_with_vulkan(raw.clone(), true, &[], true),
            vec!["h264_vaapi", "libx264"]
        );

        // Enabled + unprobed -> leaves encoders unchanged.
        assert_eq!(
            filter_encoders_with_vulkan(raw.clone(), true, &[], false),
            raw
        );
    }

    #[test]
    fn transcode_capabilities_vulkan_fields_serde_is_backwards_compatible() {
        let legacy_json = r#"{
            "ffmpeg_path": "/usr/lib/jellyfin-ffmpeg/ffmpeg",
            "encoders": ["h264_vaapi", "libx264"],
            "render_nodes": [],
            "primary_render_node": null
        }"#;
        let parsed: TranscodeCapabilities =
            serde_json::from_str(legacy_json).expect("deserialize legacy");
        assert_eq!(parsed.vulkan_compute, None);
        assert_eq!(parsed.vulkan_device, None);
        assert_eq!(parsed.vulkan_video, None);
        assert!(parsed.vulkan_video_decode_codecs.is_empty());
        assert!(parsed.vulkan_video_encode_codecs.is_empty());

        let ser = serde_json::to_string(&parsed).expect("serialize defaults");
        assert!(!ser.contains("vulkan_compute"));
        assert!(!ser.contains("vulkan_device"));
        assert!(!ser.contains("vulkan_video"));

        let mut rich = parsed;
        rich.vulkan_compute = Some(true);
        rich.vulkan_device = Some("AMD Radeon Graphics (RADV REMBRANDT)".to_string());
        rich.vulkan_video = Some(true);
        rich.vulkan_video_decode_codecs = vec!["h264".into(), "hevc".into()];
        rich.vulkan_video_encode_codecs = vec!["h264".into()];
        let rich_json = serde_json::to_string(&rich).expect("serialize rich");
        let rt: TranscodeCapabilities = serde_json::from_str(&rich_json).expect("deserialize rich");
        assert_eq!(rt.vulkan_compute, Some(true));
        assert_eq!(
            rt.vulkan_device.as_deref(),
            Some("AMD Radeon Graphics (RADV REMBRANDT)")
        );
        assert_eq!(rt.vulkan_video, Some(true));
        assert_eq!(rt.vulkan_video_decode_codecs, vec!["h264", "hevc"]);
        assert_eq!(rt.vulkan_video_encode_codecs, vec!["h264"]);
    }
}
