//! `ffmpeg` argument inspection, capability inference, and token-boundary render-node rewriting.

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
    /// Distinct hardware-specific filters referenced in video filtergraphs (e.g. `scale_vaapi`, `vpp_qsv`).
    pub filters: Vec<String>,
    /// Distinct `/dev/dri/renderD*` device paths referenced in device-option positions.
    pub render_nodes: Vec<String>,
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
                if is_output_section && (!val.eq_ignore_ascii_case("copy") || cap.encoder.is_none())
                {
                    cap.encoder = Some(val.to_string());
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
}
