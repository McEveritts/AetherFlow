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
            | "-filter_complex"
            | "-filter_complex_script"
            | "-lavfi"
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
}
