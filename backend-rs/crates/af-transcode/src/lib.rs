//! AetherFlow local transcode foundation: wire protocol, Jellyfin argv/capability analysis,
//! local `ffmpeg` shim, Unix-socket worker daemon, and capability probe.

pub mod argv;
pub mod capabilities;
pub mod config;
pub mod protocol;
pub mod shim;
pub mod worker;

pub use argv::{
    is_probe, is_valid_render_node_path, required_capability, rewrite_any_render_node,
    rewrite_render_node, Capability, HwAccel,
};
pub use capabilities::{
    probe_capabilities, select_render_node, CapabilitiesConfig, RenderNodeInfo,
    TranscodeCapabilities,
};
pub use config::{
    collect_allowed_env_subset, configured_dispatcher_socket_path, configured_handshake_timeout,
    configured_real_ffmpeg_path, configured_worker_max_jobs, configured_worker_socket_mode,
    configured_worker_socket_path, validate_real_ffmpeg_path, validate_socket_mode,
    validate_start_request, ConfigError, ALLOWED_ENV_KEYS, DEFAULT_DISPATCHER_SOCKET_PATH,
    DEFAULT_FRAME_WRITE_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_PROBE_TIMEOUT,
    DEFAULT_REAL_FFMPEG_PATH, DEFAULT_WORKER_MAX_JOBS, DEFAULT_WORKER_SOCKET_MODE,
    DEFAULT_WORKER_SOCKET_PATH, DEFAULT_WORKER_START_FRAME_TIMEOUT, ENV_DISPATCHER_SOCKET,
    ENV_HANDSHAKE_TIMEOUT_MS, ENV_REAL_FFMPEG, ENV_SHIM_RECURSION_GUARD, ENV_WORKER_MAX_JOBS,
    ENV_WORKER_SOCKET, ENV_WORKER_SOCKET_MODE, RECOMMENDED_DISPATCHER_REMOTE_START_TIMEOUT,
};
pub use protocol::{
    bounded_frame_channel, decode_frame_payload, decode_framed, encode_frame_payload,
    encode_framed, read_frame, write_frame, ErrorKind, Frame, FrameReceiver, FrameSender,
    ProtocolError, SignalKind, StartRequest, FRAME_CHANNEL_CAPACITY, FRAME_LENGTH_PREFIX_BYTES,
    MAX_ERROR_MESSAGE_BYTES, MAX_FRAME_BYTES, MAX_IO_CHUNK_BYTES, MAX_START_ARGS,
    MAX_START_ARG_BYTES, MAX_START_CWD_BYTES, MAX_START_ENV_ENTRIES, MAX_START_ENV_VALUE_BYTES,
};
pub use shim::{
    exec_real_ffmpeg, normalize_exit_code, run_shim, run_shim_protocol, LocalFallbackReason,
    ShimConfig, ShimDecision,
};
pub use worker::{
    bind_worker_socket, run_worker, serve_worker_listener, BoundWorkerSocket, WorkerConfig,
};
