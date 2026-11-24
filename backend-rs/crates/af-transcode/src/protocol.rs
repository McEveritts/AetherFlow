//! Capped length-prefixed bincode-layout framing protocol for `af-transcode`.
//!
//! Wire format:
//! - Outer frame: 4-byte big-endian unsigned payload length (`1..=MAX_FRAME_BYTES`, 1 MiB cap)
//!   followed by exact bincode v1 payload bytes.
//! - Payload layout (via maintained Apache-2.0 `wincode` v0.6.3 default configuration):
//!   - Enum discriminants: `u32` little-endian (`0..=9` in declaration order).
//!   - Sequence / string / byte-vector lengths: `u64` little-endian.
//!   - Signed integers (`Exit` code): `i32` little-endian.
//!   - Trailing bytes inside a frame are strictly rejected (`deserialize_exact`).
//!   - Both byte budget and container/string preallocation are strictly bounded before allocation.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use wincode::{SchemaRead, SchemaWrite};

/// Maximum encoded frame payload size in bytes (1 MiB).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Size of the outer big-endian length prefix in bytes.
pub const FRAME_LENGTH_PREFIX_BYTES: usize = 4;

/// Bounded channel capacity providing 64-frame backpressure between shim, dispatcher, and worker.
pub const FRAME_CHANNEL_CAPACITY: usize = 64;

/// Chunk size used when reading stdin/stdout/stderr into frames (well below 1 MiB).
pub const MAX_IO_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum argument count accepted inside `StartRequest`.
pub const MAX_START_ARGS: usize = 512;

/// Maximum single argument byte length accepted inside `StartRequest`.
pub const MAX_START_ARG_BYTES: usize = 64 * 1024;

/// Maximum environment entries accepted inside `StartRequest`.
pub const MAX_START_ENV_ENTRIES: usize = 32;

/// Maximum single environment variable value byte length accepted inside `StartRequest`.
pub const MAX_START_ENV_VALUE_BYTES: usize = 8 * 1024;

/// Maximum working-directory path length accepted inside `StartRequest`.
pub const MAX_START_CWD_BYTES: usize = 4096;

/// Maximum message byte length accepted inside `Frame::Error`.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 4096;

/// Bounded frame sender (`FRAME_CHANNEL_CAPACITY = 64`).
pub type FrameSender = mpsc::Sender<Frame>;

/// Bounded frame receiver (`FRAME_CHANNEL_CAPACITY = 64`).
pub type FrameReceiver = mpsc::Receiver<Frame>;

/// Creates a bounded 64-frame channel for backpressured frame relaying.
pub fn bounded_frame_channel() -> (FrameSender, FrameReceiver) {
    mpsc::channel(FRAME_CHANNEL_CAPACITY)
}

/// Initial job execution request sent from shim -> dispatcher -> worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SchemaWrite, SchemaRead)]
pub struct StartRequest {
    pub args: Vec<String>,
    pub cwd: String,
    pub env_subset: Vec<(String, String)>,
}

/// Forwarded Unix termination/interrupt signals.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, SchemaWrite, SchemaRead,
)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    Term,
    Int,
    Kill,
}

impl SignalKind {
    /// Converts this protocol signal to `nix::sys::signal::Signal`.
    pub const fn to_nix(self) -> nix::sys::signal::Signal {
        match self {
            Self::Term => nix::sys::signal::Signal::SIGTERM,
            Self::Int => nix::sys::signal::Signal::SIGINT,
            Self::Kill => nix::sys::signal::Signal::SIGKILL,
        }
    }
}

/// Typed transcode protocol / worker execution error kinds.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, SchemaWrite, SchemaRead,
)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidRequest,
    ProtocolViolation,
    DeviceUnavailable,
    SpawnFailed,
    Busy,
    WorkerFailed,
    Internal,
}

/// Wire protocol frame exchanged between shim, dispatcher (P9), and worker.
///
/// Variant declaration order defines the `u32` little-endian bincode discriminant (`0..=9`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SchemaWrite, SchemaRead)]
pub enum Frame {
    /// Discriminant 0: Job launch request (`args`, `cwd`, allowlisted `env_subset`).
    Start(StartRequest),
    /// Discriminant 1: Explicit pre-start decision instructing the shim to `exec` local `ffmpeg`.
    RunLocal,
    /// Discriminant 2: Worker confirmation that the remote `ffmpeg` child has spawned.
    Started,
    /// Discriminant 3: Chunk of standard input bytes forwarded to remote `ffmpeg`.
    Stdin(Vec<u8>),
    /// Discriminant 4: Explicit standard input EOF signal closing remote `ffmpeg`'s stdin pipe.
    StdinEof,
    /// Discriminant 5: Chunk of standard output bytes from remote `ffmpeg`.
    Stdout(Vec<u8>),
    /// Discriminant 6: Chunk of standard error bytes from remote `ffmpeg`.
    Stderr(Vec<u8>),
    /// Discriminant 7: Signal forwarded to the remote `ffmpeg` process group.
    Signal(SignalKind),
    /// Discriminant 8: Final process exit status (`code`, or `128 + signal` if signaled).
    Exit(i32),
    /// Discriminant 9: Typed failure emitted by dispatcher or worker.
    Error { kind: ErrorKind, message: String },
}

/// Typed codec and framing errors.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("empty frame (zero-length payload)")]
    EmptyFrame,

    #[error("frame size {len} exceeds maximum {max} bytes")]
    FrameTooLarge { len: usize, max: usize },

    #[error("truncated frame: expected {expected} bytes, got {actual}")]
    TruncatedFrame { expected: usize, actual: usize },

    #[error("trailing bytes present after decoded frame payload")]
    TrailingBytes,

    #[error("frame violates allocation or structural bound: {0}")]
    AllocationLimitExceeded(String),

    #[error("invalid bincode wire payload: {0}")]
    InvalidWireFormat(String),

    #[error("failed to encode frame: {0}")]
    EncodeFailed(String),

    #[error("stream I/O error: {0}")]
    Io(#[from] std::io::Error),
}

const fn wire_config() -> wincode::config::Configuration<
    true,
    MAX_FRAME_BYTES,
    wincode::len::BincodeLen,
    wincode::int_encoding::LittleEndian,
    wincode::int_encoding::FixInt,
    u32,
    MAX_FRAME_BYTES,
> {
    wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_FRAME_BYTES>()
        .with_deserialization_size_limit::<MAX_FRAME_BYTES>()
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, ProtocolError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ProtocolError::InvalidWireFormat("truncated u32 field".to_string()))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, ProtocolError> {
    let slice = bytes.get(offset..offset + 8).ok_or_else(|| {
        ProtocolError::InvalidWireFormat("truncated u64 length prefix".to_string())
    })?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_le_bytes(buf))
}

/// Pre-validates outer discriminant and top-level container lengths against both the semantic bounds
/// and the actual remaining wire bytes BEFORE `wincode` performs any heap allocation.
fn prevalidate_wire_bounds(bytes: &[u8]) -> Result<(), ProtocolError> {
    let tag = read_u32_le(bytes, 0)?;
    match tag {
        // Start(StartRequest { args: Vec<String>, cwd: String, env_subset: Vec<(String, String)> })
        0 => {
            let mut pos = 4usize;
            let args_len = read_u64_le(bytes, pos)?;
            pos += 8;
            let remaining = bytes.len().saturating_sub(pos);
            // Every String takes at least its 8-byte u64 length prefix on the wire.
            let max_possible_args = remaining / 8;
            if args_len > MAX_START_ARGS as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.args count {args_len} exceeds limit {MAX_START_ARGS}"
                )));
            }
            if args_len > max_possible_args as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.args count {args_len} exceeds remaining payload capacity ({max_possible_args})"
                )));
            }
            for _ in 0..(args_len as usize) {
                let s_len = read_u64_le(bytes, pos)?;
                pos += 8;
                if s_len > MAX_START_ARG_BYTES as u64 {
                    return Err(ProtocolError::AllocationLimitExceeded(format!(
                        "Start arg length {s_len} exceeds limit {MAX_START_ARG_BYTES}"
                    )));
                }
                let s_len_usize = usize::try_from(s_len).map_err(|_| {
                    ProtocolError::AllocationLimitExceeded("Start arg length overflow".to_string())
                })?;
                if s_len_usize > bytes.len().saturating_sub(pos) {
                    return Err(ProtocolError::AllocationLimitExceeded(format!(
                        "Start arg length {s_len} exceeds remaining payload bytes"
                    )));
                }
                pos += s_len_usize;
            }

            // cwd: String
            let cwd_len = read_u64_le(bytes, pos)?;
            pos += 8;
            if cwd_len > MAX_START_CWD_BYTES as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.cwd length {cwd_len} exceeds limit {MAX_START_CWD_BYTES}"
                )));
            }
            let cwd_len_usize = usize::try_from(cwd_len).map_err(|_| {
                ProtocolError::AllocationLimitExceeded("Start.cwd length overflow".to_string())
            })?;
            if cwd_len_usize > bytes.len().saturating_sub(pos) {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.cwd length {cwd_len} exceeds remaining payload bytes"
                )));
            }
            pos += cwd_len_usize;

            // env_subset: Vec<(String, String)>
            let env_len = read_u64_le(bytes, pos)?;
            pos += 8;
            let remaining = bytes.len().saturating_sub(pos);
            let max_possible_env = remaining / 16;
            if env_len > MAX_START_ENV_ENTRIES as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.env_subset count {env_len} exceeds limit {MAX_START_ENV_ENTRIES}"
                )));
            }
            if env_len > max_possible_env as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.env_subset count {env_len} exceeds remaining payload capacity ({max_possible_env})"
                )));
            }
            for _ in 0..(env_len as usize) {
                for field in ["key", "value"] {
                    let item_len = read_u64_le(bytes, pos)?;
                    pos += 8;
                    if item_len > MAX_START_ENV_VALUE_BYTES as u64 {
                        return Err(ProtocolError::AllocationLimitExceeded(format!(
                            "Start.env_subset {field} length {item_len} exceeds limit {MAX_START_ENV_VALUE_BYTES}"
                        )));
                    }
                    let item_len_usize = usize::try_from(item_len).map_err(|_| {
                        ProtocolError::AllocationLimitExceeded(format!(
                            "Start.env_subset {field} length overflow"
                        ))
                    })?;
                    if item_len_usize > bytes.len().saturating_sub(pos) {
                        return Err(ProtocolError::AllocationLimitExceeded(format!(
                            "Start.env_subset {field} length {item_len} exceeds remaining payload bytes"
                        )));
                    }
                    pos += item_len_usize;
                }
            }
            Ok(())
        }
        // Unit variants: RunLocal (1), Started (2), StdinEof (4)
        1 | 2 | 4 => Ok(()),
        // Byte payload variants: Stdin (3), Stdout (5), Stderr (6)
        3 | 5 | 6 => {
            let data_len = read_u64_le(bytes, 4)?;
            let remaining = bytes.len().saturating_sub(12);
            if data_len > remaining as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "byte chunk length {data_len} exceeds remaining payload bytes ({remaining})"
                )));
            }
            Ok(())
        }
        // Signal (7): u32 variant tag
        7 => {
            let sig_tag = read_u32_le(bytes, 4)?;
            if sig_tag > 2 {
                return Err(ProtocolError::InvalidWireFormat(format!(
                    "unknown SignalKind discriminant {sig_tag}"
                )));
            }
            Ok(())
        }
        // Exit (8): i32
        8 => {
            let _ = read_u32_le(bytes, 4)?;
            Ok(())
        }
        // Error (9): ErrorKind (u32) + message (String)
        9 => {
            let kind_tag = read_u32_le(bytes, 4)?;
            if kind_tag > 6 {
                return Err(ProtocolError::InvalidWireFormat(format!(
                    "unknown ErrorKind discriminant {kind_tag}"
                )));
            }
            let msg_len = read_u64_le(bytes, 8)?;
            if msg_len > MAX_ERROR_MESSAGE_BYTES as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Error.message length {msg_len} exceeds limit {MAX_ERROR_MESSAGE_BYTES}"
                )));
            }
            let remaining = bytes.len().saturating_sub(16);
            if msg_len > remaining as u64 {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Error.message length {msg_len} exceeds remaining payload bytes ({remaining})"
                )));
            }
            Ok(())
        }
        other => Err(ProtocolError::InvalidWireFormat(format!(
            "unknown Frame discriminant {other}"
        ))),
    }
}

fn validate_frame_bounds(frame: &Frame) -> Result<(), ProtocolError> {
    match frame {
        Frame::Start(req) => {
            if req.args.len() > MAX_START_ARGS {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.args count {} exceeds limit {MAX_START_ARGS}",
                    req.args.len()
                )));
            }
            for arg in &req.args {
                if arg.len() > MAX_START_ARG_BYTES {
                    return Err(ProtocolError::AllocationLimitExceeded(format!(
                        "Start arg length {} exceeds limit {MAX_START_ARG_BYTES}",
                        arg.len()
                    )));
                }
            }
            if req.cwd.len() > MAX_START_CWD_BYTES {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.cwd length {} exceeds limit {MAX_START_CWD_BYTES}",
                    req.cwd.len()
                )));
            }
            if req.env_subset.len() > MAX_START_ENV_ENTRIES {
                return Err(ProtocolError::AllocationLimitExceeded(format!(
                    "Start.env_subset count {} exceeds limit {MAX_START_ENV_ENTRIES}",
                    req.env_subset.len()
                )));
            }
            for (k, v) in &req.env_subset {
                if k.len() > MAX_START_ENV_VALUE_BYTES || v.len() > MAX_START_ENV_VALUE_BYTES {
                    return Err(ProtocolError::AllocationLimitExceeded(format!(
                        "Start.env_subset entry exceeds limit {MAX_START_ENV_VALUE_BYTES}"
                    )));
                }
            }
        }
        Frame::Error { message, .. } if message.len() > MAX_ERROR_MESSAGE_BYTES => {
            return Err(ProtocolError::AllocationLimitExceeded(format!(
                "Error.message length {} exceeds limit {MAX_ERROR_MESSAGE_BYTES}",
                message.len()
            )));
        }
        _ => {}
    }
    Ok(())
}

/// Serializes a `Frame` into raw bincode-compatible bytes (without the 4-byte length prefix),
/// enforcing the 1 MiB cap and structural bounds.
///
/// Suitable for single-message transports such as P9 WebSocket binary frames.
pub fn encode_frame_payload(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    validate_frame_bounds(frame)?;
    let size = wincode::config::serialized_size(frame, wire_config())
        .map_err(|err| ProtocolError::EncodeFailed(err.to_string()))?;
    let size_usize = usize::try_from(size).map_err(|_| ProtocolError::FrameTooLarge {
        len: usize::MAX,
        max: MAX_FRAME_BYTES,
    })?;
    if size_usize == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if size_usize > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            len: size_usize,
            max: MAX_FRAME_BYTES,
        });
    }
    let bytes = wincode::config::serialize(frame, wire_config())
        .map_err(|err| ProtocolError::EncodeFailed(err.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            len: bytes.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    Ok(bytes)
}

/// Deserializes raw bincode-compatible payload bytes into a `Frame`, strictly enforcing:
/// - non-empty payload and `<= MAX_FRAME_BYTES` (1 MiB),
/// - bounded preallocation and container counts before allocating,
/// - zero trailing bytes (`deserialize_exact`).
pub fn decode_frame_payload(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            len: bytes.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    prevalidate_wire_bounds(bytes)?;

    let frame: Frame =
        wincode::config::deserialize_exact(bytes, wire_config()).map_err(map_wincode_read_error)?;
    validate_frame_bounds(&frame)?;
    Ok(frame)
}

fn map_wincode_read_error(err: wincode::ReadError) -> ProtocolError {
    match err {
        wincode::ReadError::TrailingBytes => ProtocolError::TrailingBytes,
        wincode::ReadError::PreallocationSizeLimit { needed, limit } => {
            ProtocolError::AllocationLimitExceeded(format!(
                "preallocation {needed} exceeds limit {limit}"
            ))
        }
        wincode::ReadError::Io(wincode::io::ReadError::ReadSizeLimit(limit)) => {
            ProtocolError::AllocationLimitExceeded(format!("read size exceeded limit {limit}"))
        }
        other => ProtocolError::InvalidWireFormat(other.to_string()),
    }
}

/// Encodes a `Frame` with its 4-byte big-endian length prefix for Unix socket framing.
pub fn encode_framed(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    let payload = encode_frame_payload(frame)?;
    let len_u32 = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        len: payload.len(),
        max: MAX_FRAME_BYTES,
    })?;
    let mut framed = Vec::with_capacity(FRAME_LENGTH_PREFIX_BYTES + payload.len());
    framed.extend_from_slice(&len_u32.to_be_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

/// Decodes a single length-prefixed frame from a complete slice, rejecting trailing bytes.
pub fn decode_framed(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    if bytes.len() < FRAME_LENGTH_PREFIX_BYTES {
        return Err(ProtocolError::TruncatedFrame {
            expected: FRAME_LENGTH_PREFIX_BYTES,
            actual: bytes.len(),
        });
    }
    let mut len_buf = [0u8; FRAME_LENGTH_PREFIX_BYTES];
    len_buf.copy_from_slice(&bytes[..FRAME_LENGTH_PREFIX_BYTES]);
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let payload = &bytes[FRAME_LENGTH_PREFIX_BYTES..];
    if payload.len() < len {
        return Err(ProtocolError::TruncatedFrame {
            expected: len,
            actual: payload.len(),
        });
    }
    if payload.len() > len {
        return Err(ProtocolError::TrailingBytes);
    }
    decode_frame_payload(payload)
}

/// Writes one length-prefixed frame to an async byte stream and flushes it.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), ProtocolError> {
    let framed = encode_framed(frame)?;
    writer.write_all(&framed).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one length-prefixed frame from an async byte stream.
///
/// Returns `Ok(None)` on clean EOF at a frame boundary (0 bytes read for the length prefix).
/// Partial length prefixes or partial payloads return `Err(ProtocolError::TruncatedFrame { .. })`.
/// Oversized length headers (`> MAX_FRAME_BYTES`) are rejected before allocating a payload buffer.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Frame>, ProtocolError> {
    let mut len_buf = [0u8; FRAME_LENGTH_PREFIX_BYTES];
    let mut read_so_far = 0usize;
    while read_so_far < FRAME_LENGTH_PREFIX_BYTES {
        let n = reader.read(&mut len_buf[read_so_far..]).await?;
        if n == 0 {
            if read_so_far == 0 {
                return Ok(None);
            }
            return Err(ProtocolError::TruncatedFrame {
                expected: FRAME_LENGTH_PREFIX_BYTES,
                actual: read_so_far,
            });
        }
        read_so_far += n;
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }

    let mut payload = vec![0u8; len];
    let mut offset = 0usize;
    while offset < len {
        let n = reader.read(&mut payload[offset..]).await?;
        if n == 0 {
            return Err(ProtocolError::TruncatedFrame {
                expected: len,
                actual: offset,
            });
        }
        offset += n;
    }

    decode_frame_payload(&payload).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frames() -> Vec<Frame> {
        vec![
            Frame::Start(StartRequest {
                args: vec![
                    "-hide_banner".to_string(),
                    "-i".to_string(),
                    "/srv/media/clip.mkv".to_string(),
                    "-c:v".to_string(),
                    "h264_vaapi".to_string(),
                ],
                cwd: "/var/cache/jellyfin/transcodes".to_string(),
                env_subset: vec![
                    (
                        "TMPDIR".to_string(),
                        "/var/cache/jellyfin/af-tmp".to_string(),
                    ),
                    ("TZ".to_string(), "UTC".to_string()),
                ],
            }),
            Frame::RunLocal,
            Frame::Started,
            Frame::Stdin(b"q\n".to_vec()),
            Frame::StdinEof,
            Frame::Stdout(b"frame=42 fps=120\n".to_vec()),
            Frame::Stderr(b"ffmpeg warning\n".to_vec()),
            Frame::Signal(SignalKind::Term),
            Frame::Signal(SignalKind::Int),
            Frame::Signal(SignalKind::Kill),
            Frame::Exit(0),
            Frame::Exit(143),
            Frame::Exit(-15),
            Frame::Error {
                kind: ErrorKind::DeviceUnavailable,
                message: "no VA-API render node available".to_string(),
            },
            Frame::Error {
                kind: ErrorKind::Busy,
                message: "worker full".to_string(),
            },
        ]
    }

    #[test]
    fn round_trip_every_frame_variant() {
        for frame in sample_frames() {
            let payload = encode_frame_payload(&frame).expect("encode payload");
            let decoded = decode_frame_payload(&payload).expect("decode payload");
            assert_eq!(decoded, frame);

            let framed = encode_framed(&frame).expect("encode framed");
            let decoded_framed = decode_framed(&framed).expect("decode framed");
            assert_eq!(decoded_framed, frame);
        }
    }

    #[test]
    fn golden_bincode_v1_wire_layout_fixture() {
        // Bincode v1 fixed-int LE wire vectors:
        // RunLocal => variant 1u32 LE
        assert_eq!(
            encode_frame_payload(&Frame::RunLocal).unwrap(),
            1u32.to_le_bytes()
        );
        // Started => variant 2u32 LE
        assert_eq!(
            encode_frame_payload(&Frame::Started).unwrap(),
            2u32.to_le_bytes()
        );
        // Stdin(b"q") => variant 3u32 LE + len 1u64 LE + b'q'
        let mut expected_stdin = Vec::new();
        expected_stdin.extend_from_slice(&3u32.to_le_bytes());
        expected_stdin.extend_from_slice(&1u64.to_le_bytes());
        expected_stdin.push(b'q');
        assert_eq!(
            encode_frame_payload(&Frame::Stdin(b"q".to_vec())).unwrap(),
            expected_stdin
        );
        // Signal(Kill) => variant 7u32 LE + SignalKind::Kill (2u32 LE)
        let mut expected_sig = Vec::new();
        expected_sig.extend_from_slice(&7u32.to_le_bytes());
        expected_sig.extend_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            encode_frame_payload(&Frame::Signal(SignalKind::Kill)).unwrap(),
            expected_sig
        );
        // Exit(143) => variant 8u32 LE + 143i32 LE
        let mut expected_exit = Vec::new();
        expected_exit.extend_from_slice(&8u32.to_le_bytes());
        expected_exit.extend_from_slice(&143i32.to_le_bytes());
        assert_eq!(
            encode_frame_payload(&Frame::Exit(143)).unwrap(),
            expected_exit
        );
        // Error { kind: SpawnFailed (3), message: "err" } => 9u32 LE + 3u32 LE + 3u64 LE + b"err"
        let mut expected_err = Vec::new();
        expected_err.extend_from_slice(&9u32.to_le_bytes());
        expected_err.extend_from_slice(&3u32.to_le_bytes());
        expected_err.extend_from_slice(&3u64.to_le_bytes());
        expected_err.extend_from_slice(b"err");
        assert_eq!(
            encode_frame_payload(&Frame::Error {
                kind: ErrorKind::SpawnFailed,
                message: "err".to_string(),
            })
            .unwrap(),
            expected_err
        );

        // Framed prefix is 4-byte BE length + payload
        let framed = encode_framed(&Frame::Exit(143)).unwrap();
        assert_eq!(&framed[..4], &8u32.to_be_bytes());
        assert_eq!(&framed[4..], expected_exit.as_slice());
    }

    #[test]
    fn rejects_oversized_frames_over_1_mib() {
        let oversized = Frame::Stdout(vec![b'x'; MAX_FRAME_BYTES]);
        let err = encode_frame_payload(&oversized).expect_err("payload + header exceeds 1 MiB");
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));

        // Exact 1 MiB payload fits (4-byte tag + 8-byte len + data == MAX_FRAME_BYTES).
        let exact_max = Frame::Stdout(vec![b'x'; MAX_FRAME_BYTES - 12]);
        let encoded = encode_frame_payload(&exact_max).expect("exact 1 MiB fits");
        assert_eq!(encoded.len(), MAX_FRAME_BYTES);
        assert_eq!(decode_frame_payload(&encoded).unwrap(), exact_max);

        // One byte over 1 MiB is rejected on decode before allocation.
        let mut over_by_one = vec![0u8; MAX_FRAME_BYTES + 1];
        over_by_one[..4].copy_from_slice(&5u32.to_be_bytes());
        assert!(matches!(
            decode_frame_payload(&over_by_one),
            Err(ProtocolError::FrameTooLarge { len, max }) if len == MAX_FRAME_BYTES + 1 && max == MAX_FRAME_BYTES
        ));
    }

    #[test]
    fn rejects_trailing_bytes_and_malformed_wire_frames() {
        let mut with_trailing = encode_frame_payload(&Frame::Started).unwrap();
        with_trailing.push(0x00);
        assert!(matches!(
            decode_frame_payload(&with_trailing),
            Err(ProtocolError::TrailingBytes)
        ));

        let mut framed_trailing = encode_framed(&Frame::RunLocal).unwrap();
        framed_trailing.push(0xff);
        assert!(matches!(
            decode_framed(&framed_trailing),
            Err(ProtocolError::TrailingBytes)
        ));

        // Empty payload / zero length prefix
        assert!(matches!(
            decode_frame_payload(&[]),
            Err(ProtocolError::EmptyFrame)
        ));
        assert!(matches!(
            decode_framed(&0u32.to_be_bytes()),
            Err(ProtocolError::EmptyFrame)
        ));

        // Unknown frame discriminant
        assert!(matches!(
            decode_frame_payload(&99u32.to_le_bytes()),
            Err(ProtocolError::InvalidWireFormat(_))
        ));

        // Unknown SignalKind discriminant
        let mut bad_sig = Vec::new();
        bad_sig.extend_from_slice(&7u32.to_le_bytes());
        bad_sig.extend_from_slice(&9u32.to_le_bytes());
        assert!(matches!(
            decode_frame_payload(&bad_sig),
            Err(ProtocolError::InvalidWireFormat(_))
        ));

        // Invalid UTF-8 inside Error.message
        let mut bad_utf8 = Vec::new();
        bad_utf8.extend_from_slice(&9u32.to_le_bytes());
        bad_utf8.extend_from_slice(&0u32.to_le_bytes());
        bad_utf8.extend_from_slice(&2u64.to_le_bytes());
        bad_utf8.extend_from_slice(&[0xff, 0xfe]);
        assert!(matches!(
            decode_frame_payload(&bad_utf8),
            Err(ProtocolError::InvalidWireFormat(_))
        ));
    }

    #[test]
    fn rejects_forged_huge_container_and_byte_lengths_without_allocation() {
        // Forged Stdin claiming u64::MAX bytes in a 12-byte payload
        let mut forged_bytes = Vec::new();
        forged_bytes.extend_from_slice(&3u32.to_le_bytes());
        forged_bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            decode_frame_payload(&forged_bytes),
            Err(ProtocolError::AllocationLimitExceeded(_))
        ));

        // Forged Start claiming 100_000 args in a 12-byte payload
        let mut forged_args = Vec::new();
        forged_args.extend_from_slice(&0u32.to_le_bytes());
        forged_args.extend_from_slice(&100_000u64.to_le_bytes());
        assert!(matches!(
            decode_frame_payload(&forged_args),
            Err(ProtocolError::AllocationLimitExceeded(_))
        ));

        // Forged Start claiming 20 args (within MAX_START_ARGS) in a 20-byte payload
        let mut forged_small_args = Vec::new();
        forged_small_args.extend_from_slice(&0u32.to_le_bytes());
        forged_small_args.extend_from_slice(&20u64.to_le_bytes());
        forged_small_args.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            decode_frame_payload(&forged_small_args),
            Err(ProtocolError::AllocationLimitExceeded(_))
        ));

        // Forged Error claiming 5000-byte message (> MAX_ERROR_MESSAGE_BYTES)
        let mut forged_err = Vec::new();
        forged_err.extend_from_slice(&9u32.to_le_bytes());
        forged_err.extend_from_slice(&0u32.to_le_bytes());
        forged_err.extend_from_slice(&5000u64.to_le_bytes());
        assert!(matches!(
            decode_frame_payload(&forged_err),
            Err(ProtocolError::AllocationLimitExceeded(_))
        ));
    }

    #[tokio::test]
    async fn async_read_write_handles_eof_truncation_and_oversized_header() {
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        let frames = sample_frames();
        let expected = frames.clone();

        let writer = tokio::spawn(async move {
            for f in &frames {
                write_frame(&mut tx, f).await.unwrap();
            }
            drop(tx);
        });

        let mut received = Vec::new();
        while let Some(f) = read_frame(&mut rx).await.unwrap() {
            received.push(f);
        }
        writer.await.unwrap();
        assert_eq!(received, expected);

        // Truncated length header
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&[0x00, 0x01]).await.unwrap();
        drop(tx);
        assert!(matches!(
            read_frame(&mut rx).await,
            Err(ProtocolError::TruncatedFrame {
                expected: 4,
                actual: 2
            })
        ));

        // Truncated payload
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&10u32.to_be_bytes()).await.unwrap();
        tx.write_all(&[1, 2, 3]).await.unwrap();
        drop(tx);
        assert!(matches!(
            read_frame(&mut rx).await,
            Err(ProtocolError::TruncatedFrame {
                expected: 10,
                actual: 3
            })
        ));

        // Oversized length header rejected immediately without reading payload
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        drop(tx);
        assert!(matches!(
            read_frame(&mut rx).await,
            Err(ProtocolError::FrameTooLarge { len, max }) if len == MAX_FRAME_BYTES + 1 && max == MAX_FRAME_BYTES
        ));
    }

    #[test]
    fn bounded_channel_enforces_64_frame_backpressure() {
        let (tx, mut rx) = bounded_frame_channel();
        for i in 0..FRAME_CHANNEL_CAPACITY {
            tx.try_send(Frame::Exit(i as i32))
                .expect("within 64-frame capacity");
        }
        assert!(
            matches!(
                tx.try_send(Frame::Exit(999)),
                Err(mpsc::error::TrySendError::Full(_))
            ),
            "65th frame must trigger backpressure"
        );
        assert_eq!(rx.try_recv().unwrap(), Frame::Exit(0));
        tx.try_send(Frame::Exit(64))
            .expect("slot freed after draining one frame");
    }
}
