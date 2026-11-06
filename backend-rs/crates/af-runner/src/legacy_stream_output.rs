//! Cancellation-safe bounded producer records for legacy installer pipes.
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

// Reserve one byte for the newline added by the stream. Both pipe buffers and
// partial records remain bounded before anything is handed to an IPC consumer.
const MAX_RECORD_BYTES: usize = 64 * 1024 - 1;

pub(crate) struct BoundedLines<R> {
    reader: BufReader<R>,
    pending: Vec<u8>,
}

impl<R: AsyncRead + Unpin> BoundedLines<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            pending: Vec::new(),
        }
    }

    // State lives in self: cancelling this future while select! polls the other
    // pipe never drops or repeats already consumed bytes.
    pub(crate) async fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            let bytes = self.reader.fill_buf().await?;
            let newline = bytes.iter().position(|byte| *byte == b'\n');
            let take = newline.unwrap_or(bytes.len());
            if self.pending.len() + take > MAX_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "installer output record exceeds the 65535-byte limit; operation failed",
                ));
            }
            self.pending.extend_from_slice(&bytes[..take]);
            let eof = bytes.is_empty();
            self.reader.consume(take + usize::from(newline.is_some()));
            if newline.is_some() || eof {
                if eof && self.pending.is_empty() {
                    return Ok(None);
                }
                let mut line = String::from_utf8(std::mem::take(&mut self.pending))
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                if line.ends_with('\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn records_keep_crlf_empty_lines_and_final_partial_line() {
        let mut lines = BoundedLines::new(&b"first\r\n\nlast"[..]);
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("first"));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some(""));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("last"));
        assert!(lines.next_line().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cancellation_preserves_partial_records_and_newline_free_output_is_bounded() {
        let (mut output, input) = tokio::io::duplex(32);
        let mut lines = BoundedLines::new(input);
        output.write_all(b"part").await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), lines.next_line())
                .await
                .is_err()
        );
        output.write_all(b"ial\n").await.unwrap();
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("partial"));
        let writer = tokio::spawn(async move {
            for _ in 0..MAX_RECORD_BYTES / 32 + 2 {
                if output.write_all(&[b'x'; 32]).await.is_err() {
                    break;
                }
            }
        });
        let error = lines.next_line().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(lines.pending.len() <= MAX_RECORD_BYTES);
        drop(lines);
        writer.await.unwrap();
    }
}
