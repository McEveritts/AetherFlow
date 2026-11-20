//! Cancellation-safe bounded producer records for legacy installer pipes.
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

const MAX_LINE_BYTES: usize = 64 * 1024;

pub(crate) struct BoundedLines<R> {
    reader: BufReader<R>,
    pending: Vec<u8>,
    skip_lf: bool,
}

impl<R: AsyncRead + Unpin> BoundedLines<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            pending: Vec::new(),
            skip_lf: false,
        }
    }

    // State lives in self: cancelling this future while select! polls the other
    // pipe never drops or repeats already consumed bytes.
    pub(crate) async fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            let bytes = self.reader.fill_buf().await?;
            if self.skip_lf {
                self.skip_lf = false;
                if bytes.first() == Some(&b'\n') {
                    self.reader.consume(1);
                    continue;
                }
            }
            let delimiter = bytes.iter().position(|byte| matches!(byte, b'\n' | b'\r'));
            let take = delimiter.unwrap_or(bytes.len());
            let keep = take.min(MAX_LINE_BYTES - self.pending.len());
            self.pending.extend_from_slice(&bytes[..keep]);
            let eof = bytes.is_empty();
            self.skip_lf = bytes.get(take) == Some(&b'\r');
            self.reader.consume(take + usize::from(delimiter.is_some()));
            if delimiter.is_some() || eof {
                if eof && self.pending.is_empty() {
                    return Ok(None);
                }
                let mut line = String::from_utf8_lossy(&self.pending).into_owned();
                if line.len() > MAX_LINE_BYTES {
                    line.truncate(line.floor_char_boundary(MAX_LINE_BYTES));
                }
                self.pending.clear();
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
    async fn cancellation_preserves_partial_records() {
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
    }

    #[tokio::test]
    async fn localized_output_is_lossy() {
        let mut lines = BoundedLines::new(&b"caf\xe9\nvalid \xc3\xa9\n\xff"[..]);
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("caf�"));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("valid é"));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("�"));
    }

    #[tokio::test]
    async fn oversized_carriage_return_progress_is_truncated_and_drained() {
        let mut input = vec![b'x'; MAX_LINE_BYTES + 32768];
        input.extend_from_slice(b"\rprogress\r\ncomplete\n");
        let mut lines = BoundedLines::new(input.as_slice());
        assert_eq!(
            lines.next_line().await.unwrap().unwrap(),
            "x".repeat(MAX_LINE_BYTES)
        );
        assert_eq!(
            lines.next_line().await.unwrap().as_deref(),
            Some("progress")
        );
        assert_eq!(
            lines.next_line().await.unwrap().as_deref(),
            Some("complete")
        );
        assert!(lines.next_line().await.unwrap().is_none());
    }
}
