// RawChannelWriter: stream-oriented writing to a Channel

use crate::buffer::stream_data::StreamDataMessage;
use crate::buffer::MAX_CHUNK_LEN;
use crate::channel::Channel;
use crate::transport::transport::TransportState;
use crate::Result;

/// Stream-oriented writer that sends data as StreamDataMessage chunks.
pub struct RawChannelWriter {
    stream_id: u16,
    max_chunk: usize,
    eof: bool,
}

impl RawChannelWriter {
    /// Create a new writer for the given stream_id.
    /// Computes max chunk size from channel MDU minus StreamDataMessage overhead.
    pub fn new(stream_id: u16, channel: &Channel) -> Self {
        // Channel MDU minus 2-byte SDM header
        let channel_mdu = channel.mdu();
        let max_chunk = channel_mdu.saturating_sub(2).min(MAX_CHUNK_LEN);

        Self {
            stream_id,
            max_chunk,
            eof: false,
        }
    }

    /// Write data to the channel, splitting into chunks.
    /// Returns the number of bytes written, or 0 if channel not ready.
    pub fn write(
        &mut self,
        data: &[u8],
        channel: &mut Channel,
        transport: &TransportState,
    ) -> Result<usize> {
        if self.eof {
            return Ok(0);
        }
        if !channel.is_ready_to_send() {
            return Ok(0);
        }
        if data.is_empty() {
            return Ok(0);
        }

        let mut written = 0;
        let mut offset = 0;

        while offset < data.len() && channel.is_ready_to_send() {
            let end = (offset + self.max_chunk).min(data.len());
            let chunk = &data[offset..end];

            // Try bzip2 compression
            let (send_data, compressed) = match try_compress(chunk) {
                Some(compressed_data) => (compressed_data, true),
                None => (chunk.to_vec(), false),
            };

            let msg = StreamDataMessage::new(
                self.stream_id,
                false,
                compressed,
                send_data,
            )?;
            channel.send(Box::new(msg), transport)?;

            written += chunk.len();
            offset = end;
        }

        Ok(written)
    }

    /// Send a final EOF message and mark the writer as closed.
    pub fn close(
        &mut self,
        channel: &mut Channel,
        transport: &TransportState,
    ) -> Result<()> {
        if self.eof {
            return Ok(());
        }
        let msg = StreamDataMessage::new(self.stream_id, true, false, Vec::new())?;
        channel.send(Box::new(msg), transport)?;
        self.eof = true;
        Ok(())
    }

    /// Whether the writer has sent EOF.
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// The stream_id this writer is bound to.
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }
}

/// Attempt bzip2 compression. Returns Some(compressed) if smaller than original.
fn try_compress(data: &[u8]) -> Option<Vec<u8>> {
    use bzip2::write::BzEncoder;
    use bzip2::Compression;
    use std::io::Write;

    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).ok()?;
    let compressed = encoder.finish().ok()?;
    if compressed.len() < data.len() {
        Some(compressed)
    } else {
        None
    }
}
