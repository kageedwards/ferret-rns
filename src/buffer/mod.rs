// Buffer module: stream-oriented read/write I/O over a Channel

pub mod stream_data;
pub mod reader;
pub mod writer;

use crate::channel::Channel;
use reader::RawChannelReader;
use writer::RawChannelWriter;

// ── Constants ──

/// System-reserved MSGTYPE for StreamDataMessage.
pub const STREAM_DATA_MSGTYPE: u16 = 0xFF00;

/// Maximum stream_id (14 bits).
pub const STREAM_ID_MAX: u16 = 16383;

/// StreamDataMessage overhead: 2 (SDM header) + 6 (envelope header).
pub const STREAM_DATA_OVERHEAD: usize = 8;

/// Maximum write chunk size.
pub const MAX_CHUNK_LEN: usize = 16384;

// ── Factory functions ──

/// Create a buffered reader for the given stream_id.
pub fn create_reader(
    stream_id: u16,
    channel: &mut Channel,
    ready_callback: Option<Box<dyn Fn(usize) + Send + Sync>>,
) -> RawChannelReader {
    let mut reader = RawChannelReader::new(stream_id, channel);
    if let Some(cb) = ready_callback {
        reader.add_ready_callback(cb);
    }
    reader
}

/// Create a buffered writer for the given stream_id.
pub fn create_writer(stream_id: u16, channel: &Channel) -> RawChannelWriter {
    RawChannelWriter::new(stream_id, channel)
}

/// Create a bidirectional buffer (reader + writer) pair.
pub fn create_bidirectional_buffer(
    receive_stream_id: u16,
    send_stream_id: u16,
    channel: &mut Channel,
    ready_callback: Option<Box<dyn Fn(usize) + Send + Sync>>,
) -> (RawChannelReader, RawChannelWriter) {
    let reader = create_reader(receive_stream_id, channel, ready_callback);
    let writer = create_writer(send_stream_id, channel);
    (reader, writer)
}
