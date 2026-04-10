// Buffer module: stream-oriented read/write I/O over a Channel

pub mod stream_data;
pub mod reader;
pub mod writer;

// ── Constants ──

/// System-reserved MSGTYPE for StreamDataMessage.
pub const STREAM_DATA_MSGTYPE: u16 = 0xFF00;

/// Maximum stream_id (14 bits).
pub const STREAM_ID_MAX: u16 = 16383;

/// StreamDataMessage overhead: 2 (SDM header) + 6 (envelope header).
pub const STREAM_DATA_OVERHEAD: usize = 8;

/// Maximum write chunk size.
pub const MAX_CHUNK_LEN: usize = 16384;

// Factory functions (stubs — implemented in task 19.3):

// pub fn create_reader(
//     stream_id: u16,
//     channel: &mut Channel,
//     ready_callback: Option<Box<dyn Fn(usize) + Send + Sync>>,
// ) -> RawChannelReader;

// pub fn create_writer(stream_id: u16, channel: &Channel) -> RawChannelWriter;

// pub fn create_bidirectional_buffer(
//     receive_stream_id: u16,
//     send_stream_id: u16,
//     channel: &mut Channel,
//     ready_callback: Option<Box<dyn Fn(usize) + Send + Sync>>,
// ) -> (RawChannelReader, RawChannelWriter);
