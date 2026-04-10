// RawChannelReader: stream-oriented reading from a Channel

use crate::buffer::stream_data::StreamDataMessage;
use crate::buffer::STREAM_DATA_MSGTYPE;
use crate::channel::message::MessageBase;
use crate::channel::Channel;

/// Stream-oriented reader that accumulates StreamDataMessage payloads.
pub struct RawChannelReader {
    stream_id: u16,
    buffer: Vec<u8>,
    eof: bool,
    ready_callbacks: Vec<Box<dyn Fn(usize) + Send + Sync>>,
}

impl RawChannelReader {
    /// Create a new reader for the given stream_id.
    /// Registers StreamDataMessage as a system message type on the channel.
    pub fn new(stream_id: u16, channel: &mut Channel) -> Self {
        // Register the StreamDataMessage factory as a system message type
        let _ = channel.register_system_message_type(
            STREAM_DATA_MSGTYPE,
            Box::new(|| Box::new(StreamDataMessage::empty()) as Box<dyn MessageBase>),
        );

        Self {
            stream_id,
            buffer: Vec::new(),
            eof: false,
            ready_callbacks: Vec::new(),
        }
    }

    /// Handle an incoming message. Returns true if consumed.
    pub fn handle_message(&mut self, message: &dyn MessageBase) -> bool {
        if message.msgtype() != STREAM_DATA_MSGTYPE {
            return false;
        }

        // Re-unpack from the packed data to get StreamDataMessage fields
        let packed = match message.pack() {
            Ok(p) => p,
            Err(_) => return false,
        };

        let mut sdm = StreamDataMessage::empty();
        if sdm.unpack(&packed).is_err() {
            return false;
        }

        if sdm.stream_id != self.stream_id {
            return false;
        }

        // Append data to buffer
        if !sdm.data.is_empty() {
            self.buffer.extend_from_slice(&sdm.data);
        }

        // Invoke ready callbacks with current buffer length
        let buf_len = self.buffer.len();
        for cb in &self.ready_callbacks {
            cb(buf_len);
        }

        // Handle EOF
        if sdm.eof {
            self.eof = true;
        }

        true
    }

    /// Read up to `size` bytes from the internal buffer.
    /// Returns None if buffer is empty.
    pub fn read(&mut self, size: usize) -> Option<Vec<u8>> {
        if self.buffer.is_empty() {
            return None;
        }
        let n = size.min(self.buffer.len());
        let data = self.buffer.drain(..n).collect();
        Some(data)
    }

    /// Add a ready callback invoked when data arrives.
    pub fn add_ready_callback(&mut self, cb: Box<dyn Fn(usize) + Send + Sync>) {
        self.ready_callbacks.push(cb);
    }

    /// Remove a ready callback by index.
    pub fn remove_ready_callback(&mut self, index: usize) {
        if index < self.ready_callbacks.len() {
            let _ = self.ready_callbacks.remove(index);
        }
    }

    /// Close the reader, clearing callbacks.
    pub fn close(&mut self, _channel: &mut Channel) {
        self.ready_callbacks.clear();
    }

    /// Whether the stream has ended (EOF received).
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Current buffer length.
    pub fn available(&self) -> usize {
        self.buffer.len()
    }

    /// The stream_id this reader is bound to.
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }
}
