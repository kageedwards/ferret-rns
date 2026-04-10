// StreamDataMessage: pack/unpack with bzip2 compression support

use crate::buffer::{STREAM_DATA_MSGTYPE, STREAM_ID_MAX};
use crate::channel::message::MessageBase;
use crate::{FerretError, Result};

/// System message carrying binary stream data over a Channel.
///
/// Wire format (2-byte BE header + data):
///   bit 15 = EOF, bit 14 = compressed, bits 13:0 = stream_id
pub struct StreamDataMessage {
    pub stream_id: u16,
    pub eof: bool,
    pub compressed: bool,
    pub data: Vec<u8>,
}

impl StreamDataMessage {
    /// Create a new StreamDataMessage.
    pub fn new(stream_id: u16, eof: bool, compressed: bool, data: Vec<u8>) -> Result<Self> {
        if stream_id > STREAM_ID_MAX {
            return Err(FerretError::InvalidStreamId(stream_id));
        }
        Ok(Self {
            stream_id,
            eof,
            compressed,
            data,
        })
    }

    /// Create an empty StreamDataMessage for unpacking.
    pub fn empty() -> Self {
        Self {
            stream_id: 0,
            eof: false,
            compressed: false,
            data: Vec::new(),
        }
    }
}

impl MessageBase for StreamDataMessage {
    fn msgtype(&self) -> u16 {
        STREAM_DATA_MSGTYPE
    }

    fn pack(&self) -> Result<Vec<u8>> {
        if self.stream_id > STREAM_ID_MAX {
            return Err(FerretError::InvalidStreamId(self.stream_id));
        }
        let mut header: u16 = self.stream_id & 0x3FFF;
        if self.eof {
            header |= 1 << 15;
        }
        if self.compressed {
            header |= 1 << 14;
        }
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<()> {
        if raw.len() < 2 {
            return Err(FerretError::Deserialization(
                "StreamDataMessage too short".into(),
            ));
        }
        let header = u16::from_be_bytes([raw[0], raw[1]]);
        self.eof = (header & (1 << 15)) != 0;
        self.compressed = (header & (1 << 14)) != 0;
        self.stream_id = header & 0x3FFF;

        if self.stream_id > STREAM_ID_MAX {
            return Err(FerretError::InvalidStreamId(self.stream_id));
        }

        let payload = &raw[2..];
        if self.compressed {
            use bzip2::read::BzDecoder;
            use std::io::Read;
            let mut decoder = BzDecoder::new(payload);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                FerretError::Deserialization(format!("bzip2 decompress: {}", e))
            })?;
            self.data = decompressed;
        } else {
            self.data = payload.to_vec();
        }
        Ok(())
    }
}
