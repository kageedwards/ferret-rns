// Envelope: pack/unpack, 6-byte header serialization

use std::collections::HashMap;

use crate::channel::message::{MessageBase, MessageFactory};
use crate::{FerretError, Result};

/// Wrapper that frames a Message with a 6-byte header for Channel transport.
pub struct Envelope {
    /// The message being transported.
    pub message: Option<Box<dyn MessageBase>>,
    /// Serialized envelope bytes (header + payload).
    pub raw: Vec<u8>,
    /// Associated packet (set after sending).
    pub(crate) packet: Option<crate::packet::packet::Packet>,
    /// Sequence number.
    pub sequence: u16,
    /// Number of send attempts.
    pub(crate) tries: u8,
    /// Whether the envelope has been unpacked.
    pub unpacked: bool,
    /// Whether the envelope has been packed.
    pub packed: bool,
    /// Whether the envelope is tracked in the TX ring.
    pub(crate) tracked: bool,
    /// Timestamp of last send.
    pub(crate) ts: f64,
}

impl Envelope {
    /// Create a new Envelope wrapping a message with the given sequence number.
    pub fn new(message: Box<dyn MessageBase>, sequence: u16) -> Self {
        Self {
            message: Some(message),
            raw: Vec::new(),
            packet: None,
            sequence,
            tries: 0,
            unpacked: false,
            packed: false,
            tracked: false,
            ts: 0.0,
        }
    }

    /// Create an empty Envelope for receiving (will be filled by unpack).
    pub fn new_empty(sequence: u16) -> Self {
        Self {
            message: None,
            raw: Vec::new(),
            packet: None,
            sequence,
            tries: 0,
            unpacked: false,
            packed: false,
            tracked: false,
            ts: 0.0,
        }
    }

    /// Serialize: 6-byte header (msgtype u16 BE + sequence u16 BE + length u16 BE) + message data.
    pub fn pack(&mut self) -> Result<Vec<u8>> {
        let msg = self
            .message
            .as_ref()
            .ok_or(FerretError::ChannelError(crate::channel::message::ChannelError::NoMsgType))?;

        let msgtype = msg.msgtype();
        let payload = msg.pack()?;
        let length = payload.len() as u16;

        let mut raw = Vec::with_capacity(6 + payload.len());
        raw.extend_from_slice(&msgtype.to_be_bytes());
        raw.extend_from_slice(&self.sequence.to_be_bytes());
        raw.extend_from_slice(&length.to_be_bytes());
        raw.extend_from_slice(&payload);

        self.raw = raw.clone();
        self.packed = true;
        Ok(raw)
    }

    /// Deserialize: parse 6-byte header, look up factory, create and unpack message.
    pub fn unpack(
        &mut self,
        raw: &[u8],
        factories: &HashMap<u16, MessageFactory>,
    ) -> Result<()> {
        if raw.len() < 6 {
            return Err(FerretError::MalformedPacket(
                "envelope too short for header".into(),
            ));
        }

        let msgtype = u16::from_be_bytes([raw[0], raw[1]]);
        self.sequence = u16::from_be_bytes([raw[2], raw[3]]);
        let length = u16::from_be_bytes([raw[4], raw[5]]) as usize;

        if raw.len() < 6 + length {
            return Err(FerretError::MalformedPacket(
                "envelope payload shorter than declared length".into(),
            ));
        }

        let factory = factories.get(&msgtype).ok_or(FerretError::ChannelError(
            crate::channel::message::ChannelError::NotRegistered,
        ))?;

        let mut message = factory();
        message.unpack(&raw[6..6 + length])?;

        self.message = Some(message);
        self.raw = raw.to_vec();
        self.unpacked = true;
        Ok(())
    }
}
