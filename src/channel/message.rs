// MessageBase trait, MessageState enum, ChannelError enum, MessageFactory type

use crate::Result;

/// Base trait for messages sent/received on a Channel.
pub trait MessageBase: Send + Sync {
    /// Unique message type identifier.
    fn msgtype(&self) -> u16;
    /// Serialize the message to bytes.
    fn pack(&self) -> Result<Vec<u8>>;
    /// Deserialize the message from bytes.
    fn unpack(&mut self, raw: &[u8]) -> Result<()>;
}

/// Factory function type for creating message instances.
pub type MessageFactory = Box<dyn Fn() -> Box<dyn MessageBase> + Send + Sync>;

/// Delivery state of a channel message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageState {
    New       = 0,
    Sent      = 1,
    Delivered = 2,
    Failed    = 3,
}

/// Channel-specific error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelError {
    NoMsgType      = 0,
    InvalidMsgType = 1,
    NotRegistered  = 2,
    LinkNotReady   = 3,
    AlreadySent    = 4,
    TooBig         = 5,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMsgType => write!(f, "message type is None"),
            Self::InvalidMsgType => write!(f, "invalid message type (>= 0xF000)"),
            Self::NotRegistered => write!(f, "message type not registered"),
            Self::LinkNotReady => write!(f, "link not ready to send"),
            Self::AlreadySent => write!(f, "envelope already sent"),
            Self::TooBig => write!(f, "message exceeds MDU"),
        }
    }
}
