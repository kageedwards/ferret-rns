// Channel module: reliable, sequenced message delivery over a Link

pub mod channel;
pub mod envelope;
pub mod message;
pub mod outlet;

// ── Constants ──

/// Initial channel window size.
pub const WINDOW: u16 = 2;

/// Absolute minimum window.
pub const WINDOW_MIN: u16 = 2;

/// Max window for slow links.
pub const WINDOW_MAX_SLOW: u16 = 5;

/// Max window for medium links.
pub const WINDOW_MAX_MEDIUM: u16 = 12;

/// Max window for fast links.
pub const WINDOW_MAX_FAST: u16 = 48;

/// Min difference between window_max and window_min.
pub const WINDOW_FLEXIBILITY: u16 = 4;

/// Minimum window limit for medium-speed links.
pub const WINDOW_MIN_LIMIT_MEDIUM: u16 = 5;

/// Minimum window limit for fast links.
pub const WINDOW_MIN_LIMIT_FAST: u16 = 16;

/// RTT threshold for fast link (seconds).
pub const RTT_FAST: f64 = 0.18;

/// RTT threshold for medium link (seconds).
pub const RTT_MEDIUM: f64 = 0.75;

/// RTT threshold for slow link (seconds).
pub const RTT_SLOW: f64 = 1.45;

/// Consecutive rounds before window upgrade.
pub const FAST_RATE_THRESHOLD: u16 = 10;

/// Maximum sequence number.
pub const SEQ_MAX: u16 = 0xFFFF;

/// Max retransmission attempts per envelope.
pub const MAX_TRIES: u8 = 5;

// Re-export types
pub use channel::Channel;
pub use envelope::Envelope;
pub use outlet::ChannelOutlet;
pub use message::{MessageBase, MessageState, ChannelError, MessageFactory};
