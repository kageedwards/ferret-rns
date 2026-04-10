// Resource module: large data transfer with segmentation, compression, and hashmap verification

pub mod resource;
pub mod advertisement;
pub mod initiator;
pub mod receiver;
pub mod window;
pub mod watchdog;
pub mod link_integration;

use crate::error::FerretError;

// ── Enums ──

/// Resource lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceStatus {
    None          = 0x00,
    Queued        = 0x01,
    Advertised    = 0x02,
    Transferring  = 0x03,
    AwaitingProof = 0x04,
    Assembling    = 0x05,
    Complete      = 0x06,
    Failed        = 0x07,
    Corrupt       = 0x08,
}

impl TryFrom<u8> for ResourceStatus {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::Queued),
            0x02 => Ok(Self::Advertised),
            0x03 => Ok(Self::Transferring),
            0x04 => Ok(Self::AwaitingProof),
            0x05 => Ok(Self::Assembling),
            0x06 => Ok(Self::Complete),
            0x07 => Ok(Self::Failed),
            0x08 => Ok(Self::Corrupt),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "ResourceStatus", value }),
        }
    }
}

impl From<ResourceStatus> for u8 {
    fn from(v: ResourceStatus) -> u8 { v as u8 }
}

// ── Flags ──

/// Resource flags bitfield (bits 0–5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceFlags {
    pub encrypted: bool,     // bit 0
    pub compressed: bool,    // bit 1
    pub split: bool,         // bit 2
    pub is_request: bool,    // bit 3
    pub is_response: bool,   // bit 4
    pub has_metadata: bool,  // bit 5
}

impl ResourceFlags {
    /// Encode flags into a single byte.
    pub fn to_byte(&self) -> u8 {
        let mut b: u8 = 0;
        if self.encrypted    { b |= 1 << 0; }
        if self.compressed   { b |= 1 << 1; }
        if self.split        { b |= 1 << 2; }
        if self.is_request   { b |= 1 << 3; }
        if self.is_response  { b |= 1 << 4; }
        if self.has_metadata { b |= 1 << 5; }
        b
    }

    /// Decode flags from a single byte.
    pub fn from_byte(b: u8) -> Self {
        Self {
            encrypted:    b & (1 << 0) != 0,
            compressed:   b & (1 << 1) != 0,
            split:        b & (1 << 2) != 0,
            is_request:   b & (1 << 3) != 0,
            is_response:  b & (1 << 4) != 0,
            has_metadata: b & (1 << 5) != 0,
        }
    }
}

// ── Constants ──

/// Initial window size.
pub const WINDOW: usize = 4;
/// Absolute minimum window.
pub const WINDOW_MIN: usize = 2;
/// Max window for slow links.
pub const WINDOW_MAX_SLOW: usize = 10;
/// Max window for very slow links.
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
/// Max window for fast links.
pub const WINDOW_MAX_FAST: usize = 75;
/// Global maximum window (= WINDOW_MAX_FAST).
pub const WINDOW_MAX: usize = 75;
/// Consecutive fast rounds before upgrading window_max.
pub const FAST_RATE_THRESHOLD: usize = 4; // WINDOW_MAX_SLOW - WINDOW - 2
/// Consecutive very-slow rounds before downgrading window_max.
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;
/// 50 Kbps in bytes/sec.
pub const RATE_FAST: usize = 6250;
/// 2 Kbps in bytes/sec.
pub const RATE_VERY_SLOW: usize = 250;
/// Min gap between window_max and window_min.
pub const WINDOW_FLEXIBILITY: usize = 4;
/// Bytes per map hash.
pub const MAPHASH_LEN: usize = 4;
/// Bytes for random hash prefix.
pub const RANDOM_HASH_SIZE: usize = 4;
/// Maximum efficient single-segment size (1 MiB - 1).
pub const MAX_EFFICIENT_SIZE: usize = 1_048_575; // 0xFFFFF
/// Skip compression above this size (64 MiB).
pub const AUTO_COMPRESS_MAX_SIZE: usize = 67_108_864;
/// Maximum metadata size (16 MiB - 1).
pub const METADATA_MAX_SIZE: usize = 16_777_215; // 0xFFFFFF
/// Initial part timeout multiplier.
pub const PART_TIMEOUT_FACTOR: usize = 4;
/// Part timeout multiplier after first RTT.
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: usize = 2;
/// Proof timeout multiplier.
pub const PROOF_TIMEOUT_FACTOR: usize = 3;
/// Max part transfer retries.
pub const MAX_RETRIES: usize = 16;
/// Max advertisement retries.
pub const MAX_ADV_RETRIES: usize = 4;
/// Sender-side grace period (seconds).
pub const SENDER_GRACE_TIME: f64 = 10.0;
/// Processing grace period (seconds).
pub const PROCESSING_GRACE: f64 = 1.0;
/// Per-retry grace period (seconds).
pub const RETRY_GRACE_TIME: f64 = 0.25;
/// Delay per retry (seconds).
pub const PER_RETRY_DELAY: f64 = 0.5;
/// Max watchdog sleep interval (seconds).
pub const WATCHDOG_MAX_SLEEP: f64 = 1.0;
/// Hashmap not exhausted flag.
pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
/// Hashmap exhausted flag.
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;
