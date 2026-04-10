// Link module: encrypted peer-to-peer connections with ECDH handshake

pub mod link;
pub mod handshake;
pub mod receive;
pub mod request;
pub mod watchdog;

use crate::error::FerretError;

// ── Enums ──

/// Link lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkStatus {
    Pending   = 0x00,
    Handshake = 0x01,
    Active    = 0x02,
    Stale     = 0x03,
    Closed    = 0x04,
}

impl TryFrom<u8> for LinkStatus {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Pending),
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Active),
            0x03 => Ok(Self::Stale),
            0x04 => Ok(Self::Closed),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "LinkStatus", value }),
        }
    }
}

impl From<LinkStatus> for u8 {
    fn from(v: LinkStatus) -> u8 { v as u8 }
}

/// Reason a link was torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TeardownReason {
    Timeout           = 0x01,
    InitiatorClosed   = 0x02,
    DestinationClosed = 0x03,
}

impl TryFrom<u8> for TeardownReason {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Timeout),
            0x02 => Ok(Self::InitiatorClosed),
            0x03 => Ok(Self::DestinationClosed),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "TeardownReason", value }),
        }
    }
}

impl From<TeardownReason> for u8 {
    fn from(v: TeardownReason) -> u8 { v as u8 }
}

/// Link encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkMode {
    Aes128Cbc   = 0x00,
    Aes256Cbc   = 0x01,
    Aes256Gcm   = 0x02,
    OtpReserved = 0x03,
    PqReserved1 = 0x04,
    PqReserved2 = 0x05,
    PqReserved3 = 0x06,
    PqReserved4 = 0x07,
}

impl TryFrom<u8> for LinkMode {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Aes128Cbc),
            0x01 => Ok(Self::Aes256Cbc),
            0x02 => Ok(Self::Aes256Gcm),
            0x03 => Ok(Self::OtpReserved),
            0x04 => Ok(Self::PqReserved1),
            0x05 => Ok(Self::PqReserved2),
            0x06 => Ok(Self::PqReserved3),
            0x07 => Ok(Self::PqReserved4),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "LinkMode", value }),
        }
    }
}

impl From<LinkMode> for u8 {
    fn from(v: LinkMode) -> u8 { v as u8 }
}

/// Resource acceptance strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceStrategy {
    AcceptNone = 0x00,
    AcceptApp  = 0x01,
    AcceptAll  = 0x02,
}

impl TryFrom<u8> for ResourceStrategy {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::AcceptNone),
            0x01 => Ok(Self::AcceptApp),
            0x02 => Ok(Self::AcceptAll),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "ResourceStrategy", value }),
        }
    }
}

impl From<ResourceStrategy> for u8 {
    fn from(v: ResourceStrategy) -> u8 { v as u8 }
}

// ── Constants ──

/// X25519 public key (32 bytes) + Ed25519 public key (32 bytes).
pub const ECPUBSIZE: usize = 64;

/// Signalling bytes length.
pub const LINK_MTU_SIZE: usize = 3;

/// Seconds per hop for establishment timeout.
pub const ESTABLISHMENT_TIMEOUT_PER_HOP: f64 = 6.0;

/// Maximum keepalive interval (seconds).
pub const KEEPALIVE_MAX: f64 = 360.0;

/// Minimum keepalive interval (seconds).
pub const KEEPALIVE_MIN: f64 = 5.0;

/// RTT threshold for keepalive scaling.
pub const KEEPALIVE_MAX_RTT: f64 = 1.75;

/// Multiplier for stale_time = keepalive * STALE_FACTOR.
pub const STALE_FACTOR: u8 = 2;

/// Grace period after stale before teardown (seconds).
pub const STALE_GRACE: f64 = 5.0;

/// RTT multiplier for stale→closed timeout.
pub const KEEPALIVE_TIMEOUT_FACTOR: u8 = 4;

/// RTT multiplier for request timeout.
pub const TRAFFIC_TIMEOUT_FACTOR: u8 = 6;

/// 21-bit mask for MTU in signalling bytes.
pub const MTU_BYTEMASK: u32 = 0x1FFFFF;

/// 3-bit mask for mode in signalling bytes (upper bits of first byte).
pub const MODE_BYTEMASK: u8 = 0xE0;

/// Default encryption mode.
pub const MODE_DEFAULT: LinkMode = LinkMode::Aes256Cbc;

/// Currently enabled encryption modes.
pub const ENABLED_MODES: &[LinkMode] = &[LinkMode::Aes256Cbc];

// Re-export Link (uncomment once implemented in link.rs):
// pub use link::Link;
