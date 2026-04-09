pub mod destination;
pub mod announce;
pub mod ratchets;
pub mod handlers;

/// Default number of retained ratchet keys per destination.
pub const RATCHET_COUNT: usize = 512;

/// Minimum seconds between ratchet rotations.
pub const RATCHET_INTERVAL: u64 = 1800;

/// Path response tag expiry window (seconds).
pub const PR_TAG_WINDOW: u64 = 30;

/// Request policy: deny all.
pub const ALLOW_NONE: u8 = 0x00;

/// Request policy: allow all.
pub const ALLOW_ALL: u8 = 0x01;

/// Request policy: allow listed identities only.
pub const ALLOW_LIST: u8 = 0x02;

// Re-exports (uncomment as types are implemented):
// pub use destination::Destination;
