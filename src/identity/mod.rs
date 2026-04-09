pub mod identity;
pub mod store;
pub mod ratchet;
pub mod announce;

/// Derived key length for HKDF in identity encryption (bytes; 512 / 8).
pub const DERIVED_KEY_LENGTH: usize = 64;

/// Ratchet expiry time in seconds (30 days).
pub const RATCHET_EXPIRY: u64 = 2_592_000;

// Re-exports (uncomment as types are implemented):
// pub use identity::Identity;
// pub use store::IdentityStore;
// pub use ratchet::RatchetStore;
// pub use announce::{AnnounceData, validate_announce};
