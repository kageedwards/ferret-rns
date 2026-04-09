/// Maximum Transmission Unit for Reticulum packets (bytes).
pub const MTU: usize = 500;

/// Truncated hash length used for addressing (bits).
pub const TRUNCATED_HASHLENGTH: usize = 128;

/// Minimum packet header size: 2 + 1 + (TRUNCATED_HASHLENGTH / 8) * 1 (bytes).
pub const HEADER_MINSIZE: usize = 19;

/// Maximum packet header size: 2 + 1 + (TRUNCATED_HASHLENGTH / 8) * 2 (bytes).
pub const HEADER_MAXSIZE: usize = 35;

/// Minimum IFAC field size (bytes).
pub const IFAC_MIN_SIZE: usize = 1;

/// Maximum Data Unit: MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE (bytes).
pub const MDU: usize = 464;
