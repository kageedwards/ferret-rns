//! Proof-of-work stamp generation and verification.
//!
//! Implements the LXStamper algorithm from the LXMF reference:
//! 1. Expand the material into a large "workblock" via repeated HKDF rounds
//! 2. A stamp is a random 32-byte value
//! 3. Validation: `SHA-256(workblock ++ stamp)` interpreted as a big-endian
//!    integer must be ≤ `2^(256 - cost)`, i.e. have `cost` leading zero bits
//!
//! The workblock expansion is intentionally expensive — it's the anti-spam
//! mechanism that makes stamp generation costly while keeping verification
//! (which only needs to expand the workblock once) relatively cheap.

use crate::crypto::hkdf::hkdf;
use crate::identity::Identity;

/// Default workblock expansion rounds (matches LXStamper.WORKBLOCK_EXPAND_ROUNDS).
pub const WORKBLOCK_EXPAND_ROUNDS: usize = 3000;

/// Reduced rounds for name service (faster than LXMF message stamps).
pub const NAME_SERVICE_EXPAND_ROUNDS: usize = 500;

/// Stamp size in bytes (SHA-256 output = 32 bytes).
pub const STAMP_SIZE: usize = 32;

/// Expand material into a workblock via repeated HKDF rounds.
///
/// Each round produces 256 bytes via HKDF with a unique salt derived from
/// `SHA-256(material ++ msgpack(round_number))`. The total workblock size
/// is `expand_rounds * 256` bytes.
///
/// This matches the Python `LXStamper.stamp_workblock()`.
pub fn stamp_workblock(material: &[u8], expand_rounds: usize) -> Vec<u8> {
    let mut workblock = Vec::with_capacity(expand_rounds * 256);
    for n in 0..expand_rounds {
        // Salt = SHA-256(material ++ msgpack(n))
        // msgpack encoding of a small integer: single byte for 0-127, else fixint
        let n_packed = rmp_serde::to_vec(&n).unwrap_or_else(|_| n.to_be_bytes().to_vec());
        let mut salt_input = Vec::with_capacity(material.len() + n_packed.len());
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&n_packed);
        let salt = Identity::full_hash(&salt_input);

        let derived = hkdf(256, material, Some(&salt), None)
            .unwrap_or_else(|_| vec![0u8; 256]);
        workblock.extend_from_slice(&derived);
    }
    workblock
}

/// Compute the stamp value (number of leading zero bits) for a given
/// workblock and stamp.
///
/// Matches Python `LXStamper.stamp_value()`.
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
    let mut combined = Vec::with_capacity(workblock.len() + stamp.len());
    combined.extend_from_slice(workblock);
    combined.extend_from_slice(stamp);
    let hash = Identity::full_hash(&combined);
    leading_zero_bits(&hash)
}

/// Check if a stamp meets the required cost (leading zero bits).
///
/// Matches Python `LXStamper.stamp_valid()`.
pub fn stamp_valid(workblock: &[u8], stamp: &[u8], target_cost: u8) -> bool {
    stamp_value(workblock, stamp) >= target_cost as u32
}

/// Generate a stamp that meets the given cost for the provided material.
///
/// Expands the material into a workblock, then brute-forces random 32-byte
/// stamps until one meets the difficulty target.
///
/// Returns `(stamp, value)` where value is the actual leading zero bits achieved.
pub fn generate_stamp(material: &[u8], cost: u8, expand_rounds: usize) -> (Vec<u8>, u32) {
    let workblock = stamp_workblock(material, expand_rounds);

    loop {
        let mut stamp = [0u8; STAMP_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut stamp);

        if stamp_valid(&workblock, &stamp, cost) {
            let value = stamp_value(&workblock, &stamp);
            return (stamp.to_vec(), value);
        }
    }
}

/// Verify a stamp against material with the full workblock expansion.
///
/// This is the high-level verification function that expands the workblock
/// and checks the stamp in one call.
pub fn verify_stamp(material: &[u8], stamp: &[u8], cost: u8, expand_rounds: usize) -> bool {
    let workblock = stamp_workblock(material, expand_rounds);
    stamp_valid(&workblock, stamp, cost)
}

/// Count the number of leading zero bits in a byte slice.
fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in data {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workblock_deterministic() {
        let material = b"test material";
        let wb1 = stamp_workblock(material, 10);
        let wb2 = stamp_workblock(material, 10);
        assert_eq!(wb1, wb2, "workblock must be deterministic");
        assert_eq!(wb1.len(), 10 * 256);
    }

    #[test]
    fn test_stamp_roundtrip() {
        let material = b"test data";
        let cost = 4; // low cost for fast test
        let (stamp, value) = generate_stamp(material, cost, 10); // few rounds for speed
        assert!(value >= cost as u32);
        assert!(verify_stamp(material, &stamp, cost, 10));
    }

    #[test]
    fn test_stamp_value_zero_cost() {
        // Any stamp should pass cost 0
        let wb = stamp_workblock(b"x", 1);
        assert!(stamp_valid(&wb, &[0u8; 32], 0));
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x00]), 8);
    }
}
