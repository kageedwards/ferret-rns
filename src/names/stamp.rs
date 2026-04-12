//! Proof-of-work stamp generation and verification for anti-spam.

use crate::crypto::hashes::sha256;

/// Generate a proof-of-work stamp that meets the given difficulty.
///
/// The stamp is a byte sequence such that `SHA-256(data ++ stamp)` has
/// at least `difficulty` leading zero bits.
pub fn generate_stamp(data: &[u8], difficulty: u8) -> Vec<u8> {
    let mut nonce: u64 = 0;
    loop {
        let stamp = nonce.to_be_bytes().to_vec();
        if verify_stamp(data, &stamp, difficulty) {
            return stamp;
        }
        nonce += 1;
    }
}

/// Verify that a stamp meets the required difficulty.
///
/// Returns true if `SHA-256(data ++ stamp)` has at least `difficulty`
/// leading zero bits.
pub fn verify_stamp(data: &[u8], stamp: &[u8], difficulty: u8) -> bool {
    let mut combined = Vec::with_capacity(data.len() + stamp.len());
    combined.extend_from_slice(data);
    combined.extend_from_slice(stamp);
    let hash = sha256(&combined);
    leading_zero_bits(&hash) >= difficulty as u32
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
    fn test_stamp_roundtrip() {
        let data = b"test data";
        let difficulty = 8; // 8 leading zero bits = first byte is 0
        let stamp = generate_stamp(data, difficulty);
        assert!(verify_stamp(data, &stamp, difficulty));
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x00]), 8);
    }
}
