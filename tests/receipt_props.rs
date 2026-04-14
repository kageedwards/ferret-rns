use proptest::prelude::*;

use ferret_rns::identity::Identity;
use ferret_rns::packet::receipt::{PacketReceipt, ReceiptStatus, EXPL_LENGTH, IMPL_LENGTH};

/// Helper: create an Identity and a PacketReceipt wired to that identity's public key.
/// Returns (identity, receipt) where the receipt's hash is the provided `packet_hash`.
fn make_receipt(packet_hash: [u8; 32]) -> (Identity, PacketReceipt) {
    let id = Identity::new();
    let pub_key = id.get_public_key().unwrap();
    let truncated: [u8; 16] = packet_hash[..16].try_into().unwrap();
    let receipt = PacketReceipt::new(packet_hash, truncated, 30.0, Some(pub_key));
    (id, receipt)
}

// ============================================================================
// Feature: ferret-test-coverage, Property 7: Valid proof acceptance
// **Validates: Requirements 4.1, 4.2, 4.7**
// ============================================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn valid_proof_acceptance(hash_bytes in prop::array::uniform32(any::<u8>())) {
        let (id, mut receipt) = make_receipt(hash_bytes);

        // --- Explicit proof: hash(32) + signature(64) = 96 bytes ---
        let signature = id.sign(&hash_bytes).unwrap();
        let mut explicit_proof = Vec::with_capacity(EXPL_LENGTH);
        explicit_proof.extend_from_slice(&hash_bytes);
        explicit_proof.extend_from_slice(&signature);
        prop_assert_eq!(explicit_proof.len(), EXPL_LENGTH);

        let accepted = receipt.validate_proof(&explicit_proof);
        prop_assert!(accepted, "explicit proof should be accepted");
        prop_assert_eq!(receipt.status, ReceiptStatus::Delivered);
        prop_assert!(receipt.proved, "proved should be true after explicit proof");
        prop_assert!(receipt.concluded_at.is_some(), "concluded_at should be set");
        let rtt = receipt.get_rtt();
        prop_assert!(rtt.is_some(), "get_rtt() should return Some");
        prop_assert!(rtt.unwrap() >= 0.0, "RTT should be non-negative");

        // --- Implicit proof: signature(64) only ---
        // Need a fresh receipt for the implicit test
        let pub_key = id.get_public_key().unwrap();
        let truncated: [u8; 16] = hash_bytes[..16].try_into().unwrap();
        let mut receipt2 = PacketReceipt::new(hash_bytes, truncated, 30.0, Some(pub_key));

        let implicit_proof = signature.to_vec();
        prop_assert_eq!(implicit_proof.len(), IMPL_LENGTH);

        let accepted2 = receipt2.validate_proof(&implicit_proof);
        prop_assert!(accepted2, "implicit proof should be accepted");
        prop_assert_eq!(receipt2.status, ReceiptStatus::Delivered);
        prop_assert!(receipt2.proved, "proved should be true after implicit proof");
        prop_assert!(receipt2.concluded_at.is_some(), "concluded_at should be set");
        let rtt2 = receipt2.get_rtt();
        prop_assert!(rtt2.is_some(), "get_rtt() should return Some");
        prop_assert!(rtt2.unwrap() >= 0.0, "RTT should be non-negative");
    }
}

// ============================================================================
// Feature: ferret-test-coverage, Property 8: Invalid proof rejection
// **Validates: Requirements 4.3, 4.4**
// ============================================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn invalid_proof_wrong_hash(
        hash_bytes in prop::array::uniform32(any::<u8>()),
        wrong_byte in 0u8..=254u8,
    ) {
        let (id, mut receipt) = make_receipt(hash_bytes);

        // Build explicit proof with a wrong hash (flip first byte)
        let signature = id.sign(&hash_bytes).unwrap();
        let mut wrong_hash = hash_bytes;
        wrong_hash[0] = wrong_hash[0].wrapping_add(1).max(wrong_byte.wrapping_add(1));
        // Ensure wrong_hash differs from hash_bytes
        if wrong_hash == hash_bytes {
            wrong_hash[0] = wrong_hash[0].wrapping_add(1);
        }

        let mut bad_proof = Vec::with_capacity(EXPL_LENGTH);
        bad_proof.extend_from_slice(&wrong_hash);
        bad_proof.extend_from_slice(&signature);

        let accepted = receipt.validate_proof(&bad_proof);
        prop_assert!(!accepted, "proof with wrong hash should be rejected");
        prop_assert_eq!(receipt.status, ReceiptStatus::Sent, "status should remain Sent");
        prop_assert!(!receipt.proved, "proved should remain false");
    }

    #[test]
    fn invalid_proof_bad_signature(hash_bytes in prop::array::uniform32(any::<u8>())) {
        let (_id, mut receipt) = make_receipt(hash_bytes);

        // Use a different identity to produce an invalid signature
        let other_id = Identity::new();
        let bad_sig = other_id.sign(&hash_bytes).unwrap();

        // Explicit proof with correct hash but wrong signature
        let mut bad_explicit = Vec::with_capacity(EXPL_LENGTH);
        bad_explicit.extend_from_slice(&hash_bytes);
        bad_explicit.extend_from_slice(&bad_sig);

        let accepted = receipt.validate_proof(&bad_explicit);
        prop_assert!(!accepted, "explicit proof with bad signature should be rejected");
        prop_assert_eq!(receipt.status, ReceiptStatus::Sent);
        prop_assert!(!receipt.proved);

        // Implicit proof with wrong signature
        let bad_implicit = bad_sig.to_vec();
        let accepted2 = receipt.validate_proof(&bad_implicit);
        prop_assert!(!accepted2, "implicit proof with bad signature should be rejected");
        prop_assert_eq!(receipt.status, ReceiptStatus::Sent);
        prop_assert!(!receipt.proved);
    }
}

// ============================================================================
// Unit tests for PacketReceipt timeout behavior
// Requirements: 4.5, 4.6
// ============================================================================

#[test]
fn check_timeout_transitions_to_failed() {
    let hash = [0xABu8; 32];
    let truncated: [u8; 16] = hash[..16].try_into().unwrap();
    // Create receipt with a very small timeout so it's already expired
    let mut receipt = PacketReceipt::new(hash, truncated, 0.0, None);
    // sent_at is set to now, timeout=0.0 means sent_at + 0.0 < now (after any delay)
    // Force sent_at into the past to guarantee timeout
    receipt.sent_at -= 1.0;

    receipt.check_timeout();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Failed,
        "check_timeout should transition to Failed after elapsed time"
    );
    assert!(
        receipt.concluded_at.is_some(),
        "concluded_at should be set after timeout"
    );
}

#[test]
fn check_timeout_with_negative_one_transitions_to_culled() {
    let hash = [0xCDu8; 32];
    let truncated: [u8; 16] = hash[..16].try_into().unwrap();
    let mut receipt = PacketReceipt::new(hash, truncated, -1.0, None);
    // Force sent_at into the past so now > sent_at + timeout (-1.0)
    receipt.sent_at -= 1.0;

    receipt.check_timeout();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Culled,
        "check_timeout with timeout=-1.0 should transition to Culled"
    );
    assert!(
        receipt.concluded_at.is_some(),
        "concluded_at should be set after culling"
    );
}
