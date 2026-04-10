// Property-based tests for Link module
// Feature: ferret-link-channel

use proptest::prelude::*;

use ferret_rns::link::LinkMode;
use ferret_rns::link::handshake::{signalling_bytes, mtu_from_signalling, mode_from_signalling};

// ── Property 1: Signalling bytes encode/decode round trip ──
// For any valid MTU (0..2^21) and any enabled LinkMode, encode then decode
// produces original values.
// **Validates: Requirements 7.1**

proptest! {
    #[test]
    fn signalling_bytes_round_trip(
        mtu in 0u32..2_097_152u32,
    ) {
        // Only test with enabled modes (currently just Aes256Cbc)
        let mode = LinkMode::Aes256Cbc;
        let encoded = signalling_bytes(mtu, mode).unwrap();
        let decoded_mtu = mtu_from_signalling(&encoded);
        let decoded_mode = mode_from_signalling(&encoded).unwrap();
        prop_assert_eq!(decoded_mtu, mtu);
        prop_assert_eq!(decoded_mode, mode);
    }
}

// ── Property 12: Link ID determinism ──
// For any pair of X25519 and Ed25519 public keys, the link_id computed from
// a LinkRequest packet's hashable part is deterministic.
// **Validates: Requirements 1.3**

proptest! {
    #[test]
    fn link_id_determinism(
        x25519_pub in prop::array::uniform32(any::<u8>()),
        ed25519_pub in prop::array::uniform32(any::<u8>()),
    ) {
        use ferret_rns::packet::packet::Packet;
        use ferret_rns::packet::proof::ProofDestination;
        use ferret_rns::types::packet::{PacketType, PacketContext, ContextFlag, HeaderType};
        use ferret_rns::types::transport::TransportType;
        use ferret_rns::link::link::link_id_from_packet;

        // Build LinkRequest data: x25519_pub(32) + ed25519_pub(32)
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&x25519_pub);
        data.extend_from_slice(&ed25519_pub);

        let dest = ProofDestination::new([0u8; 16]);

        // First computation
        let mut pkt1 = Packet::new(
            &dest,
            data.clone(),
            PacketType::LinkRequest,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt1.pack(&dest).unwrap();
        let id1 = link_id_from_packet(&pkt1, data.len());

        // Second computation with same keys
        let mut pkt2 = Packet::new(
            &dest,
            data.clone(),
            PacketType::LinkRequest,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt2.pack(&dest).unwrap();
        let id2 = link_id_from_packet(&pkt2, data.len());

        prop_assert_eq!(id1, id2);
    }
}

// ── Property 4: Link encrypt/decrypt round trip ──
// For any plaintext (1..400 bytes) and valid 64-byte derived key,
// encrypt then decrypt produces original plaintext.
// **Validates: Requirements 3.1, 3.2**

proptest! {
    #[test]
    fn link_encrypt_decrypt_round_trip(
        plaintext in prop::collection::vec(any::<u8>(), 1..400),
        derived_key in prop::collection::vec(any::<u8>(), 64..=64),
    ) {
        use ferret_rns::crypto::token::Token;

        let token = Token::new(&derived_key).unwrap();
        let ciphertext = token.encrypt(&plaintext);
        let decrypted = token.decrypt(&ciphertext).unwrap();
        prop_assert_eq!(&decrypted, &plaintext);
    }
}
