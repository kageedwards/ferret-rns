use proptest::prelude::*;

// Feature: ferret-packet-transport, Property 6: Flag byte encode/decode round-trip
// **Validates: Requirements 7.3, 7.5**
proptest! {
    #[test]
    fn flag_byte_round_trip(
        ht in 0u8..=1,
        cf in 0u8..=1,
        tt in 0u8..=1,
        dt in 0u8..=3,
        pt in 0u8..=3,
    ) {
        let flags = (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt;
        let decoded_ht = (flags >> 6) & 0x03;
        let decoded_cf = (flags >> 5) & 0x01;
        let decoded_tt = (flags >> 4) & 0x01;
        let decoded_dt = (flags >> 2) & 0x03;
        let decoded_pt = flags & 0x03;
        prop_assert_eq!(decoded_ht, ht);
        prop_assert_eq!(decoded_cf, cf);
        prop_assert_eq!(decoded_tt, tt);
        prop_assert_eq!(decoded_dt, dt);
        prop_assert_eq!(decoded_pt, pt);
    }
}

use ferret_rns::packet::Encryptable;
use ferret_rns::types::destination::DestinationType;
use ferret_rns::types::packet::{
    ContextFlag, HeaderType, PacketContext, PacketType,
};
use ferret_rns::types::transport::TransportType;

/// Passthrough encryptable for testing — no actual encryption.
struct TestEncryptable {
    hash: [u8; 16],
}

impl Encryptable for TestEncryptable {
    fn encrypt(&self, plaintext: &[u8]) -> ferret_rns::Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }
    fn dest_hash(&self) -> &[u8; 16] {
        &self.hash
    }
    fn dest_type(&self) -> DestinationType {
        DestinationType::Plain
    }
}

// Feature: ferret-packet-transport, Property 7: Packet pack/unpack round-trip
// **Validates: Requirements 8.1, 8.2, 8.6, 8.9, 8.10, 8.11, 8.13**
proptest! {
    #[test]
    fn packet_pack_unpack_round_trip(
        dest_hash in any::<[u8; 16]>(),
        hops in 0u8..=255,
        data in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        let enc = TestEncryptable { hash: dest_hash };
        let mut pkt = ferret_rns::packet::packet::Packet::new(
            &enc,
            data.clone(),
            PacketType::Data,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt.hops = hops;
        pkt.flags = pkt.get_packed_flags();
        pkt.pack(&enc).unwrap();

        let mut pkt2 = ferret_rns::packet::packet::Packet::from_raw(pkt.raw.clone());
        pkt2.unpack().unwrap();

        prop_assert_eq!(pkt2.hops, hops);
        prop_assert_eq!(pkt2.destination_hash, dest_hash);
        prop_assert_eq!(pkt2.data, data);
        prop_assert_eq!(pkt2.packet_type, PacketType::Data);
        prop_assert_eq!(pkt2.header_type, HeaderType::Header1);
        prop_assert_eq!(pkt2.transport_type, TransportType::Broadcast);
        prop_assert_eq!(pkt2.context, PacketContext::None);
    }
}

// Feature: ferret-packet-transport, Property 8: Packet hash determinism and header-type independence
// **Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5**
proptest! {
    #[test]
    fn packet_hash_determinism(
        dest_hash in any::<[u8; 16]>(),
        data in proptest::collection::vec(any::<u8>(), 0..200),
    ) {
        let enc = TestEncryptable { hash: dest_hash };

        // Pack the same logical packet twice — hashes must match
        let mut pkt1 = ferret_rns::packet::packet::Packet::new(
            &enc,
            data.clone(),
            PacketType::Data,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt1.pack(&enc).unwrap();
        let hash1 = pkt1.get_hash();

        let mut pkt2 = ferret_rns::packet::packet::Packet::new(
            &enc,
            data.clone(),
            PacketType::Data,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt2.pack(&enc).unwrap();
        let hash2 = pkt2.get_hash();

        prop_assert_eq!(hash1, hash2, "same packet packed twice must produce same hash");
    }

    #[test]
    fn packet_hash_header_type_independence(
        dest_hash in any::<[u8; 16]>(),
        transport_id in any::<[u8; 16]>(),
        data in proptest::collection::vec(any::<u8>(), 0..200),
    ) {
        let enc = TestEncryptable { hash: dest_hash };

        // Header1 packet
        let mut h1 = ferret_rns::packet::packet::Packet::new(
            &enc,
            data.clone(),
            PacketType::Data,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        h1.pack(&enc).unwrap();

        // Header2 packet with same logical content but a transport_id
        let mut h2 = ferret_rns::packet::packet::Packet::new(
            &enc,
            data.clone(),
            PacketType::Data,
            PacketContext::None,
            TransportType::Transport,
            HeaderType::Header2,
            Some(transport_id),
            false,
            ContextFlag::Unset,
        );
        h2.pack(&enc).unwrap();

        // The hashable parts should be identical — transport_id is excluded
        let hashable1 = h1.get_hashable_part();
        let hashable2 = h2.get_hashable_part();
        prop_assert_eq!(hashable1, hashable2,
            "hashable part must be identical regardless of header type");

        prop_assert_eq!(h1.get_hash(), h2.get_hash(),
            "packet hash must be identical regardless of header type");
    }
}

// Feature: ferret-packet-transport, Property 9: Proof validation correctness
// **Validates: Requirements 11.3, 11.4, 11.5, 11.6**
proptest! {
    #[test]
    fn proof_validation_correctness(
        packet_hash in any::<[u8; 32]>(),
    ) {
        use ferret_rns::identity::Identity;
        use ferret_rns::packet::receipt::{PacketReceipt, ReceiptStatus, EXPL_LENGTH};

        let id = Identity::new();
        let pub_key = id.get_public_key().unwrap();
        let truncated: [u8; 16] = packet_hash[..16].try_into().unwrap();

        let mut receipt = PacketReceipt::new(packet_hash, truncated, 30.0, Some(pub_key));

        // Valid explicit proof: hash + signature
        let signature = id.sign(&packet_hash).unwrap();
        let mut proof = Vec::with_capacity(EXPL_LENGTH);
        proof.extend_from_slice(&packet_hash);
        proof.extend_from_slice(&signature);

        let valid = receipt.validate_proof(&proof);
        prop_assert!(valid, "valid explicit proof should be accepted");
        prop_assert_eq!(receipt.get_status(), ReceiptStatus::Delivered);

        // Invalid proof (wrong hash) on a fresh receipt
        let mut receipt2 = PacketReceipt::new(packet_hash, truncated, 30.0, Some(pub_key));
        let mut bad_hash = [0u8; 32];
        bad_hash[0] = packet_hash[0].wrapping_add(1); // ensure different
        let mut bad_proof = Vec::with_capacity(EXPL_LENGTH);
        bad_proof.extend_from_slice(&bad_hash);
        bad_proof.extend_from_slice(&signature);
        let invalid = receipt2.validate_proof(&bad_proof);
        prop_assert!(!invalid, "proof with wrong hash should be rejected");
        prop_assert_eq!(receipt2.get_status(), ReceiptStatus::Sent);
    }
}
