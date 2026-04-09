use proptest::prelude::*;

// Feature: ferret-crypto-foundation, Property 6: SHA Hash Output Size Invariant
// **Validates: Requirements 4.1, 4.2**
proptest! {
    #[test]
    fn sha256_produces_32_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let hash = ferret_rns::crypto::hashes::sha256(&data);
        prop_assert_eq!(hash.len(), 32);
    }

    #[test]
    fn sha512_produces_64_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let hash = ferret_rns::crypto::hashes::sha512(&data);
        prop_assert_eq!(hash.len(), 64);
    }
}

// Feature: ferret-crypto-foundation, Property 7: HMAC-SHA256 Output Invariant
// **Validates: Requirements 5.1, 5.4**
proptest! {
    #[test]
    fn hmac_sha256_produces_32_bytes(
        key in proptest::collection::vec(any::<u8>(), 0..256),
        data in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let tag = ferret_rns::crypto::hmac::hmac_sha256(&key, &data);
        prop_assert_eq!(tag.len(), 32);
    }
}

// Feature: ferret-crypto-foundation, Property 11: PKCS7 Padding Round-Trip
// **Validates: Requirements 8.1, 8.3, 8.5, 8.6**
proptest! {
    #[test]
    fn pkcs7_pad_unpad_round_trip(
        data in proptest::collection::vec(any::<u8>(), 0..512),
        block_size in 1u8..=255u8,
    ) {
        let bs = block_size as usize;
        let padded = ferret_rns::crypto::pkcs7::pad(&data, bs);
        let unpadded = ferret_rns::crypto::pkcs7::unpad(&padded, bs).unwrap();
        prop_assert_eq!(&unpadded, &data);

        // Padded length is always a multiple of block_size
        prop_assert_eq!(padded.len() % bs, 0);

        // When input is already aligned, padded length == input.len() + block_size
        if !data.is_empty() && data.len() % bs == 0 {
            prop_assert_eq!(padded.len(), data.len() + bs);
        }
    }
}
