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
