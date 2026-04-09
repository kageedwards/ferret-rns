// Feature: ferret-crypto-foundation, Property 14: MessagePack Serialization Round-Trip

use ferret_rns::util::msgpack;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 16.1, 16.2, 16.4**
    #[test]
    fn msgpack_roundtrip_i64(value: i64) {
        let bytes = msgpack::serialize(&value).unwrap();
        let decoded: i64 = msgpack::deserialize(&bytes).unwrap();
        prop_assert_eq!(decoded, value);
    }

    /// **Validates: Requirements 16.1, 16.2, 16.4**
    #[test]
    fn msgpack_roundtrip_string(value in "[a-zA-Z0-9]{0,256}") {
        let bytes = msgpack::serialize(&value).unwrap();
        let decoded: String = msgpack::deserialize(&bytes).unwrap();
        prop_assert_eq!(decoded, value);
    }

    /// **Validates: Requirements 16.1, 16.2, 16.4**
    #[test]
    fn msgpack_roundtrip_vec_u8(value in proptest::collection::vec(any::<u8>(), 0..512)) {
        let bytes = msgpack::serialize(&value).unwrap();
        let decoded: Vec<u8> = msgpack::deserialize(&bytes).unwrap();
        prop_assert_eq!(decoded, value);
    }
}

// Feature: ferret-crypto-foundation, Property 15: Hex Formatting Structural Invariants

use ferret_rns::util::hex;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 17.1, 17.2, 17.3**
    #[test]
    fn hex_formatting_lengths(data in proptest::collection::vec(any::<u8>(), 1..256)) {
        let n = data.len();

        let hr = hex::hexrep(&data);
        prop_assert_eq!(hr.len(), 3 * n - 1, "hexrep length mismatch for N={}", n);

        let hnd = hex::hexrep_no_delimit(&data);
        prop_assert_eq!(hnd.len(), 2 * n, "hexrep_no_delimit length mismatch for N={}", n);

        let phr = hex::prettyhexrep(&data);
        prop_assert_eq!(phr.len(), 2 * n + 2, "prettyhexrep length mismatch for N={}", n);
    }

    /// **Validates: Requirements 17.1, 17.2, 17.3**
    #[test]
    fn hex_formatting_character_sets(data in proptest::collection::vec(any::<u8>(), 1..256)) {
        let hr = hex::hexrep(&data);
        prop_assert!(hr.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
            "hexrep contains invalid chars: {}", hr);

        let hnd = hex::hexrep_no_delimit(&data);
        prop_assert!(hnd.chars().all(|c| c.is_ascii_hexdigit()),
            "hexrep_no_delimit contains non-hex chars: {}", hnd);

        let phr = hex::prettyhexrep(&data);
        prop_assert!(phr.starts_with('<'), "prettyhexrep doesn't start with '<': {}", phr);
        prop_assert!(phr.ends_with('>'), "prettyhexrep doesn't end with '>': {}", phr);
    }
}
