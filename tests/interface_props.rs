// Property-based tests for Interfaces module
// Feature: ferret-interfaces

use proptest::prelude::*;

use ferret_rns::interfaces::hdlc_codec;

// ── Property 1: HDLC encode/decode round-trip ──
// For any byte sequence of length 0 to HW_MTU, encoding then decoding
// produces the original byte sequence.
// **Validates: Requirements 1.2, 1.3, 1.4, 1.5**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn hdlc_encode_decode_round_trip(
        data in prop::collection::vec(any::<u8>(), 0..=1064),
    ) {
        let encoded = hdlc_codec::encode(&data);

        // Encoded frame must start and end with FLAG
        prop_assert_eq!(encoded[0], hdlc_codec::FLAG);
        prop_assert_eq!(*encoded.last().unwrap(), hdlc_codec::FLAG);

        // Strip FLAG delimiters, then decode the escaped content
        let inner = &encoded[1..encoded.len() - 1];
        let decoded = hdlc_codec::decode(inner);

        prop_assert_eq!(decoded, data);
    }
}
