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

use ferret_rns::interfaces::hdlc_codec::HdlcDecoder;

// ── Property 2: HDLC streaming decoder correctness ──
// For any sequence of N payloads (each ≤ HW_MTU), concatenating HDLC-encoded
// frames and feeding through HdlcDecoder yields exactly N decoded frames
// matching originals; oversized frames are discarded.
// **Validates: Requirements 1.5, 1.6**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn hdlc_streaming_decoder_correctness(
        payloads in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..=200),
            1..=10,
        ),
    ) {
        let hw_mtu: usize = 150;

        // Encode each payload and concatenate into a single byte stream
        let stream: Vec<u8> = payloads
            .iter()
            .map(|p| hdlc_codec::encode(p))
            .flatten()
            .collect();

        // Feed the entire stream through the decoder
        let mut decoder = HdlcDecoder::new(hw_mtu);
        let decoded = decoder.feed(&stream);

        // Filter originals to only those within MTU.
        // Empty payloads are excluded because HDLC encodes them as [FLAG, FLAG]
        // which the streaming decoder treats as inter-frame fill (standard behavior).
        let expected: Vec<&Vec<u8>> = payloads
            .iter()
            .filter(|p| !p.is_empty() && p.len() <= hw_mtu)
            .collect();

        // Same count
        prop_assert_eq!(
            decoded.len(),
            expected.len(),
            "decoded frame count ({}) != expected ({})",
            decoded.len(),
            expected.len(),
        );

        // Same content in same order
        for (i, (dec, exp)) in decoded.iter().zip(expected.iter()).enumerate() {
            prop_assert_eq!(
                dec,
                *exp,
                "frame {} mismatch",
                i,
            );
        }
    }
}
