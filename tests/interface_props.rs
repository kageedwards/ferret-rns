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

use ferret_rns::interfaces::kiss_codec::{self, KissDecoder};

// ── Property 3: KISS encode/decode round-trip ──
// For any byte sequence of length 0 to HW_MTU, encoding as CMD_DATA then
// decoding produces the original byte sequence.
// **Validates: Requirements 2.2, 2.3, 2.4, 2.5**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn kiss_encode_decode_round_trip(
        data in prop::collection::vec(any::<u8>(), 0..=1064),
    ) {
        let encoded = kiss_codec::encode_data(&data);

        // Encoded frame must start and end with FEND
        prop_assert_eq!(encoded[0], kiss_codec::FEND);
        prop_assert_eq!(*encoded.last().unwrap(), kiss_codec::FEND);

        // Feed through streaming decoder
        let mut decoder = KissDecoder::new(1064);
        let frames = decoder.feed(&encoded);

        // Exactly one frame returned
        prop_assert_eq!(frames.len(), 1, "expected 1 frame, got {}", frames.len());

        // Command is CMD_DATA
        prop_assert_eq!(frames[0].command, kiss_codec::CMD_DATA);

        // Decoded data matches original input
        prop_assert_eq!(&frames[0].data, &data);
    }
}


// ── Property 4: KISS streaming decoder correctness ──
// For any sequence of N payloads (each ≤ HW_MTU), concatenating KISS
// CMD_DATA-encoded frames and feeding through KissDecoder yields exactly
// N decoded frames with command CMD_DATA matching originals; oversized
// frames are discarded.
// **Validates: Requirements 2.5, 2.6**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn kiss_streaming_decoder_correctness(
        payloads in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..=200),
            1..=10,
        ),
    ) {
        let hw_mtu: usize = 150;

        // Encode each payload as a KISS CMD_DATA frame and concatenate
        let stream: Vec<u8> = payloads
            .iter()
            .flat_map(|p| kiss_codec::encode_data(p))
            .collect();

        // Feed the entire stream through the decoder
        let mut decoder = KissDecoder::new(hw_mtu);
        let decoded = decoder.feed(&stream);

        // Filter originals to only those within MTU
        let expected: Vec<&Vec<u8>> = payloads
            .iter()
            .filter(|p| p.len() <= hw_mtu)
            .collect();

        // Same count
        prop_assert_eq!(
            decoded.len(),
            expected.len(),
            "decoded frame count ({}) != expected ({})",
            decoded.len(),
            expected.len(),
        );

        // Same content, same order, all CMD_DATA
        for (i, (dec, exp)) in decoded.iter().zip(expected.iter()).enumerate() {
            prop_assert_eq!(
                dec.command,
                kiss_codec::CMD_DATA,
                "frame {} command is not CMD_DATA",
                i,
            );
            prop_assert_eq!(
                &dec.data,
                *exp,
                "frame {} data mismatch",
                i,
            );
        }
    }
}


use ferret_rns::interfaces::ifac_processor::IfacState;

// ── Property 5: IFAC derivation determinism ──
// For any pair of (ifac_netname, ifac_netkey) strings, deriving IFAC state
// twice produces identical ifac_key, ifac_identity public key bytes, and
// ifac_signature.
// **Validates: Requirements 3.1, 3.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn ifac_derivation_determinism(
        netname in ".*",
        netkey in ".*",
        ifac_size in 1usize..=32,
    ) {
        let state1 = IfacState::derive(ifac_size, Some(&netname), Some(&netkey))
            .expect("first derivation should succeed");
        let state2 = IfacState::derive(ifac_size, Some(&netname), Some(&netkey))
            .expect("second derivation should succeed");

        // ifac_key must be identical
        prop_assert_eq!(&state1.ifac_key, &state2.ifac_key, "ifac_key mismatch");

        // ifac_identity public key bytes must be identical
        let pub1 = state1.ifac_identity.get_public_key()
            .expect("get_public_key should succeed for state1");
        let pub2 = state2.ifac_identity.get_public_key()
            .expect("get_public_key should succeed for state2");
        prop_assert_eq!(pub1, pub2, "ifac_identity public key mismatch");

        // ifac_signature must be identical
        prop_assert_eq!(state1.ifac_signature, state2.ifac_signature, "ifac_signature mismatch");
    }
}
