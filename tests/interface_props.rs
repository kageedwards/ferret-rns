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

use ferret_rns::interfaces::ifac_processor::{ifac_mask, ifac_unmask, IFAC_FLAG};

// ── Property 6: IFAC mask/unmask round-trip ──
// For any raw Reticulum packet (≥ 2 bytes, ≤ MTU) and valid IFAC configuration
// (ifac_size in 1..64), masking then unmasking produces the original raw packet.
// **Validates: Requirements 3.3, 3.4, 3.5, 3.6, 3.10**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn ifac_mask_unmask_round_trip(
        raw in prop::collection::vec(any::<u8>(), 2..=500),
        ifac_size in 1usize..=32,
        netname in ".*",
        netkey in ".*",
    ) {
        let state = IfacState::derive(ifac_size, Some(&netname), Some(&netkey))
            .expect("IFAC derivation should succeed");

        // Clear the IFAC flag on the first byte to simulate a normal outbound packet
        let mut raw = raw;
        raw[0] &= !IFAC_FLAG;

        let masked = ifac_mask(&raw, &state)
            .expect("ifac_mask should succeed");

        // The masked packet must have the IFAC flag set
        prop_assert!(masked[0] & IFAC_FLAG == IFAC_FLAG, "IFAC flag must be set on masked packet");

        // The masked packet should be larger by ifac_size bytes
        prop_assert_eq!(masked.len(), raw.len() + ifac_size, "masked length mismatch");

        let unmasked = ifac_unmask(&masked, &state)
            .expect("ifac_unmask should succeed");

        // Unmasking must succeed and produce the original raw packet
        prop_assert!(unmasked.is_some(), "ifac_unmask returned None — round-trip failed");
        let unmasked = unmasked.unwrap();
        prop_assert_eq!(unmasked, raw, "unmasked packet does not match original");
    }
}


// ── Property 7: IFAC corruption detection ──
// For any raw packet and valid IFAC configuration, flipping any single bit
// in the IFAC tag region of the masked output causes unmasking to return None.
// The IFAC tag (bytes 2..2+ifac_size) is the authentication code that gets
// verified during unmasking — corrupting it must always be detected.
// **Validates: Requirements 3.7**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn ifac_corruption_detection(
        raw in prop::collection::vec(any::<u8>(), 4..=200),
        ifac_size in 2usize..=16,
        netname in "[a-z]{1,8}",
        netkey in "[a-z]{1,8}",
        bit_seed in any::<usize>(),
    ) {
        let state = IfacState::derive(ifac_size, Some(&netname), Some(&netkey))
            .expect("IFAC derivation should succeed");

        // Clear the IFAC flag on the first byte to simulate a normal outbound packet
        let mut raw = raw;
        raw[0] &= !IFAC_FLAG;

        let masked = ifac_mask(&raw, &state)
            .expect("ifac_mask should succeed");

        // Flip a bit within the IFAC tag region (bytes 2..2+ifac_size)
        let tag_bits = ifac_size * 8;
        let bit_position = bit_seed % tag_bits;
        let byte_idx = 2 + bit_position / 8;
        let bit_idx = bit_position % 8;

        let mut corrupted = masked.clone();
        corrupted[byte_idx] ^= 1 << bit_idx;

        // Corrupted IFAC tag should not unmask successfully
        let result = ifac_unmask(&corrupted, &state)
            .expect("ifac_unmask should not return Err");

        prop_assert!(
            result.is_none(),
            "Corruption at tag bit {} (byte {} bit {}) was not detected",
            bit_position,
            byte_idx,
            bit_idx,
        );
    }
}


use ferret_rns::interfaces::base::Interface;

// ── Property 8: Interface hash determinism ──
// For any interface display string, computing the interface hash twice
// produces the same 32-byte result.
// **Validates: Requirements 4.5**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn interface_hash_determinism(
        display_string in ".*",
    ) {
        let hash1 = Interface::compute_hash(&display_string);
        let hash2 = Interface::compute_hash(&display_string);

        prop_assert_eq!(hash1.len(), 32, "hash must be 32 bytes");
        prop_assert_eq!(hash2.len(), 32, "hash must be 32 bytes");
        prop_assert_eq!(hash1, hash2, "hashing the same string twice must produce identical results");
    }
}


// ── Property 9: MTU auto-configuration correctness ──
// For any bitrate value, the auto-configured HW_MTU matches the expected
// tier from the reference table.
// **Validates: Requirements 4.7**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn mtu_auto_configuration_correctness(
        bitrate in 0u64..=2_000_000_000,
    ) {
        let mut interface = Interface::new("test".into(), None);
        interface.bitrate = bitrate;
        interface.autoconfigure_mtu = true;
        interface.optimise_mtu();

        let expected = if bitrate >= 1_000_000_000 {
            Some(524288)
        } else if bitrate > 750_000_000 {
            Some(262144)
        } else if bitrate > 400_000_000 {
            Some(131072)
        } else if bitrate > 200_000_000 {
            Some(65536)
        } else if bitrate > 100_000_000 {
            Some(32768)
        } else if bitrate > 10_000_000 {
            Some(16384)
        } else if bitrate > 5_000_000 {
            Some(8192)
        } else if bitrate > 2_000_000 {
            Some(4096)
        } else if bitrate > 1_000_000 {
            Some(2048)
        } else if bitrate > 62_500 {
            Some(1024)
        } else {
            None
        };

        prop_assert_eq!(
            interface.hw_mtu,
            expected,
            "bitrate={}: expected hw_mtu={:?}, got {:?}",
            bitrate,
            expected,
            interface.hw_mtu,
        );
    }
}


use ferret_rns::interfaces::base::AnnounceQueueEntry;
use std::sync::{Arc, Mutex as StdMutex};

// ── Property 12: Announce queue processes lowest hops first ──
// For any non-empty announce queue with varying hop counts, processing
// selects the entry with minimum hops (oldest first among ties).
// **Validates: Requirements 20.1, 20.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn announce_queue_ordering(
        entries in prop::collection::vec(
            (0u8..=7, 1usize..=100),
            1..=10,
        ),
    ) {
        // Shared buffer to capture what was transmitted
        let transmitted: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
        let tx_clone = Arc::clone(&transmitted);

        let transmit_fn: Box<dyn Fn(&[u8]) -> ferret_rns::Result<()> + Send + Sync> =
            Box::new(move |data: &[u8]| {
                tx_clone.lock().unwrap().push(data.to_vec());
                Ok(())
            });

        let mut interface = Interface::new("test-announce".into(), Some(transmit_fn));
        interface.announce_cap = 1.0;
        interface.bitrate = 1_000_000;

        // Build announce queue entries with sequential timestamps for deterministic ordering.
        // Use timestamps close to now() so entries are not considered stale
        // (process_announce_queue removes entries older than QUEUED_ANNOUNCE_LIFE = 86400s).
        let base_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut queue_entries = Vec::new();
        let mut raw_payloads: Vec<(Vec<u8>, u8, f64)> = Vec::new();
        for (i, (hops, raw_len)) in entries.iter().enumerate() {
            let raw: Vec<u8> = (0..*raw_len as u8).collect();
            let time = base_time - 100.0 + (i as f64); // sequential, recent timestamps
            raw_payloads.push((raw.clone(), *hops, time));
            queue_entries.push(AnnounceQueueEntry {
                raw,
                hops: *hops,
                time,
            });
        }

        // Populate the announce queue
        {
            let mut queue = interface.announce_queue.lock().unwrap();
            *queue = queue_entries;
        }

        // Process the announce queue (transmits the best entry)
        let result = interface.process_announce_queue();
        prop_assert!(result.is_some(), "process_announce_queue should return Some for non-empty queue");

        // Determine expected: minimum hops, oldest time among ties
        let min_hops = raw_payloads.iter().map(|(_, h, _)| *h).min().unwrap();
        let expected = raw_payloads
            .iter()
            .filter(|(_, h, _)| *h == min_hops)
            .min_by(|a, b| a.2.partial_cmp(&b.2).unwrap())
            .unwrap();

        // Check that the transmitted packet matches the expected one
        let tx_buf = transmitted.lock().unwrap();
        prop_assert_eq!(tx_buf.len(), 1, "exactly one packet should be transmitted");
        prop_assert_eq!(&tx_buf[0], &expected.0, "transmitted packet should be the one with min hops (oldest among ties)");
    }
}


// ── Property 10: RNode parameter validation ──
// For any radio parameter tuple (frequency, bandwidth, spreading_factor,
// coding_rate, tx_power), validation accepts if and only if all values
// fall within the allowed ranges.
// **Validates: Requirements 14.11**

#[cfg(feature = "serial")]
mod rnode_param_tests {
    use proptest::prelude::*;
    use ferret_rns::interfaces::rnode::{
        validate_params, FREQ_MIN, FREQ_MAX, BW_MIN, BW_MAX, SF_MIN, SF_MAX, CR_MIN, CR_MAX,
        TXPOWER_MAX,
    };

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn rnode_param_validation(
            frequency in any::<u32>(),
            bandwidth in any::<u32>(),
            sf in any::<u8>(),
            cr in any::<u8>(),
            tx_power in any::<u8>(),
        ) {
            let result = validate_params(frequency, bandwidth, sf, cr, tx_power);

            let all_in_range =
                (FREQ_MIN..=FREQ_MAX).contains(&frequency)
                && (BW_MIN..=BW_MAX).contains(&bandwidth)
                && (SF_MIN..=SF_MAX).contains(&sf)
                && (CR_MIN..=CR_MAX).contains(&cr)
                && tx_power <= TXPOWER_MAX;

            if all_in_range {
                prop_assert!(result.is_ok(), "expected Ok for in-range params, got {:?}", result);
            } else {
                prop_assert!(result.is_err(), "expected Err for out-of-range params, got Ok");
            }
        }
    }
}
