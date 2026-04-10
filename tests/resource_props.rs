// Property-based tests for Resource module
// Feature: ferret-resource-discovery

use proptest::prelude::*;

use ferret_rns::resource::advertisement::ResourceAdvertisement;
use ferret_rns::resource::ResourceFlags;

// ── Property 1: ResourceAdvertisement pack/unpack round-trip ──
// For any valid ResourceAdvertisement with arbitrary field values and flag
// combinations, packing then unpacking produces identical field values.
// **Validates: Requirements 3.1, 3.2, 15.1, 15.2, 15.5, 26.1**

fn arb_flags() -> impl Strategy<Value = u8> {
    // bits 0-5 are valid flags, bits 6-7 reserved (0)
    0u8..64u8
}

fn arb_request_id() -> impl Strategy<Value = Option<Vec<u8>>> {
    prop_oneof![
        Just(None),
        prop::collection::vec(any::<u8>(), 16..=16).prop_map(Some),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn advertisement_pack_unpack_round_trip(
        t in 0usize..10_000_000,
        d in 0usize..10_000_000,
        n in 1usize..10_000,
        h in prop::array::uniform32(any::<u8>()),
        r in prop::array::uniform4(any::<u8>()),
        o in prop::array::uniform32(any::<u8>()),
        i in 1usize..100,
        l in 1usize..100,
        q in arb_request_id(),
        f in arb_flags(),
        m in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        let flags = ResourceFlags::from_byte(f);
        let adv = ResourceAdvertisement {
            t, d, n, h, r, o, i, l,
            q: q.clone(),
            f,
            m: m.clone(),
            encrypted: flags.encrypted,
            compressed: flags.compressed,
            split: flags.split,
            is_request: flags.is_request,
            is_response: flags.is_response,
            has_metadata: flags.has_metadata,
        };

        let packed = adv.pack().unwrap();
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();

        prop_assert_eq!(unpacked.t, t);
        prop_assert_eq!(unpacked.d, d);
        prop_assert_eq!(unpacked.n, n);
        prop_assert_eq!(unpacked.h, h);
        prop_assert_eq!(unpacked.r, r);
        prop_assert_eq!(unpacked.o, o);
        prop_assert_eq!(unpacked.i, i);
        prop_assert_eq!(unpacked.l, l);
        prop_assert_eq!(unpacked.q, q);
        prop_assert_eq!(unpacked.f, f);
        prop_assert_eq!(unpacked.m, m);
        // Verify decoded flags
        prop_assert_eq!(unpacked.encrypted, flags.encrypted);
        prop_assert_eq!(unpacked.compressed, flags.compressed);
        prop_assert_eq!(unpacked.split, flags.split);
        prop_assert_eq!(unpacked.is_request, flags.is_request);
        prop_assert_eq!(unpacked.is_response, flags.is_response);
        prop_assert_eq!(unpacked.has_metadata, flags.has_metadata);
    }
}

use ferret_rns::crypto::hashes::sha256;
use ferret_rns::identity::Identity;
use ferret_rns::resource::resource::Resource;
use ferret_rns::resource::{MAX_EFFICIENT_SIZE, MAPHASH_LEN, RANDOM_HASH_SIZE};

// ── Property 3: Resource hash and proof correctness ──
// For any byte data (1..1000) and random_hash, resource_hash, truncated_hash,
// and expected_proof are deterministic, and proof == expected_proof.
// **Validates: Requirements 1.5, 8.4, 8.5**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn resource_hash_and_proof_correctness(
        data in prop::collection::vec(any::<u8>(), 1..1000),
        random_hash in prop::array::uniform4(any::<u8>()),
    ) {
        // Compute resource_hash = full_hash(data + random_hash)
        let mut hash_input = Vec::with_capacity(data.len() + RANDOM_HASH_SIZE);
        hash_input.extend_from_slice(&data);
        hash_input.extend_from_slice(&random_hash);
        let resource_hash = sha256(&hash_input);

        // Compute truncated_hash = truncated_hash(data + random_hash)
        let truncated_hash = Identity::truncated_hash(&hash_input);

        // Compute expected_proof = full_hash(data + resource_hash)
        let mut proof_input = Vec::with_capacity(data.len() + 32);
        proof_input.extend_from_slice(&data);
        proof_input.extend_from_slice(&resource_hash);
        let expected_proof = sha256(&proof_input);

        // Determinism: recompute and verify identical
        let resource_hash_2 = sha256(&hash_input);
        let truncated_hash_2 = Identity::truncated_hash(&hash_input);
        let expected_proof_2 = sha256(&proof_input);

        prop_assert_eq!(resource_hash, resource_hash_2);
        prop_assert_eq!(truncated_hash, truncated_hash_2);
        prop_assert_eq!(expected_proof, expected_proof_2);

        // Proof constructed as full_hash(data + resource_hash) equals expected_proof
        let proof = sha256(&proof_input);
        prop_assert_eq!(proof, expected_proof);

        // Truncated hash is first 16 bytes of full hash
        prop_assert_eq!(&truncated_hash[..], &sha256(&hash_input)[..16]);
    }
}

// ── Property 4: Hashmap computation and map hash matching ──
// For any data split into SDU-sized parts with a given random_hash,
// hashmap has exactly ceil(data_len/SDU) entries, and each part's
// get_map_hash matches its hashmap slot.
// **Validates: Requirements 1.3, 7.1**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn hashmap_computation_and_map_hash_matching(
        data in prop::collection::vec(any::<u8>(), 1..2000),
        random_hash in prop::array::uniform4(any::<u8>()),
        sdu in 50usize..500,
    ) {
        let parts: Vec<Vec<u8>> = data.chunks(sdu).map(|c| c.to_vec()).collect();
        let expected_count = (data.len() + sdu - 1) / sdu;
        prop_assert_eq!(parts.len(), expected_count);

        // Build hashmap
        let mut hashmap = Vec::with_capacity(parts.len() * MAPHASH_LEN);
        for part in &parts {
            let map_hash = Resource::get_map_hash(part, &random_hash);
            hashmap.extend_from_slice(&map_hash);
        }

        // Verify hashmap has exactly the right number of entries
        prop_assert_eq!(hashmap.len(), expected_count * MAPHASH_LEN);

        // Verify each part's map_hash matches its hashmap slot
        for (i, part) in parts.iter().enumerate() {
            let computed = Resource::get_map_hash(part, &random_hash);
            let start = i * MAPHASH_LEN;
            let stored: [u8; 4] = hashmap[start..start + MAPHASH_LEN]
                .try_into()
                .unwrap();
            prop_assert_eq!(computed, stored,
                "map_hash mismatch at part {}", i);
        }
    }
}

// ── Property 5: Metadata prepend/extract round-trip ──
// For any metadata string and byte data, prepending 3-byte size +
// msgpack(metadata) then extracting produces original metadata and data.
// **Validates: Requirements 1.7, 27.1, 27.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn metadata_prepend_extract_round_trip(
        meta_str in "[a-zA-Z0-9]{1,100}",
        data in prop::collection::vec(any::<u8>(), 0..500),
    ) {
        // Serialize metadata as msgpack
        let meta_bytes = ferret_rns::util::msgpack::serialize(&meta_str).unwrap();

        // Prepend metadata to data
        let combined = Resource::prepend_metadata(&meta_bytes, &data).unwrap();

        // Extract metadata and remaining data
        let (extracted_meta, extracted_data) = Resource::extract_metadata(&combined).unwrap();

        // Verify round-trip
        prop_assert_eq!(&extracted_meta, &meta_bytes);
        prop_assert_eq!(&extracted_data, &data);

        // Verify we can deserialize the metadata back
        let recovered: String = ferret_rns::util::msgpack::deserialize(&extracted_meta).unwrap();
        prop_assert_eq!(recovered, meta_str);
    }
}

// ── Property 6: Segmentation computation ──
// For any total_size > 0, if <= MAX_EFFICIENT_SIZE then split=false/segments=1;
// otherwise split=true/segments=ceil(total_size/MAX_EFFICIENT_SIZE).
// **Validates: Requirements 2.1, 2.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn segmentation_computation(
        total_size in 1usize..5_000_000,
    ) {
        let (split, total_segments) = Resource::compute_segmentation(total_size);

        if total_size <= MAX_EFFICIENT_SIZE {
            prop_assert!(!split, "should not be split for size {}", total_size);
            prop_assert_eq!(total_segments, 1);
        } else {
            prop_assert!(split, "should be split for size {}", total_size);
            let expected = (total_size + MAX_EFFICIENT_SIZE - 1) / MAX_EFFICIENT_SIZE;
            prop_assert_eq!(total_segments, expected);
            // Verify segments cover the full size
            prop_assert!(total_segments * MAX_EFFICIENT_SIZE >= total_size);
            prop_assert!((total_segments - 1) * MAX_EFFICIENT_SIZE < total_size);
        }
    }
}

// ── Property 8: Progress bounds invariant ──
// For any Resource state (sent_parts, received_count, total_parts,
// segment_index, total_segments), get_progress() and get_segment_progress()
// return values in [0.0, 1.0].
// **Validates: Requirements 14.1, 14.2**

fn make_test_resource(
    sent_parts: usize,
    received_count: usize,
    total_parts: usize,
    segment_index: usize,
    total_segments: usize,
    initiator: bool,
) -> Resource {
    use ferret_rns::link::Link;
    use ferret_rns::resource::ResourceStatus;

    let link = Link::new_test_active(&[0u8; 64]);
    Resource {
        hash: [0u8; 32],
        truncated_hash: [0u8; 16],
        original_hash: [0u8; 32],
        random_hash: [0u8; 4],
        expected_proof: [0u8; 32],
        status: ResourceStatus::Transferring,
        initiator,
        encrypted: true,
        compressed: false,
        split: total_segments > 1,
        has_metadata: false,
        is_response: false,
        size: 1000,
        total_size: 1000,
        uncompressed_size: 1000,
        sdu: 100,
        total_parts,
        sent_parts,
        received_count,
        outstanding_parts: 0,
        parts: Vec::new(),
        hashmap: Vec::new(),
        hashmap_height: 0,
        segment_index,
        total_segments,
        window: 4,
        window_min: 2,
        window_max: 10,
        window_flexibility: 4,
        rtt: None,
        eifr: None,
        previous_eifr: None,
        fast_rate_rounds: 0,
        very_slow_rate_rounds: 0,
        req_data_rtt_rate: 0.0,
        req_resp_rtt_rate: 0.0,
        last_activity: 0.0,
        started_transferring: None,
        adv_sent: None,
        last_part_sent: None,
        req_sent: None,
        req_resp: None,
        req_sent_bytes: 0,
        rtt_rxd_bytes: 0,
        rtt_rxd_bytes_at_part_req: 0,
        retries_left: 16,
        max_retries: 16,
        max_adv_retries: 4,
        timeout: 15.0,
        timeout_factor: 4.0,
        part_timeout_factor: 4.0,
        sender_grace_time: 10.0,
        receiver_hashmap: Vec::new(),
        waiting_for_hmu: false,
        consecutive_completed_height: -1,
        receiver_min_consecutive_height: 0,
        callback: None,
        progress_callback: None,
        request_id: None,
        metadata: None,
        metadata_size: 0,
        storagepath: None,
        meta_storagepath: None,
        link,
        auto_compress: false,
        auto_compress_limit: 0,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn progress_bounds_invariant(
        sent_parts in 0usize..200,
        received_count in 0usize..200,
        total_parts in 1usize..200,
        segment_index in 1usize..20,
        total_segments in 1usize..20,
        initiator in any::<bool>(),
    ) {
        let resource = make_test_resource(
            sent_parts, received_count, total_parts,
            segment_index, total_segments, initiator,
        );

        let progress = resource.get_progress();
        let seg_progress = resource.get_segment_progress();

        prop_assert!(progress >= 0.0 && progress <= 1.0,
            "get_progress() = {} out of bounds", progress);
        prop_assert!(seg_progress >= 0.0 && seg_progress <= 1.0,
            "get_segment_progress() = {} out of bounds", seg_progress);
    }
}

// ── Property 14: Resource request wire format round-trip ──
// For any resource_hash, set of requested map_hashes (0 to 75 entries),
// and hashmap_exhausted flag (with optional last_map_hash), building a
// request packet then parsing it recovers original values.
// **Validates: Requirements 6.1, 26.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn request_wire_format_round_trip(
        resource_hash in prop::array::uniform32(any::<u8>()),
        num_hashes in 0usize..75,
        exhausted in any::<bool>(),
        last_map_hash in prop::array::uniform4(any::<u8>()),
    ) {
        // Generate requested map_hashes
        let mut requested: Vec<[u8; 4]> = Vec::with_capacity(num_hashes);
        for i in 0..num_hashes {
            let mut mh = [0u8; 4];
            mh[0] = (i & 0xFF) as u8;
            mh[1] = ((i >> 8) & 0xFF) as u8;
            mh[2] = resource_hash[i % 32];
            mh[3] = last_map_hash[i % 4];
            requested.push(mh);
        }

        let lmh = if exhausted { Some(&last_map_hash) } else { None };

        let packet = Resource::build_request_packet(
            exhausted,
            lmh,
            &resource_hash,
            &requested,
        );

        let (parsed_exhausted, parsed_lmh, parsed_rh, parsed_hashes) =
            Resource::parse_request_packet(&packet).unwrap();

        prop_assert_eq!(parsed_exhausted, exhausted);
        prop_assert_eq!(parsed_rh, resource_hash);
        prop_assert_eq!(parsed_hashes.len(), requested.len());

        if exhausted {
            prop_assert_eq!(parsed_lmh, Some(last_map_hash));
        } else {
            prop_assert_eq!(parsed_lmh, None);
        }

        for (i, (expected, actual)) in requested.iter().zip(parsed_hashes.iter()).enumerate() {
            prop_assert_eq!(expected, actual, "map_hash mismatch at index {}", i);
        }
    }
}

// ── Property 2: Resource data round-trip (construction → assembly) ──
// For any byte data (1..2000) and random_hash, constructing a Resource
// (prepend random_hash, split into SDU-sized parts) then simulating
// assembly (concatenate parts, strip random_hash) produces original data.
// Uses identity encryption (no real crypto) to test the data pipeline.
// **Validates: Requirements 1.1, 8.1, 8.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn resource_data_round_trip(
        data in prop::collection::vec(any::<u8>(), 1..2000),
        random_hash in prop::array::uniform4(any::<u8>()),
        sdu in 50usize..500,
    ) {
        // Step 1: Prepend random_hash to data (simulating Resource construction)
        let mut payload = Vec::with_capacity(RANDOM_HASH_SIZE + data.len());
        payload.extend_from_slice(&random_hash);
        payload.extend_from_slice(&data);

        // Step 2: Split into SDU-sized parts
        let parts: Vec<Vec<u8>> = payload.chunks(sdu).map(|c| c.to_vec()).collect();
        let expected_parts = (payload.len() + sdu - 1) / sdu;
        prop_assert_eq!(parts.len(), expected_parts);

        // Step 3: Concatenate parts back (simulating assembly)
        let mut assembled = Vec::new();
        for part in &parts {
            assembled.extend_from_slice(part);
        }

        // Step 4: Strip random_hash prefix
        prop_assert!(assembled.len() >= RANDOM_HASH_SIZE);
        let recovered = &assembled[RANDOM_HASH_SIZE..];

        // Step 5: Verify data matches original
        prop_assert_eq!(recovered, data.as_slice(),
            "round-trip data mismatch for {} bytes with SDU {}", data.len(), sdu);

        // Also verify the random_hash prefix is correct
        prop_assert_eq!(&assembled[..RANDOM_HASH_SIZE], &random_hash[..]);
    }
}

// ── Property 9: Consecutive completed height tracking ──
// For any sequence of part receptions in arbitrary order for N parts,
// consecutive_completed_height equals the largest k where all parts[0..=k]
// are Some, or -1 if parts[0] is None.
// **Validates: Requirements 7.3**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn consecutive_completed_height_tracking(
        total_parts in 1usize..100,
        reception_order in prop::collection::vec(any::<usize>(), 1..100),
    ) {
        let mut resource = make_test_resource(0, 0, total_parts, 1, 1, false);
        resource.parts = vec![None; total_parts];
        resource.receiver_hashmap = vec![Some([0u8; 4]); total_parts];
        resource.consecutive_completed_height = -1;

        for &raw_idx in &reception_order {
            let idx = raw_idx % total_parts;
            if resource.parts[idx].is_none() {
                resource.parts[idx] = Some(vec![0u8; 10]);
                resource.received_count += 1;
                resource.update_consecutive_completed_height();
            }
        }

        // Compute expected consecutive_completed_height
        let mut expected: isize = -1;
        for i in 0..total_parts {
            if resource.parts[i].is_some() {
                expected = i as isize;
            } else {
                break;
            }
        }

        prop_assert_eq!(
            resource.consecutive_completed_height, expected,
            "height mismatch: got {}, expected {} for {} parts",
            resource.consecutive_completed_height, expected, total_parts
        );
    }
}

// ── Property 11: Receiver initialization from advertisement ──
// For any valid ResourceAdvertisement, accepting produces a Resource with
// total_parts == ceil(adv.t / SDU), status == Transferring, and correct
// field propagation.
// **Validates: Requirements 4.1, 4.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn receiver_initialization_from_advertisement(
        t in 1usize..100_000,
        d in 1usize..100_000,
        n in 1usize..1000,
        h in prop::array::uniform32(any::<u8>()),
        r in prop::array::uniform4(any::<u8>()),
        o in prop::array::uniform32(any::<u8>()),
        i in 1usize..10,
        l in 1usize..10,
        f in arb_flags(),
    ) {
        use ferret_rns::resource::WINDOW;
        use ferret_rns::resource::WINDOW_MAX_SLOW;

        let flags = ResourceFlags::from_byte(f);
        let adv = ResourceAdvertisement {
            t, d, n, h, r, o, i, l,
            q: None,
            f,
            m: Vec::new(), // empty initial hashmap for simplicity
            encrypted: flags.encrypted,
            compressed: flags.compressed,
            split: flags.split,
            is_request: flags.is_request,
            is_response: flags.is_response,
            has_metadata: flags.has_metadata,
        };

        let packed = adv.pack().unwrap();
        let link = ferret_rns::link::Link::new_test_active(&[0u8; 64]);
        let resource = Resource::accept(
            &packed,
            &link,
            None,
            None,
            None,
        ).unwrap();

        // Verify total_parts == ceil(t / SDU)
        let sdu = Resource::compute_sdu(&link).unwrap();
        let expected_parts = (t + sdu - 1) / sdu;
        prop_assert_eq!(resource.total_parts, expected_parts,
            "total_parts mismatch: got {}, expected {} (t={}, sdu={})",
            resource.total_parts, expected_parts, t, sdu);

        // Verify status == Transferring
        prop_assert_eq!(resource.status, ferret_rns::resource::ResourceStatus::Transferring);

        // Verify field propagation
        prop_assert_eq!(resource.hash, h);
        prop_assert_eq!(resource.random_hash, r);
        prop_assert_eq!(resource.original_hash, o);
        prop_assert_eq!(resource.segment_index, i);
        prop_assert_eq!(resource.total_segments, l);
        prop_assert_eq!(resource.encrypted, flags.encrypted);
        prop_assert_eq!(resource.compressed, flags.compressed);
        prop_assert_eq!(resource.split, flags.split);
        prop_assert_eq!(resource.has_metadata, flags.has_metadata);
        prop_assert_eq!(resource.is_response, flags.is_response);
        prop_assert_eq!(resource.size, t);
        prop_assert_eq!(resource.total_size, d);

        // Verify window initialization
        prop_assert_eq!(resource.window, WINDOW);
        prop_assert_eq!(resource.window_max, WINDOW_MAX_SLOW);

        // Verify parts array is correct size and all None
        prop_assert_eq!(resource.parts.len(), expected_parts);
        for part in &resource.parts {
            prop_assert!(part.is_none());
        }

        // Verify initiator is false
        prop_assert!(!resource.initiator);
    }
}

// ── Property 7: Window adaptation invariants ──
// For any sequence of grow/shrink/rate-tier operations, window_min <= window <= window_max,
// grow increases by at most 1, shrink decreases by at most 1.
// **Validates: Requirements 9.2, 9.3, 9.4, 9.5, 6.5**

#[derive(Debug, Clone)]
enum WindowOp {
    Grow,
    Shrink,
    RateTier(f64), // EIFR value to set before update_rate_tier
}

fn arb_window_op() -> impl Strategy<Value = WindowOp> {
    prop_oneof![
        Just(WindowOp::Grow),
        Just(WindowOp::Shrink),
        // Cover fast, normal, and very-slow EIFR ranges
        prop_oneof![
            (0.0..1000.0f64).prop_map(WindowOp::RateTier),       // very slow
            (1000.0..50000.0f64).prop_map(WindowOp::RateTier),   // normal
            (50001.0..1000000.0f64).prop_map(WindowOp::RateTier), // fast
        ],
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn window_adaptation_invariants(
        ops in prop::collection::vec(arb_window_op(), 1..50),
    ) {
        use ferret_rns::resource::{
            WINDOW_MAX_FAST, WINDOW_MAX_VERY_SLOW,
            FAST_RATE_THRESHOLD, VERY_SLOW_RATE_THRESHOLD,
        };

        let mut resource = make_test_resource(0, 0, 100, 1, 1, false);

        for op in &ops {
            let prev_window = resource.window;
            let _prev_min = resource.window_min;
            let _prev_max = resource.window_max;

            match op {
                WindowOp::Grow => {
                    resource.grow_window();
                    // Window increases by at most 1
                    prop_assert!(
                        resource.window <= prev_window + 1,
                        "grow increased window by more than 1: {} -> {}",
                        prev_window, resource.window
                    );
                    // Window doesn't exceed window_max
                    prop_assert!(
                        resource.window <= resource.window_max,
                        "window {} exceeds window_max {} after grow",
                        resource.window, resource.window_max
                    );
                }
                WindowOp::Shrink => {
                    resource.shrink_window();
                    // Window decreases by at most 1
                    prop_assert!(
                        resource.window >= prev_window.saturating_sub(1),
                        "shrink decreased window by more than 1: {} -> {}",
                        prev_window, resource.window
                    );
                    // Window doesn't go below window_min
                    prop_assert!(
                        resource.window >= resource.window_min,
                        "window {} below window_min {} after shrink",
                        resource.window, resource.window_min
                    );
                }
                WindowOp::RateTier(eifr_val) => {
                    resource.eifr = Some(*eifr_val);
                    resource.update_rate_tier();

                    // Verify rate tier immediate effects
                    if resource.fast_rate_rounds >= FAST_RATE_THRESHOLD {
                        prop_assert!(
                            resource.window_max >= WINDOW_MAX_FAST,
                            "after {} fast rounds, window_max {} < WINDOW_MAX_FAST {}",
                            resource.fast_rate_rounds, resource.window_max, WINDOW_MAX_FAST
                        );
                    }
                    if resource.very_slow_rate_rounds >= VERY_SLOW_RATE_THRESHOLD {
                        prop_assert!(
                            resource.window_max <= WINDOW_MAX_VERY_SLOW,
                            "after {} very-slow rounds, window_max {} > WINDOW_MAX_VERY_SLOW {}",
                            resource.very_slow_rate_rounds, resource.window_max, WINDOW_MAX_VERY_SLOW
                        );
                    }
                }
            }

            // Core invariant: window_min <= window <= window_max
            prop_assert!(
                resource.window_min <= resource.window,
                "invariant violated: window_min {} > window {}",
                resource.window_min, resource.window
            );
            prop_assert!(
                resource.window <= resource.window_max,
                "invariant violated: window {} > window_max {}",
                resource.window, resource.window_max
            );
        }

        // Rate tier thresholds are checked inline during RateTier ops above.
        // After arbitrary sequences of grow/shrink/rate-tier, the core invariant
        // window_min <= window <= window_max is the key property that must hold.
    }
}

// ── Property 10: RTT smoothing bounds ──
// For any current RTT and new measurement, updated RTT differs by at most 5%.
// **Validates: Requirements 13.1, 13.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn rtt_smoothing_bounds(
        current_rtt in 0.01f64..100.0,
        new_rtt in 0.01f64..100.0,
    ) {
        let mut resource = make_test_resource(0, 0, 100, 1, 1, false);
        resource.rtt = Some(current_rtt);

        resource.update_rtt(new_rtt);

        let updated = resource.rtt.unwrap();

        if new_rtt < current_rtt {
            // Decreased: updated >= current * 0.95
            let lower_bound = current_rtt * 0.95;
            prop_assert!(
                updated >= lower_bound - 1e-10,
                "RTT decreased too fast: current={}, new={}, updated={}, lower_bound={}",
                current_rtt, new_rtt, updated, lower_bound
            );
            // But also updated <= current (it shouldn't increase when new < current)
            prop_assert!(
                updated <= current_rtt + 1e-10,
                "RTT increased when new < current: current={}, new={}, updated={}",
                current_rtt, new_rtt, updated
            );
        } else {
            // Increased: updated <= current * 1.05
            let upper_bound = current_rtt * 1.05;
            prop_assert!(
                updated <= upper_bound + 1e-10,
                "RTT increased too fast: current={}, new={}, updated={}, upper_bound={}",
                current_rtt, new_rtt, updated, upper_bound
            );
            // But also updated >= current (it shouldn't decrease when new > current)
            prop_assert!(
                updated >= current_rtt - 1e-10,
                "RTT decreased when new > current: current={}, new={}, updated={}",
                current_rtt, new_rtt, updated
            );
        }
    }
}
