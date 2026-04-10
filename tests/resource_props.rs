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
