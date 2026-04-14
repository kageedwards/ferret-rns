// Property-based tests for Discovery store persistence
// Feature: ferret-test-coverage

use proptest::prelude::*;

use ferret_rns::discovery::handler::DiscoveredInterfaceInfo;
use ferret_rns::discovery::store::InterfaceDiscovery;
use ferret_rns::transport::TransportState;

/// Generate a valid IPv4 address string for reachable_on.
fn arb_ipv4() -> impl Strategy<Value = String> {
    (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
        .prop_map(|(a, b, c, d)| format!("{}.{}.{}.{}", a, b, c, d))
}

/// Generate an optional reachable_on: either None or a valid IPv4 address.
fn arb_reachable_on() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        arb_ipv4().prop_map(Some),
    ]
}

/// Generate a unique 32-byte discovery hash from an index.
fn hash_from_index(idx: usize) -> [u8; 32] {
    let mut h = [0u8; 32];
    let bytes = idx.to_le_bytes();
    h[..bytes.len()].copy_from_slice(&bytes);
    h
}

/// Build a DiscoveredInterfaceInfo with the given fields.
fn make_info(
    interface_type: &str,
    name: &str,
    transport: bool,
    reachable_on: Option<String>,
    discovery_hash: [u8; 32],
) -> DiscoveredInterfaceInfo {
    DiscoveredInterfaceInfo {
        interface_type: interface_type.to_string(),
        transport,
        name: name.to_string(),
        received: 0.0,
        stamp: vec![0u8; 16],
        value: 0,
        transport_id: String::new(),
        network_id: String::new(),
        hops: 0,
        latitude: None,
        longitude: None,
        height: None,
        reachable_on,
        port: None,
        frequency: None,
        bandwidth: None,
        spreading_factor: None,
        coding_rate: None,
        modulation: None,
        channel: None,
        ifac_netname: None,
        ifac_netkey: None,
        config_entry: None,
        discovery_hash,
        discovered: None,
        last_heard: None,
        heard_count: None,
        status: None,
        status_code: None,
    }
}

// ── Property 11: Discovery store persistence round-trip ──
// For all valid DiscoveredInterfaceInfo records, persisting via
// interface_discovered then listing via list_discovered_interfaces
// recovers original interface type, name, transport flag, and reachable_on.
// **Validates: Requirements 12.1**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    // Feature: ferret-test-coverage, Property 11: Discovery store persistence round-trip
    #[test]
    fn prop_discovery_persistence_round_trip(
        iface_type in "[a-zA-Z]{3,12}",
        name in "[a-zA-Z0-9]{3,12}",
        transport in any::<bool>(),
        reachable_on in arb_reachable_on(),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let ts = TransportState::new();
        let store = InterfaceDiscovery::new(
            tmp.path(),
            0,
            None,
            &ts,
        ).unwrap();

        let hash = hash_from_index(1);
        let info = make_info(&iface_type, &name, transport, reachable_on.clone(), hash);

        store.interface_discovered(&info).unwrap();

        let listed = store
            .list_discovered_interfaces(false, false, None)
            .unwrap();

        prop_assert_eq!(listed.len(), 1, "expected exactly 1 interface");
        let got = &listed[0];
        prop_assert_eq!(&got.interface_type, &iface_type);
        prop_assert_eq!(&got.name, &name);
        prop_assert_eq!(got.transport, transport);
        prop_assert_eq!(&got.reachable_on, &reachable_on);
    }
}

// ── Property 12: Discovery store sort ordering ──
// list_discovered_interfaces returns results sorted by status_code
// descending then last_heard descending.
// **Validates: Requirements 12.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    // Feature: ferret-test-coverage, Property 12: Discovery store sort ordering
    #[test]
    fn prop_discovery_sort_ordering(
        count in 2usize..=6,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let ts = TransportState::new();
        let store = InterfaceDiscovery::new(
            tmp.path(),
            0,
            None,
            &ts,
        ).unwrap();

        // Insert `count` interfaces with unique hashes. Each call to
        // interface_discovered records the current wall-clock time as
        // last_heard, so inserting sequentially gives ascending last_heard.
        for i in 0..count {
            let hash = hash_from_index(i);
            let info = make_info(
                "TCPInterface",
                &format!("iface{}", i),
                false,
                Some(format!("10.0.0.{}", i + 1)),
                hash,
            );
            store.interface_discovered(&info).unwrap();
            // Small sleep to ensure distinct last_heard timestamps
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let listed = store
            .list_discovered_interfaces(false, false, None)
            .unwrap();

        prop_assert_eq!(listed.len(), count);

        // All should be "available" (same status_code = 1000) since they
        // were just inserted. Within the same status_code, results should
        // be sorted by last_heard descending (most recently heard first).
        for i in 0..listed.len() - 1 {
            let sc_a = listed[i].status_code.unwrap_or(0);
            let sc_b = listed[i + 1].status_code.unwrap_or(0);
            let lh_a = listed[i].last_heard.unwrap_or(0.0);
            let lh_b = listed[i + 1].last_heard.unwrap_or(0.0);

            if sc_a == sc_b {
                prop_assert!(
                    lh_a >= lh_b,
                    "within same status_code, last_heard should be descending: {} vs {}",
                    lh_a, lh_b
                );
            } else {
                prop_assert!(
                    sc_a > sc_b,
                    "status_code should be descending: {} vs {}",
                    sc_a, sc_b
                );
            }
        }
    }
}
