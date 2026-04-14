// Unit tests for InterfaceAnnouncer timing
// Feature: ferret-test-coverage
//
// Mirrors the BlackholeUpdater timing tests in blackhole_props.rs
// to verify the self-contained interval pattern on InterfaceAnnouncer.

use ferret_rns::discovery::announcer::{InterfaceAnnouncer, InterfaceDiscoveryInfo};
use ferret_rns::identity::Identity;
use ferret_rns::transport::TransportState;

/// Build a minimal InterfaceDiscoveryInfo for testing.
fn make_iface_info(name: &str) -> InterfaceDiscoveryInfo {
    InterfaceDiscoveryInfo {
        interface_type: "TCPServerInterface".to_string(),
        name: name.to_string(),
        transport_enabled: false,
        transport_identity_hash: [0u8; 16],
        latitude: None,
        longitude: None,
        height: None,
        reachable_on: Some("10.0.0.1".to_string()),
        port: Some(4242),
        frequency: None,
        bandwidth: None,
        spreading_factor: None,
        coding_rate: None,
        modulation: None,
        channel: None,
        ifac_netname: None,
        ifac_netkey: None,
        discovery_encrypt: false,
        discovery_stamp_value: None,
        discovery_announce_interval: 300.0,
        last_discovery_announce: 0.0,
    }
}

/// Helper: construct an InterfaceAnnouncer with a fresh identity.
fn make_announcer() -> InterfaceAnnouncer {
    let id = Identity::new();
    let transport = TransportState::new();
    InterfaceAnnouncer::new(&id, &transport).unwrap()
}

#[test]
fn check_returns_early_when_not_running() {
    let mut announcer = make_announcer();
    // Don't call start() — should_run is false
    let interfaces = vec![make_iface_info("iface0")];

    let result = announcer.check(&interfaces);
    assert!(result.is_ok());
    assert!(!announcer.is_running());
}

#[test]
fn check_returns_early_when_interval_not_elapsed() {
    let mut announcer = make_announcer();
    announcer.start();

    let interfaces = vec![make_iface_info("iface0")];

    // Immediately after construction, last_check is Instant::now(),
    // so the 60-second job_interval hasn't elapsed.
    // check() should return early without announcing.
    let result = announcer.check(&interfaces);
    assert!(result.is_ok());
}

#[test]
fn start_stop_toggles_running() {
    let mut announcer = make_announcer();
    assert!(!announcer.is_running());

    announcer.start();
    assert!(announcer.is_running());

    announcer.stop();
    assert!(!announcer.is_running());
}
