use proptest::prelude::*;

use ferret_rns::destination::Destination;
use ferret_rns::identity::Identity;
use ferret_rns::types::destination::{DestinationDirection, DestinationType};

/// Helper: create an IN/SINGLE destination with a fresh identity and ratchets enabled.
/// Returns (destination, tempdir) — keep tempdir alive to prevent cleanup.
fn make_ratchet_dest(
    ratchet_path: &std::path::Path,
) -> Destination {
    let id = Identity::new();
    let prv = id.get_private_key().unwrap();
    let id_in = Identity::from_private_key(&prv).unwrap();
    let mut dest = Destination::new(
        Some(id_in),
        DestinationDirection::In,
        DestinationType::Single,
        "testapp",
        &["ratchet"],
    )
    .unwrap();
    dest.enable_ratchets(ratchet_path).unwrap();
    dest
}

/// Force a rotation by clearing latest_ratchet_time so the interval check passes.
fn force_rotate(dest: &mut Destination) {
    dest.latest_ratchet_time = None;
    dest.rotate_ratchets().unwrap();
}

// ============================================================================
// Feature: ferret-test-coverage, Property 5: Ratchet rotation and retention limits
// **Validates: Requirements 3.2, 3.3**
// ============================================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn ratchet_rotation_and_retention_limits(
        k in 1u32..20,
        n in 1usize..16,
        m in 1usize..16,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let ratchet_path = dir.path().join("ratchets");

        let mut dest = make_ratchet_dest(&ratchet_path);
        dest.retained_ratchets = n;

        // Perform k rotations
        for _ in 0..k {
            force_rotate(&mut dest);
        }

        let ratchets = dest.ratchets.as_ref().unwrap();
        let expected_len = std::cmp::min(k as usize, n);
        prop_assert_eq!(
            ratchets.len(),
            expected_len,
            "after {} rotations with retained={}, expected {} entries, got {}",
            k, n, expected_len, ratchets.len()
        );

        // Each ratchet entry should be 32 bytes (X25519 private key)
        for (i, r) in ratchets.iter().enumerate() {
            prop_assert_eq!(
                r.len(),
                32,
                "ratchet entry {} should be 32 bytes, got {}",
                i, r.len()
            );
        }

        // Now test set_retained_ratchets(m) truncation
        let result = dest.set_retained_ratchets(m);
        prop_assert!(result, "set_retained_ratchets({}) should return true", m);

        let ratchets_after = dest.ratchets.as_ref().unwrap();
        prop_assert!(
            ratchets_after.len() <= m,
            "after set_retained_ratchets({}), list should have at most {} entries, got {}",
            m, m, ratchets_after.len()
        );
    }
}

// ============================================================================
// Feature: ferret-test-coverage, Property 6: Ratchet persistence round-trip
// **Validates: Requirements 3.6**
// ============================================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn ratchet_persistence_round_trip(
        rotations in 1u32..10,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let ratchet_path = dir.path().join("ratchets");

        // Create destination, enable ratchets, perform rotations
        let id = Identity::new();
        let prv_key = id.get_private_key().unwrap();

        let id1 = Identity::from_private_key(&prv_key).unwrap();
        let mut dest1 = Destination::new(
            Some(id1),
            DestinationDirection::In,
            DestinationType::Single,
            "testapp",
            &["ratchet"],
        )
        .unwrap();
        dest1.enable_ratchets(&ratchet_path).unwrap();

        for _ in 0..rotations {
            dest1.latest_ratchet_time = None;
            dest1.rotate_ratchets().unwrap();
        }

        let original_ratchets = dest1.ratchets.clone().unwrap();
        prop_assert!(!original_ratchets.is_empty(), "should have ratchets after rotation");

        // Verify file exists and has 64-byte signature prefix
        let file_data = std::fs::read(&ratchet_path).unwrap();
        prop_assert!(
            file_data.len() >= 64,
            "ratchet file should be at least 64 bytes (signature), got {}",
            file_data.len()
        );

        // The first 64 bytes are the Ed25519 signature
        let _signature = &file_data[..64];

        // Now create a second destination from the same identity and load ratchets
        let id2 = Identity::from_private_key(&prv_key).unwrap();
        let mut dest2 = Destination::new(
            Some(id2),
            DestinationDirection::In,
            DestinationType::Single,
            "testapp",
            &["ratchet"],
        )
        .unwrap();
        dest2.enable_ratchets(&ratchet_path).unwrap();

        let recovered_ratchets = dest2.ratchets.as_ref().unwrap();
        prop_assert_eq!(
            &original_ratchets,
            recovered_ratchets,
            "ratchet list should survive persist/enable round-trip"
        );
    }
}

// ============================================================================
// Unit tests for ratchet edge cases
// Requirements: 3.1, 3.4, 3.5, 3.7
// ============================================================================

#[test]
fn set_retained_ratchets_zero_returns_false() {
    let dir = tempfile::tempdir().unwrap();
    let mut dest = make_ratchet_dest(&dir.path().join("ratchets"));
    let original = dest.retained_ratchets;
    let result = dest.set_retained_ratchets(0);
    assert!(!result, "set_retained_ratchets(0) should return false");
    assert_eq!(
        dest.retained_ratchets, original,
        "retained_ratchets should be unchanged after rejected set"
    );
}

#[test]
fn set_ratchet_interval_zero_returns_false() {
    let dir = tempfile::tempdir().unwrap();
    let mut dest = make_ratchet_dest(&dir.path().join("ratchets"));
    let original = dest.ratchet_interval;
    let result = dest.set_ratchet_interval(0);
    assert!(!result, "set_ratchet_interval(0) should return false");
    assert_eq!(
        dest.ratchet_interval, original,
        "ratchet_interval should be unchanged after rejected set"
    );
}

#[test]
fn enable_ratchets_nonexistent_path_initializes_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("does_not_exist");
    let dest = make_ratchet_dest(&path);
    let ratchets = dest.ratchets.as_ref().unwrap();
    assert!(
        ratchets.is_empty(),
        "enable_ratchets with non-existent path should initialize empty list"
    );
}

#[test]
fn enforce_ratchets_sets_flag() {
    let dir = tempfile::tempdir().unwrap();
    let mut dest = make_ratchet_dest(&dir.path().join("ratchets"));
    assert!(!dest.enforce_ratchets_flag, "flag should start false");
    let result = dest.enforce_ratchets().unwrap();
    assert!(result, "enforce_ratchets should return true when ratchets enabled");
    assert!(
        dest.enforce_ratchets_flag,
        "enforce_ratchets_flag should be true after enforce_ratchets()"
    );
}
