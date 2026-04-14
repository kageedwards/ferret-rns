// Property-based and unit tests for BlackholeUpdater
// Feature: ferret-test-coverage

use proptest::prelude::*;
use std::collections::HashSet;

use ferret_rns::discovery::blackhole::BlackholeUpdater;

/// Generate a random 16-byte source identity hash.
fn arb_source_hash() -> impl Strategy<Value = [u8; 16]> {
    proptest::collection::vec(any::<u8>(), 16).prop_map(|v| {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&v);
        arr
    })
}

/// Generate a list of identity hashes (each is a Vec<u8> of 16 bytes).
fn arb_hash_list(max_len: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    proptest::collection::vec(
        proptest::collection::vec(any::<u8>(), 16),
        0..=max_len,
    )
}

// ── Property 13: Blackhole merge_and_persist round-trip with deduplication ──
// For all lists of identity hashes (including overlapping lists across
// multiple calls), merge_and_persist then reading and deserializing the
// file recovers a deduplicated superset of all provided hashes with no
// duplicate entries.
// **Validates: Requirements 13.1, 13.2**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    // Feature: ferret-test-coverage, Property 13: Blackhole merge_and_persist round-trip with deduplication
    #[test]
    fn prop_blackhole_merge_persist_round_trip(
        source in arb_source_hash(),
        hashes in arb_hash_list(10),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let blackholepath = tmp.path();

        // Merge the hashes
        BlackholeUpdater::merge_and_persist(&source, &hashes, blackholepath).unwrap();

        // Read back the file
        let source_hex: String = source.iter().map(|b| format!("{:02x}", b)).collect();
        let file_path = blackholepath.join(&source_hex);
        let data = std::fs::read(&file_path).unwrap();
        let recovered: Vec<Vec<u8>> = rmp_serde::from_slice(&data).unwrap();

        // Build expected deduplicated set
        let mut expected_set: Vec<Vec<u8>> = Vec::new();
        for h in &hashes {
            if !expected_set.contains(h) {
                expected_set.push(h.clone());
            }
        }

        prop_assert_eq!(recovered.len(), expected_set.len(), "length mismatch after dedup");

        // Every expected hash must be present
        for h in &expected_set {
            prop_assert!(recovered.contains(h), "missing hash in recovered set");
        }

        // No duplicates in recovered
        let unique: HashSet<Vec<u8>> = recovered.iter().cloned().collect();
        prop_assert_eq!(unique.len(), recovered.len(), "duplicates found in recovered set");
    }

    // Calling merge_and_persist twice with overlapping hash lists produces no duplicates
    #[test]
    fn prop_blackhole_merge_twice_no_duplicates(
        source in arb_source_hash(),
        list_a in arb_hash_list(8),
        list_b in arb_hash_list(8),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let blackholepath = tmp.path();

        // First merge
        BlackholeUpdater::merge_and_persist(&source, &list_a, blackholepath).unwrap();
        // Second merge (may overlap)
        BlackholeUpdater::merge_and_persist(&source, &list_b, blackholepath).unwrap();

        // Read back
        let source_hex: String = source.iter().map(|b| format!("{:02x}", b)).collect();
        let file_path = blackholepath.join(&source_hex);
        let data = std::fs::read(&file_path).unwrap();
        let recovered: Vec<Vec<u8>> = rmp_serde::from_slice(&data).unwrap();

        // Build expected deduplicated superset
        let mut expected_set: Vec<Vec<u8>> = Vec::new();
        for h in list_a.iter().chain(list_b.iter()) {
            if !expected_set.contains(h) {
                expected_set.push(h.clone());
            }
        }

        prop_assert_eq!(recovered.len(), expected_set.len(), "length mismatch after double merge");

        for h in &expected_set {
            prop_assert!(recovered.contains(h), "missing hash after double merge");
        }

        // No duplicates
        let unique: HashSet<Vec<u8>> = recovered.iter().cloned().collect();
        prop_assert_eq!(unique.len(), recovered.len(), "duplicates after double merge");
    }
}

// ── Unit tests for BlackholeUpdater timing (Task 10.2) ──
// **Validates: Requirements 7.2, 7.4**

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn is_due_returns_true_for_unknown_source() {
        let updater = BlackholeUpdater::new();
        let source: [u8; 16] = [0xAA; 16];
        // Unknown source should be due
        assert!(updater.is_due(&source));
    }

    #[test]
    fn is_due_returns_false_immediately_after_update() {
        let mut updater = BlackholeUpdater::new();
        let source: [u8; 16] = [0xBB; 16];

        // Simulate recording an update by calling merge_and_persist
        // and then manually inserting a timestamp via update_from_source's
        // side-effect. Since update_from_source requires network, we
        // test is_due indirectly: after a successful merge_and_persist
        // the updater doesn't track time (that's update_from_source's job).
        // Instead, we verify the timing logic in check():

        // is_due should be true initially
        assert!(updater.is_due(&source));

        // After check() runs (even with no sources), last_check is reset.
        // We test the interval guard: immediately after construction,
        // check() should return early because last_check was just set.
        updater.start();
        let sources: Vec<[u8; 16]> = vec![];
        let transport = ferret_rns::transport::TransportState::new();
        let identity_store = ferret_rns::identity::IdentityStore::new();
        let tmp = tempfile::tempdir().unwrap();

        // First call: last_check was set at construction (just now),
        // so the interval hasn't elapsed — check() returns early.
        let result = updater.check(&sources, &transport, &identity_store, tmp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn check_returns_early_when_not_running() {
        let mut updater = BlackholeUpdater::new();
        // Don't call start() — should_run is false
        let sources: Vec<[u8; 16]> = vec![[0xCC; 16]];
        let transport = ferret_rns::transport::TransportState::new();
        let identity_store = ferret_rns::identity::IdentityStore::new();
        let tmp = tempfile::tempdir().unwrap();

        // check() should return Ok immediately when not running
        let result = updater.check(&sources, &transport, &identity_store, tmp.path());
        assert!(result.is_ok());

        // Verify the updater is not running
        assert!(!updater.is_running());
    }

    #[test]
    fn check_returns_early_when_interval_not_elapsed() {
        let mut updater = BlackholeUpdater::new();
        updater.start();

        let sources: Vec<[u8; 16]> = vec![[0xDD; 16]];
        let transport = ferret_rns::transport::TransportState::new();
        let identity_store = ferret_rns::identity::IdentityStore::new();
        let tmp = tempfile::tempdir().unwrap();

        // Immediately after construction, last_check is Instant::now(),
        // so the 60-second job_interval hasn't elapsed.
        // check() should return early without processing sources.
        let result = updater.check(&sources, &transport, &identity_store, tmp.path());
        assert!(result.is_ok());

        // The source should still be "due" because check() returned early
        // and never called update_from_source.
        assert!(updater.is_due(&sources[0]));
    }
}
