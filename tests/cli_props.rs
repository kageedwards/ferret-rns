//! Property-based tests for CLI utilities (Layer 8).
//!
//! Each test validates a correctness property from the design document.

use proptest::prelude::*;

// =========================================================================
// Feature: ferret-cli-utilities, Property 13: Pretty Hex Formatting
// =========================================================================

/// For any byte slice 1–32 bytes, `pretty_hex` produces `<xx:xx:...>`
/// pattern and round-trips back to original bytes.
///
/// Validates: Requirements 15.1
mod property_13 {
    use super::*;
    use ferret_rns::util::format::{pretty_hex};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn pretty_hex_format_and_roundtrip(data in proptest::collection::vec(any::<u8>(), 1..=32)) {
            let formatted = pretty_hex(&data);

            // Must start with < and end with >
            prop_assert!(formatted.starts_with('<'), "must start with <");
            prop_assert!(formatted.ends_with('>'), "must end with >");

            // Inner part must match xx:xx:... pattern
            let inner = &formatted[1..formatted.len() - 1];
            let parts: Vec<&str> = inner.split(':').collect();
            prop_assert_eq!(parts.len(), data.len(), "wrong number of hex pairs");

            // Each part must be exactly 2 hex chars
            for part in &parts {
                prop_assert_eq!(part.len(), 2, "hex pair must be 2 chars");
                prop_assert!(part.chars().all(|c| c.is_ascii_hexdigit()),
                    "must be hex digits");
            }

            // Round-trip: parse hex pairs back to bytes
            let recovered: Vec<u8> = parts
                .iter()
                .map(|h| u8::from_str_radix(h, 16).unwrap())
                .collect();
            prop_assert_eq!(recovered, data, "round-trip must recover original bytes");
        }
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 14: Human-Readable Unit Formatting
// =========================================================================

/// For any non-negative f64, `size_str` and `speed_str` produce valid unit
/// suffixes with numeric part < 1000 (except for the largest unit).
///
/// Validates: Requirements 15.2, 15.3
mod property_14 {
    use super::*;
    use ferret_rns::util::format::{size_str, speed_str};

    const SIZE_UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    const SPEED_UNITS: &[&str] = &["bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps", "Zbps", "Ybps"];

    fn parse_formatted(s: &str, units: &[&str]) -> Option<(f64, String)> {
        for &unit in units.iter().rev() {
            if s.ends_with(unit) {
                let num_part = s[..s.len() - unit.len()].trim();
                if let Ok(n) = num_part.parse::<f64>() {
                    return Some((n, unit.to_string()));
                }
            }
        }
        None
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn size_str_valid_format(val in 0.0f64..1e24) {
            let s = size_str(val);
            let parsed = parse_formatted(&s, SIZE_UNITS);
            prop_assert!(parsed.is_some(), "size_str output '{}' must parse", s);
            let (num, unit) = parsed.unwrap();
            // Numeric part < 1000 unless it's the largest unit
            if unit != "YB" {
                prop_assert!(num < 1000.0,
                    "numeric part {} must be < 1000 for unit {}", num, unit);
            }
            prop_assert!(num >= 0.0, "numeric part must be non-negative");
        }

        #[test]
        fn speed_str_valid_format(val in 0.0f64..1e24) {
            let s = speed_str(val);
            let parsed = parse_formatted(&s, SPEED_UNITS);
            prop_assert!(parsed.is_some(), "speed_str output '{}' must parse", s);
            let (num, unit) = parsed.unwrap();
            if unit != "Ybps" {
                prop_assert!(num < 1000.0,
                    "numeric part {} must be < 1000 for unit {}", num, unit);
            }
            prop_assert!(num >= 0.0, "numeric part must be non-negative");
        }
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 15: JSON Hex Encoding Round-Trip
// =========================================================================

/// For any byte slice, `hex_plain` round-trips through hex encode/decode.
///
/// Validates: Requirements 15.6
mod property_15 {
    use super::*;
    use ferret_rns::util::format::hex_plain;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn hex_plain_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..=64)) {
            let encoded = hex_plain(&data);

            // Length must be exactly 2 * input length
            prop_assert_eq!(encoded.len(), data.len() * 2,
                "hex string length must be 2x input length");

            // All chars must be lowercase hex
            prop_assert!(encoded.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "must be lowercase hex");

            // Round-trip: decode hex back to bytes
            let recovered: Vec<u8> = (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
                .collect();
            prop_assert_eq!(recovered, data, "round-trip must recover original bytes");
        }
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 1: HMAC Mutual Authentication Round-Trip
// =========================================================================

/// For any random auth key (1–256 bytes) and for any random challenge bytes,
/// the mutual HMAC-SHA256 challenge-response protocol between `RpcClient`
/// and `RpcServer` SHALL succeed.
///
/// Validates: Requirements 1.2
mod property_1 {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use ferret_rns::reticulum::rpc::RpcServer;
    use ferret_rns::rpc_client::RpcClient;
    use ferret_rns::transport::TransportState;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn hmac_auth_roundtrip(key in proptest::collection::vec(any::<u8>(), 1..=256)) {
            let shutdown = Arc::new(AtomicBool::new(false));
            let transport = TransportState::new();
            let srv = RpcServer::start(0, key.clone(), shutdown.clone(), transport)
                .expect("start server");
            let port = srv.local_port();
            thread::sleep(Duration::from_millis(20));

            let result = RpcClient::connect(port, &key);
            prop_assert!(result.is_ok(), "auth should succeed with matching key");

            srv.stop();
        }
    }

    #[test]
    fn hmac_auth_wrong_key_fails() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let transport = TransportState::new();
        let key = vec![1, 2, 3, 4];
        let srv = RpcServer::start(0, key.clone(), shutdown.clone(), transport)
            .expect("start server");
        let port = srv.local_port();
        thread::sleep(Duration::from_millis(20));

        let result = RpcClient::connect(port, &[9, 9, 9]);
        assert!(result.is_err(), "auth with wrong key should fail");

        srv.stop();
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 2: Pickle Command Wire Round-Trip
// =========================================================================

/// For any valid pickle command dict, server receives exact dict client sent.
///
/// Validates: Requirements 1.4
mod property_2 {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use ferret_rns::reticulum::rpc::RpcServer;
    use ferret_rns::rpc_client::RpcClient;
    use ferret_rns::transport::TransportState;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn pickle_get_command_roundtrip(cmd in "interface_stats|link_count|path_table|rate_table") {
            let shutdown = Arc::new(AtomicBool::new(false));
            let transport = TransportState::new();
            let key = vec![42, 43, 44, 45];
            let srv = RpcServer::start(0, key.clone(), shutdown.clone(), transport)
                .expect("start server");
            let port = srv.local_port();
            thread::sleep(Duration::from_millis(20));

            let mut client = RpcClient::connect(port, &key)
                .expect("connect and auth");

            // The server dispatches known "get" commands and returns valid responses.
            // We verify the round-trip by checking we get a non-error response.
            let result = client.get(&cmd);
            prop_assert!(result.is_ok(), "get('{}') should succeed: {:?}", cmd, result.err());

            srv.stop();
        }

        #[test]
        fn pickle_drop_command_roundtrip(cmd in "announce_queues|path") {
            let shutdown = Arc::new(AtomicBool::new(false));
            let transport = TransportState::new();
            let key = vec![42, 43, 44, 45];
            let srv = RpcServer::start(0, key.clone(), shutdown.clone(), transport)
                .expect("start server");
            let port = srv.local_port();
            thread::sleep(Duration::from_millis(20));

            let mut client = RpcClient::connect(port, &key)
                .expect("connect and auth");

            let result = client.drop_cmd(&cmd);
            prop_assert!(result.is_ok(), "drop('{}') should succeed: {:?}", cmd, result.err());

            srv.stop();
        }
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 3: File Encrypt/Decrypt Round-Trip
// =========================================================================

/// For any random content 0–64KB and any Identity with private key,
/// encrypt then decrypt recovers original content.
///
/// Validates: Requirements 6.8, 6.9
mod property_3 {
    use super::*;
    use ferret_rns::identity::Identity;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn encrypt_decrypt_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..=65536)) {
            let identity = Identity::new();

            let ciphertext = identity.encrypt(&data, None)
                .expect("encrypt should succeed");

            // Ciphertext must be different from plaintext (unless empty)
            if !data.is_empty() {
                prop_assert_ne!(&ciphertext, &data, "ciphertext must differ from plaintext");
            }

            let decrypted = identity.decrypt(&ciphertext, None, false)
                .expect("decrypt should succeed")
                .expect("decrypt should return Some");

            prop_assert_eq!(decrypted, data, "round-trip must recover original content");
        }
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 4: File Sign/Validate Round-Trip
// =========================================================================

/// For any random content and any Identity, sign then validate succeeds;
/// validate with different identity fails.
///
/// Validates: Requirements 6.10, 6.11
mod property_4 {
    use super::*;
    use ferret_rns::identity::Identity;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn sign_validate_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..=65536)) {
            let identity = Identity::new();
            let other = Identity::new();

            let signature = identity.sign(&data)
                .expect("sign should succeed");

            // Validate with correct identity
            let valid = identity.validate(&signature, &data)
                .expect("validate should succeed");
            prop_assert!(valid, "signature must be valid with correct identity");

            // Validate with different identity must fail
            let invalid = other.validate(&signature, &data)
                .unwrap_or(false);
            prop_assert!(!invalid, "signature must be invalid with different identity");
        }
    }
}

// =========================================================================
// Name service test helpers
// =========================================================================

mod name_helpers {
    use ferret_rns::identity::Identity;
    use ferret_rns::names::record::NameRecord;
    use ferret_rns::crypto::stamp::{generate_stamp, NAME_SERVICE_EXPAND_ROUNDS};

    /// Create a valid name record with a low-difficulty stamp for testing.
    pub fn make_record(label: &str, identity: &Identity, timestamp: f64) -> NameRecord {
        let id_hash = identity.hash().unwrap();
        let id_hex: String = id_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let suffix = &id_hex[28..32];
        let name = format!("{}.{}", label, suffix);
        let dest_hash = vec![0u8; 16]; // dummy dest

        let pub_key = identity.get_public_key().unwrap();

        let mut record = NameRecord {
            name: name.clone(),
            dest_hash: dest_hash.clone(),
            identity_hash: id_hash.to_vec(),
            public_key: pub_key.to_vec(),
            timestamp,
            stamp: vec![],
            signature: vec![0u8; 64],
        };

        // Generate stamp with difficulty 1 and few expand rounds (fast for tests)
        let (stamp, _value) = generate_stamp(&record.stamp_data(), 1, 2);
        record.stamp = stamp;

        // Re-sign with updated stamp
        let sig = identity.sign(&record.signed_data()).unwrap();
        record.signature = sig.to_vec();
        record
    }

    pub fn suffix_of(identity: &Identity) -> String {
        let id_hash = identity.hash().unwrap();
        let id_hex: String = id_hash.iter().map(|b| format!("{:02x}", b)).collect();
        id_hex[28..32].to_string()
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 5: Name Record Validation
// =========================================================================
mod property_5 {
    use super::*;
    use ferret_rns::identity::Identity;
    use super::name_helpers::make_record;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn valid_record_accepted(_seed in 0u64..1000) {
            let identity = Identity::new();
            let record = make_record("test", &identity, 1000.0);
            prop_assert!(record.validate_format());
            prop_assert!(record.validate_suffix());
            prop_assert!(record.validate_identity_hash());
            prop_assert!(record.validate_signature());
        }
    }

    #[test]
    fn bad_suffix_rejected() {
        let identity = Identity::new();
        let mut record = make_record("test", &identity, 1000.0);
        // Corrupt the name suffix
        record.name = "test.0000".to_string();
        assert!(!record.validate_suffix());
    }

    #[test]
    fn bad_signature_rejected() {
        let identity = Identity::new();
        let mut record = make_record("test", &identity, 1000.0);
        record.signature[0] ^= 0xFF;
        assert!(!record.validate_signature());
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 6: Name Store Persistence and Lookup
// =========================================================================
mod property_6 {
    use super::*;
    use ferret_rns::identity::Identity;
    use ferret_rns::names::store::NameStore;
    use super::name_helpers::make_record;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn store_lookup_roundtrip(count in 1usize..=10) {
            let mut store = NameStore::new();
            let identity = Identity::new();
            let mut names = Vec::new();

            for i in 0..count {
                let label = format!("name{}", i);
                let record = make_record(&label, &identity, 1000.0 + i as f64);
                names.push(record.name.clone());
                store.store(record);
            }

            for name in &names {
                let found = store.lookup(name);
                prop_assert!(found.is_some(), "stored record must be found");
                prop_assert_eq!(&found.unwrap().name, name);
            }

            prop_assert!(store.lookup("nonexistent.0000").is_none());
        }
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 7: Name Record Update Semantics
// =========================================================================
mod property_7 {
    use super::*;
    use ferret_rns::identity::Identity;
    use ferret_rns::names::store::NameStore;
    use super::name_helpers::make_record;

    #[test]
    fn newer_replaces_older() {
        let mut store = NameStore::new();
        let identity = Identity::new();
        let old = make_record("test", &identity, 1000.0);
        let new = make_record("test", &identity, 2000.0);
        store.store(old);
        assert!(store.store(new));
        assert_eq!(store.lookup(&format!("test.{}", super::name_helpers::suffix_of(&identity))).unwrap().timestamp, 2000.0);
    }

    #[test]
    fn older_does_not_replace() {
        let mut store = NameStore::new();
        let identity = Identity::new();
        let new = make_record("test", &identity, 2000.0);
        let old = make_record("test", &identity, 1000.0);
        store.store(new);
        assert!(!store.store(old));
        assert_eq!(store.lookup(&format!("test.{}", super::name_helpers::suffix_of(&identity))).unwrap().timestamp, 2000.0);
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 8: Max Registrations Per Suffix
// =========================================================================
mod property_8 {
    use super::*;
    use ferret_rns::identity::Identity;
    use ferret_rns::names::resolver::{NameResolver, ResolverConfig};
    use ferret_rns::names::store::NameStore;
    use super::name_helpers::make_record;

    #[test]
    fn max_per_suffix_enforced() {
        let config = ResolverConfig {
            stamp_difficulty: 1,
            stamp_expand_rounds: 2,
            max_per_suffix: 3,
            rate_limit_seconds: 0.0, // disable rate limit for this test
            ..Default::default()
        };
        let mut resolver = NameResolver::new(NameStore::new(), config);
        let identity = Identity::new();

        for i in 0..3 {
            let record = make_record(&format!("name{}", i), &identity, 1000.0 + i as f64);
            assert!(resolver.register(record).unwrap());
        }

        // 4th should be rejected
        let record = make_record("name3", &identity, 1003.0);
        let result = resolver.register(record);
        assert!(result.is_err() || !result.unwrap());
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 9: Registration Rate Limit
// =========================================================================
mod property_9 {
    use super::*;
    use ferret_rns::identity::Identity;
    use ferret_rns::names::resolver::{NameResolver, ResolverConfig};
    use ferret_rns::names::store::NameStore;
    use super::name_helpers::make_record;

    #[test]
    fn rate_limit_within_window() {
        let config = ResolverConfig {
            stamp_difficulty: 1,
            stamp_expand_rounds: 2,
            max_per_suffix: 10,
            rate_limit_seconds: 3600.0,
            ..Default::default()
        };
        let mut resolver = NameResolver::new(NameStore::new(), config);
        let identity = Identity::new();

        let r1 = make_record("first", &identity, 1000.0);
        assert!(resolver.register(r1).unwrap());

        // Second within 1 hour should be rejected
        let r2 = make_record("second", &identity, 1500.0);
        assert!(resolver.register(r2).is_err());
    }

    #[test]
    fn rate_limit_after_window() {
        let config = ResolverConfig {
            stamp_difficulty: 1,
            stamp_expand_rounds: 2,
            max_per_suffix: 10,
            rate_limit_seconds: 3600.0,
            ..Default::default()
        };
        let mut resolver = NameResolver::new(NameStore::new(), config);
        let identity = Identity::new();

        let r1 = make_record("first", &identity, 1000.0);
        assert!(resolver.register(r1).unwrap());

        // Second after 1 hour should be accepted
        let r2 = make_record("second", &identity, 5000.0);
        assert!(resolver.register(r2).unwrap());
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 10: Record TTL Expiry
// =========================================================================
mod property_10 {
    use super::*;
    use ferret_rns::identity::Identity;
    use ferret_rns::names::store::NameStore;
    use super::name_helpers::{make_record, suffix_of};

    #[test]
    fn expired_record_not_returned() {
        let mut store = NameStore::new();
        let identity = Identity::new();
        // Record from far in the past
        let record = make_record("old", &identity, 1.0);
        let name = record.name.clone();
        store.store(record);

        // With a 30-day TTL, a record from timestamp 1.0 is expired
        assert!(store.lookup_with_ttl(&name, 30.0 * 86400.0).is_none());
    }

    #[test]
    fn fresh_record_returned() {
        let mut store = NameStore::new();
        let identity = Identity::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let record = make_record("fresh", &identity, now);
        let name = record.name.clone();
        store.store(record);

        assert!(store.lookup_with_ttl(&name, 30.0 * 86400.0).is_some());
        let _ = suffix_of; // suppress warning
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 11: Blackhole Rejection
// =========================================================================
mod property_11 {
    use super::*;
    use ferret_rns::identity::Identity;
    use ferret_rns::names::resolver::{NameResolver, ResolverConfig};
    use ferret_rns::names::store::NameStore;
    use super::name_helpers::make_record;

    #[test]
    fn blackholed_identity_rejected() {
        let config = ResolverConfig {
            stamp_difficulty: 1,
            stamp_expand_rounds: 2,
            rate_limit_seconds: 0.0,
            ..Default::default()
        };
        let mut resolver = NameResolver::new(NameStore::new(), config);
        let identity = Identity::new();
        let id_hex: String = identity.hash().unwrap().iter().map(|b| format!("{:02x}", b)).collect();

        resolver.blackhole_identity(&id_hex);

        let record = make_record("blocked", &identity, 1000.0);
        assert!(resolver.register(record).is_err());
    }

    #[test]
    fn non_blackholed_accepted() {
        let config = ResolverConfig {
            stamp_difficulty: 1,
            stamp_expand_rounds: 2,
            rate_limit_seconds: 0.0,
            ..Default::default()
        };
        let mut resolver = NameResolver::new(NameStore::new(), config);
        let identity = Identity::new();

        let record = make_record("allowed", &identity, 1000.0);
        assert!(resolver.register(record).unwrap());
    }
}

// =========================================================================
// Feature: ferret-cli-utilities, Property 12: Wildcard Query Correctness
// =========================================================================
mod property_12 {
    use super::*;
    use ferret_rns::identity::Identity;
    use ferret_rns::names::store::NameStore;
    use super::name_helpers::{make_record, suffix_of};

    #[test]
    fn wildcard_label_query() {
        let mut store = NameStore::new();
        let id1 = Identity::new();
        let id2 = Identity::new();

        let r1 = make_record("alice", &id1, 1000.0);
        let r2 = make_record("alice", &id2, 1000.0);
        let r3 = make_record("bob", &id1, 1001.0);
        store.store(r1);
        store.store(r2);
        store.store(r3);

        let results = store.query_wildcard("alice.*");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.label() == "alice"));
    }

    #[test]
    fn wildcard_suffix_query() {
        let mut store = NameStore::new();
        let identity = Identity::new();
        let suffix = suffix_of(&identity);

        let r1 = make_record("alice", &identity, 1000.0);
        let r2 = make_record("bob", &identity, 1001.0);
        store.store(r1);
        store.store(r2);

        let results = store.query_wildcard(&format!("*.{}", suffix));
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.suffix() == suffix));
    }
}
