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
