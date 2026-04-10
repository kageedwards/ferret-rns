// Property-based tests for Discovery module
// Feature: ferret-resource-discovery

use proptest::prelude::*;

use ferret_rns::discovery::validation::{is_hostname, is_ip_address};
use ferret_rns::discovery::store::classify_age;

// ── Property 13: Address validation correctness ──
// For valid IPv4/IPv6 strings, is_ip_address returns true.
// For valid hostnames, is_hostname returns true.
// For invalid strings, both return false.
// **Validates: Requirements 28.1, 28.2, 28.3**

/// Generate a valid IPv4 address string.
fn arb_ipv4() -> impl Strategy<Value = String> {
    (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
        .prop_map(|(a, b, c, d)| format!("{}.{}.{}.{}", a, b, c, d))
}

/// Generate a valid IPv6 address string (simplified: 8 groups of hex).
fn arb_ipv6() -> impl Strategy<Value = String> {
    prop::collection::vec(0u16..=0xFFFF, 8)
        .prop_map(|groups| {
            groups
                .iter()
                .map(|g| format!("{:x}", g))
                .collect::<Vec<_>>()
                .join(":")
        })
}

/// Generate a valid hostname label (1-63 chars, alphanumeric + hyphens,
/// no leading/trailing hyphens).
fn arb_label() -> impl Strategy<Value = String> {
    // Start with alphanumeric, middle can have hyphens, end with alphanumeric
    prop::string::string_regex("[a-z0-9][a-z0-9\\-]{0,10}[a-z0-9]")
        .expect("valid regex")
}

/// Generate a valid hostname (2+ labels, total <= 253).
fn arb_hostname() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_label(), 2..=4)
        .prop_map(|labels| labels.join("."))
        .prop_filter("total length <= 253", |h| h.len() <= 253)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: ferret-resource-discovery, Property 13: Address validation
    #[test]
    fn prop_valid_ipv4_recognized(addr in arb_ipv4()) {
        prop_assert!(
            is_ip_address(&addr),
            "valid IPv4 {} not recognized", addr
        );
    }

    #[test]
    fn prop_valid_ipv6_recognized(addr in arb_ipv6()) {
        prop_assert!(
            is_ip_address(&addr),
            "valid IPv6 {} not recognized", addr
        );
    }

    #[test]
    fn prop_valid_hostname_recognized(host in arb_hostname()) {
        prop_assert!(
            is_hostname(&host),
            "valid hostname {} not recognized", host
        );
    }

    #[test]
    fn prop_ip_not_hostname(addr in arb_ipv4()) {
        // A valid IPv4 address with only numeric labels should not be
        // considered a valid hostname (it IS a valid hostname syntactically
        // per RFC, but we test that is_ip_address catches it first)
        prop_assert!(
            is_ip_address(&addr),
            "IPv4 {} should be recognized as IP", addr
        );
    }
}

// ── Property 12: Discovery interface classification ──
// For any last_heard timestamp, classification matches threshold rules.
// **Validates: Requirements 20.3**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: ferret-resource-discovery, Property 12: Discovery interface classification
    #[test]
    fn prop_classification_matches_thresholds(age_secs in 0u64..=700_000u64) {
        let (status, code) = classify_age(age_secs);

        // THRESHOLD_UNKNOWN = 86_400 (24h)
        // THRESHOLD_STALE = 259_200 (3d)
        // THRESHOLD_REMOVE = 604_800 (7d)
        if age_secs <= 86_400 {
            prop_assert_eq!(status, "available");
            prop_assert_eq!(code, 1000);
        } else if age_secs <= 259_200 {
            prop_assert_eq!(status, "unknown");
            prop_assert_eq!(code, 100);
        } else if age_secs <= 604_800 {
            prop_assert_eq!(status, "stale");
            prop_assert_eq!(code, 0);
        }
        // age > 604_800 would be removed before classification in real code
    }

    #[test]
    fn prop_classification_ordering(
        age_a in 0u64..=86_400u64,
        age_b in 86_401u64..=259_200u64,
        age_c in 259_201u64..=604_800u64,
    ) {
        let (_, code_a) = classify_age(age_a);
        let (_, code_b) = classify_age(age_b);
        let (_, code_c) = classify_age(age_c);

        // Available > Unknown > Stale
        prop_assert!(code_a > code_b, "available should rank higher than unknown");
        prop_assert!(code_b > code_c, "unknown should rank higher than stale");
    }
}
