// Feature: ferret-main-process, Property 4: Log level clamping
// **Validates: Requirements 3.4**
//
// Feature: ferret-main-process, Property 7: Log entry format
// **Validates: Requirements 13.5**

use proptest::prelude::*;
use ferret_rns::reticulum::logging::{LogLevel, format_log_entry};

// ---------------------------------------------------------------------------
// Property 4: Log level clamping
// For any u8 value, LogLevel::from_u8(v) returns a LogLevel with
// discriminant in [0, 7]. Values 0-7 map to their exact variants,
// values > 7 clamp to Extreme (7).
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn log_level_clamping_in_range(v in 0u8..=255) {
        let level = LogLevel::from_u8(v);
        let disc = level as u8;
        prop_assert!(disc <= 7, "discriminant {} out of range for input {}", disc, v);
    }

    #[test]
    fn log_level_exact_mapping(v in 0u8..=7) {
        let level = LogLevel::from_u8(v);
        prop_assert_eq!(level as u8, v, "expected exact mapping for {}", v);
    }

    #[test]
    fn log_level_above_seven_clamps_to_extreme(v in 8u8..=255) {
        let level = LogLevel::from_u8(v);
        prop_assert_eq!(level, LogLevel::Extreme, "input {} should clamp to Extreme", v);
    }
}

// ---------------------------------------------------------------------------
// Property 7: Log entry format
// For any log message string and valid log level, format_log_entry produces
// a string matching `[YYYY-MM-DD HH:MM:SS] [Level]    message`.
// The timestamp portion is a valid date-time pattern.
// ---------------------------------------------------------------------------

/// Strategy that produces a LogLevel from the valid range.
fn log_level_strategy() -> impl Strategy<Value = LogLevel> {
    (0u8..=7).prop_map(LogLevel::from_u8)
}

/// Strategy for arbitrary printable log messages (no newlines to keep it
/// single-line, matching the reference format).
fn log_message_strategy() -> impl Strategy<Value = String> {
    "[^\n\r]{0,120}"
}

proptest! {
    #[test]
    fn log_entry_format_matches_pattern(
        level in log_level_strategy(),
        msg in log_message_strategy(),
    ) {
        let entry = format_log_entry(&level, &msg);

        // Must start with a bracketed timestamp: [YYYY-MM-DD HH:MM:SS]
        prop_assert!(entry.starts_with('['), "entry should start with '['");

        // Extract the timestamp portion (first 21 chars: [YYYY-MM-DD HH:MM:SS])
        prop_assert!(entry.len() >= 21, "entry too short: {}", entry.len());
        let ts = &entry[..21];
        prop_assert_eq!(&ts[0..1], "[");
        prop_assert_eq!(&ts[20..21], "]");

        // Verify digit positions in timestamp: [DDDD-DD-DD DD:DD:DD]
        let inner = &ts[1..20]; // "YYYY-MM-DD HH:MM:SS"
        for (i, c) in inner.chars().enumerate() {
            match i {
                4 | 7 => prop_assert_eq!(c, '-', "expected '-' at pos {}", i),
                10 => prop_assert_eq!(c, ' ', "expected ' ' at pos {}", i),
                13 | 16 => prop_assert_eq!(c, ':', "expected ':' at pos {}", i),
                _ => prop_assert!(c.is_ascii_digit(), "expected digit at pos {}, got '{}'", i, c),
            }
        }

        // After timestamp + space, expect the level tag
        let after_ts = &entry[22..]; // skip "] "
        let level_str = format!("[{}]", level.as_str());
        prop_assert!(
            after_ts.starts_with(&level_str),
            "expected level tag '{}' in '{}'", level_str, after_ts,
        );

        // The message should appear at the end
        prop_assert!(
            entry.ends_with(&msg),
            "entry should end with the message",
        );
    }
}

// ---------------------------------------------------------------------------
// Feature: ferret-main-process, Property 2: Configuration round-trip
// **Validates: Requirements 2.1, 2.4, 2.5, 2.6, 2.7, 14.1, 14.2, 14.3, 14.4**
//
// For any valid ParsedConfig, format_config then parse_config produces an
// equivalent ParsedConfig.
// ---------------------------------------------------------------------------

use ferret_rns::reticulum::config::{
    ParsedConfig, ReticulumSection, LoggingSection, InterfaceDefinition,
    ConfigValue, format_config, parse_config,
};

/// Strategy for a ConfigValue that round-trips cleanly.
/// Avoids Float (precision loss) and List (comma ambiguity).
/// Also avoids String values that look like bools or integers.
fn config_value_strategy() -> impl Strategy<Value = ConfigValue> {
    prop_oneof![
        // String values: alphanumeric, won't be confused with bool/int
        "[a-zA-Z][a-zA-Z0-9_]{0,15}".prop_filter(
            "must not parse as bool or integer",
            |s| {
                let lower = s.to_lowercase();
                lower != "yes" && lower != "no" && lower != "true" && lower != "false"
                    && s.parse::<i64>().is_err()
            },
        ).prop_map(ConfigValue::String),
        // Bool
        any::<bool>().prop_map(ConfigValue::Bool),
        // Integer (avoid 0/1 which could be ambiguous with bool — actually
        // infer_value checks bool first, so 0/1 stay as integers since they
        // don't match yes/no/true/false)
        (-1000i64..1000).prop_map(ConfigValue::Integer),
    ]
}

/// Strategy for a param key: alphanumeric, not colliding with reserved keys.
fn param_key_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{1,12}".prop_filter(
        "must not be reserved interface key",
        |s| s != "enabled" && s != "interface_enabled" && s != "type",
    )
}

/// Strategy for an InterfaceDefinition.
fn interface_definition_strategy() -> impl Strategy<Value = InterfaceDefinition> {
    (
        "[A-Za-z][A-Za-z0-9]{0,15}",           // name (no spaces to avoid trim issues)
        any::<bool>(),                           // enabled
        "[A-Za-z][A-Za-z0-9]{2,12}",            // interface_type
        proptest::collection::hash_map(
            param_key_strategy(),
            config_value_strategy(),
            0..4,
        ),
    )
        .prop_map(|(name, enabled, interface_type, params)| InterfaceDefinition {
            name,
            enabled,
            interface_type,
            params,
        })
}

/// Strategy for ReticulumSection with random bool fields and ports.
fn reticulum_section_strategy() -> impl Strategy<Value = ReticulumSection> {
    (
        any::<bool>(), // share_instance
        any::<bool>(), // enable_transport
        any::<bool>(), // use_implicit_proof
        any::<bool>(), // panic_on_interface_error
        any::<bool>(), // link_mtu_discovery
        any::<bool>(), // enable_remote_management
        any::<bool>(), // respond_to_probes
        any::<bool>(), // discover_interfaces
        any::<bool>(), // publish_blackhole
        (1u16..=65534u16), // shared_instance_port
        (1u16..=65534u16), // instance_control_port
    )
        .prop_map(
            |(
                share_instance,
                enable_transport,
                use_implicit_proof,
                panic_on_interface_error,
                link_mtu_discovery,
                enable_remote_management,
                respond_to_probes,
                discover_interfaces,
                publish_blackhole,
                shared_instance_port,
                instance_control_port,
            )| {
                ReticulumSection {
                    share_instance,
                    enable_transport,
                    use_implicit_proof,
                    panic_on_interface_error,
                    link_mtu_discovery,
                    enable_remote_management,
                    respond_to_probes,
                    discover_interfaces,
                    publish_blackhole,
                    shared_instance_port,
                    instance_control_port,
                    // Keep optional/complex fields at defaults for clean round-trip
                    rpc_key: None,
                    network_identity: None,
                    required_discovery_value: None,
                    blackhole_sources: Vec::new(),
                    interface_discovery_sources: Vec::new(),
                    autoconnect_discovered_interfaces: 0,
                    instance_name: None,
                }
            },
        )
}

/// Strategy for a full ParsedConfig.
fn parsed_config_strategy() -> impl Strategy<Value = ParsedConfig> {
    (
        reticulum_section_strategy(),
        (0u8..=7),  // loglevel
        proptest::collection::vec(interface_definition_strategy(), 0..4),
    )
        .prop_map(|(reticulum, loglevel, interfaces)| ParsedConfig {
            reticulum,
            logging: LoggingSection { loglevel },
            interfaces,
        })
}

proptest! {
    #[test]
    fn config_round_trip(config in parsed_config_strategy()) {
        let text = format_config(&config);
        let parsed = parse_config(&text).expect("round-trip parse should succeed");

        // Compare reticulum section
        prop_assert_eq!(&config.reticulum, &parsed.reticulum, "reticulum section mismatch");

        // Compare logging section
        prop_assert_eq!(config.logging.loglevel, parsed.logging.loglevel, "loglevel mismatch");

        // Compare interfaces
        prop_assert_eq!(
            config.interfaces.len(),
            parsed.interfaces.len(),
            "interface count mismatch"
        );
        for (orig, rt) in config.interfaces.iter().zip(parsed.interfaces.iter()) {
            prop_assert_eq!(&orig.name, &rt.name, "interface name mismatch");
            prop_assert_eq!(orig.enabled, rt.enabled, "interface enabled mismatch");
            prop_assert_eq!(&orig.interface_type, &rt.interface_type, "interface type mismatch");
            prop_assert_eq!(&orig.params, &rt.params, "interface params mismatch for '{}'", orig.name);
        }
    }
}

// ---------------------------------------------------------------------------
// Feature: ferret-main-process, Property 3: Config parser robustness
// **Validates: Requirements 2.3**
//
// For any arbitrary string input, parse_config either returns Ok or Err —
// never panics.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn config_parser_never_panics(input in "\\PC{0,500}") {
        // We only care that this doesn't panic. The result can be Ok or Err.
        let _result = parse_config(&input);
    }
}
