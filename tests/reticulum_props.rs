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
