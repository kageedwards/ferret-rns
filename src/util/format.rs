//! Output formatting utilities matching the Python RNS reference.
//!
//! Functions here produce human-readable strings for hex data, byte sizes,
//! bitrates, timestamps, and durations. Output formats are compatible with
//! the Python `RNS.prettyhexrep()`, `RNS.prettysize()`, `RNS.prettyspeed()`,
//! `RNS.prettytime()`, and `RNS.timestamp_str()` functions.

use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Hex formatting
// ---------------------------------------------------------------------------

/// Colon-delimited hex in angle brackets: `<a5:b3:c1:d2:...>`
///
/// Matches Python `RNS.prettyhexrep()`. Empty input returns `<>`.
pub fn pretty_hex(data: &[u8]) -> String {
    if data.is_empty() {
        return "<>".to_string();
    }
    let inner: String = data
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");
    format!("<{}>", inner)
}

/// Plain hex without delimiters: `a5b3c1d2...`
///
/// Matches Python `RNS.hexrep(delimit=False)`. Empty input returns `""`.
pub fn hex_plain(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Human-readable sizes and speeds
// ---------------------------------------------------------------------------

/// Human-readable byte size: `"1.23 KB"`, `"456 MB"`.
///
/// Matches Python `RNS.prettysize()` — uses SI-style 1000-based units
/// (not 1024). The numeric part stays below 1000 for all but the largest
/// unit.
pub fn size_str(num: f64) -> String {
    prettysize(num, "B")
}

/// Human-readable bitrate: `"1.23 Kbps"`, `"456 Mbps"`.
///
/// Matches Python `RNS.prettyspeed(num)` which calls
/// `prettysize(num/8, suffix="b") + "ps"`. The `prettysize` function
/// with `suffix="b"` multiplies by 8 internally, so the net input to
/// the formatter is `num` in bits/sec.
///
/// The `bytes_per_sec` parameter here matches the Python calling convention
/// where the argument is already in *bits* per second (the Python name is
/// misleading — `prettyspeed` receives bits/sec from callers like rnstatus).
pub fn speed_str(bits_per_sec: f64) -> String {
    // Python: prettyspeed(num) => prettysize(num/8, suffix="b")+"ps"
    // prettysize(x, "b") does x *= 8, so net = num in bits.
    let result = prettysize(bits_per_sec / 8.0, "b");
    format!("{}ps", result)
}

/// Core formatting engine matching Python `RNS.prettysize()`.
///
/// When `suffix` is `"b"`, the value is multiplied by 8 (bytes→bits)
/// before formatting, matching the Python reference behavior.
fn prettysize(num: f64, suffix: &str) -> String {
    let mut num = num;
    let units = ["", "K", "M", "G", "T", "P", "E", "Z"];
    let last_unit = "Y";

    if suffix == "b" {
        num *= 8.0;
    }

    for unit in &units {
        if num.abs() < 1000.0 {
            if unit.is_empty() {
                return format!("{:.0} {}{}", num, unit, suffix);
            } else {
                return format!("{:.2} {}{}", num, unit, suffix);
            }
        }
        num /= 1000.0;
    }

    format!("{:.2} {}{}", num, last_unit, suffix)
}

// ---------------------------------------------------------------------------
// Time formatting
// ---------------------------------------------------------------------------

/// Relative time description: `"5 minutes ago"`, `"2 hours ago"`.
///
/// This is a ferret-original function (no Python reference counterpart).
/// Produces a human-friendly relative time string from a UNIX timestamp.
pub fn pretty_date(timestamp: f64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let diff = now - timestamp;

    if diff < 0.0 {
        return "in the future".to_string();
    }

    let seconds = diff as u64;
    if seconds < 60 {
        return if seconds == 1 {
            "1 second ago".to_string()
        } else {
            format!("{} seconds ago", seconds)
        };
    }

    let minutes = seconds / 60;
    if minutes < 60 {
        return if minutes == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", minutes)
        };
    }

    let hours = minutes / 60;
    if hours < 24 {
        return if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        };
    }

    let days = hours / 24;
    if days == 1 {
        "1 day ago".to_string()
    } else {
        format!("{} days ago", days)
    }
}

/// Absolute timestamp: `"2024-01-15 14:30:00"`.
///
/// Matches Python `RNS.timestamp_str()` using the default log time format
/// `"%Y-%m-%d %H:%M:%S"`.
pub fn timestamp_str(time_s: f64) -> String {
    let secs = time_s as i64;
    // Break into components using libc-free arithmetic (UTC).
    let (year, month, day, hour, min, sec) = unix_to_utc(secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}

/// Duration formatting: `"5m 30s"`, `"2h 15m"`.
///
/// Matches Python `RNS.prettytime()` in non-verbose, non-compact mode.
/// Components are joined with `, ` and the last pair with ` and `.
pub fn pretty_time(seconds: f64) -> String {
    let neg = seconds < 0.0;
    let seconds = seconds.abs();

    let total_secs = seconds;
    let days = (total_secs / (24.0 * 3600.0)) as u64;
    let remainder = total_secs % (24.0 * 3600.0);
    let hours = (remainder / 3600.0) as u64;
    let remainder = remainder % 3600.0;
    let minutes = (remainder / 60.0) as u64;
    let secs = (remainder % 60.0 * 100.0).round() / 100.0; // round to 2 decimals

    let mut components = Vec::new();
    if days > 0 {
        components.push(format!("{}d", days));
    }
    if hours > 0 {
        components.push(format!("{}h", hours));
    }
    if minutes > 0 {
        components.push(format!("{}m", minutes));
    }
    if secs > 0.0 {
        // Match Python: integer seconds show as "5s", fractional as "5.25s"
        if secs == secs.floor() {
            components.push(format!("{}s", secs as u64));
        } else {
            components.push(format!("{}s", secs));
        }
    }

    if components.is_empty() {
        return "0s".to_string();
    }

    let tstr = join_components(&components);
    if neg {
        format!("-{}", tstr)
    } else {
        tstr
    }
}

/// Join components with `, ` between items and ` and ` before the last.
/// Matches the Python prettytime joining logic.
fn join_components(components: &[String]) -> String {
    match components.len() {
        0 => String::new(),
        1 => components[0].clone(),
        _ => {
            let (init, last) = components.split_at(components.len() - 1);
            format!("{} and {}", init.join(", "), last[0])
        }
    }
}

// ---------------------------------------------------------------------------
// UTC conversion (no external dependency)
// ---------------------------------------------------------------------------

/// Convert a UNIX timestamp (seconds since 1970-01-01 00:00:00 UTC) to
/// (year, month, day, hour, minute, second) in UTC.
fn unix_to_utc(timestamp: i64) -> (i64, u8, u8, u8, u8, u8) {
    let secs_per_day: i64 = 86400;
    let mut days = timestamp / secs_per_day;
    let mut day_secs = (timestamp % secs_per_day) as i64;
    if day_secs < 0 {
        day_secs += secs_per_day;
        days -= 1;
    }

    let hour = (day_secs / 3600) as u8;
    let min = ((day_secs % 3600) / 60) as u8;
    let sec = (day_secs % 60) as u8;

    // Days since 1970-01-01 (a Thursday). Convert to date using the
    // algorithm from Howard Hinnant's `chrono`-compatible date library.
    days += 719468; // shift epoch from 1970-01-01 to 0000-03-01
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u32; // day of era [0, 146096]
    let yoe =
        (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month index [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    (y, m as u8, d as u8, hour, min, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pretty_hex_basic() {
        assert_eq!(pretty_hex(&[0xde, 0xad, 0xbe, 0xef]), "<de:ad:be:ef>");
        assert_eq!(pretty_hex(&[]), "<>");
        assert_eq!(pretty_hex(&[0x00]), "<00>");
    }

    #[test]
    fn test_hex_plain_basic() {
        assert_eq!(hex_plain(&[0xde, 0xad]), "dead");
        assert_eq!(hex_plain(&[]), "");
    }

    #[test]
    fn test_size_str_basic() {
        assert_eq!(size_str(0.0), "0 B");
        assert_eq!(size_str(999.0), "999 B");
        assert_eq!(size_str(1000.0), "1.00 KB");
        assert_eq!(size_str(1_500_000.0), "1.50 MB");
    }

    #[test]
    fn test_speed_str_basic() {
        // 8000 bits/sec = 8.00 Kbps
        assert_eq!(speed_str(8000.0), "8.00 Kbps");
    }

    #[test]
    fn test_pretty_time_basic() {
        assert_eq!(pretty_time(0.0), "0s");
        assert_eq!(pretty_time(90.0), "1m and 30s");
        assert_eq!(pretty_time(3661.0), "1h, 1m and 1s");
    }

    #[test]
    fn test_timestamp_str_basic() {
        // 2024-01-15 00:00:00 UTC = 1705276800
        assert_eq!(timestamp_str(1705276800.0), "2024-01-15 00:00:00");
        // epoch
        assert_eq!(timestamp_str(0.0), "1970-01-01 00:00:00");
    }

    #[test]
    fn test_unix_to_utc_epoch() {
        assert_eq!(unix_to_utc(0), (1970, 1, 1, 0, 0, 0));
    }
}
