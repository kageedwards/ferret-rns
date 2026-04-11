use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum log file size before rotation (5 MB).
pub const LOG_MAXSIZE: u64 = 5_242_880;

/// Log severity levels matching the Python reference (0–7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Critical = 0,
    Error    = 1,
    Warning  = 2,
    Notice   = 3,
    Info     = 4,
    Verbose  = 5,
    Debug    = 6,
    Extreme  = 7,
}

impl LogLevel {
    /// Convert a `u8` to a `LogLevel`, clamping values > 7 to `Extreme`.
    pub fn from_u8(v: u8) -> LogLevel {
        match v {
            0 => LogLevel::Critical,
            1 => LogLevel::Error,
            2 => LogLevel::Warning,
            3 => LogLevel::Notice,
            4 => LogLevel::Info,
            5 => LogLevel::Verbose,
            6 => LogLevel::Debug,
            _ => LogLevel::Extreme,
        }
    }

    /// Return the level name as a static string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "Critical", Self::Error => "Error",
            Self::Warning => "Warning",   Self::Notice => "Notice",
            Self::Info => "Info",          Self::Verbose => "Verbose",
            Self::Debug => "Debug",        Self::Extreme => "Extreme",
        }
    }

    /// Bracketed, padded level tag for log lines.
    fn tag(&self) -> &'static str {
        match self {
            Self::Critical => "[Critical]", Self::Error   => "[Error]   ",
            Self::Warning  => "[Warning] ", Self::Notice  => "[Notice]  ",
            Self::Info     => "[Info]    ", Self::Verbose => "[Verbose] ",
            Self::Debug    => "[Debug]   ", Self::Extreme => "[Extreme] ",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where log output is directed.
pub enum LogDestination {
    Stdout,
    File(PathBuf),
    Callback(Box<dyn Fn(&str) + Send + Sync>),
}

/// Format a log entry as `[YYYY-MM-DD HH:MM:SS] [Level]    message`.
/// Uses `SystemTime` — no chrono dependency.
pub fn format_log_entry(level: &LogLevel, message: &str) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = secs_to_datetime(secs);
    format!(
        "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}] {} {}",
        y, mo, d, h, mi, s, level.tag(), message,
    )
}

/// Rotate a log file when it exceeds `LOG_MAXSIZE`.
/// Renames `path` → `path.1` so the caller can start a fresh file.
pub fn rotate_log_file(path: &Path) -> std::io::Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.len() <= LOG_MAXSIZE {
        return Ok(());
    }
    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(".1");
    let rotated = PathBuf::from(rotated);
    if rotated.exists() {
        fs::remove_file(&rotated)?;
    }
    fs::rename(path, &rotated)
}

// ── private helpers ─────────────────────────────────────────────────

fn secs_to_datetime(epoch: u64) -> (u64, u64, u64, u64, u64, u64) {
    let (s, mi, h) = (epoch % 60, (epoch / 60) % 60, (epoch / 3600) % 24);
    let mut days = epoch / 86400;
    let mut y = 1970u64;
    loop {
        let ylen: u64 = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if days < ylen { break; }
        days -= ylen;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let feb = if leap { 29 } else { 28 };
    let mdays = [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31u64];
    let mut mo = 0u64;
    for (i, &ml) in mdays.iter().enumerate() {
        if days < ml { mo = i as u64 + 1; break; }
        days -= ml;
    }
    (y, mo, days + 1, h, mi, s)
}
