pub mod error;
pub mod crypto;
pub mod types;
pub mod util;
pub mod identity;
pub mod destination;
pub mod packet;
pub mod transport;
pub mod link;
pub mod channel;
pub mod buffer;
pub mod resource;
pub mod discovery;
pub mod resolver;
pub mod interfaces;
pub mod reticulum;

pub use error::{FerretError, Result};

// ---------------------------------------------------------------------------
// Leveled logging macros
// ---------------------------------------------------------------------------

#[macro_export]
macro_rules! log_critical {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Critical,
            &format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Error,
            &format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! log_warning {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Warning,
            &format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! log_notice {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Notice,
            &format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Info,
            &format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! log_verbose {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Verbose,
            &format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Debug,
            &format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! log_extreme {
    ($($arg:tt)*) => {
        $crate::reticulum::logging::log(
            $crate::reticulum::logging::LogLevel::Extreme,
            &format!($($arg)*),
        )
    };
}
