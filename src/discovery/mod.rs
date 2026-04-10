// Discovery module: interface announcement, discovery, and blackhole management

pub mod announcer;
pub mod handler;
pub mod store;
pub mod autoconnect;
pub mod blackhole;
pub mod validation;

// ── Info field key constants (msgpack integer keys matching Python reference) ──

/// Interface name key.
pub const NAME: u8            = 0xFF;
/// Transport identity hash key.
pub const TRANSPORT_ID: u8    = 0xFE;
/// Interface type key.
pub const INTERFACE_TYPE: u8  = 0x00;
/// Transport enabled flag key.
pub const TRANSPORT: u8       = 0x01;
/// Reachable address key.
pub const REACHABLE_ON: u8    = 0x02;
/// Latitude key.
pub const LATITUDE: u8        = 0x03;
/// Longitude key.
pub const LONGITUDE: u8       = 0x04;
/// Height key.
pub const HEIGHT: u8          = 0x05;
/// Port key.
pub const PORT: u8            = 0x06;
/// IFAC network name key.
pub const IFAC_NETNAME: u8    = 0x07;
/// IFAC network key key.
pub const IFAC_NETKEY: u8     = 0x08;
/// Frequency key.
pub const FREQUENCY: u8       = 0x09;
/// Bandwidth key.
pub const BANDWIDTH: u8       = 0x0A;
/// Spreading factor key.
pub const SPREADINGFACTOR: u8 = 0x0B;
/// Coding rate key.
pub const CODINGRATE: u8      = 0x0C;
/// Modulation key.
pub const MODULATION: u8      = 0x0D;
/// Channel key.
pub const CHANNEL: u8         = 0x0E;

/// Application name for discovery destinations.
pub const APP_NAME: &str = "rnstransport";

// ── Discovery thresholds ──

/// Available threshold: 24 hours (seconds).
pub const THRESHOLD_UNKNOWN: u64 = 86_400;
/// Stale threshold: 3 days (seconds).
pub const THRESHOLD_STALE: u64   = 259_200;
/// Remove threshold: 7 days (seconds).
pub const THRESHOLD_REMOVE: u64  = 604_800;
