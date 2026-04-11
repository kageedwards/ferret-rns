pub mod transport;
pub mod routing;
pub mod outbound;
pub mod inbound;
pub mod announce;
pub mod cache;
pub mod hashlist;

use crate::types::interface::InterfaceMode;
use crate::Result;

/// Minimal interface contract. Layer 6 provides full implementations.
pub trait InterfaceHandle: Send + Sync {
    /// Transmit raw bytes on this interface.
    fn transmit(&self, raw: &[u8]) -> Result<()>;
    /// Whether this interface supports outbound transmission.
    fn is_outbound(&self) -> bool;
    /// Interface bitrate in bits/sec, if known.
    fn bitrate(&self) -> Option<u64>;
    /// Announce bandwidth cap as a percentage (default 2.0).
    fn announce_cap(&self) -> f64 { 2.0 }
    /// Earliest time an announce may be sent on this interface.
    fn announce_allowed_at(&self) -> f64;
    /// Update the earliest announce time.
    fn set_announce_allowed_at(&self, t: f64);
    /// Interface mode.
    fn mode(&self) -> InterfaceMode;
    /// Unique hash identifying this interface.
    fn interface_hash(&self) -> &[u8];
    /// Human-readable interface name (for RPC stats).
    fn name(&self) -> &str { "" }
    /// Total bytes received on this interface.
    fn rxb(&self) -> u64 { 0 }
    /// Total bytes transmitted on this interface.
    fn txb(&self) -> u64 { 0 }
    /// Whether this interface is currently online.
    fn is_online(&self) -> bool { false }
}

// Transport constants
pub const PATHFINDER_M: u8 = 128;
pub const PATHFINDER_R: u8 = 1;
pub const PATHFINDER_G: u64 = 5;
pub const PATHFINDER_RW: f64 = 0.5;
pub const PATHFINDER_E: u64 = 604_800;
pub const AP_PATH_TIME: u64 = 86_400;
pub const ROAMING_PATH_TIME: u64 = 21_600;
pub const LOCAL_REBROADCASTS_MAX: u8 = 2;
pub const PATH_REQUEST_TIMEOUT: u64 = 15;
pub const REVERSE_TIMEOUT: u64 = 480;
pub const DESTINATION_TIMEOUT: u64 = 604_800;
pub const MAX_RECEIPTS: usize = 1024;

// Re-exports (uncomment as types are implemented):
pub use transport::TransportState;
pub use transport::{
    ActiveLink, AnnounceEntry, AnnounceHandler, LinkEntry, PathEntry, PendingLink, ReverseEntry,
};
pub use hashlist::PacketHashlist;
