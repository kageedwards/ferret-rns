// TransportState — global routing state and registries

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::destination::destination::Destination;
use crate::identity::Identity;
use crate::link::link::Link;
use crate::packet::packet::Packet;
use crate::packet::receipt::PacketReceipt;
use crate::transport::hashlist::PacketHashlist;
use crate::transport::InterfaceHandle;
use crate::{FerretError, Result};

// ---------------------------------------------------------------------------
// Table entry structs
// ---------------------------------------------------------------------------

/// An entry in the path table, keyed by destination_hash.
pub struct PathEntry {
    pub timestamp: f64,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub receiving_interface: Arc<dyn InterfaceHandle>,
    pub packet_hash: [u8; 32],
}

/// An entry in the announce table, keyed by destination_hash.
pub struct AnnounceEntry {
    pub timestamp: f64,
    pub retransmit_timeout: f64,
    pub retries: u8,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub packet: Packet,
    pub local_rebroadcasts: u8,
    pub attached_interface: Option<Arc<dyn InterfaceHandle>>,
    pub receiving_interface: Arc<dyn InterfaceHandle>,
}

/// An entry in the reverse table, keyed by truncated packet hash.
pub struct ReverseEntry {
    pub receiving_interface: Arc<dyn InterfaceHandle>,
    pub outbound_interface: Arc<dyn InterfaceHandle>,
    pub timestamp: f64,
}

/// An entry in the link table, keyed by link_id.
pub struct LinkEntry {
    pub timestamp: f64,
    pub next_hop: [u8; 16],
    pub next_hop_interface: Arc<dyn InterfaceHandle>,
    pub remaining_hops: u8,
    pub receiving_interface: Arc<dyn InterfaceHandle>,
    pub taken_hops: u8,
    pub destination_hash: [u8; 16],
    pub validated: bool,
    pub proof_timeout: f64,
}

/// A registered announce handler with aspect filter and callback.
pub struct AnnounceHandler {
    pub aspect_filter: String,
    pub callback: Box<dyn Fn(&[u8; 16], &Identity, Option<&[u8]>) + Send + Sync>,
}

/// A link that has been requested but not yet established.
pub struct PendingLink {
    pub link_id: [u8; 16],
    pub destination_hash: [u8; 16],
    pub timestamp: f64,
    /// Optional reference to the actual Link for lifecycle checks.
    pub link: Option<Link>,
}

/// A link that has been fully established.
pub struct ActiveLink {
    pub link_id: [u8; 16],
    pub destination_hash: [u8; 16],
    pub timestamp: f64,
    /// Optional reference to the actual Link for lifecycle checks.
    pub link: Option<Link>,
}

// ---------------------------------------------------------------------------
// TransportInner — all mutable state behind the RwLock
// ---------------------------------------------------------------------------

pub(crate) struct TransportInner {
    pub(crate) identity: Option<Identity>,
    pub(crate) transport_enabled: bool,

    // Registries
    pub(crate) interfaces: Vec<Arc<dyn InterfaceHandle>>,
    pub(crate) destinations: Vec<Arc<RwLock<Destination>>>,
    pub(crate) pending_links: Vec<PendingLink>,
    pub(crate) active_links: Vec<ActiveLink>,
    pub(crate) receipts: Vec<PacketReceipt>,

    // Tables
    pub(crate) path_table: HashMap<[u8; 16], PathEntry>,
    pub(crate) announce_table: HashMap<[u8; 16], AnnounceEntry>,
    pub(crate) reverse_table: HashMap<[u8; 16], ReverseEntry>,
    pub(crate) link_table: HashMap<[u8; 16], LinkEntry>,

    // Dedup
    pub(crate) packet_hashlist: PacketHashlist,

    // Announce handlers
    pub(crate) announce_handlers: Vec<AnnounceHandler>,

    // Announce rate tracking
    pub(crate) announce_rate_table: HashMap<[u8; 16], Vec<f64>>,

    // Cache directory
    pub(crate) cache_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// TransportState — the public, cloneable handle
// ---------------------------------------------------------------------------

/// Thread-safe transport state shared across the application.
///
/// Internally wraps `Arc<RwLock<TransportInner>>` so it can be cloned
/// and passed to multiple threads cheaply.
#[derive(Clone)]
pub struct TransportState {
    pub(crate) inner: Arc<RwLock<TransportInner>>,
}

impl TransportState {
    /// Create a new, empty transport state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TransportInner {
                identity: None,
                transport_enabled: false,
                interfaces: Vec::new(),
                destinations: Vec::new(),
                pending_links: Vec::new(),
                active_links: Vec::new(),
                receipts: Vec::new(),
                path_table: HashMap::new(),
                announce_table: HashMap::new(),
                reverse_table: HashMap::new(),
                link_table: HashMap::new(),
                packet_hashlist: PacketHashlist::new(1_000_000),
                announce_handlers: Vec::new(),
                announce_rate_table: HashMap::new(),
                cache_dir: None,
            })),
        }
    }

    // -- helpers for lock acquisition --

    pub(crate) fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, TransportInner>> {
        self.inner
            .read()
            .map_err(|_| FerretError::Token("lock poisoned".into()))
    }

    pub(crate) fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, TransportInner>> {
        self.inner
            .write()
            .map_err(|_| FerretError::Token("lock poisoned".into()))
    }

    // -----------------------------------------------------------------------
    // Registration methods
    // -----------------------------------------------------------------------

    /// Register an IN-direction destination.
    ///
    /// Returns an error if a destination with the same hash is already registered.
    pub fn register_destination(&self, dest: Arc<RwLock<Destination>>) -> Result<()> {
        let hash = {
            let d = dest
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            d.hash
        };
        let mut inner = self.write()?;
        for existing in &inner.destinations {
            let e = existing
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            if e.hash == hash {
                return Err(FerretError::DuplicateDestination(hex::encode(&hash)));
            }
        }
        inner.destinations.push(dest);
        Ok(())
    }

    /// Remove a destination by its hash.
    pub fn deregister_destination(&self, hash: &[u8; 16]) -> Result<()> {
        let mut inner = self.write()?;
        inner.destinations.retain(|d| {
            d.read().map(|d| d.hash != *hash).unwrap_or(true)
        });
        Ok(())
    }

    /// Register a link. Pending links are added to `pending_links`.
    pub fn register_link(&self, link: PendingLink) -> Result<()> {
        let mut inner = self.write()?;
        inner.pending_links.push(link);
        Ok(())
    }

    /// Move a link from pending to active.
    pub fn activate_link(&self, link_id: &[u8; 16]) -> Result<()> {
        let mut inner = self.write()?;
        let pos = inner
            .pending_links
            .iter()
            .position(|l| &l.link_id == link_id);
        match pos {
            Some(idx) => {
                let pending = inner.pending_links.remove(idx);
                inner.active_links.push(ActiveLink {
                    link_id: pending.link_id,
                    destination_hash: pending.destination_hash,
                    timestamp: pending.timestamp,
                    link: pending.link,
                });
                Ok(())
            }
            None => Err(FerretError::Token(format!(
                "pending link not found: {}",
                hex::encode(link_id)
            ))),
        }
    }

    /// Register an announce handler.
    pub fn register_announce_handler(&self, handler: AnnounceHandler) -> Result<()> {
        let mut inner = self.write()?;
        inner.announce_handlers.push(handler);
        Ok(())
    }

    /// Remove an announce handler by its aspect filter.
    pub fn deregister_announce_handler(&self, aspect_filter: &str) -> Result<()> {
        let mut inner = self.write()?;
        inner
            .announce_handlers
            .retain(|h| h.aspect_filter != aspect_filter);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Dedup helpers (used by outbound/inbound in task 10)
    // -----------------------------------------------------------------------

    /// Insert a packet hash into the dedup hashlist.
    pub fn add_packet_hash(&self, hash: &[u8; 32]) -> Result<()> {
        let mut inner = self.write()?;
        inner.packet_hashlist.add(hash);
        Ok(())
    }

    /// Check whether a packet hash is already known.
    pub fn contains_packet_hash(&self, hash: &[u8; 32]) -> Result<bool> {
        let inner = self.read()?;
        Ok(inner.packet_hashlist.contains(hash))
    }

    // -----------------------------------------------------------------------
    // Link lifecycle checks (called from jobs thread)
    // -----------------------------------------------------------------------

    /// Run link lifecycle checks: expire timed-out requests on active links,
    /// check stale on active links, and check establishment timeout on pending links.
    ///
    /// Lock errors are logged and skipped (non-fatal).
    pub fn check_link_lifecycles(&self) {
        // 1. Active links: check pending request timeouts and stale detection
        let active_links: Vec<Link> = match self.read() {
            Ok(inner) => inner
                .active_links
                .iter()
                .filter_map(|al| al.link.clone())
                .collect(),
            Err(e) => {
                eprintln!("Warning: failed to read transport for active link checks: {e}");
                return;
            }
        };

        for link in &active_links {
            // Check pending request timeouts
            match link.write() {
                Ok(mut inner) => {
                    let now = crate::link::link::now();
                    for receipt in &mut inner.pending_requests {
                        if receipt.status == crate::link::request::RequestReceiptStatus::Sent
                            && (now - receipt.sent_at) > receipt.timeout
                        {
                            receipt.request_timed_out();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: failed to lock link for request timeout check: {e}");
                }
            }

            // Check stale
            if let Err(e) = link.check_stale() {
                eprintln!("Warning: failed to check link stale: {e}");
            }
        }

        // 2. Pending links: check establishment timeout
        let pending_links: Vec<Link> = match self.read() {
            Ok(inner) => inner
                .pending_links
                .iter()
                .filter_map(|pl| pl.link.clone())
                .collect(),
            Err(e) => {
                eprintln!("Warning: failed to read transport for pending link checks: {e}");
                return;
            }
        };

        for link in &pending_links {
            if let Err(e) = link.check_establishment_timeout() {
                eprintln!("Warning: failed to check link establishment timeout: {e}");
            }
        }
    }
}

// We need a tiny hex helper since we don't have the `hex` crate.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl Default for TransportState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::destination::Destination;
    use crate::types::destination::{DestinationDirection, DestinationType};
    use std::sync::{Arc, RwLock};

    fn make_dest(app_name: &str) -> Arc<RwLock<Destination>> {
        let dest = Destination::new(None, DestinationDirection::In, DestinationType::Plain, app_name, &[])
            .expect("valid destination");
        Arc::new(RwLock::new(dest))
    }

    #[test]
    fn test_register_and_deregister_destination() {
        let ts = TransportState::new();
        let dest = make_dest("testapp");
        let hash = dest.read().unwrap().hash;
        ts.register_destination(dest).unwrap();
        // duplicate should fail
        let dest2 = make_dest("testapp");
        assert!(ts.register_destination(dest2).is_err());
        // deregister
        ts.deregister_destination(&hash).unwrap();
        // now re-register should succeed
        let dest3 = make_dest("testapp");
        ts.register_destination(dest3).unwrap();
    }

    #[test]
    fn test_register_and_activate_link() {
        let ts = TransportState::new();
        let link = PendingLink {
            link_id: [0x01; 16],
            destination_hash: [0x02; 16],
            timestamp: 1000.0,
            link: None,
        };
        ts.register_link(link).unwrap();
        ts.activate_link(&[0x01; 16]).unwrap();
        // activating again should fail (no longer pending)
        assert!(ts.activate_link(&[0x01; 16]).is_err());
    }

    #[test]
    fn test_announce_handler_registration() {
        let ts = TransportState::new();
        let handler = AnnounceHandler {
            aspect_filter: "myapp".to_string(),
            callback: Box::new(|_hash, _id, _data| {}),
        };
        ts.register_announce_handler(handler).unwrap();
        ts.deregister_announce_handler("myapp").unwrap();
    }

    #[test]
    fn test_packet_hashlist_via_transport() {
        let ts = TransportState::new();
        let hash = [0xAA; 32];
        assert!(!ts.contains_packet_hash(&hash).unwrap());
        ts.add_packet_hash(&hash).unwrap();
        assert!(ts.contains_packet_hash(&hash).unwrap());
    }
}
