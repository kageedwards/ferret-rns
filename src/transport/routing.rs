// Path table queries — routing helpers on TransportState

use std::sync::Arc;

use crate::transport::InterfaceHandle;
use crate::transport::PATHFINDER_M;
use crate::Result;

use super::transport::TransportState;

impl TransportState {
    /// Check whether a path to the given destination hash exists.
    pub fn has_path(&self, dest_hash: &[u8; 16]) -> Result<bool> {
        let inner = self.read()?;
        Ok(inner.path_table.contains_key(dest_hash))
    }

    /// Return the hop count to a destination, or `PATHFINDER_M` if no path.
    pub fn hops_to(&self, dest_hash: &[u8; 16]) -> Result<u8> {
        let inner = self.read()?;
        Ok(inner
            .path_table
            .get(dest_hash)
            .map(|e| e.hops)
            .unwrap_or(PATHFINDER_M))
    }

    /// Return the next-hop transport id (received_from) for a destination.
    pub fn next_hop(&self, dest_hash: &[u8; 16]) -> Result<Option<[u8; 16]>> {
        let inner = self.read()?;
        Ok(inner.path_table.get(dest_hash).map(|e| e.received_from))
    }

    /// Return the interface on which the path to a destination was learned.
    pub fn next_hop_interface(
        &self,
        dest_hash: &[u8; 16],
    ) -> Result<Option<Arc<dyn InterfaceHandle>>> {
        let inner = self.read()?;
        Ok(inner
            .path_table
            .get(dest_hash)
            .map(|e| Arc::clone(&e.receiving_interface)))
    }

    /// Remove a path entry for the given destination hash.
    pub fn expire_path(&self, dest_hash: &[u8; 16]) -> Result<()> {
        let mut inner = self.write()?;
        inner.path_table.remove(dest_hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::transport::{PathEntry, TransportState};
    use crate::types::interface::InterfaceMode;

    /// Minimal test interface for routing tests.
    struct DummyInterface;

    impl InterfaceHandle for DummyInterface {
        fn transmit(&self, _raw: &[u8]) -> crate::Result<()> {
            Ok(())
        }
        fn is_outbound(&self) -> bool {
            true
        }
        fn bitrate(&self) -> Option<u64> {
            None
        }
        fn announce_allowed_at(&self) -> f64 {
            0.0
        }
        fn set_announce_allowed_at(&self, _t: f64) {}
        fn mode(&self) -> InterfaceMode {
            InterfaceMode::Full
        }
        fn interface_hash(&self) -> &[u8] {
            &[0u8; 16]
        }
    }

    fn insert_path(ts: &TransportState, dest_hash: [u8; 16], hops: u8) {
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);
        let entry = PathEntry {
            timestamp: 1000.0,
            received_from: [0xBB; 16],
            hops,
            expires: 2000.0,
            random_blobs: vec![],
            receiving_interface: iface,
            packet_hash: [0xCC; 32],
        };
        ts.inner
            .write()
            .unwrap()
            .path_table
            .insert(dest_hash, entry);
    }

    #[test]
    fn test_has_path() {
        let ts = TransportState::new();
        let hash = [0x01; 16];
        assert!(!ts.has_path(&hash).unwrap());
        insert_path(&ts, hash, 3);
        assert!(ts.has_path(&hash).unwrap());
    }

    #[test]
    fn test_hops_to_known_and_unknown() {
        let ts = TransportState::new();
        let hash = [0x02; 16];
        assert_eq!(ts.hops_to(&hash).unwrap(), PATHFINDER_M);
        insert_path(&ts, hash, 5);
        assert_eq!(ts.hops_to(&hash).unwrap(), 5);
    }

    #[test]
    fn test_next_hop() {
        let ts = TransportState::new();
        let hash = [0x03; 16];
        assert!(ts.next_hop(&hash).unwrap().is_none());
        insert_path(&ts, hash, 2);
        assert_eq!(ts.next_hop(&hash).unwrap().unwrap(), [0xBB; 16]);
    }

    #[test]
    fn test_next_hop_interface() {
        let ts = TransportState::new();
        let hash = [0x04; 16];
        assert!(ts.next_hop_interface(&hash).unwrap().is_none());
        insert_path(&ts, hash, 1);
        assert!(ts.next_hop_interface(&hash).unwrap().is_some());
    }

    #[test]
    fn test_expire_path() {
        let ts = TransportState::new();
        let hash = [0x05; 16];
        insert_path(&ts, hash, 4);
        assert!(ts.has_path(&hash).unwrap());
        ts.expire_path(&hash).unwrap();
        assert!(!ts.has_path(&hash).unwrap());
    }
}
