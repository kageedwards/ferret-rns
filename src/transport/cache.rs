// Packet cache — disk-backed storage for packet replay

use std::sync::Arc;

use crate::packet::packet::Packet;
use crate::transport::InterfaceHandle;
use crate::Result;

use super::transport::TransportState;

impl TransportState {
    /// Write a packet to the disk cache.
    ///
    /// Stores `[raw_bytes, interface_hash]` as msgpack to `{cache_dir}/{hex_hash}`.
    /// If `force` is false and the file already exists, this is a no-op.
    pub fn cache(
        &self,
        packet: &Packet,
        force: bool,
        interface: Option<&Arc<dyn InterfaceHandle>>,
    ) -> Result<()> {
        let inner = self.read()?;
        let cache_dir = match inner.cache_dir {
            Some(ref d) => d.clone(),
            None => return Ok(()),
        };
        drop(inner);

        let hash = packet.get_hash();
        let hex_name: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        let file_path = cache_dir.join(&hex_name);

        if !force && file_path.exists() {
            return Ok(());
        }

        // Ensure cache directory exists
        if !cache_dir.exists() {
            std::fs::create_dir_all(&cache_dir)?;
        }

        let iface_hash: Vec<u8> = interface
            .map(|i| i.interface_hash().to_vec())
            .unwrap_or_default();

        let entry: (Vec<u8>, Vec<u8>) = (packet.raw.clone(), iface_hash);
        let data = crate::util::msgpack::serialize(&entry)?;
        std::fs::write(&file_path, data)?;

        Ok(())
    }

    /// Retrieve a cached packet by its full 32-byte hash.
    ///
    /// Returns `None` if the cache file does not exist.
    pub fn get_cached_packet(&self, hash: &[u8; 32]) -> Result<Option<Packet>> {
        let inner = self.read()?;
        let cache_dir = match inner.cache_dir {
            Some(ref d) => d.clone(),
            None => return Ok(None),
        };
        drop(inner);

        let hex_name: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        let file_path = cache_dir.join(&hex_name);

        if !file_path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&file_path)?;
        let (raw, _iface_hash): (Vec<u8>, Vec<u8>) =
            crate::util::msgpack::deserialize(&data)?;

        let mut packet = Packet::from_raw(raw);
        packet.unpack()?;
        Ok(Some(packet))
    }

    /// Handle a cache request packet.
    ///
    /// If the packet's data is a 32-byte hash, look up the cached packet
    /// and replay it via inbound. Returns true if a cached packet was found
    /// and replayed.
    pub fn cache_request_packet(
        &self,
        packet: &Packet,
        interface: &Arc<dyn InterfaceHandle>,
    ) -> Result<bool> {
        if packet.data.len() != 32 {
            return Ok(false);
        }

        let mut requested_hash = [0u8; 32];
        requested_hash.copy_from_slice(&packet.data);

        let cached = self.get_cached_packet(&requested_hash)?;
        match cached {
            Some(cached_packet) => {
                self.inbound(&cached_packet.raw, interface)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::interface::InterfaceMode;
    use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
    use crate::types::transport::TransportType;
    use crate::packet::proof::ProofDestination;

    struct DummyInterface;
    impl InterfaceHandle for DummyInterface {
        fn transmit(&self, _raw: &[u8]) -> crate::Result<()> { Ok(()) }
        fn is_outbound(&self) -> bool { true }
        fn bitrate(&self) -> Option<u64> { None }
        fn announce_allowed_at(&self) -> f64 { 0.0 }
        fn set_announce_allowed_at(&self, _t: f64) {}
        fn mode(&self) -> InterfaceMode { InterfaceMode::Full }
        fn interface_hash(&self) -> &[u8] { &[0u8; 16] }
    }

    fn make_test_packet() -> Packet {
        let dest = ProofDestination::new([0xAA; 16]);
        let mut pkt = Packet::new(
            &dest,
            vec![1, 2, 3, 4],
            PacketType::Data,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt.pack(&dest).unwrap();
        pkt
    }

    #[test]
    fn test_cache_and_retrieve() {
        let ts = TransportState::new();
        let tmp = tempfile::tempdir().unwrap();
        ts.inner.write().unwrap().cache_dir = Some(tmp.path().to_path_buf());

        let pkt = make_test_packet();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);
        ts.cache(&pkt, false, Some(&iface)).unwrap();

        let hash = pkt.get_hash();
        let cached = ts.get_cached_packet(&hash).unwrap();
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.destination_hash, pkt.destination_hash);
    }

    #[test]
    fn test_get_cached_packet_missing() {
        let ts = TransportState::new();
        let tmp = tempfile::tempdir().unwrap();
        ts.inner.write().unwrap().cache_dir = Some(tmp.path().to_path_buf());

        let hash = [0xFF; 32];
        let cached = ts.get_cached_packet(&hash).unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn test_cache_no_dir_configured() {
        let ts = TransportState::new();
        let pkt = make_test_packet();
        // No cache_dir set — should be a no-op
        ts.cache(&pkt, false, None).unwrap();
        let hash = pkt.get_hash();
        assert!(ts.get_cached_packet(&hash).unwrap().is_none());
    }
}
