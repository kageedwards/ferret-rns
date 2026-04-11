// Announce processing — validation, path table updates, rebroadcast

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::identity::{validate_announce, AnnounceData, Identity, IdentityStore, RatchetStore};
use crate::packet::packet::Packet;
use crate::transport::InterfaceHandle;
use crate::types::interface::InterfaceMode;
use crate::types::packet::ContextFlag;
use crate::Result;

use super::transport::{AnnounceEntry, PathEntry, TransportState};
use super::{
    AP_PATH_TIME, LOCAL_REBROADCASTS_MAX, PATHFINDER_E, PATHFINDER_RW, ROAMING_PATH_TIME,
};

impl TransportState {
    /// Process an incoming announce packet.
    ///
    /// Validates the announce, updates the path table, queues for rebroadcast
    /// if transport is enabled, and invokes registered announce handlers.
    pub fn process_announce(
        &self,
        packet: &mut Packet,
        interface: &Arc<dyn InterfaceHandle>,
        identity_store: &IdentityStore,
        ratchet_store: &RatchetStore,
    ) -> Result<()> {
        let now = now_f64();
        let context_flag = packet.context_flag == ContextFlag::Set;

        // Parse announce data
        let announce = AnnounceData::parse(
            &packet.data,
            &packet.destination_hash,
            context_flag,
        )?;

        // Step 1: Validate signature only first
        let packet_hash = packet.get_hash();
        if !validate_announce(&announce, identity_store, ratchet_store, true, &packet_hash)? {
            return Ok(());
        }

        // Step 2: Full validation (hash check, store identity, store ratchet)
        if !validate_announce(&announce, identity_store, ratchet_store, false, &packet_hash)? {
            return Ok(());
        }

        // Determine received_from
        let received_from = packet
            .transport_id
            .unwrap_or(packet.destination_hash);

        // Extract random_blob for dedup
        let mut random_blob = [0u8; 10];
        if announce.random_hash.len() >= 10 {
            random_blob.copy_from_slice(&announce.random_hash[..10]);
        }

        // Extract emission timestamp from random_hash bytes 5..10
        let emission_ts = if announce.random_hash.len() >= 10 {
            let mut ts_bytes = [0u8; 8];
            ts_bytes[3..8].copy_from_slice(&announce.random_hash[5..10]);
            u64::from_be_bytes(ts_bytes) as f64
        } else {
            0.0
        };

        // Compute path expiry based on interface mode
        let expiry = match interface.mode() {
            InterfaceMode::AccessPoint => now + AP_PATH_TIME as f64,
            InterfaceMode::Roaming => now + ROAMING_PATH_TIME as f64,
            _ => now + PATHFINDER_E as f64,
        };

        // Step 3: Determine whether to update path table
        let should_update = {
            let inner = self.read()?;
            match inner.path_table.get(&packet.destination_hash) {
                None => true, // Unknown destination — always add
                Some(existing) => {
                    let blob_is_new = !existing.random_blobs.contains(&random_blob);
                    if packet.hops as u8 <= existing.hops {
                        // Equal or fewer hops: update if new random_blob
                        blob_is_new
                    } else {
                        // More hops: only if path expired or emission is newer
                        let path_expired = now > existing.expires;
                        (path_expired || emission_ts > existing.timestamp) && blob_is_new
                    }
                }
            }
        };

        if should_update {
            let mut inner = self.write()?;
            // Preserve existing random_blobs and append new one
            let mut random_blobs = inner
                .path_table
                .get(&packet.destination_hash)
                .map(|e| e.random_blobs.clone())
                .unwrap_or_default();
            if !random_blobs.contains(&random_blob) {
                random_blobs.push(random_blob);
            }

            let entry = PathEntry {
                timestamp: emission_ts,
                received_from,
                hops: packet.hops,
                expires: expiry,
                random_blobs,
                receiving_interface: Arc::clone(interface),
                packet_hash,
            };
            inner.path_table.insert(packet.destination_hash, entry);
            drop(inner);
        }

        // Step 4: Queue for rebroadcast if transport is enabled
        let is_path_response =
            packet.context == crate::types::packet::PacketContext::PathResponse;
        {
            let inner = self.read()?;
            if inner.transport_enabled && !is_path_response {
                drop(inner);
                self.queue_announce_rebroadcast(packet, interface, received_from, now)?;
            }
        }

        // Step 5: Invoke announce handlers
        self.invoke_announce_handlers(&announce)?;

        Ok(())
    }

    /// Queue an announce for rebroadcast in the announce table.
    fn queue_announce_rebroadcast(
        &self,
        packet: &Packet,
        interface: &Arc<dyn InterfaceHandle>,
        received_from: [u8; 16],
        now: f64,
    ) -> Result<()> {
        let mut inner = self.write()?;

        // Check if we already have this announce queued
        if let Some(existing) = inner.announce_table.get_mut(&packet.destination_hash) {
            // Another node rebroadcast — increment local_rebroadcasts
            existing.local_rebroadcasts += 1;
            if existing.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                inner.announce_table.remove(&packet.destination_hash);
            }
            return Ok(());
        }

        let retransmit_timeout = now + rand::Rng::gen_range(&mut rand::thread_rng(), 0.0..PATHFINDER_RW);

        let entry = AnnounceEntry {
            timestamp: now,
            retransmit_timeout,
            retries: 0,
            received_from,
            hops: packet.hops,
            packet: Packet::from_raw(packet.raw.clone()),
            local_rebroadcasts: 0,
            attached_interface: None,
            receiving_interface: Arc::clone(interface),
        };
        inner.announce_table.insert(packet.destination_hash, entry);

        Ok(())
    }

    /// Invoke all registered announce handlers whose aspect_filter matches.
    fn invoke_announce_handlers(&self, announce: &AnnounceData) -> Result<()> {
        let inner = self.read()?;

        // Reconstruct identity from public key for the callback
        let identity = Identity::from_public_key(&announce.public_key)?;

        // Build destination hash as [u8; 16]
        let mut dest_hash = [0u8; 16];
        if announce.destination_hash.len() >= 16 {
            dest_hash.copy_from_slice(&announce.destination_hash[..16]);
        }

        for handler in &inner.announce_handlers {
            // The aspect_filter is matched against the name_hash portion.
            // In the Python reference, this checks if the destination's
            // full name starts with the aspect_filter. Since we only have
            // the name_hash here, we invoke all handlers and let them
            // filter internally. A more precise filter would require
            // storing the full destination name in the path table.
            // For now, invoke all handlers (matching Python's behavior
            // when aspect_filter is None or empty).
            (handler.callback)(
                &dest_hash,
                &identity,
                announce.app_data.as_deref(),
            );
        }

        Ok(())
    }
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::destination::Destination;
    use crate::identity::RatchetStore;
    use crate::transport::transport::TransportState;
    use crate::types::destination::{DestinationDirection, DestinationType};
    use crate::types::interface::InterfaceMode;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    fn make_ratchet_store() -> RatchetStore {
        let tmp = tempfile::tempdir().unwrap();
        RatchetStore::new(tmp.path().to_path_buf())
    }

    #[test]
    fn test_process_announce_adds_path() {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);
        let store = IdentityStore::new();
        let ratchet_store = make_ratchet_store();

        // Build a real announce from a destination
        let mut dest = Destination::new(
            None,
            DestinationDirection::In,
            DestinationType::Single,
            "testapp",
            &["aspect1"],
        )
        .unwrap();

        let mut pkt = dest.announce(None, false, None, false, None).unwrap().unwrap();
        // Pack the announce packet to populate raw bytes
        pkt.pack(&dest).unwrap();
        let mut announce_pkt = Packet::from_raw(pkt.raw.clone());
        announce_pkt.unpack().unwrap();

        ts.process_announce(&mut announce_pkt, &iface, &store, &ratchet_store)
            .unwrap();

        // Path table should now have an entry
        assert!(ts.has_path(&announce_pkt.destination_hash).unwrap());
    }

    #[test]
    fn test_announce_handler_invoked() {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);
        let store = IdentityStore::new();
        let ratchet_store = make_ratchet_store();

        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();
        let handler = crate::transport::AnnounceHandler {
            aspect_filter: "testapp".to_string(),
            callback: Box::new(move |_hash, _id, _data| {
                cc.fetch_add(1, Ordering::SeqCst);
            }),
        };
        ts.register_announce_handler(handler).unwrap();

        let mut dest = Destination::new(
            None,
            DestinationDirection::In,
            DestinationType::Single,
            "testapp",
            &[],
        )
        .unwrap();

        let mut pkt = dest.announce(None, false, None, false, None).unwrap().unwrap();
        pkt.pack(&dest).unwrap();
        let mut announce_pkt = Packet::from_raw(pkt.raw.clone());
        announce_pkt.unpack().unwrap();

        ts.process_announce(&mut announce_pkt, &iface, &store, &ratchet_store)
            .unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
