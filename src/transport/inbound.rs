// Inbound reception — receive raw bytes, unpack, filter, route

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::identity::{IdentityStore, RatchetStore};
use crate::packet::packet::Packet;
use crate::transport::InterfaceHandle;
use crate::types::destination::DestinationType;
use crate::types::packet::{PacketContext, PacketType};
use crate::Result;

use super::transport::{ReverseEntry, TransportState};
use super::REVERSE_TIMEOUT;

impl TransportState {
    /// Receive raw bytes from an interface, unpack, filter, and route.
    ///
    /// This convenience method creates ephemeral stores. For production use,
    /// call `inbound_with_stores` with persistent stores.
    pub fn inbound(
        &self,
        raw: &[u8],
        interface: &Arc<dyn InterfaceHandle>,
    ) -> Result<()> {
        let tmp = std::env::temp_dir().join("ferret_ratchets_tmp");
        self.inbound_with_stores(raw, interface, &IdentityStore::new(), &RatchetStore::new(tmp))
    }

    /// Full inbound processing with explicit stores for announce validation.
    pub fn inbound_with_stores(
        &self,
        raw: &[u8],
        interface: &Arc<dyn InterfaceHandle>,
        identity_store: &IdentityStore,
        ratchet_store: &RatchetStore,
    ) -> Result<()> {
        // Step 1: Create packet from raw bytes, unpack, increment hops
        let mut packet = Packet::from_raw(raw.to_vec());
        packet.unpack()?;
        packet.hops = packet.hops.saturating_add(1);

        // Update the hops byte in raw as well
        if packet.raw.len() > 1 {
            packet.raw[1] = packet.hops;
        }

        // Step 1b: Local client routing — track source destinations from
        // local client interfaces so we can route replies back to them.
        let from_local_client = interface.is_local_client();
        if from_local_client {
            let mut inner = self.write()?;
            inner.local_client_destinations.insert(
                packet.destination_hash,
                Arc::clone(interface),
            );
            drop(inner);
        }

        // Step 2: Apply packet_filter
        if !self.packet_filter(&packet)? {
            return Ok(());
        }

        let packet_hash = packet.get_hash();
        let truncated_hash = packet.get_truncated_hash();

        // Step 3: Add to hashlist (unless dest_hash in link_table or LRPROOF)
        let in_link_table = {
            let inner = self.read()?;
            inner.link_table.contains_key(&packet.destination_hash)
        };
        let is_lrproof = packet.context == PacketContext::LrProof;

        if !in_link_table && !is_lrproof {
            self.add_packet_hash(&packet_hash)?;
        }

        // Step 3b: If packet arrived on a network interface and is destined
        // for a local client, forward it to the appropriate LocalClientInterface.
        if !from_local_client {
            let inner = self.read()?;
            if let Some(local_iface) = inner.local_client_destinations.get(&packet.destination_hash) {
                let local_iface = Arc::clone(local_iface);
                drop(inner);
                local_iface.transmit(&packet.raw)?;
                return Ok(());
            }
            drop(inner);
        }

        // Step 4: Transport forwarding
        if let Some(ref transport_id) = packet.transport_id {
            if self.is_our_transport_id(transport_id)? {
                self.forward_transport_packet(
                    &mut packet,
                    &packet_hash,
                    &truncated_hash,
                    interface,
                )?;
                return Ok(());
            }
        }

        // Step 5: Link table forwarding
        if in_link_table {
            self.forward_link_packet(&packet, interface)?;
            return Ok(());
        }

        // Step 6: Announce handling
        if packet.packet_type == PacketType::Announce {
            self.process_announce(&mut packet, interface, identity_store, ratchet_store)?;
            return Ok(());
        }

        // Step 7: Local delivery
        if self.deliver_local(&mut packet)? {
            return Ok(());
        }

        // Step 8: Proof routing
        if packet.packet_type == PacketType::Proof {
            self.route_proof(&packet, interface)?;
        }

        Ok(())
    }

    /// Check if a transport_id matches our identity hash.
    fn is_our_transport_id(&self, transport_id: &[u8; 16]) -> Result<bool> {
        let inner = self.read()?;
        match &inner.identity {
            Some(id) => {
                let our_hash = id.hash()?;
                Ok(our_hash == transport_id)
            }
            None => Ok(false),
        }
    }

    /// Forward a packet through transport (we are the transport node).
    fn forward_transport_packet(
        &self,
        packet: &mut Packet,
        _packet_hash: &[u8; 32],
        truncated_hash: &[u8; 16],
        receiving_interface: &Arc<dyn InterfaceHandle>,
    ) -> Result<()> {
        let inner = self.read()?;
        let path_entry = match inner.path_table.get(&packet.destination_hash) {
            Some(e) => e,
            None => return Ok(()), // No path — drop
        };

        let remaining_hops = path_entry.hops;
        let next_hop = path_entry.received_from;
        let outbound_iface = Arc::clone(&path_entry.receiving_interface);
        drop(inner);

        if remaining_hops > 1 {
            // Multi-hop: rewrite with new next_hop transport_id
            let new_raw = rewrite_transport_header(
                &packet.raw,
                packet.hops,
                &next_hop,
            );
            outbound_iface.transmit(&new_raw)?;
        } else {
            // Last hop: strip transport headers (Header2 → Header1)
            let stripped = strip_to_header1(&packet.raw, packet.flags, packet.hops);
            outbound_iface.transmit(&stripped)?;
        }

        // Add reverse table entry for proof routing
        let now = now_f64();
        let mut inner = self.write()?;
        inner.reverse_table.insert(
            *truncated_hash,
            ReverseEntry {
                receiving_interface: Arc::clone(receiving_interface),
                outbound_interface: outbound_iface,
                timestamp: now,
            },
        );

        Ok(())
    }

    /// Forward a packet via the link table.
    fn forward_link_packet(
        &self,
        packet: &Packet,
        receiving_interface: &Arc<dyn InterfaceHandle>,
    ) -> Result<()> {
        let inner = self.read()?;
        let link_entry = match inner.link_table.get(&packet.destination_hash) {
            Some(e) => e,
            None => return Ok(()),
        };

        // Forward on the opposite interface from where we received it
        let forward_iface = if Arc::ptr_eq(
            &link_entry.receiving_interface,
            receiving_interface,
        ) {
            Arc::clone(&link_entry.next_hop_interface)
        } else {
            Arc::clone(&link_entry.receiving_interface)
        };

        forward_iface.transmit(&packet.raw)?;
        Ok(())
    }

    /// Deliver a packet to a locally registered destination.
    fn deliver_local(&self, packet: &mut Packet) -> Result<bool> {
        let inner = self.read()?;
        let dest = inner
            .destinations
            .iter()
            .find(|d| {
                d.read()
                    .map(|d| d.hash == packet.destination_hash)
                    .unwrap_or(false)
            })
            .cloned();
        drop(inner);

        if let Some(dest) = dest {
            let mut d = dest
                .write()
                .map_err(|_| crate::FerretError::Token("lock poisoned".into()))?;
            d.receive(packet)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Route a proof packet via reverse table or validate against local receipts.
    fn route_proof(
        &self,
        packet: &Packet,
        _receiving_interface: &Arc<dyn InterfaceHandle>,
    ) -> Result<()> {
        let now = now_f64();

        // LRPROOF context: forward via link_table
        if packet.context == PacketContext::LrProof {
            self.forward_link_packet(packet, _receiving_interface)?;
            return Ok(());
        }

        // Check reverse table
        let truncated_hash = packet.destination_hash;
        let inner = self.read()?;
        if let Some(reverse_entry) = inner.reverse_table.get(&truncated_hash) {
            if now - reverse_entry.timestamp < REVERSE_TIMEOUT as f64 {
                let iface = Arc::clone(&reverse_entry.receiving_interface);
                drop(inner);
                iface.transmit(&packet.raw)?;
                return Ok(());
            }
        }
        drop(inner);

        // Check local receipts
        self.validate_proof_against_receipts(packet)?;

        Ok(())
    }

    /// Validate a proof against locally tracked receipts.
    fn validate_proof_against_receipts(&self, packet: &Packet) -> Result<()> {
        let mut inner = self.write()?;
        for receipt in &mut inner.receipts {
            if receipt.truncated_hash == packet.destination_hash {
                receipt.validate_proof(&packet.data);
                break;
            }
        }
        Ok(())
    }
}

impl TransportState {
    /// Apply packet filtering rules. Returns true if the packet should be processed.
    ///
    /// Rules (in order):
    /// 1. If packet has transport_id != our identity hash and not ANNOUNCE: reject
    /// 2. Context bypasses (always accept): KEEPALIVE, RESOURCE_REQ, RESOURCE_PRF,
    ///    RESOURCE, CACHE_REQUEST, CHANNEL
    /// 3. PLAIN/GROUP non-ANNOUNCE with hops > 1: reject (local-only)
    /// 4. PLAIN/GROUP ANNOUNCE: reject (invalid announce type)
    /// 5. If hash not in hashlist: accept
    /// 6. If hash in hashlist but packet is ANNOUNCE for SINGLE dest: accept (re-announce)
    /// 7. Otherwise: reject (duplicate)
    pub fn packet_filter(&self, packet: &Packet) -> Result<bool> {
        // Rule 1: Transport ID mismatch
        if let Some(ref transport_id) = packet.transport_id {
            if packet.packet_type != PacketType::Announce {
                if !self.is_our_transport_id(transport_id)? {
                    return Ok(false);
                }
            }
        }

        // Rule 2: Context bypasses
        match packet.context {
            PacketContext::Keepalive
            | PacketContext::ResourceReq
            | PacketContext::ResourcePrf
            | PacketContext::Resource
            | PacketContext::CacheRequest
            | PacketContext::Channel => return Ok(true),
            _ => {}
        }

        // Rule 3: PLAIN/GROUP non-ANNOUNCE with hops > 1
        if (packet.destination_type == DestinationType::Plain
            || packet.destination_type == DestinationType::Group)
            && packet.packet_type != PacketType::Announce
            && packet.hops > 1
        {
            return Ok(false);
        }

        // Rule 4: PLAIN/GROUP ANNOUNCE
        if (packet.destination_type == DestinationType::Plain
            || packet.destination_type == DestinationType::Group)
            && packet.packet_type == PacketType::Announce
        {
            return Ok(false);
        }

        // Rule 5: Not in hashlist — accept
        let hash = packet.get_hash();
        if !self.contains_packet_hash(&hash)? {
            return Ok(true);
        }

        // Rule 6: In hashlist but ANNOUNCE for SINGLE — allow re-announce
        if packet.packet_type == PacketType::Announce
            && packet.destination_type == DestinationType::Single
        {
            return Ok(true);
        }

        // Rule 7: Duplicate
        Ok(false)
    }
}

/// Rewrite transport header with a new next-hop transport_id.
/// Keeps the existing flags and updates hops byte in raw.
fn rewrite_transport_header(
    raw: &[u8],
    hops: u8,
    next_hop_transport_id: &[u8; 16],
) -> Vec<u8> {
    if raw.len() < 18 {
        return raw.to_vec();
    }
    let mut new_raw = raw.to_vec();
    new_raw[1] = hops;
    new_raw[2..18].copy_from_slice(next_hop_transport_id);
    new_raw
}

/// Strip a Header2 packet to Header1 by removing the transport_id.
///
/// Header2: [flags][hops][transport_id:16][dest_hash:16][context][data...]
/// Header1: [flags][hops][dest_hash:16][context][data...]
fn strip_to_header1(raw: &[u8], flags: u8, hops: u8) -> Vec<u8> {
    if raw.len() < 35 {
        return raw.to_vec();
    }
    // Clear header_type to Header1 and transport_type to Broadcast
    let new_flags = flags & 0x0F; // Keep lower nibble, clear upper

    let mut new_raw = Vec::with_capacity(raw.len() - 16);
    new_raw.push(new_flags);
    new_raw.push(hops);
    // Skip transport_id (bytes 2..18), copy dest_hash + context + data (bytes 18..)
    new_raw.extend_from_slice(&raw[18..]);
    new_raw
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
    use crate::packet::proof::ProofDestination;
    use crate::transport::transport::TransportState;
    use crate::types::interface::InterfaceMode;
    use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
    use crate::types::transport::TransportType;

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

    fn make_packed_data_packet(dest_hash: [u8; 16]) -> Packet {
        let dest = ProofDestination::new(dest_hash);
        let mut pkt = Packet::new(
            &dest,
            vec![1, 2, 3],
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
    fn test_packet_filter_accepts_new_packet() {
        let ts = TransportState::new();
        let pkt = make_packed_data_packet([0x01; 16]);
        assert!(ts.packet_filter(&pkt).unwrap());
    }

    #[test]
    fn test_packet_filter_rejects_duplicate() {
        let ts = TransportState::new();
        let pkt = make_packed_data_packet([0x02; 16]);
        let hash = pkt.get_hash();
        ts.add_packet_hash(&hash).unwrap();
        assert!(!ts.packet_filter(&pkt).unwrap());
    }

    #[test]
    fn test_packet_filter_context_bypass() {
        let ts = TransportState::new();
        let dest = ProofDestination::new([0x03; 16]);
        let mut pkt = Packet::new(
            &dest,
            vec![1, 2, 3],
            PacketType::Data,
            PacketContext::Keepalive,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt.pack(&dest).unwrap();
        // Add to hashlist — should still pass due to context bypass
        let hash = pkt.get_hash();
        ts.add_packet_hash(&hash).unwrap();
        assert!(ts.packet_filter(&pkt).unwrap());
    }

    #[test]
    fn test_packet_filter_plain_multi_hop_rejected() {
        let ts = TransportState::new();
        let dest = ProofDestination::new([0x04; 16]);
        let mut pkt = Packet::new(
            &dest,
            vec![1, 2, 3],
            PacketType::Data,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt.destination_type = DestinationType::Plain;
        pkt.hops = 2;
        pkt.pack(&dest).unwrap();
        assert!(!ts.packet_filter(&pkt).unwrap());
    }

    #[test]
    fn test_packet_filter_plain_announce_rejected() {
        let ts = TransportState::new();
        let dest = ProofDestination::new([0x05; 16]);
        let mut pkt = Packet::new(
            &dest,
            vec![1, 2, 3],
            PacketType::Announce,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt.destination_type = DestinationType::Plain;
        pkt.pack(&dest).unwrap();
        assert!(!ts.packet_filter(&pkt).unwrap());
    }

    #[test]
    fn test_packet_filter_allows_single_reannounce() {
        let ts = TransportState::new();
        let dest = ProofDestination::new([0x06; 16]);
        let mut pkt = Packet::new(
            &dest,
            vec![1, 2, 3],
            PacketType::Announce,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        pkt.destination_type = DestinationType::Single;
        pkt.pack(&dest).unwrap();
        let hash = pkt.get_hash();
        ts.add_packet_hash(&hash).unwrap();
        // Should still pass — ANNOUNCE for SINGLE allows re-announce
        assert!(ts.packet_filter(&pkt).unwrap());
    }

    #[test]
    fn test_inbound_basic_delivery() {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);

        let pkt = make_packed_data_packet([0x07; 16]);
        // No registered destination — should just pass through without error
        ts.inbound(&pkt.raw, &iface).unwrap();
    }

    #[test]
    fn test_strip_to_header1() {
        // Build a Header2 raw: flags(1) + hops(1) + tid(16) + dest(16) + ctx(1) + data
        let mut raw = vec![0x50u8]; // Header2 flags
        raw.push(3); // hops
        raw.extend_from_slice(&[0x11; 16]); // transport_id
        raw.extend_from_slice(&[0x22; 16]); // dest_hash
        raw.push(0x00); // context
        raw.extend_from_slice(&[0xAA, 0xBB]); // data

        let stripped = strip_to_header1(&raw, 0x50, 3);
        // Should be: flags(lower nibble) + hops + dest_hash + context + data
        assert_eq!(stripped[0], 0x00); // lower nibble of 0x50 = 0x00
        assert_eq!(stripped[1], 3);
        assert_eq!(&stripped[2..18], &[0x22; 16]);
        assert_eq!(stripped[18], 0x00);
        assert_eq!(&stripped[19..], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_rewrite_transport_header() {
        let mut raw = vec![0x50u8]; // flags
        raw.push(2); // hops
        raw.extend_from_slice(&[0x11; 16]); // old transport_id
        raw.extend_from_slice(&[0x22; 16]); // dest_hash
        raw.push(0x00); // context

        let new_tid = [0x33; 16];
        let rewritten = rewrite_transport_header(&raw, 5, &new_tid);
        assert_eq!(rewritten[1], 5); // updated hops
        assert_eq!(&rewritten[2..18], &new_tid); // new transport_id
        assert_eq!(&rewritten[18..34], &[0x22; 16]); // dest_hash preserved
    }
}
