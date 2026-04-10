// Outbound routing — send packets to the correct interfaces

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::packet::packet::Packet;
use crate::transport::InterfaceHandle;
use crate::types::destination::DestinationType;
use crate::types::interface::InterfaceMode;
use crate::types::packet::{HeaderType, PacketType};
use crate::types::transport::TransportType;
use crate::Result;

use super::transport::TransportState;

impl TransportState {
    /// Route an outbound packet to the correct interface(s).
    ///
    /// Returns `true` if the packet was transmitted on at least one interface.
    pub fn outbound(&self, packet: &mut Packet) -> Result<bool> {
        let mut sent = false;

        // For non-ANNOUNCE, non-PLAIN, non-GROUP packets: check path table
        let should_check_path = packet.packet_type != PacketType::Announce
            && packet.destination_type != DestinationType::Plain
            && packet.destination_type != DestinationType::Group;

        if should_check_path {
            let inner = self.read()?;
            if let Some(path_entry) = inner.path_table.get(&packet.destination_hash) {
                let hops = path_entry.hops;
                let iface = Arc::clone(&path_entry.receiving_interface);
                let next_hop = path_entry.received_from;
                drop(inner);

                if hops > 1 {
                    // Header1 → Header2 rewrite: insert transport headers
                    let new_raw = rewrite_header1_to_header2(
                        &packet.raw,
                        packet.flags,
                        packet.hops,
                        &next_hop,
                    );
                    iface.transmit(&new_raw)?;
                } else {
                    // Direct delivery — transmit as-is on path interface
                    iface.transmit(&packet.raw)?;
                }

                sent = true;
                self.mark_sent(packet)?;
                return Ok(sent);
            }
            drop(inner);
        }

        // No path found (or ANNOUNCE/PLAIN/GROUP): broadcast on all outbound interfaces
        let inner = self.read()?;
        let interfaces: Vec<Arc<dyn InterfaceHandle>> = inner
            .interfaces
            .iter()
            .filter(|i| i.is_outbound())
            .cloned()
            .collect();
        drop(inner);

        let now = now_f64();

        for iface in &interfaces {
            // For ANNOUNCE packets with hops > 0: apply rate limiting
            if packet.packet_type == PacketType::Announce && packet.hops > 0 {
                // AccessPoint mode blocks announce broadcasts
                if iface.mode() == InterfaceMode::AccessPoint {
                    continue;
                }

                // Roaming/Boundary: block unless from local destination
                if iface.mode() == InterfaceMode::Roaming
                    || iface.mode() == InterfaceMode::Boundary
                {
                    let is_local = self.is_local_destination(&packet.destination_hash)?;
                    if !is_local {
                        continue;
                    }
                }

                // Check announce rate limiting
                if !self.announce_allowed(iface, packet, now)? {
                    continue;
                }
            }

            iface.transmit(&packet.raw)?;
            sent = true;
        }

        if sent {
            self.mark_sent(packet)?;
        }

        Ok(sent)
    }

    /// Mark a packet as sent and add its hash to the hashlist.
    fn mark_sent(&self, packet: &mut Packet) -> Result<()> {
        packet.sent = true;
        packet.sent_at = Some(now_f64());
        if let Some(ref hash) = packet.packet_hash {
            self.add_packet_hash(hash)?;
        } else {
            let hash = packet.get_hash();
            self.add_packet_hash(&hash)?;
        }
        Ok(())
    }

    /// Check if a destination hash belongs to a locally registered destination.
    fn is_local_destination(&self, dest_hash: &[u8; 16]) -> Result<bool> {
        let inner = self.read()?;
        for dest in &inner.destinations {
            let d = dest
                .read()
                .map_err(|_| crate::FerretError::Token("lock poisoned".into()))?;
            if d.hash == *dest_hash {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check announce rate limiting for an interface.
    ///
    /// Returns true if the announce is allowed to be sent now.
    fn announce_allowed(
        &self,
        iface: &Arc<dyn InterfaceHandle>,
        packet: &Packet,
        now: f64,
    ) -> Result<bool> {
        let announce_cap = iface.announce_cap();
        // announce_cap >= 2.0 means no cap
        if announce_cap >= 2.0 {
            return Ok(true);
        }

        let allowed_at = iface.announce_allowed_at();
        if now < allowed_at {
            return Ok(false);
        }

        // Compute tx_time based on bitrate
        if let Some(bitrate) = iface.bitrate() {
            if bitrate > 0 {
                let tx_time = (packet.raw.len() as f64 * 8.0) / bitrate as f64;
                let wait_time = tx_time / announce_cap;
                iface.set_announce_allowed_at(now + wait_time);
            }
        }

        Ok(true)
    }
}

/// Rewrite a Header1 packet to Header2 by inserting transport headers.
///
/// New format: `[new_flags][hops][next_hop_transport_id:16][original_raw[2:]]`
fn rewrite_header1_to_header2(
    raw: &[u8],
    flags: u8,
    hops: u8,
    next_hop_transport_id: &[u8; 16],
) -> Vec<u8> {
    // Set header_type to Header2 (bit 6) and transport_type to Transport (bit 4)
    let new_flags = (HeaderType::Header2 as u8) << 6
        | (TransportType::Transport as u8) << 4
        | (flags & 0x0F);

    let mut new_raw = Vec::with_capacity(2 + 16 + raw.len() - 2);
    new_raw.push(new_flags);
    new_raw.push(hops);
    new_raw.extend_from_slice(next_hop_transport_id);
    if raw.len() > 2 {
        new_raw.extend_from_slice(&raw[2..]);
    }
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
    use crate::transport::transport::{PathEntry, TransportState};
    use crate::types::packet::{ContextFlag, PacketContext};

    struct TestInterface {
        transmitted: std::sync::Mutex<Vec<Vec<u8>>>,
        outbound: bool,
        mode: InterfaceMode,
    }

    impl TestInterface {
        fn new(outbound: bool, mode: InterfaceMode) -> Self {
            Self {
                transmitted: std::sync::Mutex::new(Vec::new()),
                outbound,
                mode,
            }
        }
        fn transmitted_count(&self) -> usize {
            self.transmitted.lock().unwrap().len()
        }
    }

    impl InterfaceHandle for TestInterface {
        fn transmit(&self, raw: &[u8]) -> crate::Result<()> {
            self.transmitted.lock().unwrap().push(raw.to_vec());
            Ok(())
        }
        fn is_outbound(&self) -> bool { self.outbound }
        fn bitrate(&self) -> Option<u64> { None }
        fn announce_allowed_at(&self) -> f64 { 0.0 }
        fn set_announce_allowed_at(&self, _t: f64) {}
        fn mode(&self) -> InterfaceMode { self.mode }
        fn interface_hash(&self) -> &[u8] { &[0u8; 16] }
    }

    fn make_data_packet(dest_hash: [u8; 16]) -> Packet {
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
    fn test_outbound_broadcast_no_path() {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> =
            Arc::new(TestInterface::new(true, InterfaceMode::Full));
        ts.inner.write().unwrap().interfaces.push(iface.clone());

        let mut pkt = make_data_packet([0x01; 16]);
        let sent = ts.outbound(&mut pkt).unwrap();
        assert!(sent);
        assert!(pkt.sent);

        let ti = iface.as_ref() as *const dyn InterfaceHandle as *const TestInterface;
        unsafe { assert_eq!((*ti).transmitted_count(), 1); }
    }

    #[test]
    fn test_outbound_via_path() {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> =
            Arc::new(TestInterface::new(true, InterfaceMode::Full));

        let dest_hash = [0x02; 16];
        let entry = PathEntry {
            timestamp: 1000.0,
            received_from: [0xBB; 16],
            hops: 3,
            expires: 9999.0,
            random_blobs: vec![],
            receiving_interface: iface.clone(),
            packet_hash: [0xCC; 32],
        };
        ts.inner.write().unwrap().path_table.insert(dest_hash, entry);

        let mut pkt = make_data_packet(dest_hash);
        let sent = ts.outbound(&mut pkt).unwrap();
        assert!(sent);
        assert!(pkt.sent);
    }

    #[test]
    fn test_outbound_no_interfaces() {
        let ts = TransportState::new();
        let mut pkt = make_data_packet([0x03; 16]);
        let sent = ts.outbound(&mut pkt).unwrap();
        assert!(!sent);
    }

    #[test]
    fn test_header_rewrite() {
        let raw = vec![0x00, 0x05, 0xAA, 0xBB, 0xCC];
        let flags = 0x00;
        let hops = 5;
        let tid = [0x11; 16];
        let new_raw = rewrite_header1_to_header2(&raw, flags, hops, &tid);
        // new_flags: Header2(1<<6) | Transport(1<<4) | lower nibble(0x00) = 0x50
        assert_eq!(new_raw[0], 0x50);
        assert_eq!(new_raw[1], 5);
        assert_eq!(&new_raw[2..18], &tid);
        assert_eq!(&new_raw[18..], &[0xAA, 0xBB, 0xCC]);
    }
}
