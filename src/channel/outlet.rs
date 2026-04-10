// ChannelOutlet trait and LinkChannelOutlet implementation

use crate::channel::message::MessageState;
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::transport::transport::TransportState;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::Result;

/// Abstract transport layer used by Channel.
pub trait ChannelOutlet: Send + Sync {
    /// Send raw bytes, returns a Packet.
    fn send(&self, raw: &[u8], transport: &TransportState) -> Result<Packet>;
    /// Resend a packet.
    fn resend(&self, packet: &mut Packet, transport: &TransportState) -> Result<()>;
    /// Maximum data unit available for channel envelopes.
    fn mdu(&self) -> usize;
    /// Current round-trip time.
    fn rtt(&self) -> f64;
    /// Whether the outlet is usable for sending.
    fn is_usable(&self) -> bool;
    /// Called when the channel times out.
    fn timed_out(&self, transport: &TransportState);
    /// Get the delivery state of a packet.
    fn get_packet_state(&self, packet: &Packet) -> MessageState;
    /// Set a timeout callback on a packet.
    fn set_packet_timeout_callback(
        &self,
        packet: &mut Packet,
        callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
        timeout: Option<f64>,
    );
    /// Set a delivered callback on a packet.
    fn set_packet_delivered_callback(
        &self,
        packet: &mut Packet,
        callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
    );
    /// Get a unique identifier for a packet.
    fn get_packet_id(&self, packet: &Packet) -> Option<[u8; 32]>;
}

// ── LinkChannelOutlet ──

use crate::link::link::Link;
use crate::link::LinkStatus;

/// ChannelOutlet implementation backed by a Link.
pub struct LinkChannelOutlet {
    link: Link,
}

impl LinkChannelOutlet {
    /// Create a new LinkChannelOutlet wrapping the given Link.
    pub fn new(link: Link) -> Self {
        Self { link }
    }
}

impl ChannelOutlet for LinkChannelOutlet {
    fn send(&self, raw: &[u8], transport: &TransportState) -> Result<Packet> {
        // Encrypt the raw channel data
        let encrypted = self.link.encrypt(raw)?;

        // Build and send a packet with Channel context
        let mut packet = Packet::new(
            &self.link as &dyn Encryptable,
            encrypted,
            PacketType::Data,
            PacketContext::Channel,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            true,
            ContextFlag::Unset,
        );
        packet.pack(&self.link as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        // Update link traffic counters
        {
            let mut inner = self.link.write()?;
            inner.last_outbound = crate::link::link::now();
            inner.tx += 1;
            inner.txbytes += packet.raw.len() as u64;
        }

        Ok(packet)
    }

    fn resend(&self, packet: &mut Packet, transport: &TransportState) -> Result<()> {
        packet.resend_packed(&self.link as &dyn Encryptable)?;
        transport.outbound(packet)?;

        let mut inner = self.link.write()?;
        inner.last_outbound = crate::link::link::now();
        inner.tx += 1;
        inner.txbytes += packet.raw.len() as u64;
        Ok(())
    }

    fn mdu(&self) -> usize {
        self.link.mdu().unwrap_or(0)
    }

    fn rtt(&self) -> f64 {
        self.link.rtt().unwrap_or(None).unwrap_or(0.5)
    }

    fn is_usable(&self) -> bool {
        self.link.status().map(|s| s == LinkStatus::Active).unwrap_or(false)
    }

    fn timed_out(&self, transport: &TransportState) {
        let _ = self.link.teardown(transport);
    }

    fn get_packet_state(&self, _packet: &Packet) -> MessageState {
        // Without direct access to PacketReceipt from the packet,
        // we return Sent as default. Real receipt tracking would
        // require storing receipts in TransportState.
        MessageState::Sent
    }

    fn set_packet_timeout_callback(
        &self,
        _packet: &mut Packet,
        _callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
        _timeout: Option<f64>,
    ) {
        // PacketReceipt callback integration deferred to full transport wiring
    }

    fn set_packet_delivered_callback(
        &self,
        _packet: &mut Packet,
        _callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
    ) {
        // PacketReceipt callback integration deferred to full transport wiring
    }

    fn get_packet_id(&self, packet: &Packet) -> Option<[u8; 32]> {
        packet.packet_hash
    }
}
