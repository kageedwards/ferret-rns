// ChannelOutlet trait and LinkChannelOutlet implementation

use crate::channel::message::MessageState;
use crate::packet::packet::Packet;
use crate::packet::receipt::{PacketReceipt, ReceiptStatus};
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
    transport: TransportState,
}

impl LinkChannelOutlet {
    /// Create a new LinkChannelOutlet wrapping the given Link and TransportState.
    pub fn new(link: Link, transport: TransportState) -> Self {
        Self { link, transport }
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

        // Create a PacketReceipt and register it with TransportState
        let hash = packet.get_hash();
        let truncated_hash = packet.get_truncated_hash();
        let rtt = self.link.rtt().unwrap_or(None).unwrap_or(0.5);
        let timeout = rtt * 2.5; // default receipt timeout based on RTT
        let receipt = PacketReceipt::new(hash, truncated_hash, timeout, None);
        {
            let mut inner = self.transport.write()?;
            inner.receipts.push(receipt);
        }

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

    fn get_packet_state(&self, packet: &Packet) -> MessageState {
        let hash = match packet.packet_hash {
            Some(h) => h,
            None => return MessageState::New,
        };
        let inner = match self.transport.read() {
            Ok(inner) => inner,
            Err(_) => return MessageState::Sent,
        };
        match inner.receipts.iter().find(|r| r.hash == hash) {
            Some(receipt) => match receipt.status {
                ReceiptStatus::Sent => MessageState::Sent,
                ReceiptStatus::Delivered => MessageState::Delivered,
                ReceiptStatus::Failed | ReceiptStatus::Culled => MessageState::Failed,
            },
            None => MessageState::New,
        }
    }

    fn set_packet_timeout_callback(
        &self,
        packet: &mut Packet,
        callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
        timeout: Option<f64>,
    ) {
        let hash = match packet.packet_hash {
            Some(h) => h,
            None => return,
        };
        if let Ok(mut inner) = self.transport.write() {
            if let Some(receipt) = inner.receipts.iter_mut().find(|r| r.hash == hash) {
                if let Some(t) = timeout {
                    receipt.set_timeout(t);
                }
                if let Some(cb) = callback {
                    // Wrap the Packet callback into a PacketReceipt callback
                    // We capture the packet hash to identify the packet later
                    let packet_hash = hash;
                    receipt.set_timeout_callback(Box::new(move |_receipt| {
                        // Create a minimal packet with the hash for the callback
                        let mut p = Packet::from_raw(Vec::new());
                        p.packet_hash = Some(packet_hash);
                        cb(&p);
                    }));
                }
            }
        }
    }

    fn set_packet_delivered_callback(
        &self,
        packet: &mut Packet,
        callback: Option<Box<dyn Fn(&Packet) + Send + Sync>>,
    ) {
        let hash = match packet.packet_hash {
            Some(h) => h,
            None => return,
        };
        if let Ok(mut inner) = self.transport.write() {
            if let Some(receipt) = inner.receipts.iter_mut().find(|r| r.hash == hash) {
                if let Some(cb) = callback {
                    let packet_hash = hash;
                    receipt.set_delivery_callback(Box::new(move |_receipt| {
                        let mut p = Packet::from_raw(Vec::new());
                        p.packet_hash = Some(packet_hash);
                        cb(&p);
                    }));
                }
            }
        }
    }

    fn get_packet_id(&self, packet: &Packet) -> Option<[u8; 32]> {
        packet.packet_hash
    }
}
