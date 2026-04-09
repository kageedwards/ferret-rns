use crate::crypto::hashes::sha256;
use crate::types::constants::{MTU, TRUNCATED_HASHLENGTH};
use crate::types::destination::DestinationType;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};
use std::time::{SystemTime, UNIX_EPOCH};

use super::proof::ProofDestination;
use super::Encryptable;

/// A Reticulum wire-format packet.
pub struct Packet {
    // Header fields
    pub header_type: HeaderType,
    pub packet_type: PacketType,
    pub transport_type: TransportType,
    pub context: PacketContext,
    pub context_flag: ContextFlag,
    pub destination_type: DestinationType,
    pub hops: u8,
    pub flags: u8,

    // Addressing
    pub destination_hash: [u8; 16],
    pub transport_id: Option<[u8; 16]>,

    // Payload
    pub data: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub raw: Vec<u8>,

    // State
    pub packed: bool,
    pub sent: bool,
    pub from_packed: bool,
    pub create_receipt: bool,
    pub sent_at: Option<f64>,
    pub packet_hash: Option<[u8; 32]>,
    pub ratchet_id: Option<[u8; 10]>,

    // Interface tracking
    pub attached_interface: Option<usize>,
    pub receiving_interface: Option<usize>,
    pub rssi: Option<f64>,
    pub snr: Option<f64>,
    pub q: Option<f64>,

    // MTU
    pub mtu: usize,
}

impl Packet {
    /// Construct a new packet addressed to a destination.
    pub fn new(
        destination: &dyn Encryptable,
        data: Vec<u8>,
        packet_type: PacketType,
        context: PacketContext,
        transport_type: TransportType,
        header_type: HeaderType,
        transport_id: Option<[u8; 16]>,
        create_receipt: bool,
        context_flag: ContextFlag,
    ) -> Self {
        let destination_hash = *destination.dest_hash();
        let destination_type = destination.dest_type();

        let mut pkt = Self {
            header_type,
            packet_type,
            transport_type,
            context,
            context_flag,
            destination_type,
            hops: 0,
            flags: 0,
            destination_hash,
            transport_id,
            data,
            ciphertext: Vec::new(),
            raw: Vec::new(),
            packed: false,
            sent: false,
            from_packed: false,
            create_receipt,
            sent_at: None,
            packet_hash: None,
            ratchet_id: None,
            attached_interface: None,
            receiving_interface: None,
            rssi: None,
            snr: None,
            q: None,
            mtu: MTU,
        };
        pkt.flags = pkt.get_packed_flags();
        pkt
    }

    /// Construct from raw wire bytes (received packet).
    pub fn from_raw(raw: Vec<u8>) -> Self {
        Self {
            header_type: HeaderType::Header1,
            packet_type: PacketType::Data,
            transport_type: TransportType::Broadcast,
            context: PacketContext::None,
            context_flag: ContextFlag::Unset,
            destination_type: DestinationType::Single,
            hops: 0,
            flags: 0,
            destination_hash: [0u8; 16],
            transport_id: None,
            data: Vec::new(),
            ciphertext: Vec::new(),
            raw,
            packed: true,
            sent: false,
            from_packed: true,
            create_receipt: false,
            sent_at: None,
            packet_hash: None,
            ratchet_id: None,
            attached_interface: None,
            receiving_interface: None,
            rssi: None,
            snr: None,
            q: None,
            mtu: MTU,
        }
    }

    /// Compute the packed flag byte.
    ///
    /// Special case: when context == LRPROOF, destination_type is forced
    /// to LINK regardless of the actual destination type.
    pub fn get_packed_flags(&self) -> u8 {
        let dt = if self.context == PacketContext::LrProof {
            DestinationType::Link as u8
        } else {
            self.destination_type as u8
        };

        let ht = self.header_type as u8;
        let cf = self.context_flag as u8;
        let tt = self.transport_type as u8;
        let pt = self.packet_type as u8;

        (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt
    }

    /// Compute the hashable part of the packet.
    ///
    /// The transport_id is excluded so the hash is consistent
    /// regardless of header type.
    pub fn get_hashable_part(&self) -> Vec<u8> {
        let mut hashable = Vec::new();
        hashable.push(self.flags & 0x0F);

        if self.header_type == HeaderType::Header2 {
            // Skip flags(1) + hops(1) + transport_id(16) = 18 bytes
            if self.raw.len() > 18 {
                hashable.extend_from_slice(&self.raw[18..]);
            }
        } else {
            // Skip flags(1) + hops(1) = 2 bytes
            if self.raw.len() > 2 {
                hashable.extend_from_slice(&self.raw[2..]);
            }
        }

        hashable
    }

    /// Compute and store the packet hash.
    pub fn update_hash(&mut self) {
        self.packet_hash = Some(self.get_hash());
    }

    /// Get the full 32-byte packet hash.
    pub fn get_hash(&self) -> [u8; 32] {
        sha256(&self.get_hashable_part())
    }

    /// Get the truncated 16-byte packet hash.
    pub fn get_truncated_hash(&self) -> [u8; 16] {
        let hash = self.get_hash();
        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&hash[..TRUNCATED_HASHLENGTH / 8]);
        truncated
    }

    /// Serialize to wire format.
    pub fn pack(&mut self, destination: &dyn Encryptable) -> Result<()> {
        self.destination_hash = *destination.dest_hash();
        self.flags = self.get_packed_flags();

        let mut header = Vec::new();
        header.push(self.flags);
        header.push(self.hops);

        if self.context == PacketContext::LrProof {
            // LRPROOF: use destination hash (link_id) directly, no encryption
            header.extend_from_slice(&self.destination_hash);
            self.ciphertext = self.data.clone();
        } else if self.header_type == HeaderType::Header1 {
            header.extend_from_slice(&self.destination_hash);

            if self.should_skip_encryption(destination) {
                self.ciphertext = self.data.clone();
            } else {
                self.ciphertext = destination.encrypt(&self.data)?;
            }
        } else if self.header_type == HeaderType::Header2 {
            let transport_id =
                self.transport_id.ok_or(FerretError::MissingTransportId)?;
            header.extend_from_slice(&transport_id);
            header.extend_from_slice(&self.destination_hash);

            if self.packet_type == PacketType::Announce {
                self.ciphertext = self.data.clone();
            } else {
                // Header2 packets in transport don't re-encrypt
                self.ciphertext = self.data.clone();
            }
        }

        header.push(self.context as u8);
        self.raw = [header, self.ciphertext.clone()].concat();

        if self.raw.len() > self.mtu {
            return Err(FerretError::PacketTooLarge {
                size: self.raw.len(),
                mtu: self.mtu,
            });
        }

        self.packed = true;
        self.update_hash();
        Ok(())
    }

    /// Deserialize from wire format.
    pub fn unpack(&mut self) -> Result<bool> {
        if self.raw.len() < 3 {
            return Err(FerretError::MalformedPacket(
                "packet too short".into(),
            ));
        }

        self.flags = self.raw[0];
        self.hops = self.raw[1];

        self.header_type =
            HeaderType::try_from((self.flags >> 6) & 0x03)?;
        self.context_flag =
            ContextFlag::try_from((self.flags >> 5) & 0x01)?;
        self.transport_type =
            TransportType::try_from((self.flags >> 4) & 0x01)?;
        self.destination_type =
            DestinationType::try_from((self.flags >> 2) & 0x03)?;
        self.packet_type =
            PacketType::try_from(self.flags & 0x03)?;

        let dst_len = TRUNCATED_HASHLENGTH / 8; // 16

        if self.header_type == HeaderType::Header2 {
            // Header2: flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1) = 35
            if self.raw.len() < 2 + dst_len * 2 + 1 {
                return Err(FerretError::MalformedPacket(
                    "Header2 packet too short".into(),
                ));
            }
            let mut tid = [0u8; 16];
            tid.copy_from_slice(&self.raw[2..2 + dst_len]);
            self.transport_id = Some(tid);
            self.destination_hash
                .copy_from_slice(&self.raw[2 + dst_len..2 + dst_len * 2]);
            self.context =
                PacketContext::try_from(self.raw[2 + dst_len * 2])?;
            self.data = self.raw[2 + dst_len * 2 + 1..].to_vec();
        } else {
            // Header1: flags(1) + hops(1) + dest_hash(16) + context(1) = 19
            if self.raw.len() < 2 + dst_len + 1 {
                return Err(FerretError::MalformedPacket(
                    "Header1 packet too short".into(),
                ));
            }
            self.transport_id = None;
            self.destination_hash
                .copy_from_slice(&self.raw[2..2 + dst_len]);
            self.context =
                PacketContext::try_from(self.raw[2 + dst_len])?;
            self.data = self.raw[2 + dst_len + 1..].to_vec();
        }

        self.packed = false;
        self.update_hash();
        Ok(true)
    }

    /// Determine whether encryption should be skipped for this packet.
    fn should_skip_encryption(&self, destination: &dyn Encryptable) -> bool {
        // Announces, link requests, and cache requests are never encrypted
        if self.packet_type == PacketType::Announce
            || self.packet_type == PacketType::LinkRequest
            || self.context == PacketContext::CacheRequest
        {
            return true;
        }

        // Resource-related contexts skip encryption
        if self.context == PacketContext::Resource
            || self.context == PacketContext::Keepalive
        {
            return true;
        }

        // Resource proof context with Proof packet type
        if self.context == PacketContext::ResourcePrf
            && self.packet_type == PacketType::Proof
        {
            return true;
        }

        // Proof packets for Link destinations
        if self.packet_type == PacketType::Proof
            && destination.dest_type() == DestinationType::Link
        {
            return true;
        }

        false
    }

    /// Generate a proof destination for this packet.
    pub fn generate_proof_destination(&self) -> ProofDestination {
        ProofDestination::new(self.get_truncated_hash())
    }

    /// Send the packet. Packs if needed and marks as sent.
    /// Full Transport integration happens in a later task.
    pub fn send_packed(&mut self, destination: &dyn Encryptable) -> Result<()> {
        if self.sent {
            return Err(FerretError::MalformedPacket("packet already sent".into()));
        }
        if !self.packed {
            self.pack(destination)?;
        }
        self.sent = true;
        self.sent_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
        );
        Ok(())
    }

    /// Re-pack and prepare for resend.
    pub fn resend_packed(&mut self, destination: &dyn Encryptable) -> Result<()> {
        if !self.sent {
            return Err(FerretError::MalformedPacket("packet not yet sent".into()));
        }
        self.pack(destination)?;
        Ok(())
    }
}
