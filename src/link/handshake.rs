// Handshake: key exchange, prove, validate_proof, signalling bytes

use std::sync::{Arc, RwLock};

use crate::crypto::hkdf::hkdf;
use crate::crypto::x25519::X25519PublicKey;
use crate::crypto::ed25519::Ed25519VerifyingKey;
use crate::destination::destination::Destination;
use crate::link::{
    LinkMode, LinkStatus, ECPUBSIZE, ENABLED_MODES, LINK_MTU_SIZE,
    MTU_BYTEMASK, MODE_DEFAULT, ESTABLISHMENT_TIMEOUT_PER_HOP, KEEPALIVE_MAX,
};
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::transport::transport::{PendingLink, TransportState};
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};

use super::link::{link_id_from_packet, compute_mdu, now, Link};

// ── Signalling bytes ──

/// Encode MTU (21 bits) and mode (3 bits) into 3-byte signalling bytes.
pub fn signalling_bytes(mtu: u32, mode: LinkMode) -> Result<[u8; 3]> {
    if !ENABLED_MODES.contains(&mode) {
        return Err(FerretError::InvalidLinkMode(format!(
            "mode {:?} not enabled",
            mode
        )));
    }
    let value = (mtu & MTU_BYTEMASK) | (((mode as u32) << 5) << 16);
    let bytes = value.to_be_bytes(); // [0, b1, b2, b3]
    Ok([bytes[1], bytes[2], bytes[3]])
}

/// Decode MTU from 3-byte signalling bytes.
pub fn mtu_from_signalling(bytes: &[u8; 3]) -> u32 {
    let value = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
    value & MTU_BYTEMASK
}

/// Decode mode from 3-byte signalling bytes, validate against ENABLED_MODES.
pub fn mode_from_signalling(bytes: &[u8; 3]) -> Result<LinkMode> {
    let mode_bits = (bytes[0] >> 5) & 0x07;
    let mode = LinkMode::try_from(mode_bits)?;
    if !ENABLED_MODES.contains(&mode) {
        return Err(FerretError::InvalidLinkMode(format!(
            "mode {:?} not enabled",
            mode
        )));
    }
    Ok(mode)
}

// ── Link handshake methods ──

impl Link {
    /// Set link_id from a packed LinkRequest packet (responder side).
    pub(crate) fn set_link_id(&mut self, packet: &Packet, data_len: usize) -> Result<()> {
        let link_id = link_id_from_packet(packet, data_len);
        {
            let mut inner = self.write()?;
            inner.link_id = link_id;
        }
        self.link_id_cache = link_id;
        Ok(())
    }

    /// Perform X25519 DH key exchange and HKDF key derivation.
    pub(crate) fn handshake(&self) -> Result<()> {
        let mut inner = self.write()?;
        if inner.status != LinkStatus::Pending || inner.prv.is_none() {
            return Err(FerretError::LinkEstablishmentFailed(
                "invalid state for handshake".into(),
            ));
        }

        let peer_pub = inner
            .peer_pub
            .as_ref()
            .ok_or(FerretError::LinkEstablishmentFailed("no peer public key".into()))?;

        let prv = inner
            .prv
            .as_ref()
            .ok_or(FerretError::MissingPrivateKey)?;

        let shared_key = prv.exchange(peer_pub);

        let derived_key_length = match inner.mode {
            LinkMode::Aes128Cbc => 32,
            LinkMode::Aes256Cbc => 64,
            _ => {
                return Err(FerretError::InvalidLinkMode(format!(
                    "unsupported mode {:?}",
                    inner.mode
                )))
            }
        };

        // Salt = link_id, context = None (matching Python get_salt/get_context)
        let derived_key = hkdf(
            derived_key_length,
            &shared_key,
            Some(&inner.link_id),
            None,
        )?;

        inner.shared_key = Some(shared_key);
        inner.derived_key = Some(derived_key);
        inner.status = LinkStatus::Handshake;

        Ok(())
    }

    /// Responder: construct and send the link proof.
    pub(crate) fn prove(&self, transport: &TransportState) -> Result<()> {
        let (_sig_data, proof_data) = {
            let inner = self.read()?;

            let pub_bytes = inner
                .pub_bytes
                .ok_or(FerretError::MissingPublicKey)?;
            let sig_pub_bytes = inner
                .sig_pub_bytes
                .ok_or(FerretError::MissingPublicKey)?;

            let sig_bytes = signalling_bytes(inner.mtu as u32, inner.mode)?;

            // signed_data = link_id(16) + pub_bytes(32) + sig_pub_bytes(32) + signalling(3)
            let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
            signed_data.extend_from_slice(&inner.link_id);
            signed_data.extend_from_slice(&pub_bytes);
            signed_data.extend_from_slice(&sig_pub_bytes);
            signed_data.extend_from_slice(&sig_bytes);

            // Get owner identity to sign
            let owner = inner
                .owner
                .as_ref()
                .ok_or(FerretError::MissingPrivateKey)?;
            let owner_guard = owner
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            let identity = owner_guard
                .identity
                .as_ref()
                .ok_or(FerretError::MissingPrivateKey)?;
            let signature = identity.sign(&signed_data)?;

            // proof_data = signature(64) + pub_bytes(32) + signalling(3)
            let mut proof = Vec::with_capacity(64 + 32 + 3);
            proof.extend_from_slice(&signature);
            proof.extend_from_slice(&pub_bytes);
            proof.extend_from_slice(&sig_bytes);

            (signed_data, proof)
        };

        // Send as LrProof packet
        let mut packet = Packet::new(
            self as &dyn Encryptable,
            proof_data,
            PacketType::Proof,
            PacketContext::LrProof,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(self as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        {
            let mut inner = self.write()?;
            inner.establishment_cost += packet.raw.len();
            inner.last_outbound = now();
        }

        Ok(())
    }

    /// Initiator: validate the link proof from the responder.
    pub(crate) fn validate_proof(
        &self,
        packet: &Packet,
        transport: &TransportState,
    ) -> Result<()> {
        let status = self.read()?.status;
        if status != LinkStatus::Pending {
            return Ok(()); // Ignore if not pending
        }

        let sig_len = 64; // Ed25519 signature
        let pub_len = 32; // X25519 public key (ECPUBSIZE/2)

        // Check for signalling bytes
        let has_signalling =
            packet.data.len() == sig_len + pub_len + LINK_MTU_SIZE;
        let has_basic = packet.data.len() == sig_len + pub_len;

        if !has_signalling && !has_basic {
            return Err(FerretError::InvalidLinkProof("invalid proof length".into()));
        }

        // Extract mode and validate
        let (confirmed_mtu, sig_bytes_for_verify) = if has_signalling {
            let sb_start = sig_len + pub_len;
            let mut sb = [0u8; 3];
            sb.copy_from_slice(&packet.data[sb_start..sb_start + 3]);
            let mode = mode_from_signalling(&sb)?;
            let my_mode = self.read()?.mode;
            if mode != my_mode {
                return Err(FerretError::InvalidLinkProof("mode mismatch".into()));
            }
            let mtu = mtu_from_signalling(&sb);
            (Some(mtu), signalling_bytes(mtu, mode)?)
        } else {
            (None, [0u8; 3])
        };

        // Extract peer pub bytes
        let mut peer_pub_bytes = [0u8; 32];
        peer_pub_bytes.copy_from_slice(&packet.data[sig_len..sig_len + pub_len]);

        // Load peer Ed25519 verifying key from Destination's Identity
        let peer_sig_pub_bytes = {
            let inner = self.read()?;
            let dest = inner
                .destination
                .as_ref()
                .ok_or(FerretError::LinkEstablishmentFailed("no destination".into()))?;
            let dest_guard = dest
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            let identity = dest_guard
                .identity
                .as_ref()
                .ok_or(FerretError::MissingPublicKey)?;
            let pub_key = identity.get_public_key()?;
            let mut sig_pub = [0u8; 32];
            sig_pub.copy_from_slice(&pub_key[32..]);
            sig_pub
        };

        // Load peer keys
        let peer_pub = X25519PublicKey::from_bytes(&peer_pub_bytes);
        let peer_sig_pub = Ed25519VerifyingKey::from_bytes(&peer_sig_pub_bytes)?;

        {
            let mut inner = self.write()?;
            inner.peer_pub = Some(peer_pub);
            inner.peer_pub_bytes = Some(peer_pub_bytes);
            inner.peer_sig_pub = Some(peer_sig_pub);
            inner.peer_sig_pub_bytes = Some(peer_sig_pub_bytes);
        }

        // Perform handshake (DH + HKDF)
        self.handshake()?;

        // Reconstruct signed_data and validate signature
        let link_id = self.read()?.link_id;
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
        signed_data.extend_from_slice(&link_id);
        signed_data.extend_from_slice(&peer_pub_bytes);
        signed_data.extend_from_slice(&peer_sig_pub_bytes);
        if has_signalling {
            signed_data.extend_from_slice(&sig_bytes_for_verify);
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&packet.data[..sig_len]);

        // Validate using destination identity
        {
            let inner = self.read()?;
            let dest = inner
                .destination
                .as_ref()
                .ok_or(FerretError::LinkEstablishmentFailed("no destination".into()))?;
            let dest_guard = dest
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            let identity = dest_guard
                .identity
                .as_ref()
                .ok_or(FerretError::MissingPublicKey)?;
            let valid = identity.validate(&signature, &signed_data)?;
            if !valid {
                return Err(FerretError::InvalidLinkProof(
                    "signature validation failed".into(),
                ));
            }
        }

        // Check we're in Handshake state after handshake()
        let status = self.read()?.status;
        if status != LinkStatus::Handshake {
            return Err(FerretError::LinkEstablishmentFailed(
                "invalid state after handshake".into(),
            ));
        }

        // Transition to Active, compute RTT
        let rtt = {
            let mut inner = self.write()?;
            let request_time = inner.request_time.unwrap_or(now());
            let rtt = now() - request_time;
            inner.rtt = Some(rtt);
            inner.status = LinkStatus::Active;
            inner.activated_at = Some(now());
            inner.last_proof = now();
            inner.establishment_cost += packet.raw.len();

            if let Some(confirmed) = confirmed_mtu {
                inner.mtu = confirmed as usize;
                inner.mdu = compute_mdu(inner.mtu);
            }

            // Update keepalive based on RTT
            let keepalive = (rtt * (super::KEEPALIVE_MAX / super::KEEPALIVE_MAX_RTT))
                .clamp(super::KEEPALIVE_MIN, super::KEEPALIVE_MAX);
            inner.keepalive = keepalive;
            inner.stale_time = keepalive * super::STALE_FACTOR as f64;

            rtt
        };

        // Activate in TransportState
        let link_id = self.read()?.link_id;
        transport.activate_link(&link_id)?;

        // Send LRRTT packet: encrypt(msgpack(rtt_f64))
        let rtt_data = crate::util::msgpack::serialize(&rtt)?;
        let encrypted_rtt = self.encrypt(&rtt_data)?;

        let mut rtt_packet = Packet::new(
            self as &dyn Encryptable,
            encrypted_rtt,
            PacketType::Data,
            PacketContext::Lrrtt,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        rtt_packet.pack(self as &dyn Encryptable)?;
        transport.outbound(&mut rtt_packet)?;

        {
            let mut inner = self.write()?;
            inner.last_outbound = now();
        }

        // Invoke link_established callback
        let cb = {
            let inner = self.read()?;
            inner.callbacks.link_established.is_some()
        };
        if cb {
            let inner = self.read()?;
            if let Some(ref callback) = inner.callbacks.link_established {
                callback(self);
            }
        }

        Ok(())
    }

    /// Static method: validate an incoming LinkRequest, create responder Link.
    pub fn validate_request(
        owner: Arc<RwLock<Destination>>,
        data: &[u8],
        packet: &Packet,
        transport: &TransportState,
    ) -> Result<Option<Link>> {
        // Validate data length: 64 (ECPUBSIZE) or 67 (ECPUBSIZE + LINK_MTU_SIZE)
        if data.len() != ECPUBSIZE && data.len() != ECPUBSIZE + LINK_MTU_SIZE {
            return Ok(None);
        }

        // Extract peer keys
        let mut peer_pub_bytes = [0u8; 32];
        peer_pub_bytes.copy_from_slice(&data[..32]);
        let mut peer_sig_pub_bytes = [0u8; 32];
        peer_sig_pub_bytes.copy_from_slice(&data[32..64]);

        // Create responder link
        let mut link = Link::new_responder(owner.clone(), &peer_pub_bytes, &peer_sig_pub_bytes)?;

        // Set link_id from packet
        link.set_link_id(packet, data.len())?;
        link.update_link_id_cache()?;

        // Parse signalling if present
        if data.len() == ECPUBSIZE + LINK_MTU_SIZE {
            let mut sb = [0u8; 3];
            sb.copy_from_slice(&data[ECPUBSIZE..]);
            let mtu = mtu_from_signalling(&sb);
            let mode = mode_from_signalling(&sb).unwrap_or(MODE_DEFAULT);
            let mut inner = link.write()?;
            inner.mtu = mtu as usize;
            inner.mdu = compute_mdu(inner.mtu);
            inner.mode = mode;
        }

        // Set establishment timeout and cost
        {
            let mut inner = link.write()?;
            inner.establishment_timeout =
                ESTABLISHMENT_TIMEOUT_PER_HOP * (packet.hops.max(1) as f64) + KEEPALIVE_MAX;
            inner.establishment_cost += packet.raw.len();
            inner.last_inbound = now();
            inner.attached_interface = packet.receiving_interface;
        }

        // Perform handshake
        link.handshake()?;

        // Send proof
        link.prove(transport)?;

        // Register as pending link
        let link_id = link.read()?.link_id;
        let dest_hash = {
            let o = owner
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            o.hash
        };
        transport.register_link(PendingLink {
            link_id,
            destination_hash: dest_hash,
            timestamp: now(),
            link: Some(link.clone()),
        })?;

        {
            let mut inner = link.write()?;
            inner.request_time = Some(now());
        }

        Ok(Some(link))
    }
}
