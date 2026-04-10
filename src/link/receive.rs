// Packet dispatch by context, identity verification, packet proving

use crate::identity::Identity;
use crate::link::link::{now, Link};
use crate::link::LinkStatus;
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::transport::transport::TransportState;
use crate::types::destination::ProofStrategy;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};

impl Link {
    /// Dispatch a received packet by its context.
    pub fn receive(&self, packet: &Packet, transport: &TransportState) -> Result<()> {
        // Update traffic counters
        {
            let mut inner = self.write()?;
            inner.last_inbound = now();
            inner.rx += 1;
            inner.rxbytes += packet.raw.len() as u64;

            // Update last_data for non-keepalive packets
            if packet.context != PacketContext::Keepalive {
                inner.last_data = now();
            }

            // Stale → Active transition on any packet receipt
            if inner.status == LinkStatus::Stale {
                inner.status = LinkStatus::Active;
            }
        }

        match packet.context {
            PacketContext::None => {
                // Decrypt data, invoke packet callback
                let plaintext = self.decrypt(&packet.data)?;
                if let Some(pt) = plaintext {
                    // Prove packet if needed
                    self.maybe_prove_packet(packet, transport)?;

                    let inner = self.read()?;
                    if let Some(ref cb) = inner.callbacks.packet {
                        cb(&pt, packet);
                    }
                }
            }
            PacketContext::Keepalive => {
                self.handle_keepalive(&packet.data, transport)?;
            }
            PacketContext::LinkIdentify => {
                self.handle_identify(packet)?;
            }
            PacketContext::LinkClose => {
                self.teardown_packet(packet)?;
            }
            PacketContext::Lrrtt => {
                // Responder side: decrypt, unpack RTT, transition to Active
                self.handle_lrrtt(packet, transport)?;
            }
            PacketContext::Request => {
                self.handle_request(packet, transport)?;
            }
            PacketContext::Response => {
                self.handle_response(packet)?;
            }
            PacketContext::Channel => {
                // Prove packet, decrypt, pass to channel
                self.prove_packet(packet, transport)?;
                let plaintext = self.decrypt(&packet.data)?;
                if let Some(pt) = plaintext {
                    let mut inner = self.write()?;
                    if let Some(ref mut channel) = inner.channel {
                        let _ = channel.receive(&pt);
                    }
                }
            }
            _ => {
                // Unknown context, ignore
            }
        }

        Ok(())
    }

    /// Handle LRRTT packet (responder side): decrypt, unpack RTT, transition to Active.
    fn handle_lrrtt(&self, packet: &Packet, transport: &TransportState) -> Result<()> {
        let plaintext = self.decrypt(&packet.data)?;
        let plaintext = match plaintext {
            Some(pt) => pt,
            None => return Ok(()),
        };

        let received_rtt: f64 = crate::util::msgpack::deserialize(&plaintext)?;

        {
            let mut inner = self.write()?;
            // Set RTT to max of received and locally measured
            let local_rtt = inner.request_time.map(|t| now() - t).unwrap_or(0.0);
            let rtt = received_rtt.max(local_rtt);
            inner.rtt = Some(rtt);

            // Update keepalive based on RTT
            let keepalive = super::watchdog::compute_keepalive(rtt);
            inner.keepalive = keepalive;
            inner.stale_time = keepalive * super::STALE_FACTOR as f64;

            inner.status = LinkStatus::Active;
            inner.activated_at = Some(now());
        }

        // Activate in TransportState
        let link_id = self.read()?.link_id;
        transport.activate_link(&link_id)?;

        // Invoke destination's link_established callback
        let owner = self.read()?.owner.clone();
        if let Some(ref owner_arc) = owner {
            let owner_guard = owner_arc
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            owner_guard.invoke_link_established(self);
        }

        Ok(())
    }

    /// Auto-prove a packet based on the destination's proof strategy.
    fn maybe_prove_packet(
        &self,
        packet: &Packet,
        transport: &TransportState,
    ) -> Result<()> {
        let owner = {
            let inner = self.read()?;
            match inner.owner.as_ref() {
                Some(o) => o.clone(),
                None => return Ok(()),
            }
        };

        let (_strategy, should_prove) = {
            let owner_guard = owner
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            let strategy = owner_guard.proof_strategy;
            let should = match strategy {
                ProofStrategy::ProveAll => true,
                ProofStrategy::ProveApp => owner_guard.invoke_proof_requested(packet),
                ProofStrategy::ProveNone => false,
            };
            (strategy, should)
        };

        if should_prove {
            self.prove_packet(packet, transport)?;
        }

        Ok(())
    }

    // ── Identity verification (11.2) ──

    /// Initiator: encrypt and send identity over the link.
    pub fn identify(
        &self,
        identity: &Identity,
        transport: &TransportState,
    ) -> Result<()> {
        let inner = self.read()?;
        if inner.status != LinkStatus::Active {
            return Err(FerretError::LinkEstablishmentFailed(
                "link not active for identify".into(),
            ));
        }
        if !inner.initiator {
            return Err(FerretError::LinkEstablishmentFailed(
                "only initiator can identify".into(),
            ));
        }
        drop(inner);

        let pub_key = identity.get_public_key()?;
        let link_id = self.read()?.link_id;

        // Sign (link_id + pub_key)
        let mut sign_data = Vec::with_capacity(16 + 64);
        sign_data.extend_from_slice(&link_id);
        sign_data.extend_from_slice(&pub_key);
        let signature = identity.sign(&sign_data)?;

        // Plaintext: pub_key(64) + signature(64) = 128 bytes
        let mut plaintext = Vec::with_capacity(128);
        plaintext.extend_from_slice(&pub_key);
        plaintext.extend_from_slice(&signature);

        let encrypted = self.encrypt(&plaintext)?;

        let mut packet = Packet::new(
            self as &dyn Encryptable,
            encrypted,
            PacketType::Data,
            PacketContext::LinkIdentify,
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
            inner.last_outbound = now();
            inner.tx += 1;
            inner.txbytes += packet.raw.len() as u64;
        }

        Ok(())
    }

    /// Handle a received LinkIdentify packet (responder side).
    fn handle_identify(&self, packet: &Packet) -> Result<()> {
        let plaintext = self.decrypt(&packet.data)?;
        let plaintext = match plaintext {
            Some(pt) => pt,
            None => return Ok(()),
        };

        if plaintext.len() != 128 {
            return Ok(()); // Invalid identify data length
        }

        let pub_key_bytes = &plaintext[..64];
        let signature: [u8; 64] = plaintext[64..128]
            .try_into()
            .map_err(|_| FerretError::Token("invalid signature length".into()))?;

        // Construct Identity from public key
        let remote_identity = Identity::from_public_key(pub_key_bytes)?;

        // Validate signature over (link_id + pub_key)
        let link_id = self.read()?.link_id;
        let mut sign_data = Vec::with_capacity(16 + 64);
        sign_data.extend_from_slice(&link_id);
        sign_data.extend_from_slice(pub_key_bytes);

        let valid = remote_identity.validate(&signature, &sign_data)?;
        if !valid {
            return Ok(()); // Invalid signature, ignore
        }

        // Store remote identity and invoke callback
        {
            let mut inner = self.write()?;
            inner.remote_identity = Some(remote_identity);
        }

        // Invoke remote_identified callback
        let inner = self.read()?;
        if let Some(ref cb) = inner.callbacks.remote_identified {
            if let Some(ref identity) = inner.remote_identity {
                cb(self, identity);
            }
        }

        Ok(())
    }

    /// Sign packet_hash with Ed25519 signing key, send Proof packet.
    pub fn prove_packet(
        &self,
        packet: &Packet,
        transport: &TransportState,
    ) -> Result<()> {
        let packet_hash = packet.get_hash();
        let signature = self.sign(&packet_hash)?;

        // Proof data: packet_hash(32) + signature(64) = 96 bytes
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(&packet_hash);
        proof_data.extend_from_slice(&signature);

        let mut proof_packet = Packet::new(
            self as &dyn Encryptable,
            proof_data,
            PacketType::Proof,
            PacketContext::LinkProof,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        proof_packet.pack(self as &dyn Encryptable)?;
        transport.outbound(&mut proof_packet)?;

        {
            let mut inner = self.write()?;
            inner.last_outbound = now();
            inner.last_proof = now();
            inner.tx += 1;
            inner.txbytes += proof_packet.raw.len() as u64;
        }

        Ok(())
    }
}
