// Resource initiator: advertise, handle requests, validate proof, cancel

use crate::link::link::now;
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::resource::advertisement::{ResourceAdvertisement, COLLISION_GUARD_SIZE, HASHMAP_MAX_LEN};
use crate::resource::resource::Resource;
use crate::resource::{
    HASHMAP_IS_EXHAUSTED, HASHMAP_IS_NOT_EXHAUSTED, MAPHASH_LEN, ResourceStatus,
};
use crate::transport::transport::TransportState;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};

impl Resource {
    /// Advertise the resource to the remote peer.
    ///
    /// Builds a ResourceAdvertisement, packs it, and sends it as a
    /// ResourceAdv packet via the Link's transport.
    pub fn advertise(&mut self, transport: &TransportState) -> Result<()> {
        let adv = ResourceAdvertisement::from_resource(self);
        let packed = adv.pack()?;

        let mut packet = Packet::new(
            &self.link as &dyn Encryptable,
            packed,
            PacketType::Data,
            PacketContext::ResourceAdv,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(&self.link as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        self.status = ResourceStatus::Advertised;
        self.adv_sent = Some(now());
        self.last_activity = now();

        Ok(())
    }

    /// Handle an incoming ResourceReq packet (initiator side).
    ///
    /// Wire format:
    /// - Byte 0: hashmap exhaustion flag (0x00 or 0xFF)
    /// - If exhausted (0xFF): bytes 1..5 = last_map_hash, 5..37 = resource_hash, 37.. = requested map_hashes
    /// - If not exhausted (0x00): bytes 1..33 = resource_hash, 33.. = requested map_hashes
    pub fn handle_request(
        &mut self,
        request_data: &[u8],
        transport: &TransportState,
    ) -> Result<()> {
        if request_data.is_empty() {
            return Err(FerretError::MalformedPacket(
                "empty resource request".into(),
            ));
        }

        let exhaustion_flag = request_data[0];
        let (last_map_hash, resource_hash, map_hashes_data) = if exhaustion_flag
            == HASHMAP_IS_EXHAUSTED
        {
            // Exhausted: [flag:1][last_map_hash:4][resource_hash:32][map_hashes:N*4]
            if request_data.len() < 37 {
                return Err(FerretError::MalformedPacket(
                    "exhausted request too short".into(),
                ));
            }
            let last_mh: [u8; 4] = request_data[1..5]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad last_map_hash".into()))?;
            let rh: [u8; 32] = request_data[5..37]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad resource_hash".into()))?;
            (Some(last_mh), rh, &request_data[37..])
        } else {
            // Not exhausted: [flag:1][resource_hash:32][map_hashes:N*4]
            if request_data.len() < 33 {
                return Err(FerretError::MalformedPacket(
                    "request too short".into(),
                ));
            }
            let rh: [u8; 32] = request_data[1..33]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad resource_hash".into()))?;
            (None, rh, &request_data[33..])
        };

        // Verify resource_hash matches
        if resource_hash != self.hash {
            return Err(FerretError::ResourceFailed(
                "resource hash mismatch in request".into(),
            ));
        }

        // Handle hashmap exhaustion: send next hashmap segment
        if let Some(last_mh) = last_map_hash {
            self.send_hashmap_update(&last_mh, transport)?;
        }

        // Send requested parts
        let num_hashes = map_hashes_data.len() / MAPHASH_LEN;
        for i in 0..num_hashes {
            let start = i * MAPHASH_LEN;
            let end = start + MAPHASH_LEN;
            if end > map_hashes_data.len() {
                break;
            }
            let requested_hash: [u8; 4] = map_hashes_data[start..end]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad map_hash".into()))?;

            if let Some(part_data) = self.find_part_by_map_hash(&requested_hash) {
                let mut packet = Packet::new(
                    &self.link as &dyn Encryptable,
                    part_data,
                    PacketType::Data,
                    PacketContext::Resource,
                    TransportType::Broadcast,
                    HeaderType::Header1,
                    None,
                    false,
                    ContextFlag::Unset,
                );
                packet.pack(&self.link as &dyn Encryptable)?;
                transport.outbound(&mut packet)?;

                self.sent_parts += 1;
                self.last_part_sent = Some(now());
            }
        }

        self.last_activity = now();

        // Transition to Transferring if still Advertised
        if self.status == ResourceStatus::Advertised {
            self.status = ResourceStatus::Transferring;
            self.started_transferring = Some(now());
        }

        // Invoke progress callback
        if let Some(ref cb) = self.progress_callback {
            cb(self);
        }

        Ok(())
    }

    /// Find a part by its map_hash within the COLLISION_GUARD_SIZE window.
    fn find_part_by_map_hash(&self, requested_hash: &[u8; 4]) -> Option<Vec<u8>> {
        let total_entries = self.hashmap.len() / MAPHASH_LEN;
        let search_end = total_entries.min(self.sent_parts + COLLISION_GUARD_SIZE);
        let search_start = self.sent_parts.saturating_sub(COLLISION_GUARD_SIZE);

        for idx in search_start..search_end {
            let hm_start = idx * MAPHASH_LEN;
            let hm_end = hm_start + MAPHASH_LEN;
            if hm_end > self.hashmap.len() {
                break;
            }
            if self.hashmap[hm_start..hm_end] == requested_hash[..] {
                // Return the part data
                if let Some(Some(ref part)) = self.parts.get(idx) {
                    return Some(part.clone());
                }
            }
        }
        None
    }

    /// Send a hashmap update (HMU) packet for the next segment.
    fn send_hashmap_update(
        &self,
        last_map_hash: &[u8; 4],
        transport: &TransportState,
    ) -> Result<()> {
        // Find the index of the last known map_hash
        let total_entries = self.hashmap.len() / MAPHASH_LEN;
        let mut start_idx = 0;
        for idx in 0..total_entries {
            let hm_start = idx * MAPHASH_LEN;
            let hm_end = hm_start + MAPHASH_LEN;
            if self.hashmap[hm_start..hm_end] == last_map_hash[..] {
                start_idx = idx + 1;
                break;
            }
        }

        if start_idx >= total_entries {
            return Ok(()); // No more hashmap data to send
        }

        // Compute the segment to send
        let end_idx = (start_idx + HASHMAP_MAX_LEN).min(total_entries);
        let segment_bytes =
            &self.hashmap[start_idx * MAPHASH_LEN..end_idx * MAPHASH_LEN];

        // Build HMU payload: resource_hash(32) + msgpack([segment_index, hashmap_bytes])
        let segment_data: (usize, &[u8]) = (start_idx, segment_bytes);
        let packed_segment = crate::util::msgpack::serialize(&segment_data)?;

        let mut payload = Vec::with_capacity(32 + packed_segment.len());
        payload.extend_from_slice(&self.hash);
        payload.extend_from_slice(&packed_segment);

        let mut packet = Packet::new(
            &self.link as &dyn Encryptable,
            payload,
            PacketType::Data,
            PacketContext::ResourceHmu,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(&self.link as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        Ok(())
    }

    /// Validate a received proof. Returns true if valid.
    ///
    /// Proof wire format: [resource_hash:32][proof_hash:32]
    pub fn validate_proof(&mut self, proof_data: &[u8]) -> Result<bool> {
        if proof_data.len() != 64 {
            return Ok(false);
        }

        let resource_hash: [u8; 32] = proof_data[..32]
            .try_into()
            .map_err(|_| FerretError::MalformedPacket("bad proof resource_hash".into()))?;
        let proof_hash: [u8; 32] = proof_data[32..64]
            .try_into()
            .map_err(|_| FerretError::MalformedPacket("bad proof_hash".into()))?;

        // Verify resource_hash matches
        if resource_hash != self.hash {
            return Ok(false);
        }

        // Verify proof_hash matches expected_proof
        if proof_hash != self.expected_proof {
            return Ok(false);
        }

        // Valid proof: transition to Complete
        self.status = ResourceStatus::Complete;
        self.last_activity = now();

        // Invoke callback
        if let Some(ref cb) = self.callback {
            cb(self);
        }

        Ok(true)
    }

    /// Cancel the resource transfer (initiator side).
    ///
    /// Sends a ResourceIcl packet and transitions to Failed.
    pub fn cancel(&mut self, transport: &TransportState) -> Result<()> {
        // Send ResourceIcl packet containing resource_hash
        let mut packet = Packet::new(
            &self.link as &dyn Encryptable,
            self.hash.to_vec(),
            PacketType::Data,
            PacketContext::ResourceIcl,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(&self.link as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        self.status = ResourceStatus::Failed;
        self.last_activity = now();

        // Invoke callback
        if let Some(ref cb) = self.callback {
            cb(self);
        }

        Ok(())
    }

    // ── Wire format helpers (public for testing) ──

    /// Build a ResourceReq wire-format packet from components.
    /// Used by receiver (request_next) and for testing round-trip.
    pub fn build_request_packet(
        exhausted: bool,
        last_map_hash: Option<&[u8; 4]>,
        resource_hash: &[u8; 32],
        requested_map_hashes: &[[u8; 4]],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        if exhausted {
            data.push(HASHMAP_IS_EXHAUSTED);
            if let Some(lmh) = last_map_hash {
                data.extend_from_slice(lmh);
            } else {
                data.extend_from_slice(&[0u8; 4]);
            }
        } else {
            data.push(HASHMAP_IS_NOT_EXHAUSTED);
        }
        data.extend_from_slice(resource_hash);
        for mh in requested_map_hashes {
            data.extend_from_slice(mh);
        }
        data
    }

    /// Parse a ResourceReq wire-format packet into components.
    /// Returns (exhausted, last_map_hash, resource_hash, requested_map_hashes).
    pub fn parse_request_packet(
        data: &[u8],
    ) -> Result<(bool, Option<[u8; 4]>, [u8; 32], Vec<[u8; 4]>)> {
        if data.is_empty() {
            return Err(FerretError::MalformedPacket("empty request".into()));
        }

        let exhausted = data[0] == HASHMAP_IS_EXHAUSTED;

        let (last_map_hash, resource_hash, map_hashes_start) = if exhausted {
            if data.len() < 37 {
                return Err(FerretError::MalformedPacket(
                    "exhausted request too short".into(),
                ));
            }
            let lmh: [u8; 4] = data[1..5]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad last_map_hash".into()))?;
            let rh: [u8; 32] = data[5..37]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad resource_hash".into()))?;
            (Some(lmh), rh, 37)
        } else {
            if data.len() < 33 {
                return Err(FerretError::MalformedPacket(
                    "request too short".into(),
                ));
            }
            let rh: [u8; 32] = data[1..33]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad resource_hash".into()))?;
            (None, rh, 33)
        };

        let remaining = &data[map_hashes_start..];
        let num_hashes = remaining.len() / MAPHASH_LEN;
        let mut map_hashes = Vec::with_capacity(num_hashes);
        for i in 0..num_hashes {
            let s = i * MAPHASH_LEN;
            let e = s + MAPHASH_LEN;
            if e > remaining.len() {
                break;
            }
            let mh: [u8; 4] = remaining[s..e]
                .try_into()
                .map_err(|_| FerretError::MalformedPacket("bad map_hash".into()))?;
            map_hashes.push(mh);
        }

        Ok((exhausted, last_map_hash, resource_hash, map_hashes))
    }
}
