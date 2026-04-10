// Resource receiver: accept, reject, receive_part, request_next, assemble, prove

use crate::crypto::hashes::sha256;
use crate::link::link::now;
use crate::link::Link;
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::resource::advertisement::ResourceAdvertisement;
use crate::resource::resource::Resource;
use crate::resource::{
    ResourceFlags, ResourceStatus, MAPHASH_LEN, WINDOW, WINDOW_MAX_SLOW,
    WINDOW_MIN, WINDOW_FLEXIBILITY,
};
use crate::transport::transport::TransportState;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};

impl Resource {
    /// Accept an advertised resource. Static constructor for receiver side.
    pub fn accept(
        adv_data: &[u8],
        link: &Link,
        callback: Option<Box<dyn Fn(&Resource) + Send + Sync>>,
        progress_callback: Option<Box<dyn Fn(&Resource) + Send + Sync>>,
        request_id: Option<[u8; 16]>,
    ) -> Result<Self> {
        let adv = ResourceAdvertisement::unpack(adv_data)?;
        let sdu = Resource::compute_sdu(link)?;
        if sdu == 0 {
            return Err(FerretError::ResourceFailed("SDU is zero".into()));
        }

        let total_parts = (adv.t + sdu - 1) / sdu;
        let flags = ResourceFlags::from_byte(adv.f);

        // Initialize parts array (all None)
        let parts: Vec<Option<Vec<u8>>> = vec![None; total_parts];

        // Parse initial hashmap segment from advertisement
        let mut receiver_hashmap: Vec<Option<[u8; 4]>> = vec![None; total_parts];
        let initial_entries = adv.m.len() / MAPHASH_LEN;
        for i in 0..initial_entries {
            if i >= total_parts {
                break;
            }
            let start = i * MAPHASH_LEN;
            let end = start + MAPHASH_LEN;
            if end > adv.m.len() {
                break;
            }
            let mut mh = [0u8; 4];
            mh.copy_from_slice(&adv.m[start..end]);
            receiver_hashmap[i] = Some(mh);
        }

        let rtt = link.rtt()?;
        let timeout = rtt.unwrap_or(15.0);

        Ok(Resource {
            hash: adv.h,
            truncated_hash: crate::identity::Identity::truncated_hash(
                &[adv.h.as_slice(), adv.r.as_slice()].concat(),
            ),
            original_hash: adv.o,
            random_hash: adv.r,
            expected_proof: [0u8; 32], // receiver doesn't know expected proof
            status: ResourceStatus::Transferring,
            initiator: false,
            encrypted: flags.encrypted,
            compressed: flags.compressed,
            split: flags.split,
            has_metadata: flags.has_metadata,
            is_response: flags.is_response,
            size: adv.t,
            total_size: adv.d,
            uncompressed_size: adv.d,
            sdu,
            total_parts,
            sent_parts: 0,
            received_count: 0,
            outstanding_parts: 0,
            parts,
            hashmap: Vec::new(),
            hashmap_height: initial_entries,
            segment_index: adv.i,
            total_segments: adv.l,
            window: WINDOW,
            window_min: WINDOW_MIN,
            window_max: WINDOW_MAX_SLOW,
            window_flexibility: WINDOW_FLEXIBILITY,
            rtt,
            eifr: None,
            previous_eifr: None,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            req_data_rtt_rate: 0.0,
            req_resp_rtt_rate: 0.0,
            last_activity: now(),
            started_transferring: Some(now()),
            adv_sent: None,
            last_part_sent: None,
            req_sent: None,
            req_resp: None,
            req_sent_bytes: 0,
            rtt_rxd_bytes: 0,
            rtt_rxd_bytes_at_part_req: 0,
            retries_left: crate::resource::MAX_RETRIES,
            max_retries: crate::resource::MAX_RETRIES,
            max_adv_retries: crate::resource::MAX_ADV_RETRIES,
            timeout,
            timeout_factor: crate::resource::PART_TIMEOUT_FACTOR as f64,
            part_timeout_factor: crate::resource::PART_TIMEOUT_FACTOR as f64,
            sender_grace_time: crate::resource::SENDER_GRACE_TIME,
            receiver_hashmap,
            waiting_for_hmu: false,
            consecutive_completed_height: -1,
            receiver_min_consecutive_height: 0,
            callback,
            progress_callback,
            request_id,
            metadata: None,
            metadata_size: 0,
            storagepath: None,
            meta_storagepath: None,
            link: link.clone(),
            auto_compress: false,
            auto_compress_limit: 0,
        })
    }

    /// Reject an advertised resource. Sends ResourceRcl packet.
    pub fn reject(
        adv_data: &[u8],
        link: &Link,
        transport: &TransportState,
    ) -> Result<()> {
        let adv = ResourceAdvertisement::unpack(adv_data)?;

        let mut packet = Packet::new(
            link as &dyn Encryptable,
            adv.h.to_vec(),
            PacketType::Data,
            PacketContext::ResourceRcl,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(link as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        Ok(())
    }

    /// Receive a resource part packet.
    ///
    /// Computes map_hash, matches against receiver_hashmap within the
    /// current window, stores the part if found.
    pub fn receive_part(&mut self, part_data: &[u8]) -> Result<()> {
        let map_hash = Resource::get_map_hash(part_data, &self.random_hash);

        // Search receiver_hashmap within current window for matching entry
        let search_start = self.consecutive_completed_height.max(0) as usize;
        let search_end = self
            .receiver_hashmap
            .len()
            .min(search_start + self.window + self.window_max);

        let mut matched_idx = None;
        for idx in search_start..search_end {
            if let Some(ref stored_hash) = self.receiver_hashmap[idx] {
                if *stored_hash == map_hash && self.parts[idx].is_none() {
                    matched_idx = Some(idx);
                    break;
                }
            }
        }

        if let Some(idx) = matched_idx {
            self.parts[idx] = Some(part_data.to_vec());
            self.received_count += 1;
            if self.outstanding_parts > 0 {
                self.outstanding_parts -= 1;
            }
            self.rtt_rxd_bytes += part_data.len();
            self.last_activity = now();

            // Update consecutive_completed_height
            self.update_consecutive_completed_height();

            // Invoke progress callback
            if let Some(ref cb) = self.progress_callback {
                cb(self);
            }

            // If all parts received, begin assembly
            if self.received_count == self.total_parts {
                self.status = ResourceStatus::Assembling;
            }
        }

        Ok(())
    }

    /// Update consecutive_completed_height by scanning forward.
    pub fn update_consecutive_completed_height(&mut self) {
        let start = (self.consecutive_completed_height + 1).max(0) as usize;
        let mut height = self.consecutive_completed_height;
        for idx in start..self.parts.len() {
            if self.parts[idx].is_some() {
                height = idx as isize;
            } else {
                break;
            }
        }
        self.consecutive_completed_height = height;
    }

    /// Request the next batch of parts from the initiator.
    pub fn request_next(&mut self, transport: &TransportState) -> Result<()> {
        if self.waiting_for_hmu {
            return Ok(());
        }

        // Determine if hashmap is exhausted
        let exhausted = self.hashmap_height >= self.receiver_hashmap.len()
            || self.all_known_hashes_received();

        let last_map_hash = if exhausted {
            // Find the last known map_hash
            self.last_known_map_hash()
        } else {
            None
        };

        // Collect requested map_hashes (up to window size, for parts not yet received)
        let mut requested: Vec<[u8; 4]> = Vec::new();
        let start = (self.consecutive_completed_height + 1).max(0) as usize;
        for idx in start..self.receiver_hashmap.len() {
            if requested.len() >= self.window {
                break;
            }
            if self.parts[idx].is_none() {
                if let Some(mh) = self.receiver_hashmap[idx] {
                    requested.push(mh);
                }
            }
        }

        if requested.is_empty() && !exhausted {
            return Ok(());
        }

        // Build request packet
        let data = Resource::build_request_packet(
            exhausted,
            last_map_hash.as_ref(),
            &self.hash,
            &requested,
        );

        let mut packet = Packet::new(
            &self.link as &dyn Encryptable,
            data.clone(),
            PacketType::Data,
            PacketContext::ResourceReq,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        packet.pack(&self.link as &dyn Encryptable)?;
        transport.outbound(&mut packet)?;

        self.outstanding_parts = requested.len();
        self.req_sent = Some(now());
        self.req_sent_bytes = data.len();
        self.rtt_rxd_bytes_at_part_req = self.rtt_rxd_bytes;
        self.last_activity = now();

        if exhausted {
            self.waiting_for_hmu = true;
        }

        Ok(())
    }

    /// Check if all known hashmap entries have been received.
    fn all_known_hashes_received(&self) -> bool {
        for (idx, mh) in self.receiver_hashmap.iter().enumerate() {
            if mh.is_some() && self.parts[idx].is_none() {
                return false;
            }
        }
        true
    }

    /// Get the last known map_hash from the receiver hashmap.
    fn last_known_map_hash(&self) -> Option<[u8; 4]> {
        for mh in self.receiver_hashmap.iter().rev() {
            if let Some(hash) = mh {
                return Some(*hash);
            }
        }
        None
    }

    /// Handle a hashmap update packet.
    ///
    /// Wire format: [resource_hash:32][msgpack([segment_index, hashmap_bytes])]
    pub fn hashmap_update_packet(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() < 33 {
            return Err(FerretError::MalformedPacket(
                "HMU packet too short".into(),
            ));
        }

        let resource_hash: [u8; 32] = plaintext[..32]
            .try_into()
            .map_err(|_| FerretError::MalformedPacket("bad HMU resource_hash".into()))?;

        if resource_hash != self.hash {
            return Err(FerretError::ResourceFailed(
                "HMU resource hash mismatch".into(),
            ));
        }

        let msgpack_data = &plaintext[32..];
        let (segment_index, hashmap_bytes): (usize, Vec<u8>) =
            crate::util::msgpack::deserialize(msgpack_data)?;

        self.hashmap_update(segment_index, &hashmap_bytes)
    }

    /// Update the local hashmap with new entries from a segment.
    pub fn hashmap_update(&mut self, segment: usize, hashmap: &[u8]) -> Result<()> {
        let num_entries = hashmap.len() / MAPHASH_LEN;

        for i in 0..num_entries {
            let target_idx = segment + i;
            if target_idx >= self.receiver_hashmap.len() {
                break;
            }
            let start = i * MAPHASH_LEN;
            let end = start + MAPHASH_LEN;
            if end > hashmap.len() {
                break;
            }
            let mut mh = [0u8; 4];
            mh.copy_from_slice(&hashmap[start..end]);
            self.receiver_hashmap[target_idx] = Some(mh);
        }

        // Update hashmap_height
        let new_height = segment + num_entries;
        if new_height > self.hashmap_height {
            self.hashmap_height = new_height;
        }

        self.waiting_for_hmu = false;
        Ok(())
    }

    /// Assemble all received parts into the final data.
    pub fn assemble(&mut self) -> Result<()> {
        self.status = ResourceStatus::Assembling;

        // Concatenate all parts in order
        let mut assembled = Vec::with_capacity(self.size);
        for (i, part) in self.parts.iter().enumerate() {
            match part {
                Some(data) => assembled.extend_from_slice(data),
                None => {
                    return Err(FerretError::ResourceCorrupt(format!(
                        "missing part {} during assembly",
                        i
                    )));
                }
            }
        }

        // Decrypt via Link
        let decrypted = self
            .link
            .decrypt(&assembled)?
            .ok_or_else(|| FerretError::ResourceCorrupt("decryption failed".into()))?;

        // Strip 4-byte random_hash prefix
        if decrypted.len() < crate::resource::RANDOM_HASH_SIZE {
            return Err(FerretError::ResourceCorrupt(
                "decrypted data too short for random_hash".into(),
            ));
        }
        let payload = &decrypted[crate::resource::RANDOM_HASH_SIZE..];

        // Decompress with bzip2 if compressed flag set
        let data = if self.compressed {
            Self::try_decompress(payload)?
        } else {
            payload.to_vec()
        };

        // Verify full_hash(assembled_data + random_hash) == self.hash
        let mut hash_input = Vec::with_capacity(data.len() + crate::resource::RANDOM_HASH_SIZE);
        hash_input.extend_from_slice(&data);
        hash_input.extend_from_slice(&self.random_hash);
        let computed_hash = sha256(&hash_input);

        if computed_hash != self.hash {
            self.status = ResourceStatus::Corrupt;
            return Err(FerretError::ResourceCorrupt(
                "assembled data hash mismatch".into(),
            ));
        }

        // Extract metadata if has_metadata
        if self.has_metadata {
            let (_meta_bytes, _remaining) = Resource::extract_metadata(&data)?;
            self.metadata = Some(_meta_bytes);
        }

        self.status = ResourceStatus::Complete;
        self.last_activity = now();

        // Invoke callback
        if let Some(ref cb) = self.callback {
            cb(self);
        }

        Ok(())
    }

    /// Send the resource proof after successful assembly.
    ///
    /// Proof: resource_hash(32) + full_hash(assembled_data + resource_hash)(32)
    pub fn prove(&self, data: &[u8], transport: &TransportState) -> Result<()> {
        let mut proof_input = Vec::with_capacity(data.len() + 32);
        proof_input.extend_from_slice(data);
        proof_input.extend_from_slice(&self.hash);
        let proof_hash = sha256(&proof_input);

        let mut proof_data = Vec::with_capacity(64);
        proof_data.extend_from_slice(&self.hash);
        proof_data.extend_from_slice(&proof_hash);

        let mut packet = Packet::new(
            &self.link as &dyn Encryptable,
            proof_data,
            PacketType::Proof,
            PacketContext::ResourcePrf,
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

    /// Try to decompress bzip2 data.
    fn try_decompress(data: &[u8]) -> Result<Vec<u8>> {
        use bzip2::read::BzDecoder;
        use std::io::Read;

        let mut decoder = BzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| FerretError::ResourceCorrupt(format!("decompression failed: {}", e)))?;
        Ok(decompressed)
    }
}
