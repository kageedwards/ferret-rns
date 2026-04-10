// Resource struct: construction, accessors, and core logic

use crate::crypto::hashes::sha256;
use crate::identity::Identity;
use crate::link::Link;
use crate::resource::{
    ResourceStatus, MAPHASH_LEN, MAX_EFFICIENT_SIZE,
    RANDOM_HASH_SIZE, AUTO_COMPRESS_MAX_SIZE, MAX_RETRIES, MAX_ADV_RETRIES,
    SENDER_GRACE_TIME, PART_TIMEOUT_FACTOR, WINDOW, WINDOW_MIN,
    WINDOW_MAX_SLOW, WINDOW_FLEXIBILITY,
};
use crate::resource::advertisement::COLLISION_GUARD_SIZE;
use crate::types::constants::{HEADER_MAXSIZE, IFAC_MIN_SIZE};
use crate::{FerretError, Result};

/// Resource: large data transfer over a Link with segmentation,
/// compression, hashmap verification, and flow control.
pub struct Resource {
    // Identity
    pub hash: [u8; 32],
    pub truncated_hash: [u8; 16],
    pub original_hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub expected_proof: [u8; 32],

    // Transfer state
    pub status: ResourceStatus,
    pub initiator: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub split: bool,
    pub has_metadata: bool,
    pub is_response: bool,

    // Sizes
    pub size: usize,
    pub total_size: usize,
    pub uncompressed_size: usize,
    pub sdu: usize,

    // Parts
    pub total_parts: usize,
    pub sent_parts: usize,
    pub received_count: usize,
    pub outstanding_parts: usize,
    pub parts: Vec<Option<Vec<u8>>>,
    pub hashmap: Vec<u8>,
    pub hashmap_height: usize,

    // Segmentation
    pub segment_index: usize,
    pub total_segments: usize,

    // Window
    pub window: usize,
    pub window_min: usize,
    pub window_max: usize,
    pub window_flexibility: usize,

    // Rate estimation
    pub rtt: Option<f64>,
    pub eifr: Option<f64>,
    pub previous_eifr: Option<f64>,
    pub fast_rate_rounds: usize,
    pub very_slow_rate_rounds: usize,
    pub req_data_rtt_rate: f64,
    pub req_resp_rtt_rate: f64,

    // Timing
    pub last_activity: f64,
    pub started_transferring: Option<f64>,
    pub adv_sent: Option<f64>,
    pub last_part_sent: Option<f64>,
    pub req_sent: Option<f64>,
    pub req_resp: Option<f64>,
    pub req_sent_bytes: usize,
    pub rtt_rxd_bytes: usize,
    pub rtt_rxd_bytes_at_part_req: usize,

    // Retry state
    pub retries_left: usize,
    pub max_retries: usize,
    pub max_adv_retries: usize,
    pub timeout: f64,
    pub timeout_factor: f64,
    pub part_timeout_factor: f64,
    pub sender_grace_time: f64,

    // Receiver hashmap state
    pub receiver_hashmap: Vec<Option<[u8; 4]>>,
    pub waiting_for_hmu: bool,
    pub consecutive_completed_height: isize,
    pub receiver_min_consecutive_height: usize,

    // Callbacks
    pub callback: Option<Box<dyn Fn(&Resource) + Send + Sync>>,
    pub progress_callback: Option<Box<dyn Fn(&Resource) + Send + Sync>>,

    // Request association
    pub request_id: Option<[u8; 16]>,

    // Metadata
    pub metadata: Option<Vec<u8>>,
    pub metadata_size: usize,

    // Storage paths (receiver)
    pub storagepath: Option<std::path::PathBuf>,
    pub meta_storagepath: Option<std::path::PathBuf>,

    // Link reference
    pub link: Link,

    // Auto-compress settings
    pub auto_compress: bool,
    pub auto_compress_limit: usize,
}

impl Resource {
    /// Compute the SDU (Service Data Unit) for a given Link.
    /// SDU = Link_MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
    pub fn compute_sdu(link: &Link) -> Result<usize> {
        let mtu = link.mtu()?;
        Ok(mtu.saturating_sub(HEADER_MAXSIZE).saturating_sub(IFAC_MIN_SIZE))
    }

    /// Compute the 4-byte map hash for a data part.
    /// map_hash = full_hash(part_data + random_hash)[0..4]
    pub fn get_map_hash(data: &[u8], random_hash: &[u8; 4]) -> [u8; 4] {
        let mut input = Vec::with_capacity(data.len() + RANDOM_HASH_SIZE);
        input.extend_from_slice(data);
        input.extend_from_slice(random_hash);
        let full = sha256(&input);
        let mut hash = [0u8; 4];
        hash.copy_from_slice(&full[..MAPHASH_LEN]);
        hash
    }

    /// Prepend metadata to data: 3-byte BE size + msgpack(metadata) + data.
    /// `metadata_bytes` should be pre-serialized msgpack bytes.
    pub fn prepend_metadata(
        metadata_bytes: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let meta_len = metadata_bytes.len();
        if meta_len > crate::resource::METADATA_MAX_SIZE {
            return Err(FerretError::ResourceFailed(
                "metadata exceeds maximum size".into(),
            ));
        }
        // 3-byte big-endian size header
        let size_bytes = [
            ((meta_len >> 16) & 0xFF) as u8,
            ((meta_len >> 8) & 0xFF) as u8,
            (meta_len & 0xFF) as u8,
        ];
        let mut result = Vec::with_capacity(3 + meta_len + data.len());
        result.extend_from_slice(&size_bytes);
        result.extend_from_slice(metadata_bytes);
        result.extend_from_slice(data);
        Ok(result)
    }

    /// Extract metadata from data that was prepended with prepend_metadata.
    /// Returns (metadata_bytes, remaining_data).
    pub fn extract_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if data.len() < 3 {
            return Err(FerretError::Deserialization(
                "data too short for metadata header".into(),
            ));
        }
        let meta_len = ((data[0] as usize) << 16)
            | ((data[1] as usize) << 8)
            | (data[2] as usize);
        if data.len() < 3 + meta_len {
            return Err(FerretError::Deserialization(
                "data too short for metadata payload".into(),
            ));
        }
        let meta_bytes = data[3..3 + meta_len].to_vec();
        let remaining = data[3 + meta_len..].to_vec();
        Ok((meta_bytes, remaining))
    }

    /// Compute segmentation parameters for a given total size.
    /// Returns (split, total_segments).
    pub fn compute_segmentation(total_size: usize) -> (bool, usize) {
        if total_size <= MAX_EFFICIENT_SIZE {
            (false, 1)
        } else {
            let segments = (total_size + MAX_EFFICIENT_SIZE - 1) / MAX_EFFICIENT_SIZE;
            (true, segments)
        }
    }

    /// Construct a new Resource as initiator from byte data.
    /// `metadata` should be pre-serialized msgpack bytes if provided.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data: &[u8],
        link: &Link,
        metadata: Option<&[u8]>,
        _advertise: bool,
        auto_compress: bool,
        callback: Option<Box<dyn Fn(&Resource) + Send + Sync>>,
        progress_callback: Option<Box<dyn Fn(&Resource) + Send + Sync>>,
        _timeout: Option<f64>,
        segment_index: usize,
        original_hash: Option<[u8; 32]>,
        request_id: Option<[u8; 16]>,
        is_response: bool,
    ) -> Result<Self> {
        let sdu = Self::compute_sdu(link)?;
        if sdu == 0 {
            return Err(FerretError::ResourceFailed("SDU is zero".into()));
        }

        // Step 1: Optionally prepend metadata
        let has_metadata = metadata.is_some();
        let mut payload = if let Some(meta) = metadata {
            Self::prepend_metadata(meta, data)?
        } else {
            data.to_vec()
        };
        let uncompressed_size = payload.len();
        let original_data = payload.clone();

        // Step 2: Optionally compress with bzip2
        let compressed = if auto_compress && payload.len() <= AUTO_COMPRESS_MAX_SIZE {
            let compressed_data = Self::try_compress(&payload)?;
            if compressed_data.len() < payload.len() {
                payload = compressed_data;
                true
            } else {
                false
            }
        } else {
            false
        };

        // Step 3: Generate random_hash
        let mut random_hash = [0u8; RANDOM_HASH_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_hash);

        // Step 4: Encrypt via Link
        let encrypted_data = link.encrypt(&payload)?;
        let size = encrypted_data.len();

        // Step 5: Compute segmentation
        let total_size = uncompressed_size;
        let (split, total_segments) = Self::compute_segmentation(total_size);
        let seg_idx = if segment_index == 0 { 1 } else { segment_index };

        // Step 6: Split into SDU-sized parts and build hashmap
        let (parts, hashmap, final_random_hash) =
            Self::build_parts_and_hashmap(&encrypted_data, sdu, &random_hash)?;
        let total_parts = parts.len();

        // Step 7: Compute hashes and proof
        let mut hash_input = Vec::with_capacity(original_data.len() + RANDOM_HASH_SIZE);
        hash_input.extend_from_slice(&original_data);
        hash_input.extend_from_slice(&final_random_hash);

        let resource_hash = sha256(&hash_input);
        let truncated_hash = Identity::truncated_hash(&hash_input);

        let mut proof_input = Vec::with_capacity(original_data.len() + 32);
        proof_input.extend_from_slice(&original_data);
        proof_input.extend_from_slice(&resource_hash);
        let expected_proof = sha256(&proof_input);

        let orig_hash = original_hash.unwrap_or(resource_hash);

        let rtt = link.rtt()?;
        let timeout = rtt.unwrap_or(15.0);

        Ok(Self {
            hash: resource_hash,
            truncated_hash,
            original_hash: orig_hash,
            random_hash: final_random_hash,
            expected_proof,
            status: ResourceStatus::None,
            initiator: true,
            encrypted: true,
            compressed,
            split,
            has_metadata,
            is_response,
            size,
            total_size,
            uncompressed_size,
            sdu,
            total_parts,
            sent_parts: 0,
            received_count: 0,
            outstanding_parts: 0,
            parts: parts.into_iter().map(Some).collect(),
            hashmap,
            hashmap_height: 0,
            segment_index: seg_idx,
            total_segments,
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
            last_activity: crate::link::link::now(),
            started_transferring: None,
            adv_sent: None,
            last_part_sent: None,
            req_sent: None,
            req_resp: None,
            req_sent_bytes: 0,
            rtt_rxd_bytes: 0,
            rtt_rxd_bytes_at_part_req: 0,
            retries_left: MAX_RETRIES,
            max_retries: MAX_RETRIES,
            max_adv_retries: MAX_ADV_RETRIES,
            timeout,
            timeout_factor: PART_TIMEOUT_FACTOR as f64,
            part_timeout_factor: PART_TIMEOUT_FACTOR as f64,
            sender_grace_time: SENDER_GRACE_TIME,
            receiver_hashmap: Vec::new(),
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
            auto_compress,
            auto_compress_limit: AUTO_COMPRESS_MAX_SIZE,
        })
    }

    /// Split encrypted data into SDU-sized parts and build the hashmap.
    /// Returns (parts, hashmap_bytes, final_random_hash).
    /// Regenerates random_hash if a collision is detected within the
    /// COLLISION_GUARD_SIZE window.
    fn build_parts_and_hashmap(
        encrypted_data: &[u8],
        sdu: usize,
        initial_random_hash: &[u8; 4],
    ) -> Result<(Vec<Vec<u8>>, Vec<u8>, [u8; 4])> {
        let mut random_hash = *initial_random_hash;

        loop {
            let parts: Vec<Vec<u8>> = encrypted_data
                .chunks(sdu)
                .map(|c| c.to_vec())
                .collect();

            let mut hashmap = Vec::with_capacity(parts.len() * MAPHASH_LEN);
            let mut collision = false;

            for (idx, part) in parts.iter().enumerate() {
                let map_hash = Self::get_map_hash(part, &random_hash);

                // Check for collisions within the guard window
                let guard_start = if idx >= COLLISION_GUARD_SIZE {
                    idx - COLLISION_GUARD_SIZE
                } else {
                    0
                };
                for prev_idx in guard_start..idx {
                    let prev_start = prev_idx * MAPHASH_LEN;
                    let prev_end = prev_start + MAPHASH_LEN;
                    if hashmap[prev_start..prev_end] == map_hash {
                        collision = true;
                        break;
                    }
                }

                if collision {
                    break;
                }
                hashmap.extend_from_slice(&map_hash);
            }

            if !collision {
                return Ok((parts, hashmap, random_hash));
            }

            // Regenerate random_hash and retry
            rand::RngCore::fill_bytes(
                &mut rand::thread_rng(),
                &mut random_hash,
            );
        }
    }

    /// Try to compress data with bzip2. Returns compressed bytes.
    fn try_compress(data: &[u8]) -> Result<Vec<u8>> {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;

        let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(data)
            .map_err(|e| FerretError::ResourceFailed(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| FerretError::ResourceFailed(e.to_string()))
    }

    // ── Accessors ──

    /// Overall transfer progress [0.0, 1.0] across all segments.
    pub fn get_progress(&self) -> f64 {
        if self.total_segments == 0 || self.total_parts == 0 {
            return 0.0;
        }
        if self.initiator {
            // Initiator: based on sent_parts across segments
            let seg_progress = self.sent_parts as f64 / self.total_parts as f64;
            let completed_segs = (self.segment_index.saturating_sub(1)) as f64;
            let total = self.total_segments as f64;
            ((completed_segs + seg_progress) / total).clamp(0.0, 1.0)
        } else {
            // Receiver: based on received_count across segments
            let seg_progress = self.received_count as f64 / self.total_parts as f64;
            let completed_segs = (self.segment_index.saturating_sub(1)) as f64;
            let total = self.total_segments as f64;
            ((completed_segs + seg_progress) / total).clamp(0.0, 1.0)
        }
    }

    /// Current segment progress [0.0, 1.0].
    pub fn get_segment_progress(&self) -> f64 {
        if self.total_parts == 0 {
            return 0.0;
        }
        if self.initiator {
            (self.sent_parts as f64 / self.total_parts as f64).clamp(0.0, 1.0)
        } else {
            (self.received_count as f64 / self.total_parts as f64).clamp(0.0, 1.0)
        }
    }

    /// Total encrypted transfer size.
    pub fn transfer_size(&self) -> usize {
        self.size
    }

    /// Original uncompressed data size.
    pub fn data_size(&self) -> usize {
        self.total_size
    }

    /// Whether the resource data is compressed.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}
