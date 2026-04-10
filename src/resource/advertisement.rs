// ResourceAdvertisement: pack/unpack for resource advertisement messages

use crate::resource::ResourceFlags;
use crate::{FerretError, Result};
use serde::{Deserialize, Serialize};

/// ResourceAdvertisement describes a Resource for the remote peer.
///
/// Serialized as a msgpack dictionary with single-letter string keys
/// matching the Python RNS reference (`umsgpack.packb(adv_dict)`).
pub struct ResourceAdvertisement {
    pub t: usize,           // transfer size (encrypted)
    pub d: usize,           // data size (original uncompressed)
    pub n: usize,           // number of parts
    pub h: [u8; 32],        // resource hash
    pub r: [u8; 4],         // random hash
    pub o: [u8; 32],        // original hash (first segment)
    pub i: usize,           // segment index (1-based)
    pub l: usize,           // total segments
    pub q: Option<Vec<u8>>, // request ID (16 bytes or nil)
    pub f: u8,              // flags byte
    pub m: Vec<u8>,         // hashmap bytes for current segment
    // Decoded flags (not serialized)
    pub encrypted: bool,
    pub compressed: bool,
    pub split: bool,
    pub is_request: bool,
    pub is_response: bool,
    pub has_metadata: bool,
}

/// Overhead bytes in the advertisement (non-hashmap portion).
pub const OVERHEAD: usize = 134;

/// Maximum number of map hashes that fit in one advertisement.
/// floor((Link_MDU - OVERHEAD) / MAPHASH_LEN)
pub const HASHMAP_MAX_LEN: usize = 82;

/// Collision guard window size: 2 * WINDOW_MAX + HASHMAP_MAX_LEN.
pub const COLLISION_GUARD_SIZE: usize = 232;

/// Serde helper for msgpack serialization with string keys.
/// The `q` field is `Option<serde_bytes::ByteBuf>` so that
/// `None` serializes as msgpack nil and `Some(bytes)` as binary.
#[derive(Serialize, Deserialize)]
struct AdvWire {
    t: u64,
    d: u64,
    n: u64,
    #[serde(with = "serde_bytes")]
    h: Vec<u8>,
    #[serde(with = "serde_bytes")]
    r: Vec<u8>,
    #[serde(with = "serde_bytes")]
    o: Vec<u8>,
    i: u64,
    l: u64,
    q: Option<serde_bytes::ByteBuf>,
    f: u8,
    #[serde(with = "serde_bytes")]
    m: Vec<u8>,
}

impl ResourceAdvertisement {
    /// Pack the advertisement to msgpack bytes.
    ///
    /// Uses `rmp_serde::to_vec_named` to produce a msgpack map with
    /// string keys ("t", "d", …) matching the Python reference.
    pub fn pack(&self) -> Result<Vec<u8>> {
        let wire = AdvWire {
            t: self.t as u64,
            d: self.d as u64,
            n: self.n as u64,
            h: self.h.to_vec(),
            r: self.r.to_vec(),
            o: self.o.to_vec(),
            i: self.i as u64,
            l: self.l as u64,
            q: self.q.as_ref().map(|v| serde_bytes::ByteBuf::from(v.clone())),
            f: self.f,
            m: self.m.clone(),
        };
        rmp_serde::to_vec_named(&wire)
            .map_err(|e| FerretError::Serialization(e.to_string()))
    }

    /// Unpack a ResourceAdvertisement from msgpack bytes.
    pub fn unpack(data: &[u8]) -> Result<Self> {
        let wire: AdvWire = rmp_serde::from_slice(data)
            .map_err(|e| FerretError::Deserialization(e.to_string()))?;

        let h: [u8; 32] = wire.h.try_into().map_err(|_| {
            FerretError::Deserialization("resource hash must be 32 bytes".into())
        })?;
        let r: [u8; 4] = wire.r.try_into().map_err(|_| {
            FerretError::Deserialization("random hash must be 4 bytes".into())
        })?;
        let o: [u8; 32] = wire.o.try_into().map_err(|_| {
            FerretError::Deserialization("original hash must be 32 bytes".into())
        })?;

        let q = wire.q.map(|b| b.into_vec());
        let flags = ResourceFlags::from_byte(wire.f);

        Ok(Self {
            t: wire.t as usize,
            d: wire.d as usize,
            n: wire.n as usize,
            h,
            r,
            o,
            i: wire.i as usize,
            l: wire.l as usize,
            q,
            f: wire.f,
            m: wire.m,
            encrypted: flags.encrypted,
            compressed: flags.compressed,
            split: flags.split,
            is_request: flags.is_request,
            is_response: flags.is_response,
            has_metadata: flags.has_metadata,
        })
    }

    /// Build a ResourceAdvertisement from a Resource's fields.
    pub fn from_resource(resource: &super::resource::Resource) -> Self {
        let flags = ResourceFlags {
            encrypted: resource.encrypted,
            compressed: resource.compressed,
            split: resource.split,
            is_request: false,
            is_response: resource.is_response,
            has_metadata: resource.has_metadata,
        };
        Self {
            t: resource.size,
            d: resource.total_size,
            n: resource.total_parts,
            h: resource.hash,
            r: resource.random_hash,
            o: resource.original_hash,
            i: resource.segment_index,
            l: resource.total_segments,
            q: resource.request_id.map(|id| id.to_vec()),
            f: flags.to_byte(),
            m: resource.hashmap.clone(),
            encrypted: flags.encrypted,
            compressed: flags.compressed,
            split: flags.split,
            is_request: false,
            is_response: resource.is_response,
            has_metadata: resource.has_metadata,
        }
    }

    /// Quick check: is this packed advertisement a request?
    pub fn is_request_adv(data: &[u8]) -> Result<bool> {
        let adv = Self::unpack(data)?;
        Ok(adv.is_request)
    }

    /// Quick check: is this packed advertisement a response?
    pub fn is_response_adv(data: &[u8]) -> Result<bool> {
        let adv = Self::unpack(data)?;
        Ok(adv.is_response)
    }

    /// Read the request_id from packed advertisement data.
    pub fn read_request_id(data: &[u8]) -> Result<Option<Vec<u8>>> {
        let adv = Self::unpack(data)?;
        Ok(adv.q)
    }

    /// Read the transfer size from packed advertisement data.
    pub fn read_transfer_size(data: &[u8]) -> Result<usize> {
        let adv = Self::unpack(data)?;
        Ok(adv.t)
    }
}
