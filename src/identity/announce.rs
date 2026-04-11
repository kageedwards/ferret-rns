// AnnounceData and validate_announce

use crate::crypto::{KEYSIZE, NAME_HASH_LENGTH, RATCHETSIZE, SIGLENGTH};
use crate::{FerretError, Result};

use super::identity::Identity;
use super::ratchet::RatchetStore;
use super::store::IdentityStore;

/// Parsed announce data, independent of the Packet module.
pub struct AnnounceData {
    pub destination_hash: Vec<u8>,  // 16 bytes
    pub public_key: Vec<u8>,       // 64 bytes
    pub name_hash: Vec<u8>,        // 10 bytes
    pub random_hash: Vec<u8>,      // 10 bytes
    pub ratchet: Vec<u8>,          // 32 bytes or empty
    pub signature: Vec<u8>,        // 64 bytes
    pub app_data: Option<Vec<u8>>, // variable or None
    pub context_flag: bool,        // true = ratchet present
}

impl AnnounceData {
    /// Parse announce data bytes with a context flag.
    /// Layout with ratchet (context_flag=true):
    ///   [pub_key:64][name_hash:10][random_hash:10][ratchet:32][signature:64][app_data:0-N]
    /// Layout without ratchet (context_flag=false):
    ///   [pub_key:64][name_hash:10][random_hash:10][signature:64][app_data:0-N]
    pub fn parse(data: &[u8], destination_hash: &[u8], context_flag: bool) -> Result<Self> {
        let keysize = KEYSIZE / 8; // 64
        let name_hash_len = NAME_HASH_LENGTH / 8; // 10
        let ratchetsize = RATCHETSIZE / 8; // 32
        let sig_len = SIGLENGTH / 8; // 64

        if context_flag {
            let min_len = keysize + name_hash_len + 10 + ratchetsize + sig_len;
            if data.len() < min_len {
                return Err(FerretError::KeyLength {
                    expected: min_len,
                    got: data.len(),
                });
            }
            let mut offset = 0;
            let public_key = data[offset..offset + keysize].to_vec();
            offset += keysize;
            let name_hash = data[offset..offset + name_hash_len].to_vec();
            offset += name_hash_len;
            let random_hash = data[offset..offset + 10].to_vec();
            offset += 10;
            let ratchet = data[offset..offset + ratchetsize].to_vec();
            offset += ratchetsize;
            let signature = data[offset..offset + sig_len].to_vec();
            offset += sig_len;
            let app_data = if data.len() > offset {
                Some(data[offset..].to_vec())
            } else {
                None
            };

            Ok(Self {
                destination_hash: destination_hash.to_vec(),
                public_key,
                name_hash,
                random_hash,
                ratchet,
                signature,
                app_data,
                context_flag,
            })
        } else {
            let min_len = keysize + name_hash_len + 10 + sig_len;
            if data.len() < min_len {
                return Err(FerretError::KeyLength {
                    expected: min_len,
                    got: data.len(),
                });
            }
            let mut offset = 0;
            let public_key = data[offset..offset + keysize].to_vec();
            offset += keysize;
            let name_hash = data[offset..offset + name_hash_len].to_vec();
            offset += name_hash_len;
            let random_hash = data[offset..offset + 10].to_vec();
            offset += 10;
            let ratchet = Vec::new();
            let signature = data[offset..offset + sig_len].to_vec();
            offset += sig_len;
            let app_data = if data.len() > offset {
                Some(data[offset..].to_vec())
            } else {
                None
            };

            Ok(Self {
                destination_hash: destination_hash.to_vec(),
                public_key,
                name_hash,
                random_hash,
                ratchet,
                signature,
                app_data,
                context_flag,
            })
        }
    }
}

/// Validate an announce. Returns true if valid.
///
/// Steps:
/// 1. Construct signed_data = dest_hash + pub_key + name_hash + random_hash + ratchet + app_data
/// 2. Verify Ed25519 signature against signed_data
/// 3. If only_validate_signature, return true here
/// 4. Verify dest_hash == truncated_hash(name_hash + identity_hash)
/// 5. Check for public key collision with existing entry
/// 6. Store identity via IdentityStore::remember
/// 7. If ratchet present, store via RatchetStore::remember_ratchet
pub fn validate_announce(
    announce: &AnnounceData,
    store: &IdentityStore,
    ratchet_store: &RatchetStore,
    only_validate_signature: bool,
    packet_hash: &[u8],
) -> Result<bool> {
    // 1. Construct signed_data
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&announce.destination_hash);
    signed_data.extend_from_slice(&announce.public_key);
    signed_data.extend_from_slice(&announce.name_hash);
    signed_data.extend_from_slice(&announce.random_hash);
    signed_data.extend_from_slice(&announce.ratchet);
    if let Some(ref app_data) = announce.app_data {
        signed_data.extend_from_slice(app_data);
    }

    // 2. Construct Identity from public_key and verify signature
    let announced_identity = Identity::from_public_key(&announce.public_key)?;
    let sig_bytes: [u8; 64] = announce.signature[..64]
        .try_into()
        .map_err(|_| FerretError::KeyLength {
            expected: 64,
            got: announce.signature.len(),
        })?;

    let valid = announced_identity.validate(&sig_bytes, &signed_data)?;
    if !valid {
        return Ok(false);
    }

    // 3. If only signature validation, return true
    if only_validate_signature {
        return Ok(true);
    }

    // 4. Verify destination_hash == truncated_hash(name_hash + identity_hash)
    let identity_hash = announced_identity.hash()?;
    let mut hash_material = Vec::new();
    hash_material.extend_from_slice(&announce.name_hash);
    hash_material.extend_from_slice(identity_hash);
    let expected_hash = Identity::full_hash(&hash_material);
    let truncated_len = crate::types::constants::TRUNCATED_HASHLENGTH / 8;
    if announce.destination_hash != expected_hash[..truncated_len] {
        return Ok(false);
    }

    // 5. Check for public key collision
    if let Some(existing) = store.recall(&announce.destination_hash) {
        if let Ok(existing_pub) = existing.get_public_key() {
            if existing_pub[..] != announce.public_key[..] {
                return Ok(false);
            }
        }
    }

    // 6. Store identity
    store.remember(
        packet_hash,
        &announce.destination_hash,
        &announce.public_key,
        announce.app_data.as_deref(),
    )?;

    // 7. Store ratchet if present
    if !announce.ratchet.is_empty() {
        ratchet_store.remember_ratchet(&announce.destination_hash, &announce.ratchet)?;
    }

    Ok(true)
}
