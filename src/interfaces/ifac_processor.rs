// IFAC (Interface Access Code) processor — cryptographic access control for interfaces.
//
// Provides key derivation, packet masking/unmasking, and flag consistency checks.
// Ported from the Python reference: Transport.transmit() and Transport.inbound() in Transport.py,
// and IFAC derivation in Reticulum.py.

use crate::crypto::{hkdf, sha256};
use crate::identity::Identity;
use crate::Result;

/// IFAC salt constant (32 bytes) — from Reticulum.IFAC_SALT.
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
    0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f,
    0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

/// IFAC flag — bit 7 of the first header byte.
pub const IFAC_FLAG: u8 = 0x80;

/// Derived IFAC state for an interface.
pub struct IfacState {
    pub ifac_size: usize,
    pub ifac_key: Vec<u8>,
    pub ifac_identity: Identity,
    pub ifac_signature: [u8; 64],
}

impl IfacState {
    /// Derive IFAC state from network name and key.
    ///
    /// ifac_origin = SHA-256(netname) || SHA-256(netkey)  (either may be absent)
    /// ifac_origin_hash = SHA-256(ifac_origin)
    /// ifac_key = HKDF(64, ifac_origin_hash, IFAC_SALT)
    /// ifac_identity = Identity::from_private_key(&ifac_key)
    /// ifac_signature = ifac_identity.sign(SHA-256(ifac_key))
    pub fn derive(
        ifac_size: usize,
        ifac_netname: Option<&str>,
        ifac_netkey: Option<&str>,
    ) -> Result<Self> {
        let mut ifac_origin = Vec::new();
        if let Some(name) = ifac_netname {
            ifac_origin.extend_from_slice(&sha256(name.as_bytes()));
        }
        if let Some(key) = ifac_netkey {
            ifac_origin.extend_from_slice(&sha256(key.as_bytes()));
        }

        let ifac_origin_hash = sha256(&ifac_origin);
        let ifac_key = hkdf(64, &ifac_origin_hash, Some(&IFAC_SALT), None)?;
        let ifac_identity = Identity::from_private_key(&ifac_key)?;
        let ifac_signature = ifac_identity.sign(&sha256(&ifac_key))?;

        Ok(Self {
            ifac_size,
            ifac_key,
            ifac_identity,
            ifac_signature,
        })
    }
}

/// Mask an outbound packet with IFAC.
///
/// 1. Compute ifac tag = last ifac_size bytes of ifac_identity.sign(raw)
/// 2. Generate mask = HKDF(len(raw)+ifac_size, ifac_tag, ifac_key)
/// 3. Set IFAC flag on header byte 0
/// 4. Assemble: header(2) + ifac_tag(ifac_size) + payload
/// 5. XOR-mask header and payload bytes; leave ifac_tag bytes unmasked
/// 6. Ensure IFAC flag stays set on first byte after masking
pub fn ifac_mask(raw: &[u8], state: &IfacState) -> Result<Vec<u8>> {
    let ifac_size = state.ifac_size;

    // Sign the raw packet and take the last ifac_size bytes as the tag
    let sig = state.ifac_identity.sign(raw)?;
    let ifac_tag = &sig[64 - ifac_size..];

    // Generate mask over the full assembled length
    let mask = hkdf(
        raw.len() + ifac_size,
        ifac_tag,
        Some(&state.ifac_key),
        None,
    )?;

    // Set IFAC flag and assemble: header(2) + ifac(ifac_size) + payload
    let new_header = [raw[0] | IFAC_FLAG, raw[1]];
    let mut new_raw = Vec::with_capacity(raw.len() + ifac_size);
    new_raw.extend_from_slice(&new_header);
    new_raw.extend_from_slice(ifac_tag);
    if raw.len() > 2 {
        new_raw.extend_from_slice(&raw[2..]);
    }

    // XOR-mask: mask header bytes and payload, skip ifac tag bytes
    let mut masked = Vec::with_capacity(new_raw.len());
    for (i, &byte) in new_raw.iter().enumerate() {
        if i == 0 {
            // Mask first header byte, keep IFAC flag set
            masked.push((byte ^ mask[i]) | IFAC_FLAG);
        } else if i == 1 || i > ifac_size + 1 {
            // Mask second header byte and payload
            masked.push(byte ^ mask[i]);
        } else {
            // Don't mask the IFAC tag itself (bytes 2..2+ifac_size)
            masked.push(byte);
        }
    }

    Ok(masked)
}

/// Unmask an inbound packet with IFAC.
///
/// Returns `Ok(Some(unmasked))` if verification succeeds.
/// Returns `Ok(None)` if the IFAC tag doesn't match (packet should be dropped).
pub fn ifac_unmask(masked: &[u8], state: &IfacState) -> Result<Option<Vec<u8>>> {
    let ifac_size = state.ifac_size;

    if masked.len() < 2 + ifac_size {
        return Ok(None);
    }

    // Extract the IFAC tag from bytes [2..2+ifac_size]
    let ifac_tag = &masked[2..2 + ifac_size];

    // Generate mask over the full masked length
    let mask = hkdf(masked.len(), ifac_tag, Some(&state.ifac_key), None)?;

    // Unmask: XOR header bytes and payload, skip ifac tag bytes
    let mut unmasked_raw = Vec::with_capacity(masked.len());
    for (i, &byte) in masked.iter().enumerate() {
        if i <= 1 || i > ifac_size + 1 {
            unmasked_raw.push(byte ^ mask[i]);
        } else {
            unmasked_raw.push(byte);
        }
    }

    // Clear IFAC flag
    let new_header = [unmasked_raw[0] & !IFAC_FLAG, unmasked_raw[1]];

    // Re-assemble without the IFAC tag
    let mut new_raw = Vec::with_capacity(masked.len() - ifac_size);
    new_raw.extend_from_slice(&new_header);
    new_raw.extend_from_slice(&unmasked_raw[2 + ifac_size..]);

    // Compute expected IFAC tag
    let expected_sig = state.ifac_identity.sign(&new_raw)?;
    let expected_ifac = &expected_sig[64 - ifac_size..];

    if ifac_tag == expected_ifac {
        Ok(Some(new_raw))
    } else {
        Ok(None)
    }
}

/// Check IFAC flag/config consistency.
///
/// Returns `(flag_set, consistent)`:
/// - `flag_set`: whether the IFAC flag (bit 7) is set on the first byte
/// - `consistent`: whether the flag state matches the interface config
///
/// A packet should only be processed when `consistent` is true.
pub fn ifac_check(raw: &[u8], has_ifac: bool) -> (bool, bool) {
    let flag_set = !raw.is_empty() && (raw[0] & IFAC_FLAG) == IFAC_FLAG;
    (flag_set, flag_set == has_ifac)
}
