pub mod packet;
pub mod packing;
pub mod receipt;
pub mod proof;

use crate::types::destination::DestinationType;
use crate::Result;

/// Trait breaking the Destination↔Packet circular dependency.
/// Implemented by Destination and ProofDestination.
pub trait Encryptable: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn dest_hash(&self) -> &[u8; 16];
    fn dest_type(&self) -> DestinationType;
}

/// Max encrypted payload in a single packet (bytes).
/// floor((MDU - TOKEN_OVERHEAD - KEYSIZE/16) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
pub const ENCRYPTED_MDU: usize = 383;

/// Max plaintext payload in a single unencrypted packet (bytes). Equal to MDU.
pub const PLAIN_MDU: usize = 464;

/// Packet receipt timeout added per hop (seconds).
pub const TIMEOUT_PER_HOP: usize = 6;
