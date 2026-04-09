use crate::types::destination::DestinationType;
use crate::Result;

use super::Encryptable;

/// A lightweight destination used to route proofs back to the original sender.
/// Proofs are not encrypted, so encrypt returns plaintext unchanged.
pub struct ProofDestination {
    pub hash: [u8; 16],
}

impl ProofDestination {
    pub fn new(packet_truncated_hash: [u8; 16]) -> Self {
        Self {
            hash: packet_truncated_hash,
        }
    }
}

impl Encryptable for ProofDestination {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn dest_hash(&self) -> &[u8; 16] {
        &self.hash
    }

    fn dest_type(&self) -> DestinationType {
        DestinationType::Single
    }
}
