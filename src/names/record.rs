//! Name record: a self-signed registration binding a human-readable name
//! to a Reticulum destination hash.

use serde::{Deserialize, Serialize};

use crate::crypto::hashes::sha256;
use crate::identity::Identity;

/// A signed name record in the rnnamed service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NameRecord {
    /// Full name: "<label>.<suffix>" e.g. "alice.54d2"
    pub name: String,
    /// 16-byte destination hash this name resolves to
    #[serde(with = "serde_bytes")]
    pub dest_hash: Vec<u8>,
    /// 16-byte identity hash of the registrant
    #[serde(with = "serde_bytes")]
    pub identity_hash: Vec<u8>,
    /// 64-byte public key (X25519 ++ Ed25519)
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Registration timestamp (UNIX seconds)
    pub timestamp: f64,
    /// Proof-of-work stamp bytes
    #[serde(with = "serde_bytes")]
    pub stamp: Vec<u8>,
    /// Ed25519 signature over all preceding fields
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl NameRecord {
    /// Extract the label portion of the name (before the dot).
    pub fn label(&self) -> &str {
        self.name.split('.').next().unwrap_or("")
    }

    /// Extract the suffix portion of the name (after the dot).
    pub fn suffix(&self) -> &str {
        self.name.split('.').nth(1).unwrap_or("")
    }

    /// Validate the name format: `<label>.<suffix>` where label is
    /// lowercase alphanumeric + hyphens (1–32 chars) and suffix is 4 hex chars.
    pub fn validate_format(&self) -> bool {
        let parts: Vec<&str> = self.name.split('.').collect();
        if parts.len() != 2 {
            return false;
        }
        let label = parts[0];
        let suffix = parts[1];

        if label.is_empty() || label.len() > 32 {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return false;
        }
        if suffix.len() != 4 || !suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        true
    }

    /// Check that the suffix matches the last 4 hex chars of the identity hash.
    pub fn validate_suffix(&self) -> bool {
        if self.identity_hash.len() != 16 {
            return false;
        }
        let id_hex: String = self.identity_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let expected_suffix = &id_hex[28..32]; // last 4 hex chars
        self.suffix() == expected_suffix
    }

    /// Check that SHA-256(public_key)[..16] equals the identity hash.
    pub fn validate_identity_hash(&self) -> bool {
        if self.public_key.len() != 64 || self.identity_hash.len() != 16 {
            return false;
        }
        let hash = sha256(&self.public_key);
        hash[..16] == self.identity_hash[..]
    }

    /// Compute the bytes used for stamp generation/verification (without stamp).
    pub fn stamp_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(&self.dest_hash);
        data.extend_from_slice(&self.identity_hash);
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data
    }

    /// Compute the bytes that are signed: name ++ dest_hash ++ identity_hash ++ public_key ++ timestamp ++ stamp
    pub fn signed_data(&self) -> Vec<u8> {
        let mut data = self.stamp_data();
        data.extend_from_slice(&self.stamp);
        data
    }

    /// Verify the Ed25519 signature using the embedded public key.
    pub fn validate_signature(&self) -> bool {
        if self.signature.len() != 64 || self.public_key.len() != 64 {
            return false;
        }
        let identity = match Identity::from_public_key(&self.public_key) {
            Ok(id) => id,
            Err(_) => return false,
        };
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.signature);
        identity.validate(&sig, &self.signed_data()).unwrap_or(false)
    }

    /// Create a signed record from an identity.
    pub fn create(
        name: &str,
        dest_hash: &[u8],
        identity: &Identity,
        stamp: Vec<u8>,
        timestamp: f64,
    ) -> crate::Result<Self> {
        let pub_key = identity.get_public_key()?;
        let id_hash = identity.hash()?;

        let mut record = Self {
            name: name.to_string(),
            dest_hash: dest_hash.to_vec(),
            identity_hash: id_hash.to_vec(),
            public_key: pub_key.to_vec(),
            timestamp,
            stamp,
            signature: vec![0u8; 64],
        };

        let sig = identity.sign(&record.signed_data())?;
        record.signature = sig.to_vec();
        Ok(record)
    }
}
