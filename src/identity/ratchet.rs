// RatchetStore: ratchet key lifecycle

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::crypto::hashes::sha256;
use crate::crypto::x25519::X25519PrivateKey;
use crate::crypto::{NAME_HASH_LENGTH, RATCHETSIZE};
use crate::util::hex::hexrep_no_delimit;
use crate::{FerretError, Result};

/// MsgPack-serialized ratchet data stored on disk.
#[derive(Serialize, Deserialize)]
struct RatchetData {
    ratchet: Vec<u8>,
    received: f64,
}

/// Thread-safe ratchet key store with disk persistence.
pub struct RatchetStore {
    ratchets: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>, // dest_hash -> ratchet_prv_bytes
    ratchet_dir: PathBuf,
}

impl RatchetStore {
    /// Create a new RatchetStore, ensuring the ratchet directory exists.
    pub fn new(ratchet_dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&ratchet_dir);
        Self {
            ratchets: Arc::new(RwLock::new(HashMap::new())),
            ratchet_dir,
        }
    }

    /// Generate a new random ratchet. Returns 32-byte private key bytes.
    pub fn generate() -> [u8; 32] {
        X25519PrivateKey::generate().to_bytes()
    }

    /// Derive the 32-byte public key from ratchet private key bytes.
    pub fn ratchet_public_bytes(ratchet_prv: &[u8; 32]) -> [u8; 32] {
        X25519PrivateKey::from_bytes(ratchet_prv).public_key().to_bytes()
    }

    /// Compute the ratchet ID: first 10 bytes of SHA-256(public_key_bytes).
    pub fn get_ratchet_id(ratchet_pub: &[u8; 32]) -> [u8; 10] {
        let hash = sha256(ratchet_pub);
        let len = NAME_HASH_LENGTH / 8; // 10
        let mut id = [0u8; 10];
        id.copy_from_slice(&hash[..len]);
        id
    }

    /// Store a ratchet for a destination. Persists to disk atomically.
    pub fn remember_ratchet(
        &self,
        destination_hash: &[u8],
        ratchet: &[u8],
    ) -> Result<()> {
        // Check if already stored with same value
        {
            let map = self
                .ratchets
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            if let Some(existing) = map.get(destination_hash) {
                if existing == ratchet {
                    return Ok(());
                }
            }
        }

        // Store in memory
        {
            let mut map = self
                .ratchets
                .write()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;
            map.insert(destination_hash.to_vec(), ratchet.to_vec());
        }

        // Persist to disk atomically
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let data = RatchetData {
            ratchet: ratchet.to_vec(),
            received: timestamp,
        };

        let serialized = crate::util::msgpack::serialize(&data)?;
        let hexhash = hexrep_no_delimit(destination_hash);
        let tmp_path = self.ratchet_dir.join(format!("{}.out", hexhash));
        let final_path = self.ratchet_dir.join(&hexhash);

        std::fs::write(&tmp_path, &serialized)?;
        std::fs::rename(&tmp_path, &final_path)?;

        Ok(())
    }

    /// Get the ratchet for a destination (from memory or disk).
    pub fn get_ratchet(&self, destination_hash: &[u8]) -> Option<Vec<u8>> {
        // Check memory first
        {
            let map = self.ratchets.read().ok()?;
            if let Some(ratchet) = map.get(destination_hash) {
                return Some(ratchet.clone());
            }
        }

        // Try loading from disk
        let hexhash = hexrep_no_delimit(destination_hash);
        let path = self.ratchet_dir.join(&hexhash);
        let bytes = std::fs::read(&path).ok()?;
        let data: RatchetData = crate::util::msgpack::deserialize(&bytes).ok()?;

        // Validate length
        let expected_len = RATCHETSIZE / 8; // 32
        if data.ratchet.len() != expected_len {
            return None;
        }

        // Validate not expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        if data.received + (super::RATCHET_EXPIRY as f64) <= now {
            return None;
        }

        // Cache in memory
        if let Ok(mut map) = self.ratchets.write() {
            map.insert(destination_hash.to_vec(), data.ratchet.clone());
        }

        Some(data.ratchet)
    }

    /// Get the current ratchet ID for a destination, or None.
    pub fn current_ratchet_id(&self, destination_hash: &[u8]) -> Option<[u8; 10]> {
        let ratchet = self.get_ratchet(destination_hash)?;
        let prv_bytes: [u8; 32] = ratchet.try_into().ok()?;
        let pub_bytes = Self::ratchet_public_bytes(&prv_bytes);
        Some(Self::get_ratchet_id(&pub_bytes))
    }

    /// Remove expired and corrupted ratchet files.
    pub fn clean_ratchets(&self) -> Result<()> {
        let entries = std::fs::read_dir(&self.ratchet_dir)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let should_delete = match std::fs::read(&path) {
                Ok(bytes) => match crate::util::msgpack::deserialize::<RatchetData>(&bytes) {
                    Ok(data) => data.received + (super::RATCHET_EXPIRY as f64) < now,
                    Err(_) => true, // corrupted
                },
                Err(_) => true, // unreadable
            };

            if should_delete {
                let _ = std::fs::remove_file(&path);
            }
        }

        Ok(())
    }
}
