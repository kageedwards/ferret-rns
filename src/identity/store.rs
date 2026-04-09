// IdentityStore: thread-safe known-destinations map

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::types::constants::TRUNCATED_HASHLENGTH;
use crate::{FerretError, Result};

use super::identity::Identity;

/// Entry in the known destinations map.
#[derive(Clone, Serialize, Deserialize)]
pub struct KnownDestination {
    pub timestamp: f64,
    pub packet_hash: Vec<u8>,
    pub public_key: Vec<u8>,
    pub app_data: Option<Vec<u8>>,
}

/// Thread-safe store for known destinations.
pub struct IdentityStore {
    destinations: Arc<RwLock<HashMap<Vec<u8>, KnownDestination>>>,
}

impl IdentityStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            destinations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store a known destination. Validates public_key is 64 bytes.
    pub fn remember(
        &self,
        packet_hash: &[u8],
        destination_hash: &[u8],
        public_key: &[u8],
        app_data: Option<&[u8]>,
    ) -> Result<()> {
        if public_key.len() != 64 {
            return Err(FerretError::KeyLength {
                expected: 64,
                got: public_key.len(),
            });
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let entry = KnownDestination {
            timestamp,
            packet_hash: packet_hash.to_vec(),
            public_key: public_key.to_vec(),
            app_data: app_data.map(|d| d.to_vec()),
        };

        let mut map = self
            .destinations
            .write()
            .map_err(|_| FerretError::Token("lock poisoned".into()))?;
        map.insert(destination_hash.to_vec(), entry);
        Ok(())
    }

    /// Recall an identity by destination hash.
    pub fn recall(&self, destination_hash: &[u8]) -> Option<Identity> {
        let map = self.destinations.read().ok()?;
        let entry = map.get(destination_hash)?;
        Identity::from_public_key(&entry.public_key).ok()
    }

    /// Recall an identity by identity hash (searches all entries).
    pub fn recall_by_identity_hash(&self, identity_hash: &[u8]) -> Option<Identity> {
        let map = self.destinations.read().ok()?;
        for entry in map.values() {
            let hash = Identity::truncated_hash(&entry.public_key);
            if hash == identity_hash {
                return Identity::from_public_key(&entry.public_key).ok();
            }
        }
        None
    }

    /// Recall app_data for a destination hash.
    pub fn recall_app_data(&self, destination_hash: &[u8]) -> Option<Vec<u8>> {
        let map = self.destinations.read().ok()?;
        let entry = map.get(destination_hash)?;
        entry.app_data.clone()
    }

    /// Persist the map to a file using MessagePack.
    pub fn save(&self, path: &Path) -> Result<()> {
        let map = self
            .destinations
            .read()
            .map_err(|_| FerretError::Token("lock poisoned".into()))?;
        let data = crate::util::msgpack::serialize(&*map)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Load the map from a file using MessagePack.
    /// Validates each key is exactly 16 bytes.
    pub fn load(&self, path: &Path) -> Result<()> {
        let data = std::fs::read(path)?;
        let loaded: HashMap<Vec<u8>, KnownDestination> =
            crate::util::msgpack::deserialize(&data)?;

        let hash_len = TRUNCATED_HASHLENGTH / 8;
        let mut map = self
            .destinations
            .write()
            .map_err(|_| FerretError::Token("lock poisoned".into()))?;
        for (key, value) in loaded {
            if key.len() == hash_len {
                map.insert(key, value);
            }
        }
        Ok(())
    }
}
