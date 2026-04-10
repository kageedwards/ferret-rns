// BlackholeUpdater: background blackhole identity list fetcher

use std::collections::HashMap;
use std::path::Path;

use crate::transport::TransportState;
use crate::Result;

/// Initial wait before first update check (seconds).
pub const INITIAL_WAIT: u64 = 20;
/// Job check interval (seconds).
pub const JOB_INTERVAL: u64 = 60;
/// Update interval per source (seconds, 1 hour).
pub const UPDATE_INTERVAL: u64 = 3600;
/// Timeout for source link establishment (seconds).
pub const SOURCE_TIMEOUT: u64 = 25;

/// Background service that periodically fetches blackhole identity lists
/// from configured sources.
pub struct BlackholeUpdater {
    should_run: bool,
    last_updates: HashMap<[u8; 16], f64>,
    job_interval: u64,
}

impl BlackholeUpdater {
    /// Create a new BlackholeUpdater.
    pub fn new() -> Self {
        Self {
            should_run: false,
            last_updates: HashMap::new(),
            job_interval: JOB_INTERVAL,
        }
    }

    /// Start the updater.
    pub fn start(&mut self) {
        self.should_run = true;
    }

    /// Stop the updater.
    pub fn stop(&mut self) {
        self.should_run = false;
    }

    /// Check if the updater is running.
    pub fn is_running(&self) -> bool {
        self.should_run
    }

    /// Check if a source is due for an update.
    pub fn is_due(&self, source_hash: &[u8; 16]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        match self.last_updates.get(source_hash) {
            Some(&last) => (now - last) >= UPDATE_INTERVAL as f64,
            None => true,
        }
    }

    /// Fetch blackhole list from a source and merge into transport state.
    ///
    /// In a full implementation, this would:
    /// 1. Resolve destination hash for "rnstransport.info.blackhole"
    /// 2. Establish a Link to the source
    /// 3. Request "/list" over the Link
    /// 4. Parse the response as a list of identity hashes
    /// 5. Merge into transport's blackholed_identities
    /// 6. Persist to disk
    /// 7. Tear down the Link
    ///
    /// Actual Link establishment and request/response is deferred since
    /// it requires a running network. We implement the data structures,
    /// persistence, and merge logic.
    pub fn update_from_source(
        &mut self,
        source_identity_hash: &[u8; 16],
        _transport: &TransportState,
        blackholepath: &Path,
    ) -> Result<()> {
        // Ensure blackhole storage directory exists
        std::fs::create_dir_all(blackholepath)?;

        let source_hex: String = source_identity_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let file_path = blackholepath.join(&source_hex);

        // Placeholder: In a real implementation, we would establish a Link
        // and request the blackhole list. For now, we just load any existing
        // persisted data and update the timestamp.

        // Load existing blackhole list if present
        let _existing_hashes: Vec<Vec<u8>> = if file_path.exists() {
            let data = std::fs::read(&file_path)?;
            crate::util::msgpack::deserialize(&data).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Record the update timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        self.last_updates.insert(*source_identity_hash, now);

        Ok(())
    }

    /// Merge a list of identity hashes into the blackhole store and persist.
    pub fn merge_and_persist(
        source_identity_hash: &[u8; 16],
        new_hashes: &[Vec<u8>],
        blackholepath: &Path,
    ) -> Result<()> {
        std::fs::create_dir_all(blackholepath)?;

        let source_hex: String = source_identity_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let file_path = blackholepath.join(&source_hex);

        // Load existing
        let mut all_hashes: Vec<Vec<u8>> = if file_path.exists() {
            let data = std::fs::read(&file_path)?;
            crate::util::msgpack::deserialize(&data).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Merge new hashes (deduplicate)
        for hash in new_hashes {
            if !all_hashes.contains(hash) {
                all_hashes.push(hash.clone());
            }
        }

        // Persist
        let serialized = crate::util::msgpack::serialize(&all_hashes)?;
        std::fs::write(&file_path, serialized)?;

        Ok(())
    }
}

impl Default for BlackholeUpdater {
    fn default() -> Self {
        Self::new()
    }
}
