// BlackholeUpdater: background blackhole identity list fetcher

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::destination::destination::Destination;
use crate::identity::IdentityStore;
use crate::link::link::Link;
use crate::link::request::RequestReceiptStatus;
use crate::transport::TransportState;
use crate::types::destination::{DestinationDirection, DestinationType};
use crate::Result;
use crate::log_warning;

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
    last_check: Instant,
}

impl BlackholeUpdater {
    /// Create a new BlackholeUpdater.
    pub fn new() -> Self {
        Self {
            should_run: false,
            last_updates: HashMap::new(),
            job_interval: JOB_INTERVAL,
            last_check: Instant::now(),
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

    /// Periodic check: if enough time has elapsed since the last check,
    /// iterate the given sources and update any that are due.
    ///
    /// Returns early if the updater is not running or the `job_interval`
    /// has not yet elapsed. Failures on individual sources are logged and
    /// skipped so the loop continues.
    pub fn check(
        &mut self,
        sources: &[[u8; 16]],
        transport: &TransportState,
        identity_store: &IdentityStore,
        blackholepath: &Path,
    ) -> Result<()> {
        if !self.should_run {
            return Ok(());
        }

        if self.last_check.elapsed() < Duration::from_secs(self.job_interval) {
            return Ok(());
        }

        self.last_check = Instant::now();

        for source in sources {
            if self.is_due(source) {
                if let Err(e) = self.update_from_source(source, transport, identity_store, blackholepath) {
                    log_warning!(
                        "Blackhole update from source {} failed: {}",
                        hex_encode(source),
                        e
                    );
                }
            }
        }

        Ok(())
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

    /// Fetch blackhole list from a source by establishing a Link, requesting
    /// `/list`, parsing the response, and merging into the local blackhole set.
    ///
    /// Steps:
    /// 1. Compute destination hash for "rnstransport.info.blackhole" using the source identity
    /// 2. Recall the remote identity from the IdentityStore
    /// 3. Create an OUT/SINGLE Destination to the source
    /// 4. Establish a Link to the destination
    /// 5. Send a `/list` request over the Link
    /// 6. Poll for the response (with timeout)
    /// 7. Parse the response as a list of identity hashes
    /// 8. Merge into local blackhole set via `merge_and_persist()`
    /// 9. Tear down the Link
    ///
    /// All failures are logged and non-fatal — the updater continues to the
    /// next source on error.
    pub fn update_from_source(
        &mut self,
        source_identity_hash: &[u8; 16],
        transport: &TransportState,
        identity_store: &IdentityStore,
        blackholepath: &Path,
    ) -> Result<()> {
        // Ensure blackhole storage directory exists
        std::fs::create_dir_all(blackholepath)?;

        // 1. Recall the remote identity from the store
        let remote_identity = match identity_store.recall_by_identity_hash(source_identity_hash) {
            Some(id) => id,
            None => {
                log_warning!(
                    "No known identity for blackhole source {}, skipping",
                    hex_encode(source_identity_hash)
                );
                return Ok(());
            }
        };

        // 2. Compute the destination hash for "rnstransport.info.blackhole"
        let dest_hash = Destination::hash_for(
            Some(&remote_identity),
            "rnstransport",
            &["info", "blackhole"],
        )?;

        // 3. Check if we have a path to the destination
        if !transport.has_path(&dest_hash)? {
            log_warning!(
                "No path to blackhole source {}, skipping",
                hex_encode(source_identity_hash)
            );
            return Ok(());
        }

        // 4. Create an OUT/SINGLE Destination
        let destination = Destination::new(
            Some(remote_identity),
            DestinationDirection::Out,
            DestinationType::Single,
            "rnstransport",
            &["info", "blackhole"],
        )?;
        let destination = Arc::new(RwLock::new(destination));

        // 5. Establish a Link to the destination
        let link = match Link::new(destination, transport, None, None) {
            Ok(l) => l,
            Err(e) => {
                log_warning!(
                    "Failed to establish link for blackhole update from {}: {}",
                    hex_encode(source_identity_hash),
                    e
                );
                return Ok(());
            }
        };

        // 6. Wait for link establishment (poll with timeout)
        let timeout_secs = SOURCE_TIMEOUT as f64;
        let start = std::time::Instant::now();
        loop {
            let status = match link.status() {
                Ok(s) => s,
                Err(e) => {
                    log_warning!(
                        "Failed to check link status for blackhole update: {}",
                        e
                    );
                    return Ok(());
                }
            };
            if status == crate::link::LinkStatus::Active {
                break;
            }
            if status == crate::link::LinkStatus::Closed {
                log_warning!(
                    "Link closed before establishment for blackhole source {}",
                    hex_encode(source_identity_hash)
                );
                return Ok(());
            }
            if start.elapsed().as_secs_f64() > timeout_secs {
                log_warning!(
                    "Link establishment timed out for blackhole source {}",
                    hex_encode(source_identity_hash)
                );
                let _ = link.teardown(transport);
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // 7. Send a request for "/list" over the Link
        let receipt = match link.request("/list", None, transport, Some(timeout_secs)) {
            Ok(r) => r,
            Err(e) => {
                log_warning!(
                    "Failed to send /list request for blackhole update from {}: {}",
                    hex_encode(source_identity_hash),
                    e
                );
                let _ = link.teardown(transport);
                return Ok(());
            }
        };
        let request_id = receipt.request_id;

        // 8. Poll for the response on the link's pending_requests
        let poll_start = std::time::Instant::now();
        let response_data: Option<Vec<u8>> = loop {
            if poll_start.elapsed().as_secs_f64() > timeout_secs {
                log_warning!(
                    "/list request timed out for blackhole source {}",
                    hex_encode(source_identity_hash)
                );
                break None;
            }

            // Check the receipt status in the link's pending_requests
            let concluded = match link.read() {
                Ok(inner) => {
                    inner
                        .pending_requests
                        .iter()
                        .find(|r| r.request_id == request_id)
                        .map(|r| (r.status, r.response.clone()))
                }
                Err(_) => None,
            };

            match concluded {
                Some((RequestReceiptStatus::Ready, resp)) => break resp,
                Some((RequestReceiptStatus::Failed, _)) => {
                    log_warning!(
                        "/list request failed for blackhole source {}",
                        hex_encode(source_identity_hash)
                    );
                    break None;
                }
                _ => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        };

        // 9. Teardown the link
        let _ = link.teardown(transport);

        // 10. Parse response and merge
        if let Some(data) = response_data {
            match crate::util::msgpack::deserialize::<Vec<Vec<u8>>>(&data) {
                Ok(hashes) => {
                    if let Err(e) =
                        Self::merge_and_persist(source_identity_hash, &hashes, blackholepath)
                    {
                        log_warning!(
                            "Failed to persist blackhole list from {}: {}",
                            hex_encode(source_identity_hash),
                            e
                        );
                    }
                }
                Err(e) => {
                    log_warning!(
                        "Failed to parse blackhole list from {}: {}",
                        hex_encode(source_identity_hash),
                        e
                    );
                }
            }
        }

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

/// Hex-encode a byte slice for logging.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Default for BlackholeUpdater {
    fn default() -> Self {
        Self::new()
    }
}
