// Background persistence and cache cleanup jobs.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::identity::IdentityStore;
use crate::transport::TransportState;
use crate::{log_debug, log_warning};

/// Resource cache lifetime: 24 hours.
pub const RESOURCE_CACHE: u64 = 86_400;

/// Background job check interval: 1 second.
pub const JOB_INTERVAL: u64 = 1;

/// Cache clean interval: 15 minutes.
pub const CLEAN_INTERVAL: u64 = 900;

/// Data persist interval: 12 hours.
pub const PERSIST_INTERVAL: u64 = 43_200;

/// Minimum time between gracious persists: 5 minutes.
pub const GRACIOUS_PERSIST_INTERVAL: u64 = 300;

/// Serializable subset of a path table entry (no interface reference).
#[derive(Serialize, Deserialize)]
pub struct SerializedPathEntry {
    pub timestamp: f64,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub packet_hash: [u8; 32],
}

/// Persist the path table from TransportState to `storagepath/path_table`.
///
/// Errors are logged and ignored (non-fatal).
pub fn persist_path_table(transport: &TransportState, storagepath: &Path) {
    let result = (|| -> crate::Result<()> {
        let inner = transport.read()?;
        let serializable: std::collections::HashMap<[u8; 16], SerializedPathEntry> = inner
            .path_table
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    SerializedPathEntry {
                        timestamp: v.timestamp,
                        received_from: v.received_from,
                        hops: v.hops,
                        expires: v.expires,
                        random_blobs: v.random_blobs.clone(),
                        packet_hash: v.packet_hash,
                    },
                )
            })
            .collect();
        let data = crate::util::msgpack::serialize(&serializable)?;
        std::fs::write(storagepath.join("path_table"), data)?;
        Ok(())
    })();

    if let Err(e) = result {
        log_warning!("Failed to persist path table: {}", e);
    }
}

/// Run the background jobs loop.
///
/// Sleeps `JOB_INTERVAL` between iterations. Each iteration checks the
/// `shutdown` flag and, when enough time has elapsed, cleans caches or
/// persists state.
pub fn run_jobs(
    shutdown: Arc<AtomicBool>,
    cachepath: std::path::PathBuf,
    resourcepath: std::path::PathBuf,
    transport: TransportState,
    identity_store: Arc<IdentityStore>,
    storagepath: PathBuf,
) {
    let mut last_clean = Instant::now();
    let mut last_persist = Instant::now();

    loop {
        std::thread::sleep(Duration::from_secs(JOB_INTERVAL));

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Link lifecycle checks (request timeouts, stale, establishment timeout)
        transport.check_link_lifecycles();

        // Cache cleanup
        if last_clean.elapsed() >= Duration::from_secs(CLEAN_INTERVAL) {
            clean_caches(&cachepath, &resourcepath);
            last_clean = Instant::now();
        }

        // Persist transport state and identity store
        if last_persist.elapsed() >= Duration::from_secs(PERSIST_INTERVAL) {
            log_debug!("Persisting path table and identity store");
            persist_path_table(&transport, &storagepath);

            if let Err(e) = identity_store.save(&storagepath.join("known_destinations")) {
                log_warning!("Failed to persist known destinations: {}", e);
            }

            last_persist = Instant::now();
        }
    }
}

/// Remove stale files from both the cache and resource directories.
fn clean_caches(cachepath: &Path, resourcepath: &Path) {
    clean_cache_dir(resourcepath, RESOURCE_CACHE);
    // Scan cachepath for files (not directories)
    clean_cache_dir(cachepath, RESOURCE_CACHE);
}

/// Scan `dir` for files and remove those whose modification time exceeds
/// `max_age_secs`. Returns the number of files removed.
///
/// Directories inside `dir` are skipped. Errors on individual file
/// deletions are logged and ignored so the scan continues.
pub fn clean_cache_dir(dir: &Path, max_age_secs: u64) -> usize {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    let mut removed = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let dominated = match path.metadata() {
            Ok(meta) => match meta.modified() {
                Ok(mtime) => match SystemTime::now().duration_since(mtime) {
                    Ok(age) => age.as_secs() > max_age_secs,
                    Err(_) => false,
                },
                Err(_) => false,
            },
            Err(_) => false,
        };

        if dominated {
            if let Err(e) = std::fs::remove_file(&path) {
                log_warning!(
                    "Failed to remove cache file {}: {}",
                    path.display(),
                    e
                );
            } else {
                removed += 1;
            }
        }
    }

    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_clean_cache_dir_removes_old_files() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("old.dat");
        fs::write(&old, b"data").unwrap();
        // Set mtime to 2 days ago
        let two_days_ago = filetime::FileTime::from_system_time(
            SystemTime::now() - Duration::from_secs(2 * 86_400),
        );
        filetime::set_file_mtime(&old, two_days_ago).unwrap();

        let fresh = tmp.path().join("fresh.dat");
        fs::write(&fresh, b"data").unwrap();

        let removed = clean_cache_dir(tmp.path(), RESOURCE_CACHE);
        assert_eq!(removed, 1);
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn test_clean_cache_dir_skips_directories() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("subdir")).unwrap();
        let removed = clean_cache_dir(tmp.path(), 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_clean_cache_dir_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let removed = clean_cache_dir(tmp.path(), RESOURCE_CACHE);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_clean_cache_dir_nonexistent_dir() {
        let removed = clean_cache_dir(Path::new("/nonexistent/path"), RESOURCE_CACHE);
        assert_eq!(removed, 0);
    }
}
