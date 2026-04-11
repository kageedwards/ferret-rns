// Background persistence and cache cleanup jobs.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Resource cache lifetime: 24 hours.
pub const RESOURCE_CACHE: u64 = 86_400;

/// Background job check interval: 5 minutes.
pub const JOB_INTERVAL: u64 = 300;

/// Cache clean interval: 15 minutes.
pub const CLEAN_INTERVAL: u64 = 900;

/// Data persist interval: 12 hours.
pub const PERSIST_INTERVAL: u64 = 43_200;

/// Minimum time between gracious persists: 5 minutes.
pub const GRACIOUS_PERSIST_INTERVAL: u64 = 300;

/// Run the background jobs loop.
///
/// Sleeps `JOB_INTERVAL` between iterations. Each iteration checks the
/// `shutdown` flag and, when enough time has elapsed, cleans caches or
/// updates the persist timestamp.
pub fn run_jobs(
    shutdown: Arc<AtomicBool>,
    cachepath: std::path::PathBuf,
    resourcepath: std::path::PathBuf,
) {
    let mut last_clean = Instant::now();
    let mut last_persist = Instant::now();

    loop {
        std::thread::sleep(Duration::from_secs(JOB_INTERVAL));

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Cache cleanup
        if last_clean.elapsed() >= Duration::from_secs(CLEAN_INTERVAL) {
            clean_caches(&cachepath, &resourcepath);
            last_clean = Instant::now();
        }

        // Persist (placeholder — full wiring in task 17)
        if last_persist.elapsed() >= Duration::from_secs(PERSIST_INTERVAL) {
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
                eprintln!(
                    "Warning: failed to remove cache file {}: {}",
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
