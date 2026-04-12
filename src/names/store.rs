//! Persistent name record database backed by msgpack.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::names::record::NameRecord;

/// Persistent name database keyed by full name string.
pub struct NameStore {
    records: HashMap<String, NameRecord>,
    path: Option<PathBuf>,
}

impl NameStore {
    /// Create an in-memory store (no persistence).
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            path: None,
        }
    }

    /// Create a store backed by a file at the given path.
    pub fn open(path: &Path) -> crate::Result<Self> {
        let records = if path.exists() {
            let data = std::fs::read(path)?;
            rmp_serde::from_slice(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Ok(Self {
            records,
            path: Some(path.to_path_buf()),
        })
    }

    /// Store a record, replacing any existing record for the same name
    /// only if the new record has a later timestamp.
    pub fn store(&mut self, record: NameRecord) -> bool {
        if let Some(existing) = self.records.get(&record.name) {
            if record.timestamp <= existing.timestamp {
                return false;
            }
        }
        self.records.insert(record.name.clone(), record);
        self.persist();
        true
    }

    /// Look up a record by exact name.
    pub fn lookup(&self, name: &str) -> Option<&NameRecord> {
        self.records.get(name)
    }

    /// Look up with TTL enforcement. Returns None if the record is expired.
    pub fn lookup_with_ttl(&self, name: &str, ttl_seconds: f64) -> Option<&NameRecord> {
        let record = self.records.get(name)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        if now - record.timestamp > ttl_seconds {
            return None;
        }
        Some(record)
    }

    /// Wildcard query: `label.*` returns all records with matching label,
    /// `*.suffix` returns all records with matching suffix.
    pub fn query_wildcard(&self, pattern: &str) -> Vec<&NameRecord> {
        if pattern.ends_with(".*") {
            let label = &pattern[..pattern.len() - 2];
            self.records
                .values()
                .filter(|r| r.label() == label)
                .collect()
        } else if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            self.records
                .values()
                .filter(|r| r.suffix() == suffix)
                .collect()
        } else {
            self.lookup(pattern).into_iter().collect()
        }
    }

    /// Return all stored records.
    pub fn all_records(&self) -> Vec<&NameRecord> {
        self.records.values().collect()
    }

    /// Count records for a given suffix.
    pub fn count_by_suffix(&self, suffix: &str) -> usize {
        self.records.values().filter(|r| r.suffix() == suffix).count()
    }

    /// Remove expired records.
    pub fn cleanup_expired(&mut self, ttl_seconds: f64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        self.records.retain(|_, r| now - r.timestamp <= ttl_seconds);
        self.persist();
    }

    fn persist(&self) {
        if let Some(ref path) = self.path {
            if let Ok(data) = rmp_serde::to_vec(&self.records) {
                let _ = std::fs::write(path, data);
            }
        }
    }
}
