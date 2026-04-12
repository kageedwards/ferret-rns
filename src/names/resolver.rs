//! Name resolver: validates records, enforces rate limits, manages registrations.

use std::collections::HashMap;

use crate::names::record::NameRecord;
use crate::names::stamp::verify_stamp;
use crate::names::store::NameStore;

/// Configuration for the name resolver.
pub struct ResolverConfig {
    /// Minimum proof-of-work difficulty (default: 14)
    pub stamp_difficulty: u8,
    /// Maximum registrations per identity suffix (default: 5)
    pub max_per_suffix: usize,
    /// Record TTL in seconds (default: 30 days)
    pub ttl_seconds: f64,
    /// Rate limit: minimum seconds between registrations per identity
    pub rate_limit_seconds: f64,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            stamp_difficulty: 14,
            max_per_suffix: 5,
            ttl_seconds: 30.0 * 24.0 * 3600.0, // 30 days
            rate_limit_seconds: 3600.0,          // 1 hour
        }
    }
}

/// Name resolver service logic.
pub struct NameResolver {
    pub store: NameStore,
    pub config: ResolverConfig,
    /// Tracks last registration timestamp per identity hash (hex string).
    last_registration: HashMap<String, f64>,
    /// Set of blackholed identity hashes (hex strings).
    blackhole: std::collections::HashSet<String>,
}

impl NameResolver {
    pub fn new(store: NameStore, config: ResolverConfig) -> Self {
        Self {
            store,
            config,
            last_registration: HashMap::new(),
            blackhole: std::collections::HashSet::new(),
        }
    }

    /// Add an identity hash to the blackhole list.
    pub fn blackhole_identity(&mut self, identity_hash_hex: &str) {
        self.blackhole.insert(identity_hash_hex.to_string());
    }

    /// Check if an identity is blackholed.
    pub fn is_blackholed(&self, identity_hash_hex: &str) -> bool {
        self.blackhole.contains(identity_hash_hex)
    }

    /// Validate and register a name record. Returns Ok(true) if accepted,
    /// Ok(false) if rejected, or Err with reason.
    pub fn register(&mut self, record: NameRecord) -> Result<bool, String> {
        // 1. Validate name format
        if !record.validate_format() {
            return Err("invalid name format".into());
        }

        // 2. Validate suffix matches identity hash
        if !record.validate_suffix() {
            return Err(format!(
                "name suffix '{}' does not match identity hash",
                record.suffix()
            ));
        }

        // 3. Validate identity hash matches public key
        if !record.validate_identity_hash() {
            return Err("public key does not hash to identity hash".into());
        }

        // 4. Verify stamp difficulty
        if !verify_stamp(
            &record.signed_data(),
            &record.stamp,
            self.config.stamp_difficulty,
        ) {
            return Err(format!(
                "proof-of-work stamp does not meet minimum difficulty {}",
                self.config.stamp_difficulty
            ));
        }

        // 5. Verify signature
        if !record.validate_signature() {
            return Err("record signature verification failed".into());
        }

        // 6. Check blackhole
        let id_hex: String = record.identity_hash.iter().map(|b| format!("{:02x}", b)).collect();
        if self.is_blackholed(&id_hex) {
            return Err("identity is blackholed".into());
        }

        // 7. Check rate limit
        if let Some(&last_ts) = self.last_registration.get(&id_hex) {
            if record.timestamp - last_ts < self.config.rate_limit_seconds {
                return Err("registration rate limit exceeded".into());
            }
        }

        // 8. Check max registrations per suffix
        let suffix = record.suffix().to_string();
        if self.store.count_by_suffix(&suffix) >= self.config.max_per_suffix {
            // Allow if this is an update to an existing name
            if self.store.lookup(&record.name).is_none() {
                return Err(format!(
                    "maximum registrations ({}) for suffix '.{}' reached",
                    self.config.max_per_suffix, suffix
                ));
            }
        }

        // 9. Store (handles timestamp-based update semantics)
        let stored = self.store.store(record.clone());
        if stored {
            self.last_registration.insert(id_hex, record.timestamp);
        }
        Ok(stored)
    }

    /// Look up a name, respecting TTL.
    pub fn lookup(&self, name: &str) -> Option<&NameRecord> {
        self.store.lookup_with_ttl(name, self.config.ttl_seconds)
    }

    /// Wildcard query.
    pub fn query(&self, pattern: &str) -> Vec<&NameRecord> {
        self.store.query_wildcard(pattern)
    }
}
