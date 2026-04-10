// Auto-connect logic and interface monitoring

use std::collections::HashMap;

use crate::crypto::hashes::sha256;
use crate::Result;

/// Monitor interval for checking interface status (seconds).
pub const MONITOR_INTERVAL: u64 = 5;
/// Detach threshold for disconnected interfaces (seconds).
pub const DETACH_THRESHOLD: u64 = 12;
/// Maximum auto-connected interfaces (default).
pub const DEFAULT_MAX_AUTOCONNECTED: usize = 5;

/// State for an auto-connected interface.
#[derive(Debug, Clone)]
pub struct AutoconnectedInterface {
    pub autoconnect_hash: [u8; 32],
    pub endpoint: String,
    pub connected: bool,
    pub last_seen: f64,
    pub interface_index: Option<usize>,
}

/// Manages auto-connection to discovered transport interfaces.
pub struct AutoconnectManager {
    max_autoconnected: usize,
    autoconnected: HashMap<[u8; 32], AutoconnectedInterface>,
    bootstrap_active: bool,
    monitoring: bool,
}

impl AutoconnectManager {
    /// Create a new auto-connect manager.
    pub fn new(max_autoconnected: Option<usize>) -> Self {
        Self {
            max_autoconnected: max_autoconnected
                .unwrap_or(DEFAULT_MAX_AUTOCONNECTED),
            autoconnected: HashMap::new(),
            bootstrap_active: false,
            monitoring: false,
        }
    }

    /// Compute the autoconnect hash for an endpoint specifier.
    pub fn autoconnect_hash(endpoint: &str) -> [u8; 32] {
        sha256(endpoint.as_bytes())
    }

    /// Check if there are available auto-connect slots.
    pub fn has_available_slots(&self) -> bool {
        self.autoconnected.len() < self.max_autoconnected
    }

    /// Number of currently auto-connected interfaces.
    pub fn connected_count(&self) -> usize {
        self.autoconnected
            .values()
            .filter(|i| i.connected)
            .count()
    }

    /// Attempt initial auto-connect to previously discovered interfaces.
    ///
    /// Stub: In a full implementation, this would iterate discovered
    /// transport interfaces and create BackboneInterface connections.
    /// Actual interface creation is deferred to Layer 6.
    pub fn initial_autoconnect(
        &mut self,
        _discovered: &[super::handler::DiscoveredInterfaceInfo],
    ) -> Result<Vec<String>> {
        let mut connected = Vec::new();

        for info in _discovered.iter().take(self.max_autoconnected) {
            if !info.transport {
                continue;
            }
            if let Some(ref endpoint) = info.reachable_on {
                let hash = Self::autoconnect_hash(endpoint);
                if !self.autoconnected.contains_key(&hash) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0);

                    self.autoconnected.insert(
                        hash,
                        AutoconnectedInterface {
                            autoconnect_hash: hash,
                            endpoint: endpoint.clone(),
                            connected: false, // stub: not actually connected
                            last_seen: now,
                            interface_index: None,
                        },
                    );
                    connected.push(endpoint.clone());

                    if !self.has_available_slots() {
                        break;
                    }
                }
            }
        }

        Ok(connected)
    }

    /// Try to auto-connect a newly discovered interface.
    ///
    /// Stub: actual interface creation deferred to Layer 6.
    pub fn try_autoconnect(
        &mut self,
        info: &super::handler::DiscoveredInterfaceInfo,
    ) -> Result<bool> {
        if !info.transport || !self.has_available_slots() {
            return Ok(false);
        }

        if let Some(ref endpoint) = info.reachable_on {
            let hash = Self::autoconnect_hash(endpoint);
            if !self.autoconnected.contains_key(&hash) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);

                self.autoconnected.insert(
                    hash,
                    AutoconnectedInterface {
                        autoconnect_hash: hash,
                        endpoint: endpoint.clone(),
                        connected: false,
                        last_seen: now,
                        interface_index: None,
                    },
                );
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Monitor auto-connected interfaces, detaching those that have been
    /// disconnected longer than DETACH_THRESHOLD.
    ///
    /// Returns the endpoints that were detached.
    pub fn monitor_interfaces(&mut self) -> Vec<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut detached = Vec::new();

        self.autoconnected.retain(|_, iface| {
            if !iface.connected {
                let down_time = now - iface.last_seen;
                if down_time > DETACH_THRESHOLD as f64 {
                    detached.push(iface.endpoint.clone());
                    return false;
                }
            }
            true
        });

        detached
    }

    /// Check if all auto-connected interfaces are offline.
    pub fn all_offline(&self) -> bool {
        self.autoconnected.is_empty()
            || self.autoconnected.values().all(|i| !i.connected)
    }

    /// Check if bootstrap should be re-enabled.
    pub fn should_enable_bootstrap(&self) -> bool {
        self.all_offline() && !self.bootstrap_active
    }

    /// Check if bootstrap should be torn down (target count reached).
    pub fn should_teardown_bootstrap(&self) -> bool {
        self.connected_count() >= self.max_autoconnected
            && self.bootstrap_active
    }

    /// Set bootstrap state.
    pub fn set_bootstrap_active(&mut self, active: bool) {
        self.bootstrap_active = active;
    }

    /// Start monitoring.
    pub fn start_monitoring(&mut self) {
        self.monitoring = true;
    }

    /// Stop monitoring.
    pub fn stop_monitoring(&mut self) {
        self.monitoring = false;
    }

    /// Check if monitoring is active.
    pub fn is_monitoring(&self) -> bool {
        self.monitoring
    }
}
