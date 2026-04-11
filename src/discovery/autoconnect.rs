// Auto-connect logic and interface monitoring

use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::hashes::sha256;
use crate::interfaces::tcp_client::TCPClientInterface;
use crate::transport::{InterfaceHandle, TransportState};
use crate::{FerretError, Result};

/// Monitor interval for checking interface status (seconds).
pub const MONITOR_INTERVAL: u64 = 5;
/// Detach threshold for disconnected interfaces (seconds).
pub const DETACH_THRESHOLD: u64 = 12;
/// Maximum auto-connected interfaces (default).
pub const DEFAULT_MAX_AUTOCONNECTED: usize = 5;

/// State for an auto-connected interface.
#[derive(Clone)]
pub struct AutoconnectedInterface {
    pub autoconnect_hash: [u8; 32],
    pub endpoint: String,
    pub connected: bool,
    pub last_seen: f64,
    /// The interface handle registered with TransportState (if connected).
    pub interface_handle: Option<Arc<dyn InterfaceHandle>>,
}

/// Manages auto-connection to discovered transport interfaces.
pub struct AutoconnectManager {
    max_autoconnected: usize,
    autoconnected: HashMap<[u8; 32], AutoconnectedInterface>,
    bootstrap_active: bool,
    monitoring: bool,
    transport: TransportState,
}

impl AutoconnectManager {
    /// Create a new auto-connect manager.
    pub fn new(max_autoconnected: Option<usize>, transport: TransportState) -> Self {
        Self {
            max_autoconnected: max_autoconnected
                .unwrap_or(DEFAULT_MAX_AUTOCONNECTED),
            autoconnected: HashMap::new(),
            bootstrap_active: false,
            monitoring: false,
            transport,
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
    /// Creates real TCPClientInterface connections for discovered transport
    /// interfaces and registers them with TransportState.
    pub fn initial_autoconnect(
        &mut self,
        discovered: &[super::handler::DiscoveredInterfaceInfo],
    ) -> Result<Vec<String>> {
        let mut connected = Vec::new();

        for info in discovered.iter().take(self.max_autoconnected) {
            if !info.transport {
                continue;
            }
            if let Some(ref endpoint) = info.reachable_on {
                let hash = Self::autoconnect_hash(endpoint);
                if self.autoconnected.contains_key(&hash) {
                    continue;
                }

                let port = info.port.unwrap_or(4242);
                let name = format!("AutoTCP/{}", endpoint);

                match Self::create_and_register_interface(
                    endpoint,
                    port,
                    &name,
                    &self.transport,
                ) {
                    Ok(handle) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);

                        self.autoconnected.insert(
                            hash,
                            AutoconnectedInterface {
                                autoconnect_hash: hash,
                                endpoint: endpoint.clone(),
                                connected: true,
                                last_seen: now,
                                interface_handle: Some(handle),
                            },
                        );
                        connected.push(endpoint.clone());
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: autoconnect to {} failed: {}",
                            endpoint, e
                        );
                    }
                }

                if !self.has_available_slots() {
                    break;
                }
            }
        }

        Ok(connected)
    }

    /// Try to auto-connect a newly discovered interface.
    ///
    /// Creates a real TCPClientInterface and registers it with TransportState.
    pub fn try_autoconnect(
        &mut self,
        info: &super::handler::DiscoveredInterfaceInfo,
    ) -> Result<bool> {
        if !info.transport || !self.has_available_slots() {
            return Ok(false);
        }

        if let Some(ref endpoint) = info.reachable_on {
            let hash = Self::autoconnect_hash(endpoint);
            if self.autoconnected.contains_key(&hash) {
                return Ok(false);
            }

            let port = info.port.unwrap_or(4242);
            let name = format!("AutoTCP/{}", endpoint);

            match Self::create_and_register_interface(
                endpoint,
                port,
                &name,
                &self.transport,
            ) {
                Ok(handle) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0);

                    self.autoconnected.insert(
                        hash,
                        AutoconnectedInterface {
                            autoconnect_hash: hash,
                            endpoint: endpoint.clone(),
                            connected: true,
                            last_seen: now,
                            interface_handle: Some(handle),
                        },
                    );
                    return Ok(true);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: autoconnect to {} failed: {}",
                        endpoint, e
                    );
                    return Ok(false);
                }
            }
        }

        Ok(false)
    }

    /// Monitor auto-connected interfaces, detaching those that have been
    /// disconnected longer than DETACH_THRESHOLD.
    ///
    /// Removes detached interfaces from TransportState. Returns the endpoints
    /// that were detached.
    pub fn monitor_interfaces(&mut self) -> Vec<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut detached = Vec::new();
        let mut hashes_to_remove: Vec<[u8; 32]> = Vec::new();

        // Collect interfaces that need detaching
        for (hash, iface) in &self.autoconnected {
            if !iface.connected {
                let down_time = now - iface.last_seen;
                if down_time > DETACH_THRESHOLD as f64 {
                    detached.push(iface.endpoint.clone());
                    hashes_to_remove.push(*hash);
                }
            }
        }

        // Remove from TransportState and local map
        for hash in &hashes_to_remove {
            if let Some(entry) = self.autoconnected.remove(hash) {
                if let Some(ref handle) = entry.interface_handle {
                    let iface_hash = handle.interface_hash().to_vec();
                    if let Ok(mut inner) = self.transport.write() {
                        inner.interfaces.retain(|h| h.interface_hash() != iface_hash.as_slice());
                    }
                }
            }
        }

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

    /// Create a TCPClientInterface, wire it to TransportState, and register it.
    ///
    /// Returns the `Arc<dyn InterfaceHandle>` for the newly created interface.
    fn create_and_register_interface(
        target_ip: &str,
        target_port: u16,
        name: &str,
        transport: &TransportState,
    ) -> Result<Arc<dyn InterfaceHandle>> {
        let iface = TCPClientInterface::connect(
            target_ip.to_string(),
            target_port,
            name.to_string(),
            false, // kiss_framing
            false, // i2p_tunneled
            None,  // max_reconnect_tries
        )?;

        let handle: Arc<dyn InterfaceHandle> = iface.base.clone();
        iface.base.set_transport(transport.clone(), handle.clone());
        transport.write().map_err(|e| {
            FerretError::Token(format!("failed to lock transport for interface registration: {}", e))
        })?.interfaces.push(handle.clone());

        Ok(handle)
    }
}
