// InterfaceDiscovery: persistent store and classification

use std::path::{Path, PathBuf};

use crate::transport::TransportState;
use crate::Result;

use super::handler::{DiscoveredInterfaceInfo, InterfaceAnnounceHandler};
use super::validation::{is_hostname, is_ip_address};

/// Status code for stale interfaces (heard > 3 days ago).
pub const STATUS_STALE: u32 = 0;
/// Status code for unknown interfaces (heard > 24h but <= 3 days).
pub const STATUS_UNKNOWN: u32 = 100;
/// Status code for available interfaces (heard within 24h).
pub const STATUS_AVAILABLE: u32 = 1000;

/// Monitor interval for checking auto-connected interfaces (seconds).
pub const MONITOR_INTERVAL: u64 = 5;
/// Detach threshold for disconnected interfaces (seconds).
pub const DETACH_THRESHOLD: u64 = 12;

/// Persistent store of discovered interfaces with classification.
pub struct InterfaceDiscovery {
    storagepath: PathBuf,
    required_value: u8,
    handler: InterfaceAnnounceHandler,
    discovery_callback:
        Option<Box<dyn Fn(&DiscoveredInterfaceInfo) + Send + Sync>>,
    monitored_interfaces: Vec<usize>,
    monitoring_autoconnects: bool,
    initial_autoconnect_ran: bool,
}

impl InterfaceDiscovery {
    /// Create a new InterfaceDiscovery, registering the handler and
    /// initializing the storage directory.
    pub fn new(
        storagepath: &Path,
        required_value: u8,
        callback: Option<Box<dyn Fn(&DiscoveredInterfaceInfo) + Send + Sync>>,
        _transport: &TransportState,
    ) -> Result<Self> {
        let interfaces_dir = storagepath.join("discovery").join("interfaces");
        std::fs::create_dir_all(&interfaces_dir)?;

        let handler = InterfaceAnnounceHandler::new(required_value, None);

        Ok(Self {
            storagepath: interfaces_dir,
            required_value,
            handler,
            discovery_callback: callback,
            monitored_interfaces: Vec::new(),
            monitoring_autoconnects: false,
            initial_autoconnect_ran: false,
        })
    }

    /// Get a reference to the handler.
    pub fn handler(&self) -> &InterfaceAnnounceHandler {
        &self.handler
    }

    /// Handle a newly discovered interface: persist to disk as msgpack.
    pub fn interface_discovered(
        &self,
        info: &DiscoveredInterfaceInfo,
    ) -> Result<()> {
        let hash_hex: String = info
            .discovery_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let file_path = self.storagepath.join(&hash_hex);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        // Load existing record if present, to update heard_count
        let mut record = if file_path.exists() {
            let data = std::fs::read(&file_path)?;
            crate::util::msgpack::deserialize::<StoredRecord>(&data)
                .unwrap_or_else(|_| StoredRecord::from_info(info, now))
        } else {
            StoredRecord::from_info(info, now)
        };

        record.last_heard = now;
        record.heard_count += 1;
        record.interface_type = info.interface_type.clone();
        record.transport = info.transport;
        record.name = info.name.clone();
        record.transport_id = info.transport_id.clone();
        record.network_id = info.network_id.clone();
        record.reachable_on = info.reachable_on.clone();
        record.port = info.port;
        record.stamp = info.stamp.clone();

        let serialized = crate::util::msgpack::serialize(&record)?;
        std::fs::write(&file_path, serialized)?;

        if let Some(ref cb) = self.discovery_callback {
            cb(info);
        }

        Ok(())
    }

    /// List all discovered interfaces, classified by freshness.
    pub fn list_discovered_interfaces(
        &self,
        only_available: bool,
        only_transport: bool,
        _discovery_sources: Option<&[[u8; 16]]>,
    ) -> Result<Vec<DiscoveredInterfaceInfo>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut results = Vec::new();

        let entries = std::fs::read_dir(&self.storagepath)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let record: StoredRecord = match crate::util::msgpack::deserialize(&data) {
                Ok(r) => r,
                Err(_) => {
                    // Corrupt record, remove it
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            };

            let age = now - record.last_heard;
            let age_secs = age as u64;

            // Remove records older than THRESHOLD_REMOVE
            if age_secs > super::THRESHOLD_REMOVE {
                let _ = std::fs::remove_file(&path);
                continue;
            }

            // Validate reachable_on
            if let Some(ref addr) = record.reachable_on {
                if !is_ip_address(addr) && !is_hostname(addr) {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            }

            // Classify
            let (status, status_code) = classify_age(age_secs);

            if only_available && status_code != STATUS_AVAILABLE {
                continue;
            }
            if only_transport && !record.transport {
                continue;
            }

            let discovery_hash = hex_to_hash(
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(""),
            );

            let info = DiscoveredInterfaceInfo {
                interface_type: record.interface_type,
                transport: record.transport,
                name: record.name,
                received: record.discovered,
                stamp: record.stamp,
                value: self.required_value,
                transport_id: record.transport_id,
                network_id: record.network_id,
                hops: 0,
                latitude: record.latitude,
                longitude: record.longitude,
                height: record.height,
                reachable_on: record.reachable_on,
                port: record.port,
                frequency: record.frequency,
                bandwidth: record.bandwidth,
                spreading_factor: record.spreading_factor,
                coding_rate: record.coding_rate,
                modulation: record.modulation,
                channel: record.channel,
                ifac_netname: record.ifac_netname,
                ifac_netkey: record.ifac_netkey,
                config_entry: None,
                discovery_hash,
                discovered: Some(record.discovered),
                last_heard: Some(record.last_heard),
                heard_count: Some(record.heard_count),
                status: Some(status.to_string()),
                status_code: Some(status_code),
            };

            results.push(info);
        }

        // Sort by (status_code desc, last_heard desc)
        results.sort_by(|a, b| {
            let sc_cmp = b
                .status_code
                .unwrap_or(0)
                .cmp(&a.status_code.unwrap_or(0));
            if sc_cmp != std::cmp::Ordering::Equal {
                return sc_cmp;
            }
            b.last_heard
                .unwrap_or(0.0)
                .partial_cmp(&a.last_heard.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(results)
    }
}

/// Classify an interface by age in seconds.
pub fn classify_age(age_secs: u64) -> (&'static str, u32) {
    if age_secs <= super::THRESHOLD_UNKNOWN {
        ("available", STATUS_AVAILABLE)
    } else if age_secs <= super::THRESHOLD_STALE {
        ("unknown", STATUS_UNKNOWN)
    } else {
        ("stale", STATUS_STALE)
    }
}

/// Stored record for persistence (msgpack-serializable).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRecord {
    interface_type: String,
    transport: bool,
    name: String,
    transport_id: String,
    network_id: String,
    discovered: f64,
    last_heard: f64,
    heard_count: u64,
    stamp: Vec<u8>,
    reachable_on: Option<String>,
    port: Option<u16>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    height: Option<f64>,
    frequency: Option<u64>,
    bandwidth: Option<u64>,
    spreading_factor: Option<u8>,
    coding_rate: Option<u8>,
    modulation: Option<String>,
    channel: Option<u8>,
    ifac_netname: Option<String>,
    ifac_netkey: Option<String>,
}

impl StoredRecord {
    fn from_info(info: &DiscoveredInterfaceInfo, now: f64) -> Self {
        Self {
            interface_type: info.interface_type.clone(),
            transport: info.transport,
            name: info.name.clone(),
            transport_id: info.transport_id.clone(),
            network_id: info.network_id.clone(),
            discovered: info.discovered.unwrap_or(now),
            last_heard: info.last_heard.unwrap_or(now),
            heard_count: info.heard_count.unwrap_or(1),
            stamp: info.stamp.clone(),
            reachable_on: info.reachable_on.clone(),
            port: info.port,
            latitude: info.latitude,
            longitude: info.longitude,
            height: info.height,
            frequency: info.frequency,
            bandwidth: info.bandwidth,
            spreading_factor: info.spreading_factor,
            coding_rate: info.coding_rate,
            modulation: info.modulation.clone(),
            channel: info.channel,
            ifac_netname: info.ifac_netname.clone(),
            ifac_netkey: info.ifac_netkey.clone(),
        }
    }
}

/// Parse a hex string into a 32-byte hash. Returns zeroed hash on failure.
fn hex_to_hash(hex: &str) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            hex.get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();
    let len = bytes.len().min(32);
    hash[..len].copy_from_slice(&bytes[..len]);
    hash
}
