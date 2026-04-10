// InterfaceAnnouncer: periodic interface discovery announce sender

use std::collections::HashMap;

use crate::identity::Identity;
use crate::transport::TransportState;
use crate::{FerretError, Result};

use super::handler::FLAG_ENCRYPTED;

/// Job check interval in seconds.
pub const JOB_INTERVAL: u64 = 60;
/// Default proof-of-work stamp difficulty.
pub const DEFAULT_STAMP_VALUE: u8 = 14;
/// Workblock expand rounds for stamp computation.
pub const WORKBLOCK_EXPAND_ROUNDS: u8 = 20;

/// Interface types eligible for discovery announcement.
pub const DISCOVERABLE_INTERFACE_TYPES: &[&str] = &[
    "BackboneInterface",
    "TCPServerInterface",
    "TCPClientInterface",
    "RNodeInterface",
    "WeaveInterface",
    "I2PInterface",
    "KISSInterface",
];

/// Structured info about a discoverable interface, passed to the announcer.
#[derive(Debug, Clone)]
pub struct InterfaceDiscoveryInfo {
    pub interface_type: String,
    pub name: String,
    pub transport_enabled: bool,
    pub transport_identity_hash: [u8; 16],
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    pub reachable_on: Option<String>,
    pub port: Option<u16>,
    pub frequency: Option<u64>,
    pub bandwidth: Option<u64>,
    pub spreading_factor: Option<u8>,
    pub coding_rate: Option<u8>,
    pub modulation: Option<String>,
    pub channel: Option<u8>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub discovery_encrypt: bool,
    pub discovery_stamp_value: Option<u8>,
    pub discovery_announce_interval: f64,
    pub last_discovery_announce: f64,
}

/// Background service that periodically announces discoverable interfaces.
pub struct InterfaceAnnouncer {
    should_run: bool,
    job_interval: u64,
    stamp_cache: HashMap<[u8; 32], Vec<u8>>,
    // Placeholder: real Destination created in new()
    // discovery_destination would be a Destination, but we store minimal state
    _identity_hash: [u8; 16],
}

impl InterfaceAnnouncer {
    /// Create a new InterfaceAnnouncer.
    ///
    /// In a full implementation, this creates a Destination with app_name
    /// "rnstransport" and aspects ["discovery", "interface"]. For now we
    /// store the identity hash and defer actual Destination creation to
    /// Layer 7 when the full Reticulum process is available.
    pub fn new(identity: &Identity, _transport: &TransportState) -> Result<Self> {
        let id_hash = *identity.hash()?;
        Ok(Self {
            should_run: false,
            job_interval: JOB_INTERVAL,
            stamp_cache: HashMap::new(),
            _identity_hash: id_hash,
        })
    }

    /// Start the announcer background loop.
    pub fn start(&mut self) {
        self.should_run = true;
    }

    /// Stop the announcer background loop.
    pub fn stop(&mut self) {
        self.should_run = false;
    }

    /// Check if the announcer is running.
    pub fn is_running(&self) -> bool {
        self.should_run
    }

    /// Build the announce app_data for an interface.
    ///
    /// Returns: flags(1) + payload (optionally encrypted with network_identity).
    /// The payload is msgpack(info_dict) + stamp_bytes.
    pub fn get_interface_announce_data(
        &mut self,
        info: &InterfaceDiscoveryInfo,
        network_identity: Option<&Identity>,
    ) -> Result<Option<Vec<u8>>> {
        // Build msgpack info dictionary with integer keys
        let mut entries: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();

        entries.push((
            rmpv::Value::from(super::INTERFACE_TYPE as u64),
            rmpv::Value::from(info.interface_type.as_str()),
        ));
        entries.push((
            rmpv::Value::from(super::TRANSPORT as u64),
            rmpv::Value::from(info.transport_enabled),
        ));
        entries.push((
            rmpv::Value::from(super::TRANSPORT_ID as u64),
            rmpv::Value::Binary(info.transport_identity_hash.to_vec()),
        ));
        entries.push((
            rmpv::Value::from(super::NAME as u64),
            rmpv::Value::from(info.name.as_str()),
        ));

        if let Some(ref addr) = info.reachable_on {
            entries.push((
                rmpv::Value::from(super::REACHABLE_ON as u64),
                rmpv::Value::from(addr.as_str()),
            ));
        }
        if let Some(lat) = info.latitude {
            entries.push((
                rmpv::Value::from(super::LATITUDE as u64),
                rmpv::Value::from(lat),
            ));
        }
        if let Some(lon) = info.longitude {
            entries.push((
                rmpv::Value::from(super::LONGITUDE as u64),
                rmpv::Value::from(lon),
            ));
        }
        if let Some(h) = info.height {
            entries.push((
                rmpv::Value::from(super::HEIGHT as u64),
                rmpv::Value::from(h),
            ));
        }
        if let Some(p) = info.port {
            entries.push((
                rmpv::Value::from(super::PORT as u64),
                rmpv::Value::from(p as u64),
            ));
        }
        if let Some(ref nn) = info.ifac_netname {
            entries.push((
                rmpv::Value::from(super::IFAC_NETNAME as u64),
                rmpv::Value::from(nn.as_str()),
            ));
        }
        if let Some(ref nk) = info.ifac_netkey {
            entries.push((
                rmpv::Value::from(super::IFAC_NETKEY as u64),
                rmpv::Value::from(nk.as_str()),
            ));
        }
        if let Some(f) = info.frequency {
            entries.push((
                rmpv::Value::from(super::FREQUENCY as u64),
                rmpv::Value::from(f),
            ));
        }
        if let Some(bw) = info.bandwidth {
            entries.push((
                rmpv::Value::from(super::BANDWIDTH as u64),
                rmpv::Value::from(bw),
            ));
        }
        if let Some(sf) = info.spreading_factor {
            entries.push((
                rmpv::Value::from(super::SPREADINGFACTOR as u64),
                rmpv::Value::from(sf as u64),
            ));
        }
        if let Some(cr) = info.coding_rate {
            entries.push((
                rmpv::Value::from(super::CODINGRATE as u64),
                rmpv::Value::from(cr as u64),
            ));
        }
        if let Some(ref m) = info.modulation {
            entries.push((
                rmpv::Value::from(super::MODULATION as u64),
                rmpv::Value::from(m.as_str()),
            ));
        }
        if let Some(ch) = info.channel {
            entries.push((
                rmpv::Value::from(super::CHANNEL as u64),
                rmpv::Value::from(ch as u64),
            ));
        }

        let map_value = rmpv::Value::Map(entries);
        let mut packed_info = Vec::new();
        rmpv::encode::write_value(&mut packed_info, &map_value).map_err(|e| {
            FerretError::Serialization(format!("msgpack encode: {}", e))
        })?;

        // Compute proof-of-work stamp (placeholder: random bytes)
        let stamp_value = info
            .discovery_stamp_value
            .unwrap_or(DEFAULT_STAMP_VALUE);
        let info_hash = crate::crypto::hashes::sha256(&packed_info);

        let stamp = self
            .stamp_cache
            .get(&info_hash)
            .cloned()
            .unwrap_or_else(|| {
                // Placeholder stamp: 8 random bytes (real PoW deferred to Layer 7)
                let mut s = vec![0u8; 8];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
                s
            });
        self.stamp_cache.insert(info_hash, stamp.clone());

        // Build payload = packed_info + stamp
        let mut payload = packed_info;
        payload.extend_from_slice(&stamp);

        // Construct flags byte
        let mut flags: u8 = 0;
        let _ = stamp_value; // used for real PoW later

        // Optionally encrypt with network_identity
        let final_payload = if info.discovery_encrypt {
            if let Some(net_id) = network_identity {
                flags |= FLAG_ENCRYPTED;
                net_id.encrypt(&payload, None)?
            } else {
                payload
            }
        } else {
            payload
        };

        // Result: flags(1) + final_payload
        let mut result = Vec::with_capacity(1 + final_payload.len());
        result.push(flags);
        result.extend_from_slice(&final_payload);

        Ok(Some(result))
    }
}
