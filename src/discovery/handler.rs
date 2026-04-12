// InterfaceAnnounceHandler: announce receiver and validator

use std::collections::HashMap;

use crate::crypto::hashes::sha256;
use crate::identity::Identity;
use crate::transport::TransportState;
use crate::{FerretError, Result};

use super::validation::{is_hostname, is_ip_address};

/// Flag: announce payload is signed.
pub const FLAG_SIGNED: u8 = 0x01;
/// Flag: announce payload is encrypted.
pub const FLAG_ENCRYPTED: u8 = 0x02;

/// Structured info record for a discovered interface.
#[derive(Debug, Clone)]
pub struct DiscoveredInterfaceInfo {
    pub interface_type: String,
    pub transport: bool,
    pub name: String,
    pub received: f64,
    pub stamp: Vec<u8>,
    pub value: u8,
    pub transport_id: String,
    pub network_id: String,
    pub hops: u8,
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
    pub config_entry: Option<String>,
    pub discovery_hash: [u8; 32],
    // Persistence fields
    pub discovered: Option<f64>,
    pub last_heard: Option<f64>,
    pub heard_count: Option<u64>,
    pub status: Option<String>,
    pub status_code: Option<u32>,
}

/// Handler for interface discovery announces.
pub struct InterfaceAnnounceHandler {
    pub aspect_filter: String,
    pub required_value: u8,
    callback: Option<Box<dyn Fn(&DiscoveredInterfaceInfo) + Send + Sync>>,
}

impl InterfaceAnnounceHandler {
    /// Create a new handler with the given stamp requirement and callback.
    pub fn new(
        required_value: u8,
        callback: Option<Box<dyn Fn(&DiscoveredInterfaceInfo) + Send + Sync>>,
    ) -> Self {
        Self {
            aspect_filter: format!("{}.discovery.interface", super::APP_NAME),
            required_value,
            callback,
        }
    }

    /// Handle a received interface discovery announce.
    pub fn received_announce(
        &self,
        _destination_hash: &[u8; 16],
        announced_identity: &Identity,
        app_data: Option<&[u8]>,
        _transport: &TransportState,
        network_identity: Option<&Identity>,
        discovery_sources: Option<&[[u8; 16]]>,
    ) -> Result<()> {
        let app_data = app_data.ok_or_else(|| {
            FerretError::DiscoveryError("no app_data in announce".into())
        })?;

        if app_data.is_empty() {
            return Err(FerretError::DiscoveryError("empty app_data".into()));
        }

        // Verify authorized source if discovery_sources configured
        if let Some(sources) = discovery_sources {
            let id_hash = announced_identity.hash()?;
            if !sources.contains(id_hash) {
                return Err(FerretError::DiscoveryError(
                    "announce from unauthorized source".into(),
                ));
            }
        }

        // Extract flags byte
        let flags = app_data[0];
        let encrypted = (flags & FLAG_ENCRYPTED) != 0;
        let payload = &app_data[1..];

        // Decrypt if encrypted
        let decrypted;
        let working_payload = if encrypted {
            if let Some(net_id) = network_identity {
                decrypted = net_id
                    .decrypt(payload, None, false)?
                    .ok_or_else(|| {
                        FerretError::DiscoveryError("decryption failed".into())
                    })?;
                &decrypted[..]
            } else {
                return Err(FerretError::DiscoveryError(
                    "encrypted announce but no network identity".into(),
                ));
            }
        } else {
            payload
        };

        if working_payload.is_empty() {
            return Err(FerretError::DiscoveryError("empty payload".into()));
        }

        // Separate packed info from stamp (stamp is at the end)
        // Try to unpack msgpack from the beginning; remainder is stamp
        let (info_dict, stamp) = Self::split_info_and_stamp(working_payload)?;

        // Validate stamp via LXStamper PoW algorithm
        if stamp.is_empty() {
            return Err(FerretError::DiscoveryError("missing stamp".into()));
        }

        // Compute info_hash for workblock generation (same as announcer)
        let info_bytes = &working_payload[..working_payload.len() - stamp.len()];
        let info_hash = crate::crypto::hashes::sha256(info_bytes);
        let workblock = crate::crypto::stamp::stamp_workblock(
            &info_hash,
            crate::crypto::stamp::WORKBLOCK_EXPAND_ROUNDS,
        );

        if !crate::crypto::stamp::stamp_valid(&workblock, stamp, self.required_value) {
            return Err(FerretError::DiscoveryError(
                format!("stamp does not meet required value {}", self.required_value),
            ));
        }

        let value = crate::crypto::stamp::stamp_value(&workblock, stamp) as u8;

        // Build DiscoveredInterfaceInfo from the info dictionary
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let network_id_hex = announced_identity
            .hexhash()
            .unwrap_or("unknown")
            .to_string();

        let transport_id_bytes = Self::get_bytes(&info_dict, super::TRANSPORT_ID);
        let transport_id_hex = transport_id_bytes
            .as_ref()
            .map(|b| b.iter().map(|x| format!("{:02x}", x)).collect::<String>())
            .unwrap_or_default();

        let name = Self::get_string(&info_dict, super::NAME)
            .unwrap_or_default();

        let interface_type = Self::get_string(&info_dict, super::INTERFACE_TYPE)
            .unwrap_or_default();

        let transport = Self::get_bool(&info_dict, super::TRANSPORT)
            .unwrap_or(false);

        let reachable_on = Self::get_string(&info_dict, super::REACHABLE_ON);

        // Validate reachable_on
        if let Some(ref addr) = reachable_on {
            if !is_ip_address(addr) && !is_hostname(addr) {
                return Err(FerretError::DiscoveryError(
                    format!("invalid reachable_on address: {}", addr),
                ));
            }
        }

        // Compute discovery_hash = full_hash(transport_id_bytes + name_bytes)
        let mut hash_input = Vec::new();
        if let Some(ref tid) = transport_id_bytes {
            hash_input.extend_from_slice(tid);
        }
        hash_input.extend_from_slice(name.as_bytes());
        let discovery_hash = sha256(&hash_input);

        let info = DiscoveredInterfaceInfo {
            interface_type,
            transport,
            name,
            received: now,
            stamp: stamp.to_vec(),
            value: value,
            transport_id: transport_id_hex,
            network_id: network_id_hex,
            hops: 0,
            latitude: Self::get_f64(&info_dict, super::LATITUDE),
            longitude: Self::get_f64(&info_dict, super::LONGITUDE),
            height: Self::get_f64(&info_dict, super::HEIGHT),
            reachable_on,
            port: Self::get_u64(&info_dict, super::PORT).map(|v| v as u16),
            frequency: Self::get_u64(&info_dict, super::FREQUENCY),
            bandwidth: Self::get_u64(&info_dict, super::BANDWIDTH),
            spreading_factor: Self::get_u64(&info_dict, super::SPREADINGFACTOR)
                .map(|v| v as u8),
            coding_rate: Self::get_u64(&info_dict, super::CODINGRATE)
                .map(|v| v as u8),
            modulation: Self::get_string(&info_dict, super::MODULATION),
            channel: Self::get_u64(&info_dict, super::CHANNEL).map(|v| v as u8),
            ifac_netname: Self::get_string(&info_dict, super::IFAC_NETNAME),
            ifac_netkey: Self::get_string(&info_dict, super::IFAC_NETKEY),
            config_entry: None,
            discovery_hash,
            discovered: Some(now),
            last_heard: Some(now),
            heard_count: Some(1),
            status: Some("available".to_string()),
            status_code: Some(1000),
        };

        // Invoke callback
        if let Some(ref cb) = self.callback {
            cb(&info);
        }

        Ok(())
    }

    /// Split working payload into (info_dict, stamp).
    /// The info is msgpack-encoded at the start; the stamp is the remainder.
    fn split_info_and_stamp(
        data: &[u8],
    ) -> Result<(HashMap<u8, rmpv::Value>, &[u8])> {
        let mut cursor = std::io::Cursor::new(data);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|e| {
            FerretError::Deserialization(format!("msgpack decode: {}", e))
        })?;
        let consumed = cursor.position() as usize;
        let stamp = &data[consumed..];

        // Convert the msgpack value to a HashMap<u8, Value>
        let map = match value {
            rmpv::Value::Map(entries) => {
                let mut m = HashMap::new();
                for (k, v) in entries {
                    if let Some(key) = k.as_u64() {
                        m.insert(key as u8, v);
                    }
                }
                m
            }
            _ => {
                return Err(FerretError::Deserialization(
                    "expected msgpack map".into(),
                ));
            }
        };

        Ok((map, stamp))
    }

    fn get_string(map: &HashMap<u8, rmpv::Value>, key: u8) -> Option<String> {
        map.get(&key).and_then(|v| v.as_str().map(|s| s.to_string()))
    }

    fn get_bytes(map: &HashMap<u8, rmpv::Value>, key: u8) -> Option<Vec<u8>> {
        map.get(&key).and_then(|v| match v {
            rmpv::Value::Binary(b) => Some(b.clone()),
            _ => None,
        })
    }

    fn get_bool(map: &HashMap<u8, rmpv::Value>, key: u8) -> Option<bool> {
        map.get(&key).and_then(|v| v.as_bool())
    }

    fn get_f64(map: &HashMap<u8, rmpv::Value>, key: u8) -> Option<f64> {
        map.get(&key).and_then(|v| v.as_f64())
    }

    fn get_u64(map: &HashMap<u8, rmpv::Value>, key: u8) -> Option<u64> {
        map.get(&key).and_then(|v| v.as_u64())
    }
}
