// Feature: ferret-integration-wiring, Property 1: Inbound packet delivery end-to-end
// **Validates: Requirements 1.1, 1.5, 16.1**
//
// Feature: ferret-integration-wiring, Property 2: Path table persist/load round-trip
// **Validates: Requirements 5.2, 5.5**
//
// Feature: ferret-integration-wiring, Property 3: RPC path_table query reflects transport state
// **Validates: Requirements 4.2**
//
// Feature: ferret-integration-wiring, Property 4: RPC link_count reflects pending + active links
// **Validates: Requirements 4.5**
//
// Feature: ferret-integration-wiring, Property 5: RPC drop path removes entry
// **Validates: Requirements 4.6**
//
// Feature: ferret-integration-wiring, Property 6: Announce rate table recording
// **Validates: Requirements 8.2**
//
// Feature: ferret-integration-wiring, Property 7: Announce rate suppression
// **Validates: Requirements 8.1, 8.3**

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use proptest::prelude::*;
use serde_pickle::value::{HashableValue, Value};

use ferret_rns::crypto::hmac::hmac_sha256;
use ferret_rns::interfaces::base::Interface;
use ferret_rns::packet::packet::Packet;
use ferret_rns::packet::proof::ProofDestination;
use ferret_rns::reticulum::jobs::{persist_path_table, SerializedPathEntry};
use ferret_rns::reticulum::rpc::RpcServer;
use ferret_rns::transport::transport::{LinkEntry, PathEntry, TransportState};
use ferret_rns::transport::InterfaceHandle;
use ferret_rns::types::interface::InterfaceMode;
use ferret_rns::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use ferret_rns::types::transport::TransportType;

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

/// Minimal InterfaceHandle for tests.
struct DummyInterface;

impl InterfaceHandle for DummyInterface {
    fn transmit(&self, _raw: &[u8]) -> ferret_rns::Result<()> { Ok(()) }
    fn is_outbound(&self) -> bool { true }
    fn bitrate(&self) -> Option<u64> { None }
    fn announce_allowed_at(&self) -> f64 { 0.0 }
    fn set_announce_allowed_at(&self, _t: f64) {}
    fn mode(&self) -> InterfaceMode { InterfaceMode::Full }
    fn interface_hash(&self) -> &[u8] { &[0u8; 16] }
}

/// Build a valid Header1 data packet from a destination hash and payload.
fn make_packed_data_packet(dest_hash: [u8; 16], payload: Vec<u8>) -> Packet {
    let dest = ProofDestination::new(dest_hash);
    let mut pkt = Packet::new(
        &dest,
        payload,
        PacketType::Data,
        PacketContext::None,
        TransportType::Broadcast,
        HeaderType::Header1,
        None,
        false,
        ContextFlag::Unset,
    );
    pkt.pack(&dest).unwrap();
    pkt
}

/// Strategy for a 16-byte destination hash.
fn dest_hash_strategy() -> impl Strategy<Value = [u8; 16]> {
    proptest::collection::vec(any::<u8>(), 16).prop_map(|v| {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&v);
        arr
    })
}

/// Strategy for a 32-byte packet hash.
fn packet_hash_strategy() -> impl Strategy<Value = [u8; 32]> {
    proptest::collection::vec(any::<u8>(), 32).prop_map(|v| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        arr
    })
}

/// Strategy for a 10-byte random blob.
fn random_blob_strategy() -> impl Strategy<Value = [u8; 10]> {
    proptest::collection::vec(any::<u8>(), 10).prop_map(|v| {
        let mut arr = [0u8; 10];
        arr.copy_from_slice(&v);
        arr
    })
}

// ---------------------------------------------------------------------------
// RPC pickle wire helpers (matching Python multiprocessing.connection protocol)
// ---------------------------------------------------------------------------

const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
const DIGEST_PREFIX: &[u8] = b"{sha256}";
const WELCOME: &[u8] = b"#WELCOME#";

/// Send a length-prefixed frame (4-byte big-endian i32 + payload).
fn send_bytes(stream: &mut TcpStream, data: &[u8]) {
    let len = data.len() as i32;
    stream.write_all(&len.to_be_bytes()).unwrap();
    stream.write_all(data).unwrap();
    stream.flush().unwrap();
}

/// Receive a length-prefixed frame.
fn recv_bytes(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = i32::from_be_bytes(len_buf);
    assert!(len >= 0 && len <= 1_048_576, "frame length out of range");
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).unwrap();
    buf
}

/// Perform the client side of the HMAC-SHA256 challenge-response handshake.
fn client_authenticate(stream: &mut TcpStream, authkey: &[u8]) {
    let challenge = recv_bytes(stream);
    assert!(challenge.starts_with(CHALLENGE_PREFIX));
    let message = &challenge[CHALLENGE_PREFIX.len()..];
    let mac = hmac_sha256(authkey, message);
    let mut response = Vec::with_capacity(DIGEST_PREFIX.len() + 32);
    response.extend_from_slice(DIGEST_PREFIX);
    response.extend_from_slice(&mac);
    send_bytes(stream, &response);
    let result = recv_bytes(stream);
    assert_eq!(result, WELCOME, "HMAC authentication should succeed");
}

/// Build a pickle dict Value from key-value pairs.
fn pickle_dict(entries: Vec<(&str, Value)>) -> Value {
    let mut map = BTreeMap::new();
    for (k, v) in entries {
        map.insert(HashableValue::String(k.to_string()), v);
    }
    Value::Dict(map)
}

fn pickle_string(s: &str) -> Value { Value::String(s.to_string()) }
fn pickle_none() -> Value { Value::None }
fn pickle_bytes(b: &[u8]) -> Value { Value::Bytes(b.to_vec()) }

/// Send a pickle command and receive a pickle response over an authenticated stream.
fn rpc_call(stream: &mut TcpStream, command: &Value) -> Value {
    let payload = serde_pickle::value_to_vec(command, serde_pickle::SerOptions::new()).unwrap();
    send_bytes(stream, &payload);
    let response_bytes = recv_bytes(stream);
    serde_pickle::value_from_slice(&response_bytes, serde_pickle::DeOptions::new()).unwrap()
}

/// Connect, authenticate, send one pickle command, return the response.
fn rpc_request(port: u16, key: &[u8], command: &Value) -> Value {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client_authenticate(&mut stream, key);
    rpc_call(&mut stream, command)
}

fn start_rpc_server(transport: TransportState) -> (Arc<RpcServer>, u16, Vec<u8>) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let key = vec![1, 2, 3, 4];
    let srv = RpcServer::start(0, key.clone(), shutdown, transport).unwrap();
    let port = srv.local_port();
    thread::sleep(Duration::from_millis(50));
    (srv, port, key)
}

/// Extract bytes from a pickle Value.
fn val_bytes(v: &Value) -> Option<&[u8]> {
    match v { Value::Bytes(b) => Some(b.as_slice()), _ => None }
}

/// Extract i64 from a pickle Value.
fn val_i64(v: &Value) -> Option<i64> {
    match v { Value::I64(n) => Some(*n), _ => None }
}

/// Look up a key in a pickle dict Value.
fn dict_get<'a>(dict: &'a Value, key: &str) -> Option<&'a Value> {
    match dict {
        Value::Dict(map) => map.get(&HashableValue::String(key.to_string())),
        _ => None,
    }
}


// ---------------------------------------------------------------------------
// Property 1: Inbound packet delivery end-to-end
// Feature: ferret-integration-wiring, Property 1: Inbound packet delivery end-to-end
// **Validates: Requirements 1.1, 1.5, 16.1**
//
// For any valid packet bytes fed into Interface::process_incoming() on an
// Interface wired to a TransportState (with no IFAC configured), the
// packet's hash SHALL appear in the TransportState's packet hashlist after
// processing.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn inbound_packet_delivery_end_to_end(
        dest_hash in dest_hash_strategy(),
        payload in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        // Build a valid packed data packet
        let pkt = make_packed_data_packet(dest_hash, payload);
        let raw = pkt.raw.clone();
        let _expected_hash = pkt.get_hash();

        // Create TransportState and Interface wired together (no IFAC)
        let ts = TransportState::new();
        let iface = Arc::new(Interface::new("test-iface".to_string(), None));
        iface.set_transport(ts.clone(), iface.clone() as Arc<dyn InterfaceHandle>);

        // Feed raw bytes through process_incoming
        iface.process_incoming(&raw);

        // After inbound processing, the packet hash should be in the hashlist.
        // Note: inbound() increments hops and recomputes the hash, so we need
        // to compute the hash the same way inbound does.
        // inbound() does: unpack, hops += 1, raw[1] = hops, then get_hash().
        // So we replicate that to get the expected hash.
        let mut check_pkt = Packet::from_raw(raw);
        check_pkt.unpack().unwrap();
        check_pkt.hops = check_pkt.hops.saturating_add(1);
        if check_pkt.raw.len() > 1 {
            check_pkt.raw[1] = check_pkt.hops;
        }
        let inbound_hash = check_pkt.get_hash();

        prop_assert!(
            ts.contains_packet_hash(&inbound_hash).unwrap(),
            "packet hash should be in hashlist after inbound processing"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 2: Path table persist/load round-trip
// Feature: ferret-integration-wiring, Property 2: Path table persist/load round-trip
// **Validates: Requirements 5.2, 5.5**
//
// For any set of path table entries (with serializable fields), serializing
// the path table to disk and loading it back SHALL produce entries with
// identical timestamp, received_from, hops, expires, random_blobs, and
// packet_hash values.
// ---------------------------------------------------------------------------

/// Strategy for a serializable path entry.
fn path_entry_strategy() -> impl Strategy<Value = (
    [u8; 16],  // dest_hash
    f64,       // timestamp
    [u8; 16],  // received_from
    u8,        // hops
    f64,       // expires
    Vec<[u8; 10]>, // random_blobs
    [u8; 32],  // packet_hash
)> {
    (
        dest_hash_strategy(),
        any::<f64>().prop_filter("must be finite", |v| v.is_finite()),
        dest_hash_strategy(),
        any::<u8>(),
        any::<f64>().prop_filter("must be finite", |v| v.is_finite()),
        proptest::collection::vec(random_blob_strategy(), 0..4),
        packet_hash_strategy(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn path_table_persist_load_round_trip(
        entries in proptest::collection::vec(path_entry_strategy(), 1..10),
    ) {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);

        // Insert entries into the path table
        {
            let mut inner = ts.inner.write().unwrap();
            for (dest_hash, timestamp, received_from, hops, expires, random_blobs, packet_hash) in &entries {
                let entry = PathEntry {
                    timestamp: *timestamp,
                    received_from: *received_from,
                    hops: *hops,
                    expires: *expires,
                    random_blobs: random_blobs.clone(),
                    receiving_interface: iface.clone(),
                    packet_hash: *packet_hash,
                };
                inner.path_table.insert(*dest_hash, entry);
            }
        }

        // Persist to temp dir
        let tmp = tempfile::tempdir().unwrap();
        persist_path_table(&ts, tmp.path());

        // Load back
        let path_table_file = tmp.path().join("path_table");
        prop_assert!(path_table_file.exists(), "path_table file should exist");

        let data = std::fs::read(&path_table_file).unwrap();
        let loaded: HashMap<[u8; 16], SerializedPathEntry> =
            rmp_serde::from_slice(&data).unwrap();

        // Compare: each entry we inserted should be in the loaded map with
        // identical serializable fields. Note: if multiple entries share the
        // same dest_hash, only the last one survives (HashMap semantics).
        let inner = ts.inner.read().unwrap();
        prop_assert_eq!(
            inner.path_table.len(),
            loaded.len(),
            "loaded entry count should match"
        );

        for (dest_hash, original) in &inner.path_table {
            let loaded_entry = loaded.get(dest_hash).unwrap();
            prop_assert_eq!(original.timestamp, loaded_entry.timestamp, "timestamp mismatch");
            prop_assert_eq!(original.received_from, loaded_entry.received_from, "received_from mismatch");
            prop_assert_eq!(original.hops, loaded_entry.hops, "hops mismatch");
            prop_assert_eq!(original.expires, loaded_entry.expires, "expires mismatch");
            prop_assert_eq!(&original.random_blobs, &loaded_entry.random_blobs, "random_blobs mismatch");
            prop_assert_eq!(original.packet_hash, loaded_entry.packet_hash, "packet_hash mismatch");
        }
    }
}


// ---------------------------------------------------------------------------
// Property 3: RPC path_table query reflects transport state
// Feature: ferret-integration-wiring, Property 3: RPC path_table query reflects transport state
// **Validates: Requirements 4.2**
//
// For any set of path entries inserted into TransportState, the RPC dispatch
// for `get path_table` SHALL return entries whose destination hashes and hop
// counts match the TransportState contents exactly.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn rpc_path_table_reflects_transport_state(
        entries in proptest::collection::vec(
            (dest_hash_strategy(), any::<u8>()),
            1..8,
        ),
    ) {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);

        // Deduplicate by dest_hash (HashMap semantics)
        let mut expected: HashMap<[u8; 16], u8> = HashMap::new();
        {
            let mut inner = ts.inner.write().unwrap();
            for (dest_hash, hops) in &entries {
                let entry = PathEntry {
                    timestamp: 1000.0,
                    received_from: [0xBB; 16],
                    hops: *hops,
                    expires: 9999.0,
                    random_blobs: vec![],
                    receiving_interface: iface.clone(),
                    packet_hash: [0xCC; 32],
                };
                inner.path_table.insert(*dest_hash, entry);
                expected.insert(*dest_hash, *hops);
            }
        }

        // Start RPC server with this transport
        let (srv, port, key) = start_rpc_server(ts);

        // Query path_table via pickle command
        let cmd = pickle_dict(vec![
            ("get", pickle_string("path_table")),
            ("max_hops", pickle_none()),
        ]);
        let resp = rpc_request(port, &key, &cmd);
        srv.stop();

        // Response is a pickle list of dicts
        let rpc_entries = match &resp {
            Value::List(v) => v,
            other => {
                prop_assert!(false, "expected List, got {:?}", other);
                unreachable!()
            }
        };
        prop_assert_eq!(
            rpc_entries.len(),
            expected.len(),
            "RPC entry count should match transport state"
        );

        // Decode each entry dict and verify dest_hash + hops
        let mut rpc_map: HashMap<Vec<u8>, i64> = HashMap::new();
        for entry in rpc_entries {
            let hash = val_bytes(dict_get(entry, "hash").unwrap()).unwrap().to_vec();
            let hops = val_i64(dict_get(entry, "hops").unwrap()).unwrap();
            rpc_map.insert(hash, hops);
        }

        for (dest_hash, hops) in &expected {
            let rpc_hops = rpc_map.get(&dest_hash.to_vec());
            prop_assert_eq!(
                rpc_hops,
                Some(&(*hops as i64)),
                "hops mismatch for dest {:?}",
                dest_hash
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 4: RPC link_count reflects link_table size
// Feature: ferret-integration-wiring, Property 4: RPC link_count reflects pending + active links
// **Validates: Requirements 4.5**
//
// For any number of link entries registered in TransportState's link_table,
// the RPC dispatch for `get link_count` SHALL return a count equal to
// link_table.len().
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn rpc_link_count_reflects_pending_plus_active(
        n_links in 0usize..10,
    ) {
        let ts = TransportState::new();

        {
            let mut inner = ts.inner.write().unwrap();
            for i in 0..n_links {
                let mut link_id = [0u8; 16];
                link_id[0] = i as u8;
                inner.link_table.insert(link_id, LinkEntry {
                    timestamp: 1000.0,
                    next_hop: [0u8; 16],
                    next_hop_interface: Arc::new(DummyInterface) as Arc<dyn InterfaceHandle>,
                    remaining_hops: 3,
                    receiving_interface: Arc::new(DummyInterface) as Arc<dyn InterfaceHandle>,
                    taken_hops: 0,
                    destination_hash: [0u8; 16],
                    validated: false,
                    proof_timeout: 0.0,
                });
            }
        }

        let expected_count = n_links as i64;

        let (srv, port, key) = start_rpc_server(ts);

        let cmd = pickle_dict(vec![("get", pickle_string("link_count"))]);
        let resp = rpc_request(port, &key, &cmd);
        srv.stop();

        match resp {
            Value::I64(n) => prop_assert_eq!(
                n,
                expected_count,
                "link_count should equal link_table.len()"
            ),
            other => prop_assert!(false, "expected I64, got {:?}", other),
        }
    }
}

// ---------------------------------------------------------------------------
// Property 5: RPC drop path removes entry
// Feature: ferret-integration-wiring, Property 5: RPC drop path removes entry
// **Validates: Requirements 4.6**
//
// For any destination hash present in the TransportState path table, after
// RPC dispatch for `drop path` with that hash, TransportState::has_path()
// SHALL return false for that hash.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn rpc_drop_path_removes_entry(
        dest_hash in dest_hash_strategy(),
    ) {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);

        // Insert a path entry
        {
            let mut inner = ts.inner.write().unwrap();
            inner.path_table.insert(dest_hash, PathEntry {
                timestamp: 1000.0,
                received_from: [0xBB; 16],
                hops: 3,
                expires: 9999.0,
                random_blobs: vec![],
                receiving_interface: iface.clone(),
                packet_hash: [0xCC; 32],
            });
        }

        prop_assert!(ts.has_path(&dest_hash).unwrap(), "path should exist before drop");

        let (srv, port, key) = start_rpc_server(ts.clone());

        let cmd = pickle_dict(vec![
            ("drop", pickle_string("path")),
            ("destination_hash", pickle_bytes(&dest_hash)),
        ]);
        let resp = rpc_request(port, &key, &cmd);
        srv.stop();

        prop_assert_eq!(resp, Value::Bool(true), "RPC drop response should be True");
        prop_assert!(
            !ts.has_path(&dest_hash).unwrap(),
            "has_path should return false after drop"
        );
    }
}


// ---------------------------------------------------------------------------
// Property 6: Announce rate table recording
// Feature: ferret-integration-wiring, Property 6: Announce rate table recording
// **Validates: Requirements 8.2**
//
// For any valid announce packet processed through
// TransportState::process_announce(), the announce_rate_table SHALL contain
// at least one timestamp entry for that announce's destination hash.
//
// Approach: We construct a real announce via Destination::announce(), feed
// it through process_announce(), and verify the rate table.
// ---------------------------------------------------------------------------

use ferret_rns::destination::destination::Destination;
use ferret_rns::identity::{IdentityStore, RatchetStore};
use ferret_rns::types::destination::{DestinationDirection, DestinationType};

fn make_ratchet_store() -> RatchetStore {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_path_buf();
    // Keep the tempdir alive by leaking it
    std::mem::forget(tmp);
    RatchetStore::new(path)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn announce_rate_table_recording(
        app_suffix in "[a-z]{3,8}",
    ) {
        let ts = TransportState::new();
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface);
        let store = IdentityStore::new();
        let ratchet_store = make_ratchet_store();

        // Build a real announce from a fresh destination
        let mut dest = Destination::new(
            None,
            DestinationDirection::In,
            DestinationType::Single,
            &app_suffix,
            &[],
        ).unwrap();

        let mut pkt = dest.announce(None, false, None, false, None).unwrap().unwrap();
        pkt.pack(&dest).unwrap();
        let mut announce_pkt = Packet::from_raw(pkt.raw.clone());
        announce_pkt.unpack().unwrap();

        let dest_hash = announce_pkt.destination_hash;

        ts.process_announce(&mut announce_pkt, &iface, &store, &ratchet_store)
            .unwrap();

        // The announce_rate_table should have at least one timestamp for this dest
        let inner = ts.inner.read().unwrap();
        let timestamps = inner.announce_rate_table.get(&dest_hash);
        prop_assert!(
            timestamps.is_some() && !timestamps.unwrap().is_empty(),
            "announce_rate_table should contain at least one timestamp for dest {:?}",
            dest_hash
        );
    }
}

// ---------------------------------------------------------------------------
// Property 7: Announce rate suppression
// Feature: ferret-integration-wiring, Property 7: Announce rate suppression
// **Validates: Requirements 8.1, 8.3**
//
// For any destination hash with a recent timestamp in the
// announce_rate_table (within the minimum rebroadcast interval), a
// subsequent outbound announce for that destination SHALL be suppressed
// (not transmitted).
//
// Approach: Insert a very recent timestamp into the rate table, then call
// outbound() with an announce packet for that destination. The announce
// should be suppressed (outbound returns false / no transmit).
// ---------------------------------------------------------------------------

/// A recording interface that counts transmissions.
struct RecordingInterface {
    transmitted: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl RecordingInterface {
    fn new() -> Self {
        Self {
            transmitted: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn count(&self) -> usize {
        self.transmitted.lock().unwrap().len()
    }
}

impl InterfaceHandle for RecordingInterface {
    fn transmit(&self, raw: &[u8]) -> ferret_rns::Result<()> {
        self.transmitted.lock().unwrap().push(raw.to_vec());
        Ok(())
    }
    fn is_outbound(&self) -> bool { true }
    fn bitrate(&self) -> Option<u64> { None }
    fn announce_cap(&self) -> f64 { 2.0 } // no cap
    fn announce_allowed_at(&self) -> f64 { 0.0 }
    fn set_announce_allowed_at(&self, _t: f64) {}
    fn mode(&self) -> InterfaceMode { InterfaceMode::Full }
    fn interface_hash(&self) -> &[u8] { &[0u8; 16] }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn announce_rate_suppression(
        dest_hash in dest_hash_strategy(),
        payload in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        let ts = TransportState::new();
        let iface = Arc::new(RecordingInterface::new());

        // Register the interface as outbound
        {
            let mut inner = ts.inner.write().unwrap();
            inner.interfaces.push(iface.clone() as Arc<dyn InterfaceHandle>);
        }

        // Insert a very recent timestamp (now) into the rate table
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        {
            let mut inner = ts.inner.write().unwrap();
            inner.announce_rate_table.insert(dest_hash, vec![now]);
        }

        // Build an announce packet for this destination
        let dest = ProofDestination::new(dest_hash);
        let mut pkt = Packet::new(
            &dest,
            payload,
            PacketType::Announce,
            PacketContext::None,
            TransportType::Broadcast,
            HeaderType::Header1,
            None,
            false,
            ContextFlag::Unset,
        );
        // Force destination_type to Single so it passes the packet_filter
        // (Plain/Group announces are rejected by the filter)
        pkt.destination_type = ferret_rns::types::destination::DestinationType::Single;
        pkt.pack(&dest).unwrap();

        let sent = ts.outbound(&mut pkt).unwrap();

        // The announce should be suppressed because the rate table has a
        // recent timestamp within the minimum rebroadcast interval (1.0s).
        prop_assert!(
            !sent,
            "announce should be suppressed when rate table has recent timestamp"
        );
        prop_assert_eq!(
            iface.count(),
            0,
            "no packets should have been transmitted"
        );
    }
}
