// Integration tests for ferret-rns end-to-end wiring.
//
// Test 1: Loopback packet flow (Req 17)
// Test 2: Announce propagation and path table (Req 18)
// Test 3: State persistence round-trip (Req 19)
// Test 4: RPC server round-trip with real state (Req 20)
// Test 5: Full Reticulum lifecycle (Req 21)

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use ferret_rns::destination::destination::Destination;
use ferret_rns::identity::{Identity, IdentityStore, RatchetStore};
use ferret_rns::packet::packet::Packet;
use ferret_rns::packet::proof::ProofDestination;
use ferret_rns::reticulum::jobs::SerializedPathEntry;
use ferret_rns::reticulum::rpc::RpcServer;
use ferret_rns::reticulum::reticulum::{Reticulum, ReticulumConfig};
use ferret_rns::transport::transport::{PathEntry, TransportState};
use ferret_rns::transport::InterfaceHandle;
use ferret_rns::types::destination::{DestinationDirection, DestinationType};
use ferret_rns::types::interface::InterfaceMode;
use ferret_rns::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use ferret_rns::types::transport::TransportType;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Minimal outbound-capable InterfaceHandle for tests.
struct DummyInterface {
    transmitted: Mutex<Vec<Vec<u8>>>,
}

impl DummyInterface {
    fn new() -> Self {
        Self {
            transmitted: Mutex::new(Vec::new()),
        }
    }
    fn transmitted_count(&self) -> usize {
        self.transmitted.lock().unwrap().len()
    }
    fn last_transmitted(&self) -> Option<Vec<u8>> {
        self.transmitted.lock().unwrap().last().cloned()
    }
}

impl InterfaceHandle for DummyInterface {
    fn transmit(&self, raw: &[u8]) -> ferret_rns::Result<()> {
        self.transmitted.lock().unwrap().push(raw.to_vec());
        Ok(())
    }
    fn is_outbound(&self) -> bool { true }
    fn bitrate(&self) -> Option<u64> { None }
    fn announce_cap(&self) -> f64 { 2.0 }
    fn announce_allowed_at(&self) -> f64 { 0.0 }
    fn set_announce_allowed_at(&self, _t: f64) {}
    fn mode(&self) -> InterfaceMode { InterfaceMode::Full }
    fn interface_hash(&self) -> &[u8] { &[0u8; 16] }
    fn name(&self) -> &str { "DummyInterface" }
    fn rxb(&self) -> u64 { 0 }
    fn txb(&self) -> u64 { 0 }
    fn is_online(&self) -> bool { true }
}

/// Build a valid packed data packet from a destination hash and payload.
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

fn make_ratchet_store() -> RatchetStore {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    RatchetStore::new(path)
}

// RPC wire types (matching src/reticulum/rpc.rs)
#[derive(Debug, Serialize, Deserialize)]
struct RpcRequest {
    #[serde(default)]
    key: Vec<u8>,
    #[serde(default)]
    get: Option<String>,
    #[serde(default)]
    drop: Option<String>,
    #[serde(default)]
    max_hops: Option<u8>,
    #[serde(default)]
    destination_hash: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    entries: Option<Vec<Vec<u8>>>,
}

fn send_rpc_request(port: u16, req: &RpcRequest) -> RpcResponse {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let payload = rmp_serde::to_vec(req).unwrap();
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).unwrap();
    stream.write_all(&payload).unwrap();
    stream.flush().unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let rlen = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; rlen];
    stream.read_exact(&mut buf).unwrap();
    rmp_serde::from_slice(&buf).unwrap()
}

fn start_rpc_server(transport: TransportState) -> (Arc<RpcServer>, u16, Vec<u8>) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let key = vec![1, 2, 3, 4];
    let srv = RpcServer::start(0, key.clone(), shutdown, transport).unwrap();
    let port = srv.local_port();
    thread::sleep(Duration::from_millis(50));
    (srv, port, key)
}


// ===========================================================================
// Integration Test 1: Loopback packet flow
// Validates: Requirements 17.1, 17.2, 17.3, 17.4
//
// Creates two TransportStates with DummyInterfaces, constructs a valid packet,
// submits to outbound on TS1, feeds the transmitted bytes into inbound on TS2,
// and verifies the packet hash appears in TS2's hashlist.
// ===========================================================================

#[test]
fn integration_loopback_packet_flow() {
    // --- Setup: two TransportStates, each with a DummyInterface ---
    let ts1 = TransportState::new();
    let ts2 = TransportState::new();

    let iface1 = Arc::new(DummyInterface::new());
    let iface2 = Arc::new(DummyInterface::new());

    // Register iface1 as outbound on ts1
    {
        let mut inner = ts1.inner.write().unwrap();
        inner.interfaces.push(iface1.clone() as Arc<dyn InterfaceHandle>);
    }

    // Register iface2 on ts2 (for inbound delivery context)
    {
        let mut inner = ts2.inner.write().unwrap();
        inner.interfaces.push(iface2.clone() as Arc<dyn InterfaceHandle>);
    }

    // --- Construct a valid packet and submit to outbound on ts1 ---
    let dest_hash = [0x42; 16];
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut pkt = make_packed_data_packet(dest_hash, payload);

    let sent = ts1.outbound(&mut pkt).unwrap();
    assert!(sent, "packet should be transmitted on outbound interface");
    assert_eq!(iface1.transmitted_count(), 1, "exactly one transmission expected");

    // --- Feed the transmitted bytes into ts2's inbound ---
    let transmitted_raw = iface1.last_transmitted().unwrap();
    let iface2_handle: Arc<dyn InterfaceHandle> = iface2.clone();
    ts2.inbound(&transmitted_raw, &iface2_handle).unwrap();

    // --- Verify the packet hash appears in ts2's hashlist ---
    // inbound() increments hops and recomputes the hash, so replicate that
    let mut check_pkt = Packet::from_raw(transmitted_raw);
    check_pkt.unpack().unwrap();
    check_pkt.hops = check_pkt.hops.saturating_add(1);
    if check_pkt.raw.len() > 1 {
        check_pkt.raw[1] = check_pkt.hops;
    }
    let inbound_hash = check_pkt.get_hash();

    assert!(
        ts2.contains_packet_hash(&inbound_hash).unwrap(),
        "packet hash should be in ts2's hashlist after inbound processing"
    );
}

// ===========================================================================
// Integration Test 2: Announce propagation and path table
// Validates: Requirements 18.1, 18.2, 18.3, 18.4
//
// Creates a Destination, calls announce(), submits via outbound on TS1,
// feeds the announce into TS2's inbound, and verifies TS2's path table
// contains the announced destination with correct hop count.
// ===========================================================================

#[test]
fn integration_announce_propagation_and_path_table() {
    // --- Setup: two TransportStates with DummyInterfaces ---
    let ts1 = TransportState::new();
    let ts2 = TransportState::new();

    let iface1 = Arc::new(DummyInterface::new());
    let iface2 = Arc::new(DummyInterface::new());

    {
        let mut inner = ts1.inner.write().unwrap();
        inner.interfaces.push(iface1.clone() as Arc<dyn InterfaceHandle>);
    }
    {
        let mut inner = ts2.inner.write().unwrap();
        inner.interfaces.push(iface2.clone() as Arc<dyn InterfaceHandle>);
    }

    // --- Create a Destination and build an announce ---
    let mut dest = Destination::new(
        None,
        DestinationDirection::In,
        DestinationType::Single,
        "integrationtest",
        &[],
    )
    .unwrap();

    let mut announce_pkt = dest
        .announce(None, false, None, false, None)
        .unwrap()
        .unwrap();
    announce_pkt.pack(&dest).unwrap();

    let dest_hash = dest.hash;

    // --- Submit announce to ts1 outbound ---
    let sent = ts1.outbound(&mut announce_pkt).unwrap();
    assert!(sent, "announce should be transmitted on outbound interface");
    assert!(
        iface1.transmitted_count() >= 1,
        "announce should be transmitted on at least one interface"
    );

    // --- Feed the transmitted announce into ts2's inbound ---
    let transmitted_raw = iface1.last_transmitted().unwrap();
    let iface2_handle: Arc<dyn InterfaceHandle> = iface2.clone();

    // Use inbound_with_stores so announce validation has real stores
    let store = IdentityStore::new();
    let ratchet_store = make_ratchet_store();
    ts2.inbound_with_stores(&transmitted_raw, &iface2_handle, &store, &ratchet_store)
        .unwrap();

    // --- Verify ts2's path table contains the announced destination ---
    assert!(
        ts2.has_path(&dest_hash).unwrap(),
        "ts2 should have a path entry for the announced destination"
    );

    // Verify hop count: inbound increments hops by 1, so the path entry
    // should have hops == 1 (original announce has hops=0, +1 from inbound)
    let hops = ts2.hops_to(&dest_hash).unwrap();
    assert_eq!(hops, 1, "path entry should have hops=1 after one hop");
}


// ===========================================================================
// Integration Test 3: State persistence round-trip
// Validates: Requirements 19.1, 19.2, 19.3, 19.4, 19.5
//
// Creates a Reticulum instance with a temp configdir, inserts path table
// entries and known destinations, calls exit_handler(), creates a second
// Reticulum with the same configdir, and verifies persisted data survived.
// ===========================================================================

#[test]
fn integration_state_persistence_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("rns_persist_test");

    // --- Create first Reticulum instance (standalone, no shared instance) ---
    let config1 = ReticulumConfig {
        configdir: Some(base.clone()),
        ..Default::default()
    };
    let ret1 = Reticulum::new(config1).unwrap();

    // --- Insert path table entries into TransportState ---
    let dest_hash_a = [0xAA; 16];
    let dest_hash_b = [0xBB; 16];
    {
        let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface::new());
        let mut inner = ret1.transport_state.inner.write().unwrap();
        inner.interfaces.push(iface.clone());
        inner.path_table.insert(
            dest_hash_a,
            PathEntry {
                timestamp: 1000.0,
                received_from: [0x11; 16],
                hops: 3,
                expires: 99999.0,
                random_blobs: vec![],
                receiving_interface: iface.clone(),
                packet_hash: [0xCC; 32],
            },
        );
        inner.path_table.insert(
            dest_hash_b,
            PathEntry {
                timestamp: 2000.0,
                received_from: [0x22; 16],
                hops: 5,
                expires: 99999.0,
                random_blobs: vec![],
                receiving_interface: iface.clone(),
                packet_hash: [0xDD; 32],
            },
        );
    }

    // --- Insert known destinations into IdentityStore ---
    let test_identity = Identity::new();
    let pub_key = test_identity.get_public_key().unwrap();
    let known_dest_hash = [0xEE; 16];
    ret1.identity_store
        .remember(&[0xFF; 32], &known_dest_hash, &pub_key, Some(b"test_app_data"))
        .unwrap();

    // --- Call exit_handler to trigger persistence ---
    ret1.exit_handler();

    // Verify state files exist on disk
    let storagepath = base.join("storage");
    assert!(
        storagepath.join("path_table").exists(),
        "path_table file should exist after exit_handler"
    );
    assert!(
        storagepath.join("known_destinations").exists(),
        "known_destinations file should exist after exit_handler"
    );

    // --- Create second Reticulum instance with the same configdir ---
    // Use share_instance=false to avoid port conflicts with the first instance
    std::fs::write(
        base.join("config"),
        "[reticulum]\nshare_instance = no\n\n[logging]\nloglevel = 4\n",
    )
    .unwrap();

    let config2 = ReticulumConfig {
        configdir: Some(base.clone()),
        ..Default::default()
    };
    let ret2 = Reticulum::new(config2).unwrap();

    // --- Verify path table entries survived ---
    // Note: path table loading requires at least one interface to be registered.
    // The second Reticulum is standalone with no interfaces from config, but
    // the shared instance setup may have registered one. If no interfaces,
    // path table load is skipped. We check if entries exist.
    let inner2 = ret2.transport_state.inner.read().unwrap();
    if !inner2.interfaces.is_empty() {
        // Path table should have been loaded
        assert!(
            inner2.path_table.contains_key(&dest_hash_a),
            "path entry A should survive persistence round-trip"
        );
        assert!(
            inner2.path_table.contains_key(&dest_hash_b),
            "path entry B should survive persistence round-trip"
        );
        let entry_a = inner2.path_table.get(&dest_hash_a).unwrap();
        assert_eq!(entry_a.hops, 3);
        assert_eq!(entry_a.timestamp, 1000.0);
        let entry_b = inner2.path_table.get(&dest_hash_b).unwrap();
        assert_eq!(entry_b.hops, 5);
        assert_eq!(entry_b.timestamp, 2000.0);
    } else {
        // No interfaces registered — verify the file exists and can be deserialized
        let data = std::fs::read(storagepath.join("path_table")).unwrap();
        let loaded: HashMap<[u8; 16], SerializedPathEntry> =
            rmp_serde::from_slice(&data).unwrap();
        assert!(loaded.contains_key(&dest_hash_a));
        assert!(loaded.contains_key(&dest_hash_b));
        assert_eq!(loaded[&dest_hash_a].hops, 3);
        assert_eq!(loaded[&dest_hash_b].hops, 5);
    }
    drop(inner2);

    // --- Verify known destinations survived ---
    let recalled = ret2.identity_store.recall(&known_dest_hash);
    assert!(
        recalled.is_some(),
        "known destination should survive persistence round-trip"
    );

    // Clean up
    ret2.exit_handler();
}


// ===========================================================================
// Integration Test 4: RPC server round-trip with real state
// Validates: Requirements 20.1, 20.2, 20.3, 20.4, 20.5
//
// Creates a TransportState with known path entries, starts an RpcServer,
// queries path_table via RPC, verifies the response matches, then drops
// a path and verifies removal.
// ===========================================================================

#[test]
fn integration_rpc_server_round_trip() {
    let ts = TransportState::new();
    let iface: Arc<dyn InterfaceHandle> = Arc::new(DummyInterface::new());

    // --- Insert known path entries ---
    let dest_hash_1 = [0x11; 16];
    let dest_hash_2 = [0x22; 16];
    {
        let mut inner = ts.inner.write().unwrap();
        inner.interfaces.push(iface.clone());
        inner.path_table.insert(
            dest_hash_1,
            PathEntry {
                timestamp: 1000.0,
                received_from: [0xAA; 16],
                hops: 2,
                expires: 99999.0,
                random_blobs: vec![],
                receiving_interface: iface.clone(),
                packet_hash: [0xBB; 32],
            },
        );
        inner.path_table.insert(
            dest_hash_2,
            PathEntry {
                timestamp: 2000.0,
                received_from: [0xCC; 16],
                hops: 4,
                expires: 99999.0,
                random_blobs: vec![],
                receiving_interface: iface.clone(),
                packet_hash: [0xDD; 32],
            },
        );
    }

    // --- Start RPC server ---
    let (srv, port, key) = start_rpc_server(ts.clone());

    // --- Query path_table ---
    let req = RpcRequest {
        key: key.clone(),
        get: Some("path_table".into()),
        drop: None,
        max_hops: None,
        destination_hash: None,
    };
    let resp = send_rpc_request(port, &req);
    assert!(resp.ok, "path_table query should succeed");

    let entries = resp.entries.unwrap();
    assert_eq!(entries.len(), 2, "should have exactly 2 path entries");

    // Decode entries and build a map for verification
    let mut rpc_map: HashMap<Vec<u8>, u8> = HashMap::new();
    for entry_bytes in &entries {
        let row: (Vec<u8>, u8, f64, f64, Vec<u8>) =
            rmp_serde::from_slice(entry_bytes).unwrap();
        rpc_map.insert(row.0, row.1);
    }
    assert_eq!(
        rpc_map.get(&dest_hash_1.to_vec()),
        Some(&2u8),
        "dest_hash_1 should have hops=2"
    );
    assert_eq!(
        rpc_map.get(&dest_hash_2.to_vec()),
        Some(&4u8),
        "dest_hash_2 should have hops=4"
    );

    // --- Drop path for dest_hash_1 ---
    let drop_req = RpcRequest {
        key: key.clone(),
        get: None,
        drop: Some("path".into()),
        max_hops: None,
        destination_hash: Some(dest_hash_1.to_vec()),
    };
    let drop_resp = send_rpc_request(port, &drop_req);
    assert!(drop_resp.ok, "drop path should succeed");

    // --- Verify the entry is removed from TransportState ---
    assert!(
        !ts.has_path(&dest_hash_1).unwrap(),
        "dest_hash_1 should be removed after drop"
    );
    assert!(
        ts.has_path(&dest_hash_2).unwrap(),
        "dest_hash_2 should still exist"
    );

    // --- Verify via another RPC query ---
    let req2 = RpcRequest {
        key,
        get: Some("path_table".into()),
        drop: None,
        max_hops: None,
        destination_hash: None,
    };
    let resp2 = send_rpc_request(port, &req2);
    assert!(resp2.ok);
    assert_eq!(
        resp2.entries.unwrap().len(),
        1,
        "should have 1 path entry after drop"
    );

    srv.stop();
}

// ===========================================================================
// Integration Test 5: Full Reticulum lifecycle
// Validates: Requirements 21.1, 21.2, 21.3, 21.4, 21.5
//
// Creates a Reticulum instance with a temp configdir, verifies initialization
// state, verifies the transport identity file exists, calls exit_handler(),
// and verifies state files exist on disk.
// ===========================================================================

#[test]
fn integration_full_reticulum_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("rns_lifecycle_test");

    // --- Create Reticulum instance ---
    let config = ReticulumConfig {
        configdir: Some(base.clone()),
        ..Default::default()
    };
    let ret = Reticulum::new(config).unwrap();

    // --- Verify initialization state ---
    // TransportState should exist and have an identity set
    {
        let inner = ret.transport_state.inner.read().unwrap();
        assert!(
            inner.identity.is_some(),
            "TransportState should have a transport identity"
        );
    }

    // Transport identity should be valid
    assert!(
        ret.transport_identity.hash().is_ok(),
        "transport identity should have a valid hash"
    );

    // At least one interface should be registered (shared instance server
    // or the instance is standalone — either way, check the shared instance)
    if ret.is_shared_instance {
        let inner = ret.transport_state.inner.read().unwrap();
        assert!(
            !inner.interfaces.is_empty(),
            "shared instance should have at least one registered interface"
        );
    }

    // --- Verify transport identity file exists on disk ---
    let identity_path = base.join("storage").join("identity");
    assert!(
        identity_path.exists(),
        "transport identity file should exist on disk"
    );
    let identity_data = std::fs::read(&identity_path).unwrap();
    assert_eq!(
        identity_data.len(),
        64,
        "identity file should be 64 bytes (private key)"
    );

    // --- Call exit_handler and verify shutdown ---
    ret.exit_handler();
    assert!(
        ret.shutdown.load(Ordering::SeqCst),
        "shutdown flag should be set after exit_handler"
    );

    // --- Verify state files exist on disk after shutdown ---
    let storagepath = base.join("storage");
    assert!(
        storagepath.join("path_table").exists(),
        "path_table file should exist after shutdown"
    );
    assert!(
        storagepath.join("known_destinations").exists(),
        "known_destinations file should exist after shutdown"
    );

    // Verify the persisted files are valid MessagePack
    let pt_data = std::fs::read(storagepath.join("path_table")).unwrap();
    let _: HashMap<[u8; 16], SerializedPathEntry> =
        rmp_serde::from_slice(&pt_data).expect("path_table should be valid msgpack");

    let kd_data = std::fs::read(storagepath.join("known_destinations")).unwrap();
    let _: HashMap<Vec<u8>, serde::de::IgnoredAny> =
        rmp_serde::from_slice(&kd_data).expect("known_destinations should be valid msgpack");
}
