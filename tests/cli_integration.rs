//! Integration tests for CLI utilities.
//!
//! Tests that require a running rnsd instance are marked `#[ignore]`.
//! Run with: `cargo test --test cli_integration -- --test-threads=1`

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_pickle::value::Value;

use ferret_rns::reticulum::rpc::RpcServer;
use ferret_rns::rpc_client::RpcClient;
use ferret_rns::transport::TransportState;

/// Helper: start a test RPC server and return (server, port, key).
fn start_test_server() -> (Arc<RpcServer>, u16, Vec<u8>) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let key = vec![10, 20, 30, 40];
    let transport = TransportState::new();
    let srv = RpcServer::start(0, key.clone(), shutdown, transport)
        .expect("start server");
    let port = srv.local_port();
    thread::sleep(Duration::from_millis(50));
    (srv, port, key)
}

// =========================================================================
// Test: RPC client connect + authenticate + query interface_stats
// =========================================================================

#[test]
fn test_rpc_connect_and_query_interface_stats() {
    let (srv, port, key) = start_test_server();

    let mut client = RpcClient::connect(port, &key)
        .expect("connect and auth");

    let stats = client.get("interface_stats")
        .expect("query interface_stats");

    match stats {
        Value::Dict(d) => {
            assert!(d.contains_key(
                &serde_pickle::value::HashableValue::String("interfaces".into())
            ));
        }
        other => panic!("expected Dict, got {:?}", other),
    }

    srv.stop();
}

// =========================================================================
// Test: RPC client query link_count
// =========================================================================

#[test]
fn test_rpc_query_link_count() {
    let (srv, port, key) = start_test_server();

    let mut client = RpcClient::connect(port, &key)
        .expect("connect and auth");

    let count = client.get("link_count")
        .expect("query link_count");

    match count {
        Value::I64(n) => assert_eq!(n, 0),
        other => panic!("expected I64, got {:?}", other),
    }

    srv.stop();
}

// =========================================================================
// Test: RPC client query path_table (empty)
// =========================================================================

#[test]
fn test_rpc_query_path_table_empty() {
    let (srv, port, key) = start_test_server();

    let mut client = RpcClient::connect(port, &key)
        .expect("connect and auth");

    let table = client.get_with("path_table", &[("max_hops", Value::None)])
        .expect("query path_table");

    match table {
        Value::List(entries) => assert!(entries.is_empty()),
        other => panic!("expected List, got {:?}", other),
    }

    srv.stop();
}

// =========================================================================
// Test: RPC client drop announce_queues
// =========================================================================

#[test]
fn test_rpc_drop_announce_queues() {
    let (srv, port, key) = start_test_server();

    let mut client = RpcClient::connect(port, &key)
        .expect("connect and auth");

    let result = client.drop_cmd("announce_queues")
        .expect("drop announce_queues");

    match result {
        Value::Bool(true) => {}
        other => panic!("expected Bool(true), got {:?}", other),
    }

    srv.stop();
}

// =========================================================================
// Test: RPC client auth failure
// =========================================================================

#[test]
fn test_rpc_auth_failure_returns_error() {
    let (srv, port, _key) = start_test_server();

    let result = RpcClient::connect(port, &[99, 99, 99]);
    assert!(result.is_err(), "wrong key should fail auth");

    srv.stop();
}

// =========================================================================
// Tests requiring a running rnsd instance (ignored by default)
// =========================================================================

#[test]
#[ignore]
fn test_rnstatus_against_live_instance() {
    // This test requires a running rnsd instance on the default port.
    // Run with: cargo test --test cli_integration test_rnstatus_against_live_instance -- --ignored
    let storage_path = {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(home).join(".reticulum").join("storage")
    };

    let rpc_key = ferret_rns::rpc_client::derive_rpc_key(&storage_path)
        .expect("derive RPC key");

    let mut client = RpcClient::connect(37429, &rpc_key)
        .expect("connect to live instance");

    let stats = client.get("interface_stats")
        .expect("query interface_stats");

    match stats {
        Value::Dict(_) => println!("Successfully queried live instance"),
        other => panic!("unexpected response: {:?}", other),
    }
}
