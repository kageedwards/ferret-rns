//! Local RPC server for shared-instance queries.
//!
//! Speaks the Python `multiprocessing.connection` wire protocol so that
//! Python RNS clients (NomadNet, rnstatus, etc.) can connect directly.
//!
//! ## Wire protocol
//!
//! **Framing:** 4-byte big-endian *signed* i32 length prefix + payload.
//!
//! **Authentication (HMAC-SHA256 challenge-response):**
//! 1. Server sends `b"#CHALLENGE#" + b"{sha256}" + 40_random_bytes`
//! 2. Client responds with `b"{sha256}" + HMAC-SHA256(authkey, b"{sha256}" + random)`
//! 3. Server verifies and sends `b"#WELCOME#"` or `b"#FAILURE#"`
//!
//! **Commands:** pickle-serialized dicts, e.g. `{"get": "interface_stats"}`.
//! Responses are pickle-serialized values matching the Python reference.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_pickle::value::{HashableValue, Value};

use crate::crypto::hmac::hmac_sha256;
use crate::error::Result;
use crate::transport::TransportState;
use crate::{log_debug, log_verbose, log_warning};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
const DIGEST_PREFIX: &[u8] = b"{sha256}";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";
const CHALLENGE_RANDOM_LEN: usize = 40;
const MAX_FRAME_LEN: i32 = 1_048_576; // 1 MiB

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Send a length-prefixed frame (Python `_send_bytes`).
fn send_bytes(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as i32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

/// Receive a length-prefixed frame (Python `_recv_bytes`).
fn recv_bytes(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = i32::from_be_bytes(len_buf);
    if len < 0 || len > MAX_FRAME_LEN {
        return Err(crate::error::FerretError::Deserialization(
            format!("RPC frame length out of range: {len}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Pickle helpers
// ---------------------------------------------------------------------------

fn pickle_none() -> Value {
    Value::None
}

fn pickle_bool(v: bool) -> Value {
    Value::Bool(v)
}

fn pickle_i64(v: i64) -> Value {
    Value::I64(v)
}

fn pickle_f64(v: f64) -> Value {
    Value::F64(v)
}

fn pickle_string(s: &str) -> Value {
    Value::String(s.to_string())
}

fn pickle_bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn pickle_list(items: Vec<Value>) -> Value {
    Value::List(items)
}

fn pickle_dict(entries: Vec<(&str, Value)>) -> Value {
    let mut map = BTreeMap::new();
    for (k, v) in entries {
        map.insert(HashableValue::String(k.to_string()), v);
    }
    Value::Dict(map)
}

/// Serialize a `Value` to pickle bytes (protocol 2).
fn to_pickle(val: &Value) -> Result<Vec<u8>> {
    serde_pickle::value_to_vec(val, serde_pickle::SerOptions::new())
        .map_err(|e| crate::error::FerretError::Serialization(format!("pickle encode: {e}")))
}

/// Deserialize pickle bytes into a `Value`.
fn from_pickle(data: &[u8]) -> Result<Value> {
    serde_pickle::value_from_slice(data, serde_pickle::DeOptions::new())
        .map_err(|e| crate::error::FerretError::Deserialization(format!("pickle decode: {e}")))
}

/// Extract a string value from a pickle dict by key.
fn dict_get_str(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<String> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
}

/// Extract bytes from a pickle dict by key.
fn dict_get_bytes(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<Vec<u8>> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        })
}

/// Extract an optional u8 from a pickle dict by key (for max_hops).
fn dict_get_opt_u8(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<u8> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::I64(n) => {
                let n = *n;
                if n >= 0 && n <= 255 { Some(n as u8) } else { None }
            }
            Value::None => None,
            _ => None,
        })
}

// ---------------------------------------------------------------------------
// RpcServer
// ---------------------------------------------------------------------------

pub struct RpcServer {
    listener: Option<TcpListener>,
    rpc_key: Vec<u8>,
    shutdown: Arc<AtomicBool>,
    transport: TransportState,
}

impl RpcServer {
    /// Start the RPC server on `127.0.0.1:port`.
    ///
    /// Spawns a background thread that accepts connections, authenticates
    /// them via the Python `multiprocessing.connection` HMAC challenge-
    /// response, and dispatches pickle-encoded commands.
    pub fn start(
        port: u16,
        rpc_key: Vec<u8>,
        shutdown: Arc<AtomicBool>,
        transport: TransportState,
    ) -> Result<Arc<Self>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        listener.set_nonblocking(true)?;

        let server = Arc::new(Self {
            listener: Some(listener),
            rpc_key,
            shutdown,
            transport,
        });

        let srv = Arc::clone(&server);
        thread::Builder::new()
            .name("rpc-server".into())
            .spawn(move || srv.accept_loop())?;

        Ok(server)
    }

    /// Signal the server to stop accepting connections.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Return the local port the server is listening on.
    pub fn local_port(&self) -> u16 {
        self.listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Internal — accept loop
    // -----------------------------------------------------------------------

    fn accept_loop(&self) {
        let listener = match self.listener.as_ref() {
            Some(l) => l,
            None => return,
        };

        while !self.shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    log_verbose!("RPC client connected from {}", addr);
                    if let Err(e) = self.handle_connection(stream) {
                        log_debug!("RPC connection error: {e}");
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    log_warning!("RPC accept error: {e}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Connection handler
    // -----------------------------------------------------------------------

    fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;

        // --- HMAC challenge-response authentication ---
        if !self.deliver_challenge(&mut stream)? {
            return Ok(());
        }

        // --- Read command, dispatch, respond ---
        let request_bytes = recv_bytes(&mut stream)?;
        let request_val = from_pickle(&request_bytes)?;

        let response_val = self.dispatch(&request_val);
        let response_bytes = to_pickle(&response_val)?;
        send_bytes(&mut stream, &response_bytes)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // HMAC challenge-response (Python multiprocessing.connection protocol)
    // -----------------------------------------------------------------------

    /// Perform the server side of the HMAC-SHA256 challenge-response.
    /// Returns `true` if the client authenticated successfully.
    fn deliver_challenge(&self, stream: &mut TcpStream) -> Result<bool> {
        // 1. Generate 40 random bytes
        let mut random_bytes = [0u8; CHALLENGE_RANDOM_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_bytes);

        // 2. Send: #CHALLENGE# + {sha256} + random_40_bytes
        let mut challenge_msg =
            Vec::with_capacity(CHALLENGE_PREFIX.len() + DIGEST_PREFIX.len() + CHALLENGE_RANDOM_LEN);
        challenge_msg.extend_from_slice(CHALLENGE_PREFIX);
        challenge_msg.extend_from_slice(DIGEST_PREFIX);
        challenge_msg.extend_from_slice(&random_bytes);
        send_bytes(stream, &challenge_msg)?;

        // 3. Read client response
        let response = recv_bytes(stream)?;

        // 4. Verify: response should be {sha256} + HMAC(key, {sha256} + random)
        if response.len() < DIGEST_PREFIX.len() {
            send_bytes(stream, FAILURE)?;
            return Ok(false);
        }

        let (prefix, client_mac) = response.split_at(DIGEST_PREFIX.len());
        if prefix != DIGEST_PREFIX || client_mac.len() != 32 {
            send_bytes(stream, FAILURE)?;
            return Ok(false);
        }

        // Compute expected MAC: HMAC-SHA256(authkey, {sha256} + random_bytes)
        let mut hmac_message = Vec::with_capacity(DIGEST_PREFIX.len() + CHALLENGE_RANDOM_LEN);
        hmac_message.extend_from_slice(DIGEST_PREFIX);
        hmac_message.extend_from_slice(&random_bytes);
        let expected_mac = hmac_sha256(&self.rpc_key, &hmac_message);

        // Constant-time comparison
        if !constant_time_eq(client_mac, &expected_mac) {
            send_bytes(stream, FAILURE)?;
            return Ok(false);
        }

        send_bytes(stream, WELCOME)?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Command dispatch
    // -----------------------------------------------------------------------

    fn dispatch(&self, val: &Value) -> Value {
        let dict = match val {
            Value::Dict(d) => d,
            _ => return pickle_none(),
        };

        if let Some(cmd) = dict_get_str(dict, "get") {
            return self.dispatch_get(&cmd, dict);
        }

        if let Some(cmd) = dict_get_str(dict, "drop") {
            return self.dispatch_drop(&cmd, dict);
        }

        pickle_none()
    }

    fn dispatch_get(
        &self,
        cmd: &str,
        dict: &BTreeMap<HashableValue, Value>,
    ) -> Value {
        match cmd {
            "path_table" => self.get_path_table(dict),
            "interface_stats" => self.get_interface_stats(),
            "rate_table" => self.get_rate_table(),
            "link_count" => self.get_link_count(),
            "next_hop_if_name" => {
                let dh = dict_get_bytes(dict, "destination_hash");
                self.get_next_hop_if_name(dh.as_deref())
            }
            "next_hop" => {
                let dh = dict_get_bytes(dict, "destination_hash");
                self.get_next_hop(dh.as_deref())
            }
            "first_hop_timeout" => {
                let dh = dict_get_bytes(dict, "destination_hash");
                self.get_first_hop_timeout(dh.as_deref())
            }
            "packet_rssi" | "packet_snr" | "packet_q" => {
                // Not yet tracked in ferret — return None
                pickle_none()
            }
            "blackholed_identities" => pickle_list(vec![]),
            _ => pickle_none(),
        }
    }

    fn dispatch_drop(
        &self,
        cmd: &str,
        dict: &BTreeMap<HashableValue, Value>,
    ) -> Value {
        match cmd {
            "path" => {
                let dh = dict_get_bytes(dict, "destination_hash");
                self.drop_path(dh.as_deref())
            }
            "announce_queues" => self.drop_announce_queues(),
            "all_via" => {
                let dh = dict_get_bytes(dict, "destination_hash");
                self.drop_all_via(dh.as_deref())
            }
            _ => pickle_none(),
        }
    }

    // -----------------------------------------------------------------------
    // Command implementations
    // -----------------------------------------------------------------------

    /// Returns a dict matching the Python `get_interface_stats()` format:
    /// `{"interfaces": [...], "rxb": int, "txb": int, ...}`
    fn get_interface_stats(&self) -> Value {
        let inner = match self.transport.read() {
            Ok(g) => g,
            Err(_) => return pickle_none(),
        };

        let mut iface_list = Vec::new();
        for iface in &inner.interfaces {
            let ifstats = pickle_dict(vec![
                ("name", pickle_string(iface.name())),
                ("short_name", pickle_string(iface.name())),
                ("hash", pickle_bytes(iface.interface_hash())),
                ("type", pickle_string("Interface")),
                ("rxb", pickle_i64(iface.rxb() as i64)),
                ("txb", pickle_i64(iface.txb() as i64)),
                ("status", pickle_bool(iface.is_online())),
                ("mode", pickle_i64(iface.mode() as i64)),
                ("bitrate", pickle_none()),
                ("clients", pickle_none()),
                ("ifac_signature", pickle_none()),
                ("ifac_size", pickle_none()),
                ("ifac_netname", pickle_none()),
                ("announce_queue", pickle_none()),
                ("held_announces", pickle_i64(0)),
                ("incoming_announce_frequency", pickle_f64(0.0)),
                ("outgoing_announce_frequency", pickle_f64(0.0)),
                ("rxs", pickle_i64(0)),
                ("txs", pickle_i64(0)),
                ("autoconnect_source", pickle_none()),
            ]);
            iface_list.push(ifstats);
        }

        pickle_dict(vec![
            ("interfaces", pickle_list(iface_list)),
            ("rxb", pickle_i64(0)),
            ("txb", pickle_i64(0)),
            ("rxs", pickle_i64(0)),
            ("txs", pickle_i64(0)),
        ])
    }

    /// Returns a list of path entry dicts matching the Python format.
    fn get_path_table(
        &self,
        dict: &BTreeMap<HashableValue, Value>,
    ) -> Value {
        let max_hops = dict_get_opt_u8(dict, "max_hops");

        let inner = match self.transport.read() {
            Ok(g) => g,
            Err(_) => return pickle_list(vec![]),
        };

        let mut entries = Vec::new();
        for (dest_hash, entry) in &inner.path_table {
            if let Some(mh) = max_hops {
                if entry.hops > mh {
                    continue;
                }
            }
            let iface_name = entry.receiving_interface.name().to_string();
            let row = pickle_dict(vec![
                ("hash", pickle_bytes(dest_hash)),
                ("timestamp", pickle_f64(entry.timestamp)),
                ("via", pickle_bytes(&entry.received_from)),
                ("hops", pickle_i64(entry.hops as i64)),
                ("expires", pickle_f64(entry.expires)),
                ("interface", pickle_string(&iface_name)),
            ]);
            entries.push(row);
        }

        pickle_list(entries)
    }

    /// Returns a list of rate entry dicts matching the Python format.
    fn get_rate_table(&self) -> Value {
        let inner = match self.transport.read() {
            Ok(g) => g,
            Err(_) => return pickle_list(vec![]),
        };

        let mut entries = Vec::new();
        for (dest_hash, timestamps) in &inner.announce_rate_table {
            let ts_vals: Vec<Value> = timestamps.iter().map(|t| pickle_f64(*t)).collect();
            let row = pickle_dict(vec![
                ("hash", pickle_bytes(dest_hash)),
                ("last", if timestamps.is_empty() {
                    pickle_f64(0.0)
                } else {
                    pickle_f64(*timestamps.last().unwrap_or(&0.0))
                }),
                ("rate_violations", pickle_i64(0)),
                ("blocked_until", pickle_f64(0.0)),
                ("timestamps", pickle_list(ts_vals)),
            ]);
            entries.push(row);
        }

        pickle_list(entries)
    }

    /// Returns the number of active links (integer).
    fn get_link_count(&self) -> Value {
        let inner = match self.transport.read() {
            Ok(g) => g,
            Err(_) => return pickle_i64(0),
        };
        pickle_i64(inner.link_table.len() as i64)
    }

    /// Returns the interface name for the next hop, or None.
    fn get_next_hop_if_name(&self, dest_hash: Option<&[u8]>) -> Value {
        let dh = match dest_hash_16(dest_hash) {
            Some(h) => h,
            None => return pickle_none(),
        };
        let inner = match self.transport.read() {
            Ok(g) => g,
            Err(_) => return pickle_none(),
        };
        match inner.path_table.get(&dh) {
            Some(entry) => pickle_string(entry.receiving_interface.name()),
            None => pickle_none(),
        }
    }

    /// Returns the next hop bytes, or None.
    fn get_next_hop(&self, dest_hash: Option<&[u8]>) -> Value {
        let dh = match dest_hash_16(dest_hash) {
            Some(h) => h,
            None => return pickle_none(),
        };
        match self.transport.next_hop(&dh) {
            Ok(Some(nh)) => pickle_bytes(&nh),
            _ => pickle_none(),
        }
    }

    /// Returns the first hop timeout as a float, or the default.
    fn get_first_hop_timeout(&self, dest_hash: Option<&[u8]>) -> Value {
        let dh = match dest_hash_16(dest_hash) {
            Some(h) => h,
            None => return pickle_f64(6.0), // DEFAULT_PER_HOP_TIMEOUT
        };
        let inner = match self.transport.read() {
            Ok(g) => g,
            Err(_) => return pickle_f64(6.0),
        };
        match inner.path_table.get(&dh) {
            Some(entry) => {
                let hops = entry.hops as f64;
                pickle_f64(hops * 6.0)
            }
            None => pickle_f64(6.0),
        }
    }

    /// Drop a path entry. Returns True on success, None if not found.
    fn drop_path(&self, dest_hash: Option<&[u8]>) -> Value {
        let dh = match dest_hash_16(dest_hash) {
            Some(h) => h,
            None => return pickle_none(),
        };
        match self.transport.expire_path(&dh) {
            Ok(()) => pickle_bool(true),
            Err(_) => pickle_none(),
        }
    }

    /// Drop all paths via a given transport hash. Returns count dropped.
    fn drop_all_via(&self, transport_hash: Option<&[u8]>) -> Value {
        let th = match dest_hash_16(transport_hash) {
            Some(h) => h,
            None => return pickle_i64(0),
        };
        let mut inner = match self.transport.write() {
            Ok(g) => g,
            Err(_) => return pickle_i64(0),
        };
        let before = inner.path_table.len();
        inner.path_table.retain(|_, entry| entry.received_from != th);
        let dropped = before - inner.path_table.len();
        pickle_i64(dropped as i64)
    }

    /// Drop announce queues. Returns True.
    fn drop_announce_queues(&self) -> Value {
        match self.transport.write() {
            Ok(mut inner) => {
                inner.announce_table.clear();
                pickle_bool(true)
            }
            Err(_) => pickle_none(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an optional byte slice to a `[u8; 16]` destination hash.
fn dest_hash_16(bytes: Option<&[u8]>) -> Option<[u8; 16]> {
    bytes.and_then(|b| {
        if b.len() == 16 {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(b);
            Some(arr)
        } else {
            None
        }
    })
}

/// Constant-time byte comparison to prevent timing attacks on HMAC.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportState;
    use std::net::TcpStream;

    /// Perform the client side of the HMAC challenge-response handshake.
    fn client_authenticate(stream: &mut TcpStream, authkey: &[u8]) -> bool {
        // 1. Receive challenge
        let challenge = recv_bytes(stream).expect("recv challenge");

        // Verify it starts with #CHALLENGE#
        assert!(challenge.starts_with(CHALLENGE_PREFIX));

        // Extract the message part after #CHALLENGE# (= {sha256} + random)
        let message = &challenge[CHALLENGE_PREFIX.len()..];

        // 2. Compute HMAC and send response: {sha256} + HMAC(key, message)
        let mac = hmac_sha256(authkey, message);
        let mut response = Vec::with_capacity(DIGEST_PREFIX.len() + 32);
        response.extend_from_slice(DIGEST_PREFIX);
        response.extend_from_slice(&mac);
        send_bytes(stream, &response).expect("send auth response");

        // 3. Read welcome/failure
        let result = recv_bytes(stream).expect("recv auth result");
        result == WELCOME
    }

    /// Send a pickle command and receive a pickle response.
    fn rpc_call(stream: &mut TcpStream, command: &Value) -> Value {
        let payload = to_pickle(command).expect("pickle encode");
        send_bytes(stream, &payload).expect("send command");
        let response_bytes = recv_bytes(stream).expect("recv response");
        from_pickle(&response_bytes).expect("pickle decode")
    }

    fn start_server() -> (Arc<RpcServer>, u16, Vec<u8>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let key = vec![1, 2, 3, 4];
        let transport = TransportState::new();
        let srv = RpcServer::start(0, key.clone(), shutdown, transport)
            .expect("start server");
        let port = srv.local_port();
        // Give the accept loop a moment to start.
        thread::sleep(Duration::from_millis(50));
        (srv, port, key)
    }

    fn connect_and_auth(port: u16, key: &[u8]) -> TcpStream {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        assert!(client_authenticate(&mut stream, key), "auth should succeed");
        stream
    }

    #[test]
    fn test_rpc_auth_failure() {
        let (srv, port, _key) = start_server();
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");

        // Use wrong key
        let ok = client_authenticate(&mut stream, &[9, 9, 9]);
        assert!(!ok, "auth with wrong key should fail");
        srv.stop();
    }

    #[test]
    fn test_rpc_auth_success() {
        let (srv, port, key) = start_server();
        let _stream = connect_and_auth(port, &key);
        srv.stop();
    }

    #[test]
    fn test_rpc_get_link_count() {
        let (srv, port, key) = start_server();
        let mut stream = connect_and_auth(port, &key);

        let cmd = pickle_dict(vec![("get", pickle_string("link_count"))]);
        let resp = rpc_call(&mut stream, &cmd);

        match resp {
            Value::I64(n) => assert_eq!(n, 0),
            other => panic!("expected I64, got {:?}", other),
        }
        srv.stop();
    }

    #[test]
    fn test_rpc_get_path_table_empty() {
        let (srv, port, key) = start_server();
        let mut stream = connect_and_auth(port, &key);

        let cmd = pickle_dict(vec![
            ("get", pickle_string("path_table")),
            ("max_hops", pickle_none()),
        ]);
        let resp = rpc_call(&mut stream, &cmd);

        match resp {
            Value::List(entries) => assert!(entries.is_empty()),
            other => panic!("expected List, got {:?}", other),
        }
        srv.stop();
    }

    #[test]
    fn test_rpc_get_interface_stats() {
        let (srv, port, key) = start_server();
        let mut stream = connect_and_auth(port, &key);

        let cmd = pickle_dict(vec![("get", pickle_string("interface_stats"))]);
        let resp = rpc_call(&mut stream, &cmd);

        match resp {
            Value::Dict(d) => {
                assert!(d.contains_key(&HashableValue::String("interfaces".into())));
            }
            other => panic!("expected Dict, got {:?}", other),
        }
        srv.stop();
    }

    #[test]
    fn test_rpc_drop_announce_queues() {
        let (srv, port, key) = start_server();
        let mut stream = connect_and_auth(port, &key);

        let cmd = pickle_dict(vec![("drop", pickle_string("announce_queues"))]);
        let resp = rpc_call(&mut stream, &cmd);

        match resp {
            Value::Bool(true) => {}
            other => panic!("expected Bool(true), got {:?}", other),
        }
        srv.stop();
    }

    #[test]
    fn test_rpc_unknown_get_returns_none() {
        let (srv, port, key) = start_server();
        let mut stream = connect_and_auth(port, &key);

        let cmd = pickle_dict(vec![("get", pickle_string("nonexistent"))]);
        let resp = rpc_call(&mut stream, &cmd);

        assert!(matches!(resp, Value::None));
        srv.stop();
    }

    #[test]
    fn test_rpc_get_rate_table_empty() {
        let (srv, port, key) = start_server();
        let mut stream = connect_and_auth(port, &key);

        let cmd = pickle_dict(vec![("get", pickle_string("rate_table"))]);
        let resp = rpc_call(&mut stream, &cmd);

        match resp {
            Value::List(entries) => assert!(entries.is_empty()),
            other => panic!("expected List, got {:?}", other),
        }
        srv.stop();
    }
}
