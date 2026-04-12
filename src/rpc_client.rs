//! RPC client for connecting to the shared-instance control port.
//!
//! Speaks the Python `multiprocessing.connection` wire protocol with
//! mutual HMAC-SHA256 challenge-response authentication, matching the
//! server implementation in `reticulum::rpc`.
//!
//! ## Usage
//!
//! ```no_run
//! use ferret_rns::rpc_client::RpcClient;
//!
//! let mut client = RpcClient::connect(37429, b"my_rpc_key").unwrap();
//! let stats = client.get("interface_stats").unwrap();
//! ```

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_pickle::value::{HashableValue, Value};

use crate::crypto::hmac::hmac_sha256;
use crate::error::{FerretError, Result};

// ---------------------------------------------------------------------------
// Constants (must match reticulum::rpc)
// ---------------------------------------------------------------------------

const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
const DIGEST_PREFIX: &[u8] = b"{sha256}";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";
const CHALLENGE_RANDOM_LEN: usize = 40;
const MAX_FRAME_LEN: i32 = 1_048_576; // 1 MiB
const DEFAULT_TIMEOUT_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Wire helpers (duplicated from rpc.rs — small enough to not warrant shared)
// ---------------------------------------------------------------------------

/// Send a length-prefixed frame.
fn send_bytes(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as i32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

/// Receive a length-prefixed frame.
fn recv_bytes(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = i32::from_be_bytes(len_buf);
    if len < 0 || len > MAX_FRAME_LEN {
        return Err(FerretError::Deserialization(
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

fn to_pickle(val: &Value) -> Result<Vec<u8>> {
    serde_pickle::value_to_vec(val, serde_pickle::SerOptions::new())
        .map_err(|e| FerretError::Serialization(format!("pickle encode: {e}")))
}

fn from_pickle(data: &[u8]) -> Result<Value> {
    serde_pickle::value_from_slice(data, serde_pickle::DeOptions::new())
        .map_err(|e| FerretError::Deserialization(format!("pickle decode: {e}")))
}

fn pickle_string(s: &str) -> Value {
    Value::String(s.to_string())
}

fn pickle_dict(entries: Vec<(&str, Value)>) -> Value {
    let mut map = BTreeMap::new();
    for (k, v) in entries {
        map.insert(HashableValue::String(k.to_string()), v);
    }
    Value::Dict(map)
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

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
// RPC key derivation
// ---------------------------------------------------------------------------

/// Derive the RPC authentication key from a transport identity's private key.
///
/// Reads the 64-byte key from `{storagepath}/transport_identity` and returns
/// `SHA-256(private_key)`. This matches the server-side derivation in
/// `reticulum.rs`.
pub fn derive_rpc_key(storage_path: &std::path::Path) -> Result<Vec<u8>> {
    let id_path = storage_path.join("transport_identity");
    let key_bytes = std::fs::read(&id_path).map_err(|e| {
        FerretError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read transport identity from {}: {}", id_path.display(), e),
        ))
    })?;
    let hash = crate::crypto::hashes::sha256(&key_bytes);
    Ok(hash.to_vec())
}

// ---------------------------------------------------------------------------
// RpcClient
// ---------------------------------------------------------------------------

/// Client for the shared-instance RPC control port.
///
/// Connects via TCP, performs mutual HMAC-SHA256 authentication, then
/// sends pickle-encoded commands and receives pickle-encoded responses.
pub struct RpcClient {
    stream: TcpStream,
}

impl RpcClient {
    /// Connect to `127.0.0.1:{port}` and perform mutual HMAC authentication.
    ///
    /// Returns an authenticated client ready to send commands.
    pub fn connect(port: u16, rpc_key: &[u8]) -> Result<Self> {
        let addr = format!("127.0.0.1:{}", port);
        let mut stream = TcpStream::connect(&addr).map_err(|e| {
            FerretError::InterfaceConnectionFailed(
                format!("no shared instance available on port {}: {}", port, e),
            )
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS)))?;
        stream.set_write_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS)))?;

        Self::authenticate(&mut stream, rpc_key)?;

        Ok(Self { stream })
    }

    /// Perform the mutual HMAC-SHA256 challenge-response handshake.
    ///
    /// Step 1: Answer the server's challenge.
    /// Step 2: Challenge the server and verify its response.
    fn authenticate(stream: &mut TcpStream, authkey: &[u8]) -> Result<()> {
        // --- Step 1: Answer server's challenge ---
        let challenge = recv_bytes(stream)?;
        if !challenge.starts_with(CHALLENGE_PREFIX) {
            return Err(FerretError::Token(
                "RPC authentication failed: invalid server challenge".into(),
            ));
        }
        let message = &challenge[CHALLENGE_PREFIX.len()..];
        let mac = hmac_sha256(authkey, message);
        let mut response = Vec::with_capacity(DIGEST_PREFIX.len() + 32);
        response.extend_from_slice(DIGEST_PREFIX);
        response.extend_from_slice(&mac);
        send_bytes(stream, &response)?;

        let result = recv_bytes(stream)?;
        if result != WELCOME {
            return Err(FerretError::Token(
                "RPC authentication failed: server rejected credentials".into(),
            ));
        }

        // --- Step 2: Challenge the server ---
        let mut random_bytes = [0u8; CHALLENGE_RANDOM_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_bytes);

        let mut challenge_msg = Vec::with_capacity(
            CHALLENGE_PREFIX.len() + DIGEST_PREFIX.len() + CHALLENGE_RANDOM_LEN,
        );
        challenge_msg.extend_from_slice(CHALLENGE_PREFIX);
        challenge_msg.extend_from_slice(DIGEST_PREFIX);
        challenge_msg.extend_from_slice(&random_bytes);
        send_bytes(stream, &challenge_msg)?;

        // Verify server's response
        let server_response = recv_bytes(stream)?;
        if server_response.len() < DIGEST_PREFIX.len() {
            return Err(FerretError::Token(
                "RPC authentication failed: invalid server response".into(),
            ));
        }
        let (prefix, server_mac) = server_response.split_at(DIGEST_PREFIX.len());
        if prefix != DIGEST_PREFIX || server_mac.len() != 32 {
            return Err(FerretError::Token(
                "RPC authentication failed: malformed server HMAC".into(),
            ));
        }

        let mut hmac_message = Vec::with_capacity(DIGEST_PREFIX.len() + CHALLENGE_RANDOM_LEN);
        hmac_message.extend_from_slice(DIGEST_PREFIX);
        hmac_message.extend_from_slice(&random_bytes);
        let expected_mac = hmac_sha256(authkey, &hmac_message);

        if !constant_time_eq(server_mac, &expected_mac) {
            send_bytes(stream, FAILURE)?;
            return Err(FerretError::Token(
                "RPC authentication failed: server HMAC mismatch".into(),
            ));
        }

        send_bytes(stream, WELCOME)?;
        Ok(())
    }

    /// Send a pickle command and receive the response.
    pub fn call(&mut self, command: &Value) -> Result<Value> {
        let payload = to_pickle(command)?;
        send_bytes(&mut self.stream, &payload)?;
        let response_bytes = recv_bytes(&mut self.stream)?;
        from_pickle(&response_bytes)
    }

    /// Send `{"get": cmd}` and return the response.
    pub fn get(&mut self, cmd: &str) -> Result<Value> {
        let command = pickle_dict(vec![("get", pickle_string(cmd))]);
        self.call(&command)
    }

    /// Send `{"get": cmd, extra_key: extra_val, ...}` and return the response.
    pub fn get_with(&mut self, cmd: &str, extras: &[(&str, Value)]) -> Result<Value> {
        let mut entries: Vec<(&str, Value)> = vec![("get", pickle_string(cmd))];
        for (k, v) in extras {
            entries.push((k, v.clone()));
        }
        let command = pickle_dict(entries);
        self.call(&command)
    }

    /// Send `{"drop": cmd}` and return the response.
    pub fn drop_cmd(&mut self, cmd: &str) -> Result<Value> {
        let command = pickle_dict(vec![("drop", pickle_string(cmd))]);
        self.call(&command)
    }

    /// Send `{"drop": cmd, extra_key: extra_val, ...}` and return the response.
    pub fn drop_with(&mut self, cmd: &str, extras: &[(&str, Value)]) -> Result<Value> {
        let mut entries: Vec<(&str, Value)> = vec![("drop", pickle_string(cmd))];
        for (k, v) in extras {
            entries.push((k, v.clone()));
        }
        let command = pickle_dict(entries);
        self.call(&command)
    }
}
