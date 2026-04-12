//! Local RPC server for shared-instance queries.
//!
//! Listens on `127.0.0.1:<control_port>` for authenticated MessagePack
//! requests. The first message on each connection must contain the RPC key.
//! Supported commands: get path_table / interface_stats / rate_table /
//! link_count, drop path / announce_queues.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::transport::TransportState;
use crate::{log_debug, log_warning};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
struct RpcResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entries: Option<Vec<Vec<u8>>>,
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
    /// them, and dispatches commands. Returns an `Arc<Self>` so the caller
    /// can later call `stop()`.
    pub fn start(
        port: u16,
        rpc_key: Vec<u8>,
        shutdown: Arc<AtomicBool>,
        transport: TransportState,
    ) -> Result<Arc<Self>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        // Non-blocking so the accept loop can check the shutdown flag.
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
    // Internal
    // -----------------------------------------------------------------------

    fn accept_loop(&self) {
        let listener = match self.listener.as_ref() {
            Some(l) => l,
            None => return,
        };

        while !self.shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _addr)) => {
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

    fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        let request = Self::read_request(&mut stream)?;

        // Authenticate
        if request.key != self.rpc_key {
            let resp = RpcResponse {
                ok: false,
                error: Some("authentication failed".into()),
                count: None,
                entries: None,
            };
            Self::write_response(&mut stream, &resp)?;
            return Ok(());
        }

        let resp = self.dispatch(&request);
        Self::write_response(&mut stream, &resp)?;
        Ok(())
    }

    fn dispatch(&self, req: &RpcRequest) -> RpcResponse {
        if let Some(ref cmd) = req.get {
            match cmd.as_str() {
                "path_table" => self.dispatch_get_path_table(req),
                "interface_stats" => self.dispatch_get_interface_stats(),
                "rate_table" => self.dispatch_get_rate_table(),
                "link_count" => self.dispatch_get_link_count(),
                _ => RpcResponse {
                    ok: false,
                    error: Some(format!("unknown get command: {cmd}")),
                    count: None,
                    entries: None,
                },
            }
        } else if let Some(ref cmd) = req.drop {
            match cmd.as_str() {
                "path" => self.dispatch_drop_path(req),
                "announce_queues" => self.dispatch_drop_announce_queues(),
                _ => RpcResponse {
                    ok: false,
                    error: Some(format!("unknown drop command: {cmd}")),
                    count: None,
                    entries: None,
                },
            }
        } else {
            RpcResponse {
                ok: false,
                error: Some("no command specified".into()),
                count: None,
                entries: None,
            }
        }
    }

    fn dispatch_get_path_table(&self, req: &RpcRequest) -> RpcResponse {
        let inner = match self.transport.read() {
            Ok(guard) => guard,
            Err(e) => return Self::error_response(format!("transport read error: {e}")),
        };
        let max_hops = req.max_hops.unwrap_or(u8::MAX);
        let mut entries = Vec::new();
        for (dest_hash, entry) in &inner.path_table {
            if entry.hops > max_hops {
                continue;
            }
            let iface_hash = entry.receiving_interface.interface_hash().to_vec();
            let row: (Vec<u8>, u8, f64, f64, Vec<u8>) = (
                dest_hash.to_vec(),
                entry.hops,
                entry.timestamp,
                entry.expires,
                iface_hash,
            );
            match rmp_serde::to_vec(&row) {
                Ok(bytes) => entries.push(bytes),
                Err(e) => return Self::error_response(format!("serialize path entry: {e}")),
            }
        }
        RpcResponse {
            ok: true,
            error: None,
            count: None,
            entries: Some(entries),
        }
    }

    fn dispatch_get_interface_stats(&self) -> RpcResponse {
        let inner = match self.transport.read() {
            Ok(guard) => guard,
            Err(e) => return Self::error_response(format!("transport read error: {e}")),
        };
        let mut entries = Vec::new();
        for iface in &inner.interfaces {
            let row: (String, u64, u64, bool, u8) = (
                iface.name().to_string(),
                iface.rxb(),
                iface.txb(),
                iface.is_online(),
                iface.mode() as u8,
            );
            match rmp_serde::to_vec(&row) {
                Ok(bytes) => entries.push(bytes),
                Err(e) => return Self::error_response(format!("serialize interface stat: {e}")),
            }
        }
        RpcResponse {
            ok: true,
            error: None,
            count: None,
            entries: Some(entries),
        }
    }

    fn dispatch_get_rate_table(&self) -> RpcResponse {
        let inner = match self.transport.read() {
            Ok(guard) => guard,
            Err(e) => return Self::error_response(format!("transport read error: {e}")),
        };
        let mut entries = Vec::new();
        for (dest_hash, timestamps) in &inner.announce_rate_table {
            let row: (Vec<u8>, Vec<f64>) = (dest_hash.to_vec(), timestamps.clone());
            match rmp_serde::to_vec(&row) {
                Ok(bytes) => entries.push(bytes),
                Err(e) => return Self::error_response(format!("serialize rate entry: {e}")),
            }
        }
        RpcResponse {
            ok: true,
            error: None,
            count: None,
            entries: Some(entries),
        }
    }

    fn dispatch_get_link_count(&self) -> RpcResponse {
        let inner = match self.transport.read() {
            Ok(guard) => guard,
            Err(e) => return Self::error_response(format!("transport read error: {e}")),
        };
        let count = (inner.pending_links.len() + inner.active_links.len()) as u64;
        RpcResponse {
            ok: true,
            error: None,
            count: Some(count),
            entries: None,
        }
    }

    fn dispatch_drop_path(&self, req: &RpcRequest) -> RpcResponse {
        let dest_hash_bytes = match req.destination_hash.as_ref() {
            Some(h) => h,
            None => {
                return Self::error_response("drop path requires destination_hash".into());
            }
        };
        if dest_hash_bytes.len() != 16 {
            return Self::error_response(format!(
                "destination_hash must be 16 bytes, got {}",
                dest_hash_bytes.len()
            ));
        }
        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(dest_hash_bytes);
        match self.transport.expire_path(&dest_hash) {
            Ok(()) => RpcResponse {
                ok: true,
                error: None,
                count: None,
                entries: None,
            },
            Err(e) => Self::error_response(format!("expire_path error: {e}")),
        }
    }

    fn dispatch_drop_announce_queues(&self) -> RpcResponse {
        match self.transport.write() {
            Ok(mut inner) => {
                inner.announce_table.clear();
                RpcResponse {
                    ok: true,
                    error: None,
                    count: None,
                    entries: None,
                }
            }
            Err(e) => Self::error_response(format!("transport write error: {e}")),
        }
    }

    fn error_response(msg: String) -> RpcResponse {
        RpcResponse {
            ok: false,
            error: Some(msg),
            count: None,
            entries: None,
        }
    }

    // -----------------------------------------------------------------------
    // Framing: 4-byte big-endian length prefix + msgpack payload
    // -----------------------------------------------------------------------

    fn read_request(stream: &mut TcpStream) -> Result<RpcRequest> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1_048_576 {
            return Err(crate::error::FerretError::Deserialization(
                "RPC request too large".into(),
            ));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        rmp_serde::from_slice(&buf).map_err(|e| {
            crate::error::FerretError::Deserialization(format!("RPC decode: {e}"))
        })
    }

    fn write_response(stream: &mut TcpStream, resp: &RpcResponse) -> Result<()> {
        let payload = rmp_serde::to_vec_named(resp).map_err(|e| {
            crate::error::FerretError::Serialization(format!("RPC encode: {e}"))
        })?;
        let len = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(&payload)?;
        stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportState;
    use std::net::TcpStream;

    fn send_request(port: u16, req: &RpcRequest) -> RpcResponse {
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

    fn start_server() -> (Arc<RpcServer>, u16, Vec<u8>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let key = vec![1, 2, 3, 4];
        let transport = TransportState::new();
        let srv = RpcServer::start(0, key.clone(), shutdown, transport).unwrap();
        let port = srv.listener.as_ref().unwrap().local_addr().unwrap().port();
        // Give the accept loop a moment to start.
        thread::sleep(Duration::from_millis(50));
        (srv, port, key)
    }

    #[test]
    fn test_rpc_auth_failure() {
        let (srv, port, _key) = start_server();
        let req = RpcRequest {
            key: vec![9, 9, 9],
            get: Some("link_count".into()),
            drop: None,
            max_hops: None,
            destination_hash: None,
        };
        let resp = send_request(port, &req);
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("authentication"));
        srv.stop();
    }

    #[test]
    fn test_rpc_get_link_count() {
        let (srv, port, key) = start_server();
        let req = RpcRequest {
            key,
            get: Some("link_count".into()),
            drop: None,
            max_hops: None,
            destination_hash: None,
        };
        let resp = send_request(port, &req);
        assert!(resp.ok);
        assert_eq!(resp.count, Some(0));
        srv.stop();
    }

    #[test]
    fn test_rpc_get_path_table() {
        let (srv, port, key) = start_server();
        let req = RpcRequest {
            key,
            get: Some("path_table".into()),
            drop: None,
            max_hops: None,
            destination_hash: None,
        };
        let resp = send_request(port, &req);
        assert!(resp.ok);
        assert_eq!(resp.entries, Some(vec![]));
        srv.stop();
    }

    #[test]
    fn test_rpc_drop_announce_queues() {
        let (srv, port, key) = start_server();
        let req = RpcRequest {
            key,
            get: None,
            drop: Some("announce_queues".into()),
            max_hops: None,
            destination_hash: None,
        };
        let resp = send_request(port, &req);
        assert!(resp.ok);
        srv.stop();
    }

    #[test]
    fn test_rpc_unknown_command() {
        let (srv, port, key) = start_server();
        let req = RpcRequest {
            key,
            get: Some("nonexistent".into()),
            drop: None,
            max_hops: None,
            destination_hash: None,
        };
        let resp = send_request(port, &req);
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("unknown"));
        srv.stop();
    }
}
