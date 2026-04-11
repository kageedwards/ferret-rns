// BackboneInterface — high-performance TCP server/client with HDLC framing
// and a large HW_MTU (1 MB) for backbone links.
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/BackboneInterface.py
//
// The Python reference uses a shared epoll loop across all backbone listeners
// and spawned clients. In this Rust port we use the simpler per-connection
// thread model (same as TCPServerInterface) which is already efficient for
// the expected connection counts. The `mio` dependency is available for a
// future migration to an event-loop model if needed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::hdlc_codec::{self, HdlcDecoder};
use crate::Result;

// ── Constants ──

/// Hardware MTU for backbone links (1 MB).
pub const HW_MTU: usize = 1_048_576;
/// Bitrate guess for backbone links (1 Gbps).
pub const BITRATE_GUESS: u64 = 1_000_000_000;
/// Default IFAC size.
pub const DEFAULT_IFAC_SIZE: usize = 16;

const INITIAL_CONNECT_TIMEOUT: u64 = 5;
const RECONNECT_WAIT: u64 = 5;

// ── BackboneInterface (server) ──

pub struct BackboneInterface {
    pub base: Arc<Interface>,
    pub bind_ip: String,
    pub bind_port: u16,
    pub prefer_ipv6: bool,
    pub spawned: Mutex<Vec<Arc<BackboneClientInterface>>>,
    listener: Mutex<Option<TcpListener>>,
    shutdown: AtomicBool,
}

impl BackboneInterface {
    /// Bind a TCP listener and spawn an accept loop thread.
    pub fn bind(
        bind_ip: String,
        bind_port: u16,
        name: String,
        prefer_ipv6: bool,
    ) -> Result<Arc<Self>> {
        let addr = format!("{}:{}", bind_ip, bind_port);
        let listener = TcpListener::bind(&addr).map_err(|e| {
            crate::FerretError::InterfaceConnectionFailed(format!(
                "Backbone bind failed on {}: {}",
                addr, e
            ))
        })?;

        // Server doesn't transmit directly — spawned clients do.
        let mut base = Interface::new(name, None);
        base.bitrate = BITRATE_GUESS;
        base.dir_in = false;
        base.dir_out = false;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base),
            bind_ip,
            bind_port,
            prefer_ipv6,
            spawned: Mutex::new(Vec::new()),
            listener: Mutex::new(Some(listener)),
            shutdown: AtomicBool::new(false),
        });

        let iface_clone = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("bb-srv-{}", iface.base.name))
            .spawn(move || iface_clone.accept_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {}", e)))?;

        Ok(iface)
    }

    /// Accept incoming connections, spawning a BackboneClientInterface for each.
    fn accept_loop(self: &Arc<Self>) {
        let listener = {
            let guard = self.listener.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref().and_then(|l| l.try_clone().ok()) {
                Some(l) => l,
                None => return,
            }
        };

        for stream in listener.incoming() {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let stream = match stream {
                Ok(s) => s,
                Err(_) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
            };

            let client_name = format!("Client on {}", self.base.name);
            let client = match BackboneClientInterface::from_socket(stream, client_name) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut spawned = self.spawned.lock().unwrap_or_else(|e| e.into_inner());
            spawned.retain(|c| !c.base.detached.load(Ordering::Relaxed));
            spawned.push(client);
        }
    }

    /// Shut down the server and all spawned client interfaces.
    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);

        {
            let mut guard = self.listener.lock().unwrap_or_else(|e| e.into_inner());
            let _ = guard.take();
        }

        let spawned = self.spawned.lock().unwrap_or_else(|e| e.into_inner());
        for client in spawned.iter() {
            client.detach();
        }
    }
}

// ── BackboneClientInterface ──

pub struct BackboneClientInterface {
    pub base: Arc<Interface>,
    pub target_ip: String,
    pub target_port: u16,
    pub initiator: bool,
    pub max_reconnect_tries: Option<u32>,
    socket: Mutex<Option<TcpStream>>,
    shutdown: AtomicBool,
}

impl BackboneClientInterface {
    /// Connect to a remote backbone host as initiator.
    pub fn connect(
        target_ip: String,
        target_port: u16,
        name: String,
        max_reconnect_tries: Option<u32>,
    ) -> Result<Arc<Self>> {
        let addr = format!("{}:{}", target_ip, target_port);
        let sock_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr.as_str())
            .map_err(|e| {
                crate::FerretError::InterfaceConnectionFailed(format!(
                    "cannot resolve {}: {}", addr, e
                ))
            })?
            .next()
            .ok_or_else(|| {
                crate::FerretError::InterfaceConnectionFailed(format!(
                    "no addresses found for {}", addr
                ))
            })?;
        let stream = TcpStream::connect_timeout(
            &sock_addr,
            Duration::from_secs(INITIAL_CONNECT_TIMEOUT),
        )?;
        stream.set_nodelay(true)?;

        let iface = Self::build(stream, name, target_ip, target_port, true, max_reconnect_tries)?;

        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("bb-read-{}", iface.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {}", e)))?;

        Ok(iface)
    }

    /// Wrap an already-accepted socket (used by BackboneInterface server).
    pub fn from_socket(socket: TcpStream, name: String) -> Result<Arc<Self>> {
        let _ = socket.set_nodelay(true);
        let (ip, port) = socket
            .peer_addr()
            .map(|a| (a.ip().to_string(), a.port()))
            .unwrap_or_default();

        let iface = Self::build(socket, name, ip, port, false, None)?;

        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("bb-read-{}", iface.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {}", e)))?;

        Ok(iface)
    }

    fn build(
        socket: TcpStream,
        name: String,
        target_ip: String,
        target_port: u16,
        initiator: bool,
        max_reconnect_tries: Option<u32>,
    ) -> Result<Arc<Self>> {
        let tx_stream = socket.try_clone()?;
        let tx = Arc::new(Mutex::new(tx_stream));

        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx);
            Box::new(move |data: &[u8]| {
                let framed = hdlc_codec::encode(data);
                let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                guard.write_all(&framed).map_err(|e| {
                    crate::FerretError::InterfaceError(format!("Backbone write error: {}", e))
                })
            })
        };

        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE_GUESS;
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);
        base.autoconfigure_mtu = true;
        base.optimise_mtu();

        Ok(Arc::new(Self {
            base: Arc::new(base),
            target_ip,
            target_port,
            initiator,
            max_reconnect_tries,
            socket: Mutex::new(Some(socket)),
            shutdown: AtomicBool::new(false),
        }))
    }

    /// Read loop — reads bytes, decodes HDLC frames, delivers to base.
    fn read_loop(self: &Arc<Self>) {
        let mut decoder = HdlcDecoder::new(HW_MTU);
        let mut buf = [0u8; 4096];
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let n = {
                let mut guard = self.socket.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_mut() {
                    Some(s) => match s.read(&mut buf) {
                        Ok(0) | Err(_) => 0,
                        Ok(n) => n,
                    },
                    None => break,
                }
            };
            if n == 0 {
                self.handle_disconnect();
                break;
            }
            for frame in decoder.feed(&buf[..n]) {
                if !frame.is_empty() {
                    self.base.process_incoming(&frame);
                }
            }
        }
    }

    fn handle_disconnect(self: &Arc<Self>) {
        self.base.online.store(false, Ordering::Relaxed);
        if self.initiator && !self.shutdown.load(Ordering::Relaxed) {
            self.reconnect();
        } else {
            self.detach();
        }
    }

    fn reconnect(self: &Arc<Self>) {
        if !self.initiator || self.shutdown.load(Ordering::Relaxed) {
            return;
        }

        let mut attempts = 0u32;
        while !self.base.online.load(Ordering::Relaxed) {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_secs(RECONNECT_WAIT));
            attempts += 1;

            if let Some(max) = self.max_reconnect_tries {
                if attempts > max {
                    self.detach();
                    break;
                }
            }

            let addr = format!("{}:{}", self.target_ip, self.target_port);
            if let Ok(mut addrs) = std::net::ToSocketAddrs::to_socket_addrs(&addr.as_str()) {
                if let Some(sock_addr) = addrs.next() {
                    if let Ok(stream) =
                        TcpStream::connect_timeout(&sock_addr, Duration::from_secs(INITIAL_CONNECT_TIMEOUT))
                    {
                        let _ = stream.set_nodelay(true);
                        *self.socket.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream);
                        self.base.online.store(true, Ordering::Relaxed);
                    }
                }
            }
        }

        // If reconnected, spawn a new read loop
        if self.base.online.load(Ordering::Relaxed) && !self.shutdown.load(Ordering::Relaxed) {
            let c = Arc::clone(self);
            let _ = std::thread::Builder::new()
                .name(format!("bb-read-{}", self.base.name))
                .spawn(move || c.read_loop());
        }
    }

    /// Shut down the interface.
    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);

        if let Some(stream) = self.socket.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}
