// LocalInterface — local shared-instance interface using TCP loopback + HDLC framing.
// Ported from lxcf/_ref_rns/Interfaces/LocalInterface.py

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::interfaces::base::Interface;
use crate::interfaces::hdlc_codec::{self, HdlcDecoder};
use crate::Result;

/// Loopback bitrate: 1 Gbps.
pub const BITRATE: u64 = 1_000_000_000;
/// Reconnect delay for client (seconds).
const RECONNECT_WAIT: u64 = 8;

// ── LocalServerInterface ──

pub struct LocalServerInterface {
    pub base: Arc<Interface>,
    pub bind_addr: String,
    pub bind_port: u16,
    pub spawned: Mutex<Vec<Arc<LocalClientInterface>>>,
    listener: Mutex<Option<TcpListener>>,
    shutdown: AtomicBool,
}

impl LocalServerInterface {
    /// Bind a TCP listener on loopback and spawn an accept loop.
    pub fn bind(bind_addr: String, bind_port: u16, name: String) -> Result<Arc<Self>> {
        let addr = format!("{}:{}", bind_addr, bind_port);
        let listener = TcpListener::bind(&addr).map_err(|e| {
            crate::FerretError::InterfaceConnectionFailed(format!("Local bind {}: {}", addr, e))
        })?;
        // Server doesn't transmit directly — spawned clients do.
        let mut base = Interface::new(name, None);
        base.bitrate = BITRATE;
        base.online.store(true, Ordering::Relaxed);

        let iface = Arc::new(Self {
            base: Arc::new(base),
            bind_addr, bind_port,
            spawned: Mutex::new(Vec::new()),
            listener: Mutex::new(Some(listener)),
            shutdown: AtomicBool::new(false),
        });
        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("local-srv-{}", iface.base.name))
            .spawn(move || c.accept_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn: {}", e)))?;
        Ok(iface)
    }

    fn accept_loop(self: &Arc<Self>) {
        let listener = {
            let g = self.listener.lock().unwrap_or_else(|e| e.into_inner());
            match g.as_ref().and_then(|l| l.try_clone().ok()) {
                Some(l) => l,
                None => return,
            }
        };
        crate::log_verbose!("Shared instance listening on {}:{}", self.bind_addr, self.bind_port);
        for stream in listener.incoming() {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            let stream = match stream {
                Ok(s) => s,
                Err(_) => { if self.shutdown.load(Ordering::Relaxed) { break; } continue; }
            };
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into());
            crate::log_verbose!("Local client connected from {}", peer);
            let name = format!("Client on {}", self.base.name);
            match LocalClientInterface::from_socket(stream, name) {
                Ok(client) => {
                    crate::log_debug!("Spawned local client interface for {}", peer);
                    let mut spawned = self.spawned.lock().unwrap_or_else(|e| e.into_inner());
                    spawned.retain(|c| !c.base.detached.load(Ordering::Relaxed));
                    spawned.push(client);
                }
                Err(e) => {
                    crate::log_warning!("Failed to create local client for {}: {}", peer, e);
                }
            }
        }
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
        { let mut g = self.listener.lock().unwrap_or_else(|e| e.into_inner()); let _ = g.take(); }
        let spawned = self.spawned.lock().unwrap_or_else(|e| e.into_inner());
        for c in spawned.iter() { c.detach(); }
    }
}

// ── LocalClientInterface ──

pub struct LocalClientInterface {
    pub base: Arc<Interface>,
    target_addr: String,
    target_port: u16,
    initiator: bool,
    socket: Mutex<Option<TcpStream>>,
    shutdown: AtomicBool,
}

impl LocalClientInterface {
    /// Connect to the shared instance on loopback.
    pub fn connect(target_addr: String, target_port: u16, name: String) -> Result<Arc<Self>> {
        let addr = format!("{}:{}", target_addr, target_port);
        crate::log_debug!("Connecting to shared instance at {}", addr);
        let stream = TcpStream::connect(&addr).map_err(|e| {
            crate::FerretError::InterfaceConnectionFailed(format!("Local connect {}: {}", addr, e))
        })?;
        stream.set_nodelay(true)?;
        crate::log_verbose!("Connected to shared instance at {}", addr);
        let iface = Self::build(stream, name, target_addr, target_port, true)?;
        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("local-read-{}", iface.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn: {}", e)))?;
        Ok(iface)
    }

    /// Wrap an accepted socket (called by LocalServerInterface).
    pub fn from_socket(socket: TcpStream, name: String) -> Result<Arc<Self>> {
        let _ = socket.set_nodelay(true);
        let (addr, port) = socket.peer_addr()
            .map(|a| (a.ip().to_string(), a.port()))
            .unwrap_or_default();
        let iface = Self::build(socket, name, addr, port, false)?;
        let c = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("local-read-{}", iface.base.name))
            .spawn(move || c.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn: {}", e)))?;
        Ok(iface)
    }

    fn build(
        socket: TcpStream, name: String,
        target_addr: String, target_port: u16, initiator: bool,
    ) -> Result<Arc<Self>> {
        let tx_stream = socket.try_clone()?;
        let tx = Arc::new(Mutex::new(tx_stream));
        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx);
            Box::new(move |data: &[u8]| {
                let framed = hdlc_codec::encode(data);
                let mut g = tx.lock().unwrap_or_else(|e| e.into_inner());
                g.write_all(&framed).map_err(|e| {
                    crate::FerretError::InterfaceError(format!("Local write: {}", e))
                })
            })
        };
        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE;
        base.dir_in = true;
        base.online.store(true, Ordering::Relaxed);
        base.autoconfigure_mtu = true;
        base.optimise_mtu();
        // Ingress limiting disabled — trusted local connection.

        Ok(Arc::new(Self {
            base: Arc::new(base),
            target_addr, target_port, initiator,
            socket: Mutex::new(Some(socket)),
            shutdown: AtomicBool::new(false),
        }))
    }

    fn read_loop(self: &Arc<Self>) {
        let hw_mtu = self.base.hw_mtu.unwrap_or(524_288);
        let mut decoder = HdlcDecoder::new(hw_mtu);
        let mut buf = [0u8; 4096];
        crate::log_debug!("Local interface read loop started: {}", self.base.name);
        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            let n = {
                let mut g = self.socket.lock().unwrap_or_else(|e| e.into_inner());
                match g.as_mut() {
                    Some(s) => match s.read(&mut buf) { Ok(0) | Err(_) => 0, Ok(n) => n },
                    None => break,
                }
            };
            if n == 0 { self.handle_disconnect(); break; }
            crate::log_extreme!("{}: received {} bytes", self.base.name, n);
            for frame in decoder.feed(&buf[..n]) {
                if !frame.is_empty() {
                    crate::log_extreme!("{}: decoded frame ({} bytes)", self.base.name, frame.len());
                    self.base.process_incoming(&frame);
                }
            }
        }
        crate::log_debug!("Local interface read loop ended: {}", self.base.name);
    }

    fn handle_disconnect(self: &Arc<Self>) {
        crate::log_verbose!("Local client disconnected: {}:{}", self.target_addr, self.target_port);
        self.base.online.store(false, Ordering::Relaxed);
        if self.initiator && !self.shutdown.load(Ordering::Relaxed) {
            crate::log_debug!("Attempting reconnect to shared instance");
            self.reconnect();
        } else {
            self.detach();
        }
    }

    fn reconnect(self: &Arc<Self>) {
        if !self.initiator || self.shutdown.load(Ordering::Relaxed) { return; }
        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            std::thread::sleep(Duration::from_secs(RECONNECT_WAIT));
            let addr = format!("{}:{}", self.target_addr, self.target_port);
            crate::log_debug!("Reconnecting to shared instance at {}", addr);
            if let Ok(stream) = TcpStream::connect(&addr) {
                let _ = stream.set_nodelay(true);
                *self.socket.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream);
                self.base.online.store(true, Ordering::Relaxed);
                crate::log_verbose!("Reconnected to shared instance at {}", addr);
                break;
            }
        }
        if self.base.online.load(Ordering::Relaxed) && !self.shutdown.load(Ordering::Relaxed) {
            let c = Arc::clone(self);
            let _ = std::thread::Builder::new()
                .name(format!("local-read-{}", self.base.name))
                .spawn(move || c.read_loop());
        }
    }

    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);
        if let Some(s) = self.socket.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}
