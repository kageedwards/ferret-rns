// TCPClientInterface — TCP client with HDLC or KISS framing.
//
// Ported from the Python reference: lxcf/_ref_rns/Interfaces/TCPInterface.py

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::SockRef;

use crate::interfaces::base::Interface;
use crate::interfaces::hdlc_codec::{self, HdlcDecoder};
use crate::interfaces::kiss_codec::{self, KissDecoder};
use crate::Result;

// ── Constants ──

pub const TCP_USER_TIMEOUT: u32 = 24;
pub const TCP_PROBE_AFTER: u32 = 5;
pub const TCP_PROBE_INTERVAL: u32 = 2;
pub const TCP_PROBES: u32 = 12;
pub const INITIAL_CONNECT_TIMEOUT: u64 = 5;
pub const RECONNECT_WAIT: u64 = 5;

pub const I2P_USER_TIMEOUT: u32 = 45;
pub const I2P_PROBE_AFTER: u32 = 10;
pub const I2P_PROBE_INTERVAL: u32 = 9;
pub const I2P_PROBES: u32 = 5;

pub const BITRATE_GUESS: u64 = 10_000_000;
pub const DEFAULT_IFAC_SIZE: usize = 16;

/// HW_MTU for TCP interfaces (matches Python reference TCPInterface.HW_MTU).
const HW_MTU: usize = 262_144;

// ── TCPClientInterface ──

pub struct TCPClientInterface {
    pub base: Arc<Interface>,
    pub target_ip: String,
    pub target_port: u16,
    pub initiator: bool,
    pub kiss_framing: bool,
    pub i2p_tunneled: bool,
    pub reconnecting: AtomicBool,
    pub max_reconnect_tries: Option<u32>,
    socket: Mutex<Option<TcpStream>>,
    shutdown: AtomicBool,
}

impl TCPClientInterface {
    /// Connect to a remote host. Returns an Arc<Self> with a read thread running.
    pub fn connect(
        target_ip: String,
        target_port: u16,
        name: String,
        kiss_framing: bool,
        i2p_tunneled: bool,
        max_reconnect_tries: Option<u32>,
    ) -> Result<Arc<Self>> {
        let addr = format!("{}:{}", target_ip, target_port);
        let stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| {
                crate::FerretError::InterfaceConnectionFailed(format!(
                    "invalid address {}: {}",
                    addr, e
                ))
            })?,
            Duration::from_secs(INITIAL_CONNECT_TIMEOUT),
        )?;
        stream.set_nodelay(true)?;
        configure_keepalive(&stream, i2p_tunneled)?;

        let socket_for_tx = stream.try_clone()?;
        let tx_mutex = Arc::new(Mutex::new(socket_for_tx));
        let kiss = kiss_framing;

        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx_mutex);
            Box::new(move |data: &[u8]| {
                let framed = if kiss {
                    kiss_codec::encode_data(data)
                } else {
                    hdlc_codec::encode(data)
                };
                let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                guard.write_all(&framed).map_err(|e| {
                    crate::FerretError::InterfaceError(format!("TCP write error: {}", e))
                })?;
                Ok(())
            })
        };

        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE_GUESS;
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);
        base.autoconfigure_mtu = true;
        base.optimise_mtu();

        let iface = Arc::new(Self {
            base: Arc::new(base),
            target_ip,
            target_port,
            initiator: true,
            kiss_framing,
            i2p_tunneled,
            reconnecting: AtomicBool::new(false),
            max_reconnect_tries,
            socket: Mutex::new(Some(stream)),
            shutdown: AtomicBool::new(false),
        });

        // Spawn read thread
        let iface_clone = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("tcp-read-{}", iface.base.name))
            .spawn(move || iface_clone.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {}", e)))?;

        Ok(iface)
    }

    /// Wrap an already-connected socket (used by TCPServerInterface for accepted connections).
    pub fn from_socket(
        socket: TcpStream,
        name: String,
        kiss_framing: bool,
        i2p_tunneled: bool,
    ) -> Result<Arc<Self>> {
        socket.set_nodelay(true)?;
        configure_keepalive(&socket, i2p_tunneled)?;

        let peer = socket.peer_addr().ok();
        let (target_ip, target_port) = match peer {
            Some(a) => (a.ip().to_string(), a.port()),
            None => (String::new(), 0),
        };

        let socket_for_tx = socket.try_clone()?;
        let tx_mutex = Arc::new(Mutex::new(socket_for_tx));
        let kiss = kiss_framing;

        let transmit_fn: Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = {
            let tx = Arc::clone(&tx_mutex);
            Box::new(move |data: &[u8]| {
                let framed = if kiss {
                    kiss_codec::encode_data(data)
                } else {
                    hdlc_codec::encode(data)
                };
                let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                guard.write_all(&framed).map_err(|e| {
                    crate::FerretError::InterfaceError(format!("TCP write error: {}", e))
                })?;
                Ok(())
            })
        };

        let mut base = Interface::new(name, Some(transmit_fn));
        base.bitrate = BITRATE_GUESS;
        base.dir_in = true;
        base.dir_out = true;
        base.online.store(true, Ordering::Relaxed);
        base.autoconfigure_mtu = true;
        base.optimise_mtu();

        let iface = Arc::new(Self {
            base: Arc::new(base),
            target_ip,
            target_port,
            initiator: false,
            kiss_framing,
            i2p_tunneled,
            reconnecting: AtomicBool::new(false),
            max_reconnect_tries: None,
            socket: Mutex::new(Some(socket)),
            shutdown: AtomicBool::new(false),
        });

        let iface_clone = Arc::clone(&iface);
        std::thread::Builder::new()
            .name(format!("tcp-read-{}", iface.base.name))
            .spawn(move || iface_clone.read_loop())
            .map_err(|e| crate::FerretError::InterfaceError(format!("spawn error: {}", e)))?;

        Ok(iface)
    }

    /// Read loop — reads bytes from the socket, decodes frames, delivers to base.
    fn read_loop(self: &Arc<Self>) {
        let mut buf = [0u8; 4096];

        if self.kiss_framing {
            let mut decoder = KissDecoder::new(HW_MTU);
            loop {
                if self.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let n = {
                    let mut guard = self.socket.lock().unwrap_or_else(|e| e.into_inner());
                    match guard.as_mut() {
                        Some(s) => match s.read(&mut buf) {
                            Ok(0) => 0,
                            Ok(n) => n,
                            Err(_) => 0,
                        },
                        None => break,
                    }
                };
                if n == 0 {
                    self.handle_disconnect();
                    break;
                }
                for frame in decoder.feed(&buf[..n]) {
                    if frame.command == kiss_codec::CMD_DATA && !frame.data.is_empty() {
                        self.base.process_incoming(&frame.data);
                    }
                }
            }
        } else {
            let mut decoder = HdlcDecoder::new(HW_MTU);
            loop {
                if self.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let n = {
                    let mut guard = self.socket.lock().unwrap_or_else(|e| e.into_inner());
                    match guard.as_mut() {
                        Some(s) => match s.read(&mut buf) {
                            Ok(0) => 0,
                            Ok(n) => n,
                            Err(_) => 0,
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
    }

    /// Handle a disconnect: if initiator, reconnect; otherwise detach.
    fn handle_disconnect(self: &Arc<Self>) {
        self.base.online.store(false, Ordering::Relaxed);
        if self.initiator && !self.shutdown.load(Ordering::Relaxed) {
            self.reconnect();
        } else {
            self.detach();
        }
    }

    /// Attempt to reconnect with delay and max retries.
    fn reconnect(self: &Arc<Self>) {
        if !self.initiator || self.shutdown.load(Ordering::Relaxed) {
            return;
        }
        if self.reconnecting.swap(true, Ordering::SeqCst) {
            return; // already reconnecting
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
            if let Ok(parsed) = addr.parse() {
                if let Ok(stream) =
                    TcpStream::connect_timeout(&parsed, Duration::from_secs(INITIAL_CONNECT_TIMEOUT))
                {
                    let _ = stream.set_nodelay(true);
                    let _ = configure_keepalive(&stream, self.i2p_tunneled);
                    {
                        let mut guard = self.socket.lock().unwrap_or_else(|e| e.into_inner());
                        *guard = Some(stream);
                    }
                    self.base.online.store(true, Ordering::Relaxed);
                }
            }
        }

        self.reconnecting.store(false, Ordering::Relaxed);

        // If we reconnected, spawn a new read loop
        if self.base.online.load(Ordering::Relaxed) && !self.shutdown.load(Ordering::Relaxed) {
            let iface_clone = Arc::clone(self);
            let _ = std::thread::Builder::new()
                .name(format!("tcp-read-{}", self.base.name))
                .spawn(move || iface_clone.read_loop());
        }
    }

    /// Shut down the interface.
    pub fn detach(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.base.online.store(false, Ordering::Relaxed);
        self.base.detached.store(true, Ordering::Relaxed);

        let mut guard = self.socket.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stream) = guard.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

// ── Keepalive configuration ──

fn configure_keepalive(stream: &TcpStream, i2p_tunneled: bool) -> Result<()> {
    let sock = SockRef::from(stream);
    let keepalive = if i2p_tunneled {
        socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(I2P_PROBE_AFTER as u64))
            .with_interval(Duration::from_secs(I2P_PROBE_INTERVAL as u64))
    } else {
        socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(TCP_PROBE_AFTER as u64))
            .with_interval(Duration::from_secs(TCP_PROBE_INTERVAL as u64))
    };
    sock.set_tcp_keepalive(&keepalive)?;
    Ok(())
}
